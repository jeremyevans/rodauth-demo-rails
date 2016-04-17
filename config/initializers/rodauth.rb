unless ENV['DATABASE_URL']
  $stderr.puts "Must set DATABASE_URL environment variable before running"
  exit(1)
end

require 'sequel'
require 'mail'
require 'roda'
require 'yaml'

DB = Sequel.connect(ENV['DATABASE_URL'])

::Mail.defaults do
  delivery_method :test
end

class RodauthDemo < Roda
  MAILS = {}
  SMS = {}
  MUTEX = Mutex.new

  plugin :render, :escape=>true, :check_paths=>true, :views=>'app/views', :layout=>'layouts/application.html'
  plugin :hooks

  secret = YAML.load(File.read('config/secrets.yml'))['development']['secret_key_base']

  plugin :middleware
  plugin :rodauth, :json=>true, :csrf=>false, :flash=>false do
    enable :change_login, :change_password, :close_account, :create_account,
           :lockout, :login, :logout, :remember, :reset_password, :verify_account,
           :otp, :recovery_codes, :sms_codes, :password_complexity,
           :disallow_password_reuse, :password_expiration, :password_grace_period,
           :account_expiration, :single_session, :jwt, :session_expiration,
           :verify_account_grace_period, :verify_change_login
    max_invalid_logins 2
    allow_password_change_after 60
    verify_account_grace_period 300
    title_instance_variable :@page_title
    only_json? false
    jwt_secret secret
    sms_send do |phone_number, message|
      MUTEX.synchronize{SMS[session_value] = "Would have sent the following SMS to #{phone_number}: #{message}"}
    end
  end

  def last_sms_sent
    MUTEX.synchronize{SMS.delete(rodauth.session_value)}
  end

  def last_mail_sent
    MUTEX.synchronize{MAILS.delete(rodauth.session_value)}
  end

  after do
    Mail::TestMailer.deliveries.each do |mail|
      MUTEX.synchronize{MAILS[rodauth.session_value] = mail}
    end
    Mail::TestMailer.deliveries.clear
  end

  route do |r|
    if r.post? && rodauth.class.route_hash[r.remaining_path] && env['CONTENT_TYPE'] !~ /application\/json/
      # Check CSRF header
      unless valid_authenticity_token?(session, r['authenticity_token'])
        response.status = 400
        response.write view(:content=>"<h1>Invalid authenticity token</h1>")
        r.halt
      end
    end

    rodauth.load_memory
    rodauth.check_session_expiration
    rodauth.update_last_activity
    if session['single_session_check']
      rodauth.check_single_session
    end
    r.rodauth

    r.post "single-session" do
      session['single_session_check'] = !r['d']
      r.redirect '/'
    end
    
    env['roda.flash'] = flash
    env['rodauth'] = rodauth
  end

  ### Rails 4.2 Integration, most code from Rails

  Flash = ActionDispatch::Flash
  def flash
    env[Flash::KEY] ||= Flash::FlashHash.from_session_value(session["flash"])
  end

  def csrf_tag
    "<input type='hidden' name='authenticity_token' value=\"#{masked_authenticity_token(session)}\" />"
  end

  AUTHENTICITY_TOKEN_LENGTH = 32

  # Creates a masked version of the authenticity token that varies
  # on each request. The masking is used to mitigate SSL attacks
  # like BREACH.
  def masked_authenticity_token(session)
    one_time_pad = SecureRandom.random_bytes(AUTHENTICITY_TOKEN_LENGTH)
    encrypted_csrf_token = xor_byte_strings(one_time_pad, real_csrf_token(session))
    masked_token = one_time_pad + encrypted_csrf_token
    Base64.strict_encode64(masked_token)
  end

  # Checks the client's masked token to see if it matches the
  # session token. Essentially the inverse of
  # +masked_authenticity_token+.
  def valid_authenticity_token?(session, encoded_masked_token)
    if encoded_masked_token.nil? || encoded_masked_token.empty? || !encoded_masked_token.is_a?(String)
      return false
    end

    begin
      masked_token = Base64.strict_decode64(encoded_masked_token)
    rescue ArgumentError # encoded_masked_token is invalid Base64
      return false
    end

    # See if it's actually a masked token or not. In order to
    # deploy this code, we should be able to handle any unmasked
    # tokens that we've issued without error.

    if masked_token.length == AUTHENTICITY_TOKEN_LENGTH
      # This is actually an unmasked token. This is expected if
      # you have just upgraded to masked tokens, but should stop
      # happening shortly after installing this gem
      compare_with_real_token masked_token, session

    elsif masked_token.length == AUTHENTICITY_TOKEN_LENGTH * 2
      # Split the token into the one-time pad and the encrypted
      # value and decrypt it
      one_time_pad = masked_token[0...AUTHENTICITY_TOKEN_LENGTH]
      encrypted_csrf_token = masked_token[AUTHENTICITY_TOKEN_LENGTH..-1]
      csrf_token = xor_byte_strings(one_time_pad, encrypted_csrf_token)

      compare_with_real_token csrf_token, session

    else
      false # Token is malformed
    end
  end

  def compare_with_real_token(token, session)
    ActiveSupport::SecurityUtils.secure_compare(token, real_csrf_token(session))
  end

  def real_csrf_token(session)
    session[:_csrf_token] ||= SecureRandom.base64(AUTHENTICITY_TOKEN_LENGTH)
    Base64.strict_decode64(session[:_csrf_token])
  end

  def xor_byte_strings(s1, s2)
    s1.bytes.zip(s2.bytes).map { |(c1,c2)| c1 ^ c2 }.pack('c*')
  end
  
  freeze
end

Rails.application.config.middleware.use RodauthDemo

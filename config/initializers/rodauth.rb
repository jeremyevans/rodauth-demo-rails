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
  secret = YAML.load(File.read('config/secrets.yml'))['development']['secret_key_base']

  plugin :render, :escape=>true, :check_paths=>true, :views=>'app/views', :layout=>'layouts/application.html'
  plugin :hooks
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

  plugin :rails42,
    :check_csrf=>lambda{|r| r.post? && rodauth.class.route_hash[r.remaining_path] && env['CONTENT_TYPE'] !~ /application\/json/},
    :invalid_csrf=>(lambda do |r|
      response.status = 400
      response.write view(:content=>"<h1>Invalid authenticity token</h1>")
      r.halt
    end)

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

  freeze
end

Rails.application.config.middleware.use RodauthDemo

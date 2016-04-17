module ApplicationHelper
  def csrf_tag
    hidden_field_tag :authenticity_token, form_authenticity_token
  end

  def last_sms_sent
    RodauthDemo::MUTEX.synchronize{RodauthDemo::SMS.delete(rodauth.session_value)}
  end

  def last_mail_sent
    RodauthDemo::MUTEX.synchronize{RodauthDemo::MAILS.delete(rodauth.session_value)}
  end
end

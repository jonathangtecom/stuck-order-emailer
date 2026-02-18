import logging
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Email, To, Content

logger = logging.getLogger(__name__)


def send_email(to_email, from_email, from_name, subject, html_content, sendgrid_api_key):
    """Send an HTML email via SendGrid.

    Returns True on success, False on failure.
    """
    try:
        message = Mail(
            from_email=Email(from_email, from_name),
            to_emails=To(to_email),
            subject=subject,
            html_content=Content("text/html", html_content),
        )

        sg = SendGridAPIClient(api_key=sendgrid_api_key)
        response = sg.client.mail.send.post(request_body=message.get())

        if response.status_code in (200, 201, 202):
            logger.info("Email sent to %s (subject: %s)", to_email, subject)
            return True
        else:
            logger.error("SendGrid returned %d for email to %s: %s",
                         response.status_code, to_email, response.body)
            return False

    except Exception as e:
        body = getattr(e, 'body', None)
        logger.error("Failed to send email to %s: %s (body: %s)", to_email, e, body)
        return False

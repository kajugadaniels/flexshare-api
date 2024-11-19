import random
import logging
from twilio.rest import Client
from django.conf import settings
from django.core.mail import send_mail

logger = logging.getLogger(__name__)

def generate_otp(length=7):
    """Generate a numeric OTP of specified length."""
    return ''.join([str(random.randint(0, 9)) for _ in range(length)])

def send_email(subject, message, recipient_list):
    """Send email using Django's send_mail function."""
    from_email = settings.DEFAULT_FROM_EMAIL
    try:
        send_mail(subject, message, from_email, recipient_list)
        return True
    except Exception as e:
        # Log the exception with detailed information
        logger.error(f"Failed to send email to {recipient_list}: {e}", exc_info=True)
        return False

def send_sms(phone_number, message):
    """Send SMS to the specified phone number using Twilio."""
    client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
    try:
        client.messages.create(
            body=message,
            from_=settings.TWILIO_PHONE_NUMBER,
            to=phone_number
        )
        return True
    except Exception as e:
        # Log the exception with detailed information
        logger.error(f"Failed to send SMS to {phone_number}: {e}", exc_info=True)
        return False

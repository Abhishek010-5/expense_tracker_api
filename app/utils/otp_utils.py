import logging
import random
import  string
import smtplib
from email.message import EmailMessage
from app.redisdb import connect_to_redis
import redis

from app.config import settings

logger = logging.getLogger(__name__)


def generate_otp(length: int = 6) -> str:
    """
    Generate a random numeric OTP of specified length.
    """
    if length <= 0:
        logger.error("Invalid OTP length requested: %s", length)
        raise ValueError("OTP length must be positive")
    return "".join(random.choices(string.digits, k=length))

def send_otp_to_user(to_email: str, otp: str) -> bool:
    """
    Send a 6-digit OTP via email using Gmail SMTP.

    Args:
        to_email (str): Recipient email address
        otp (str): The OTP to send

    Returns:
        bool: True if email sent successfully, False otherwise
    """
    if not settings.mail or not settings.mail_password:
        logger.error("Email credentials not configured in settings")
        return False

    sender = settings.mail
    password = settings.mail_password

    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = to_email
    msg["Subject"] = "Your verification code"
    msg.set_content(
        f"Your verification code is {otp}\n\n"
        "It expires in 5 minutes.\n"
        "Do not share this code with anyone."
    )

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender, password)
            server.send_message(msg)
        return True

    except smtplib.SMTPAuthenticationError:
        logger.error("Failed to authenticate with Gmail SMTP (invalid credentials)")
        return False
    except smtplib.SMTPRecipientsRefused:
        logger.error("Recipient email rejected: %s", to_email)
        return False
    except smtplib.SMTPServerDisconnected:
        logger.error("SMTP server disconnected unexpectedly")
        return False
    except Exception as e:
        logger.exception("Unexpected error sending OTP email to %s: %s", to_email, e)
        return False
    
def sendOtp(email: str, expiry_seconds: int = 300) -> bool:
    """
    Generate OTP, store in Redis with expiry, and send via email.

    Args:
        email (str): User's email
        expiry_seconds (int): OTP validity duration

    Returns:
        bool: True if OTP generated, stored, and sent successfully
    """
    try:
        otp = generate_otp()
        key = f"otp:{email}"

        redis_client = connect_to_redis()
        redis_client.set(key, otp, ex=expiry_seconds)

        success = send_otp_to_user(email, otp)
        if success:
            return True
        else:
            # Clean up Redis if email failed
            try:
                redis_client.delete(key)
            except:
                pass
            logger.warning("OTP stored but email failed to send for %s", email)
            return False

    except redis.RedisError as e:
        logger.error("Redis error while storing OTP for %s: %s", email, e)
        return False
    except Exception as e:
        logger.exception("Unexpected error in sendOtp for %s: %s", email, e)
        return False
    
def verify_user_otp(email: str, entered_otp: str) -> bool:
    """
    Verify entered OTP against stored value in Redis.
    Deletes OTP on success (one-time use) or if invalid/expired.

    Returns:
        bool: True only if OTP matches and is valid
    """
    try:
        redis_client = connect_to_redis()
        key = f"otp:{email}"
        stored_otp_bytes = redis_client.get(key)

        if stored_otp_bytes is None:
            logger.info("OTP verification failed: expired or not found for %s", email)
            return False

        stored_otp = stored_otp_bytes.decode('utf-8') if isinstance(stored_otp_bytes, bytes) else stored_otp_bytes

        if stored_otp == entered_otp.strip():
            redis_client.delete(key)
            return True
        else:
            logger.info("Invalid OTP entered for %s", email)
            # Optional: delete on too many failures? Rate limit elsewhere.
            return False

    except redis.RedisError as e:
        logger.error("Redis error during OTP verification for %s: %s", email, e)
        return False
    except Exception as e:
        logger.exception("Unexpected error verifying OTP for %s: %s", email, e)
        return False
    finally:
        # Optional: always clean up on verification attempt?
        # Not recommended — allows replay if not deleted on success
        pass
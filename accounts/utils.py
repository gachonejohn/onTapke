
# utils.py - Create this file for utility functions
from django.core.mail import send_mail
from django.conf import settings
from .models import OTPDevice
import pyotp

# def send_otp_email(user):
#     """Send OTP via email to user"""
#     device, created = OTPDevice.objects.get_or_create(user=user)
#     otp = device.generate_otp()
    
#     subject = "Your Login OTP"
#     message = f"Your OTP for logging in is: {otp}. This code will expire in 5 minutes."
#     from_email = settings.DEFAULT_FROM_EMAIL
#     recipient_list = [user.email]
    
#     send_mail(subject, message, from_email, recipient_list)
#     return True


def send_otp_email(user):
    """Send OTP via email to user"""
    device, created = OTPDevice.objects.get_or_create(user=user)
    
    # Always generate a fresh key for each login attempt for better security
    device.key = pyotp.random_base32()
    device.save()
    
    otp = device.generate_otp()
    
    subject = "Your Login OTP"
    message = f"Your OTP for logging in is: {otp}. This code will expire in 5 minutes."
    from_email = settings.DEFAULT_FROM_EMAIL
    recipient_list = [user.email]
    
    # Add logging for troubleshooting
    try:
        send_mail(subject, message, from_email, recipient_list)
        return True
    except Exception as e:
        # Log the error but don't expose details
        print(f"Error sending OTP email: {str(e)}")
        return False
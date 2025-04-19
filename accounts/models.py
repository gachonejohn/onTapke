# from django.db import models
# from django.contrib.auth.models import AbstractUser, BaseUserManager
# from django.utils.translation import gettext_lazy as _

# class CustomUserManager(BaseUserManager):
#     def create_user(self, email, password=None, **extra_fields):
#         if not email:
#             raise ValueError(_('The Email must be set'))
#         email = self.normalize_email(email)
#         user = self.model(email=email, **extra_fields)
#         user.set_password(password)
#         user.save()
#         return user

#     def create_superuser(self, email, password=None, **extra_fields):
#         extra_fields.setdefault('is_staff', True)
#         extra_fields.setdefault('is_superuser', True)
#         extra_fields.setdefault('is_active', True)

#         if extra_fields.get('is_staff') is not True:
#             raise ValueError(_('Superuser must have is_staff=True.'))
#         if extra_fields.get('is_superuser') is not True:
#             raise ValueError(_('Superuser must have is_superuser=True.'))
#         return self.create_user(email, password, **extra_fields)


# class CustomUser(AbstractUser): 
#     username = None  
#     email = models.EmailField(_('email address'), unique=True)
#     first_name = models.CharField(_('first name'), max_length=30)
#     last_name = models.CharField(_('last name'), max_length=30)
    
#     USERNAME_FIELD = 'email'
#     REQUIRED_FIELDS = ['first_name', 'last_name']
    
#     objects = CustomUserManager()
    
#     def __str__(self):
#         return self.email





from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils.translation import gettext_lazy as _
import uuid
import hashlib
from django.conf import settings
from cryptography.fernet import Fernet


# encrypt email fields and and present
class EncryptedEmailField(models.EmailField):
    def __init__(self, *args, **kwargs):
        kwargs['unique'] = True
        super().__init__(*args, **kwargs)

    # getting the encryption key
    def get_key(self):
        key = getattr(settings, 'EMAIL_ENCRYPTION_KEY', None)
        if key is None:
            raise ValueError("EMAIL_ENCRYPTION_KEY must be defined in settings")
        return key

    def get_cipher(self):
        return Fernet(self.get_key())
    # creating a hash email to help in look up and authentication 
    @staticmethod
    def hash_email(email):
        if not email:
            return None
        # Use a secure hash function (SHA-256)
        return hashlib.sha256(email.lower().encode()).hexdigest()

    def from_db_value(self, value, expression, connection):
        if value is None:
            return value
        try:
            cipher = self.get_cipher()
            # Decrypt the value from the database
            decrypted = cipher.decrypt(value.encode('utf-8'))
            return decrypted.decode('utf-8')
        except Exception as e:
            # Log the error in production
            return None  # Return None if decryption fails

    def to_python(self, value):
        if value is None or not isinstance(value, str):
            return value
        # Value is already in Python format
        return value

    def get_prep_value(self, value):
        if value is None:
            return value
        # Encrypt the value before saving to database
        cipher = self.get_cipher()
        encrypted = cipher.encrypt(value.encode('utf-8'))
        return encrypted.decode('utf-8')
    
    # preserve uniqueness in migrations
    def deconstruct(self):
        name, path, args, kwargs = super().deconstruct()
        # Keep unique=True for migrations
        kwargs['unique'] = True
        return name, path, args, kwargs

# hash UUID for the user ID
def hash_uuid():
    random_uuid = uuid.uuid4()
    return hashlib.sha256(str(random_uuid).encode()).hexdigest()


class CustomUserManager(BaseUserManager):
    def get_by_natural_key(self, email):
        # Normalize the email first
        email = self.normalize_email(email)
        # Calculate the hash and use it for lookup
        email_hash = EncryptedEmailField.hash_email(email)
        return self.get(email_hash=email_hash)
        
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError(_('The Email must be set'))
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        # The email_hash will be automatically set by the pre_save method
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff=True.'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser must have is_superuser=True.'))
        return self.create_user(email, password, **extra_fields)


class CustomUser(AbstractUser): 
    # Use hashed UUID as primary key
    id = models.CharField(primary_key=True, max_length=64, default=hash_uuid, editable=False)
    
   
    username = None
    
    # Use encrypted email field - marked as unique to satisfy Django's auth system
    email = EncryptedEmailField(_('email address'))
    
    # Add a hashed email field for lookups and actual uniqueness constraints
    email_hash = models.CharField(max_length=64, unique=True, db_index=True, editable=False)
    
    first_name = models.CharField(_('first name'), max_length=30)
    last_name = models.CharField(_('last name'), max_length=30)
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']
    
    objects = CustomUserManager()
    
    def __str__(self):
        return self.email
    
    def save(self, *args, **kwargs):
        # Generate the email hash before saving
        if self.email:
            self.email_hash = EncryptedEmailField.hash_email(self.email)
        super().save(*args, **kwargs)







from django.db import models
from django.conf import settings
import pyotp
from datetime import datetime, timedelta
from django.utils import timezone

# class OTPDevice(models.Model):
#     user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
#     key = models.CharField(max_length=40, blank=True)
#     last_verified = models.DateTimeField(null=True)
#     created_at = models.DateTimeField(auto_now_add=True)
    
#     def __str__(self):
#         return f"{self.user.email}'s OTP Device"
    
#     def generate_otp(self):
#         """Generate a new OTP for this device"""
#         if not self.key:
#             self.key = pyotp.random_base32()
#             self.save()
        
#         totp = pyotp.TOTP(self.key, interval=300)  # 5-minute interval
#         return totp.now()
    
#     def verify_otp(self, otp):
#         """Verify the provided OTP"""
#         if not self.key:
#             return False
        
#         totp = pyotp.TOTP(self.key, interval=300)  # 5-minute interval
#         verified = totp.verify(otp)
        
#         if verified:
#             self.last_verified = datetime.now()
#             self.save()
        
#         return verified

class OTPDevice(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    key = models.CharField(max_length=40, blank=True)
    last_verified = models.DateTimeField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.user.email}'s OTP Device"
    
    def generate_otp(self):
        """Generate a new OTP for this device"""
        if not self.key:
            self.key = pyotp.random_base32()
            self.save()
        
        totp = pyotp.TOTP(self.key, interval=300)  # 5-minute interval
        return totp.now()
    
    def verify_otp(self, otp):
        """Verify the provided OTP with a window to handle slight time differences"""
        if not self.key:
            return False
        
        totp = pyotp.TOTP(self.key, interval=300)  # 5-minute interval
        
        # Use a window parameter (±1 interval) to handle small time discrepancies
        verified = totp.verify(otp, valid_window=1)
        
        if verified:
            self.last_verified = timezone.now()
            self.save()
        
        return verified
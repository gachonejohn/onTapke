from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from rest_framework.validators import UniqueValidator
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from .models import EncryptedEmailField

from .models import OTPDevice
from .utils import send_otp_email


User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'first_name', 'last_name']
        read_only_fields = ['id']


class OTPVerificationSerializer(serializers.Serializer):
    otp = serializers.CharField(max_length=6, min_length=6)
    user_id = serializers.CharField()
    
    def validate_otp(self, value):
        if not value.isdigit() or len(value) != 6:
            raise serializers.ValidationError("OTP must be a 6-digit number")
        return value
        
    def validate(self, attrs):
        otp = attrs.get('otp')
        user_id = attrs.get('user_id')
        
        try:
            user = User.objects.get(id=user_id)
            device = OTPDevice.objects.get(user=user)
            
            if device.verify_otp(otp):
                attrs['user'] = user
                return attrs
            else:
                raise serializers.ValidationError({"otp": "Invalid or expired OTP"})
                
        except User.DoesNotExist:
            raise serializers.ValidationError({"user_id": "User not found"})
        except OTPDevice.DoesNotExist:
            raise serializers.ValidationError({"user_id": "OTP device not configured for user"})


# class LoginSerializer(TokenObtainPairSerializer):
#     def validate(self, attrs):
#         data = super().validate(attrs)
#         data['user'] = UserSerializer(self.user).data
#         return data

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(style={'input_type': 'password'})
    
    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        
        try:
            # First check if user exists with this email hash
            email_hash = EncryptedEmailField.hash_email(email)
            user = User.objects.get(email_hash=email_hash)
            
            # Then authenticate
            if user.check_password(password):
                # Send OTP
                send_otp_email(user)
                
                return {
                    'user_id': user.id,
                    'message': 'OTP has been sent to your email'
                }
            else:
                raise serializers.ValidationError({"non_field_errors": ["Invalid email or password"]})
                
        except User.DoesNotExist:
            # Security best practice: don't reveal if email exists
            raise serializers.ValidationError({"non_field_errors": ["Invalid email or password"]})



# class RegisterSerializer(serializers.ModelSerializer):
#     email = serializers.EmailField(
#         required=True,
#         validators=[UniqueValidator(queryset=User.objects.all())]
#     )
#     password = serializers.CharField(
#         write_only=True, 
#         required=True, 
#         validators=[validate_password]
#     )
#     password_confirm = serializers.CharField(write_only=True, required=True)

#     class Meta:
#         model = User
#         fields = ['email', 'password', 'password_confirm', 'first_name', 'last_name']

#     def validate(self, attrs):
#         if attrs['password'] != attrs['password_confirm']:
#             raise serializers.ValidationError({"password": "Password fields didn't match."})
#         return attrs

#     def create(self, validated_data):
#         validated_data.pop('password_confirm')
#         user = User.objects.create_user(**validated_data)
#         return user
class RegisterSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(
        write_only=True, 
        required=True, 
        validators=[validate_password]
    )
    password_confirm = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ['email', 'password', 'password_confirm', 'first_name', 'last_name']

    def validate_email(self, value):
        if value:
            email_hash = EncryptedEmailField.hash_email(value)
            if User.objects.filter(email_hash=email_hash).exists():
                raise serializers.ValidationError("This email address is already in use.")
        return value

    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        return attrs

    def create(self, validated_data):
        validated_data.pop('password_confirm')
        user = User.objects.create_user(**validated_data)
        return user


# class PasswordResetSerializer(serializers.Serializer):
#     email = serializers.EmailField(required=True)


# class PasswordResetConfirmSerializer(serializers.Serializer):
#     new_password = serializers.CharField(required=True, validators=[validate_password])
#     token = serializers.CharField(required=True)
#     uidb64 = serializers.CharField(required=True)


# class ChangePasswordSerializer(serializers.Serializer):
#     old_password = serializers.CharField(required=True)
#     new_password = serializers.CharField(required=True, validators=[validate_password])
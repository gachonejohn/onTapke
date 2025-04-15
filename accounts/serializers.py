from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from rest_framework.validators import UniqueValidator
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from .models import EncryptedEmailField


User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'first_name', 'last_name']
        read_only_fields = ['id']



class LoginSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)
        data['user'] = UserSerializer(self.user).data
        return data



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
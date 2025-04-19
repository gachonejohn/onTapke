from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from .models import CustomUser, EncryptedEmailField

User = get_user_model()

class CustomUserCreationForm(UserCreationForm):
    email = forms.EmailField(
        max_length=254,
        widget=forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'Email address'})
    )
    first_name = forms.CharField(
        max_length=30,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'First Name'})
    )
    last_name = forms.CharField(
        max_length=30,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Last Name'})
    )
    password1 = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Password (min. 8 characters)'})
    )
    password2 = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Confirm Password'})
    )
    
    class Meta:
        model = User
        fields = ('email', 'first_name', 'last_name', 'password1', 'password2')
    
    def clean_email(self):
        email = self.cleaned_data.get('email')
        if email:
            # Check if the email hash already exists
            email_hash = EncryptedEmailField.hash_email(email)
            if CustomUser.objects.filter(email_hash=email_hash).exists():
                raise forms.ValidationError("This email address is already in use.")
        return email


class CustomAuthenticationForm(AuthenticationForm):
    username = forms.EmailField(
        widget=forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'john@example.com'})
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': '●●●●●●●'})
    )
    remember = forms.BooleanField(required=False)




from django.contrib.auth.forms import PasswordResetForm

class CustomPasswordResetForm(PasswordResetForm):
    def get_users(self, email):
        email_hash = EncryptedEmailField.hash_email(email)
        
        
        active_users = CustomUser.objects.filter(
            email_hash=email_hash,
            is_active=True
        )
        
        return active_users    






# forms.py - Add to your existing forms
# from django import forms
# from django.contrib.auth import get_user_model
# from django.contrib.auth.forms import AuthenticationForm

# User = get_user_model()

# class OTPVerificationForm(forms.Form):
#     otp = forms.CharField(
#         label='Enter OTP',
#         max_length=6,
#         required=True,
#         widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter 6-digit OTP'})
#     )
    
#     email = forms.EmailField(widget=forms.HiddenInput())
    
#     def clean_otp(self):
#         otp = self.cleaned_data.get('otp')
#         if not otp.isdigit() or len(otp) != 6:
#             raise forms.ValidationError("OTP must be a 6-digit number")
#         return otp


from django import forms
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError

User = get_user_model()

# class OTPVerificationForm(forms.Form):
#     otp = forms.CharField(
#         label='Enter OTP',
#         max_length=6,
#         required=True,
#         widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter 6-digit OTP'})
#     )
    
#     def __init__(self, *args, **kwargs):
#         # Extract user_id from kwargs
#         self.user_id = kwargs.pop('user_id', None)
#         super(OTPVerificationForm, self).__init__(*args, **kwargs)
    
#     def clean_otp(self):
#         otp = self.cleaned_data.get('otp')
#         if not otp.isdigit() or len(otp) != 6:
#             raise forms.ValidationError("OTP must be a 6-digit number")
#         return otp
    
#     def clean(self):
#         cleaned_data = super().clean()
        
#         # Verify user exists
#         if self.user_id:
#             try:
#                 user = User.objects.get(id=self.user_id)
#                 # We're not validating the OTP here, just making sure the user exists
#                 cleaned_data['user'] = user
#             except User.DoesNotExist:
#                 raise ValidationError("Invalid session. Please try logging in again.")
#         else:
#             raise ValidationError("Session expired. Please try logging in again.")
            
#         return cleaned_data


# Updated OTPVerificationForm
class OTPVerificationForm(forms.Form):
    otp = forms.CharField(
        label='Enter OTP',
        max_length=6,
        min_length=6,
        required=True,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter 6-digit OTP'})
    )
    
    def __init__(self, *args, **kwargs):
        self.user_id = kwargs.pop('user_id', None)
        super(OTPVerificationForm, self).__init__(*args, **kwargs)
    
    def clean_otp(self):
        otp = self.cleaned_data.get('otp')
        if not otp.isdigit() or len(otp) != 6:
            raise forms.ValidationError("OTP must be a 6-digit number")
        return otp
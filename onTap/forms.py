from django import forms
from .models import WaitingSubscriber
from django.core.exceptions import ValidationError

# contact form 
class ContactForm(forms.Form):
    name = forms.CharField(
        max_length=100,
        required=True,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'id': 'name',
        })
    )
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'id': 'email',
        })
    )
    message = forms.CharField(
        required=True,
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'id': 'message',
            'rows': '5',
            'placeholder': 'Type your message...'
        })
    )
    terms = forms.BooleanField(
        required=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-check-input',
            'id': 'terms',
        })
    )

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if email and not email.strip():
            raise forms.ValidationError("Email cannot be empty.")
        return email

    def clean_message(self):
        message = self.cleaned_data.get('message')
        if message and len(message) < 10:
            raise forms.ValidationError("Message must be at least 10 characters long.")
        return message


# waiting emails form
class WaitingSubscriptionForm(forms.ModelForm):
    class Meta:
        model = WaitingSubscriber
        fields = ['email']
        widgets = {
            'email': forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'Email Address'})
        }    
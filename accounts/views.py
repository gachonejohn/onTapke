from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate
from django.contrib import messages
from django.views.generic import CreateView, FormView
from django.urls import reverse_lazy
from django.contrib.auth.views import LoginView, LogoutView

from .forms import CustomUserCreationForm, CustomAuthenticationForm, CustomPasswordResetForm

from django.contrib.auth.views import PasswordResetView, PasswordResetDoneView, PasswordResetConfirmView, PasswordResetCompleteView

from .models import EncryptedEmailField

from django.shortcuts import render, redirect
from django.contrib.auth import login, get_user_model
from django.contrib import messages
from django.views.generic import FormView
from django.urls import reverse_lazy
from django.contrib.auth.mixins import UserPassesTestMixin

from .forms import CustomAuthenticationForm, OTPVerificationForm
from .models import OTPDevice
from .utils import send_otp_email

from django.views import View
from django.http import JsonResponse


# class SignUpView(CreateView):
#     form_class = CustomUserCreationForm
#     template_name = 'registration/signup.html'
#     success_url = reverse_lazy('login')
    
#     def form_valid(self, form):
#         response = super().form_valid(form)
#         messages.success(self.request, "Your account has been created successfully. Please log in.")
#         return response
    
#     def form_invalid(self, form):
#         for field, errors in form.errors.items():
#             for error in errors:
#                 messages.error(self.request, f"{error}")
#         return super().form_invalid(form)
class SignUpView(CreateView):
    form_class = CustomUserCreationForm
    template_name = 'registration/signup.html'
    success_url = reverse_lazy('login')
    
    def form_valid(self, form):
        response = super().form_valid(form)
        messages.success(self.request, "Your account has been created successfully. Please log in.")
        return response
    
    def form_invalid(self, form):
        for field, errors in form.errors.items():
            for error in errors:
                messages.error(self.request, f"{error}")
        return super().form_invalid(form)



# class CustomLoginView(FormView):
#     form_class = CustomAuthenticationForm
#     template_name = 'registration/login.html'
#     success_url = reverse_lazy('verify_otp')
    
#     def form_valid(self, form):
#         email = form.cleaned_data.get('username')  # Email is used as username
#         password = form.cleaned_data.get('password')
        
#         try:
#             # First check if user exists with this email hash
#             email_hash = EncryptedEmailField.hash_email(email)
#             user = User.objects.get(email_hash=email_hash)
            
#             # Then authenticate
#             user = authenticate(self.request, username=email, password=password)
            
#             if user is not None:
#                 # Store the user ID in session for the next step
#                 self.request.session['otp_user_id'] = user.id
                
#                 # Send OTP via email
#                 send_otp_email(user)
                
#                 messages.success(self.request, "OTP has been sent to your email.")
#                 return super().form_valid(form)
#             else:
#                 messages.error(self.request, "Invalid email or password. Please try again.")
#                 return self.form_invalid(form)
                
#         except User.DoesNotExist:
#             # We don't want to reveal if the email exists or not (security best practice)
#             messages.error(self.request, "Invalid email or password. Please try again.")
#             return self.form_invalid(form)

class CustomLoginView(FormView):
    form_class = CustomAuthenticationForm
    template_name = 'registration/login.html'
    success_url = reverse_lazy('verify_otp')
    
    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect('dashboard')  
        return super().dispatch(request, *args, **kwargs)
    
    def form_valid(self, form):
        email = form.cleaned_data.get('username')  
        password = form.cleaned_data.get('password')
        
        try:
           
            User = get_user_model()
            email_hash = EncryptedEmailField.hash_email(email)
            user = User.objects.get(email_hash=email_hash)
            
           
            user = authenticate(self.request, username=email, password=password)
            
            if user is not None:
                
                self.request.session['otp_user_id'] = user.id
                
                # Send OTP via email
                send_otp_email(user)
                
                messages.success(self.request, "OTP has been sent to your email.")
                return super().form_valid(form)
            else:
                messages.error(self.request, "Invalid email or password. Please try again.")
                return self.form_invalid(form)
                
        except User.DoesNotExist:
            
            messages.error(self.request, "Invalid email or password. Please try again.")
            return self.form_invalid(form)



class CustomLogoutView(LogoutView):
    next_page = 'login'  
    
    def dispatch(self, request, *args, **kwargs):
        messages.success(request, "You have been successfully logged out.")
        return super().dispatch(request, *args, **kwargs)


class CustomPasswordResetView(PasswordResetView):
    template_name = 'registration/password_reset.html'
    email_template_name = 'registration/reset_email.html'
    subject_template_name = 'registration/reset_subject.txt'
    form_class = CustomPasswordResetForm 

class CustomPasswordResetDoneView(PasswordResetDoneView):
    template_name = 'registration/reset_done.html'

class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    template_name = 'registration/reset_confirm.html'

class CustomPasswordResetCompleteView(PasswordResetCompleteView):
    template_name = 'registration/reset_complete.html'





User = get_user_model()


class VerifyOTPView(FormView):
    form_class = OTPVerificationForm
    template_name = 'registration/verify_otp.html'
    success_url = reverse_lazy('dashboard')
    
    def dispatch(self, request, *args, **kwargs):
        if 'otp_user_id' not in request.session:
            messages.error(request, "Please log in first.")
            return redirect('login')
        return super().dispatch(request, *args, **kwargs)
    
    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['user_id'] = self.request.session.get('otp_user_id')
        return kwargs
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Add user email to context for display
        try:
            user = User.objects.get(id=self.request.session.get('otp_user_id'))
            context['email'] = user.email
        except User.DoesNotExist:
            context['email'] = ''
        return context
    
    def form_valid(self, form):
        user_id = self.request.session.get('otp_user_id')
        otp = form.cleaned_data.get('otp')
        
        try:
            user = User.objects.get(id=user_id)
            device, created = OTPDevice.objects.get_or_create(user=user)
            
            # Use a window parameter to handle slight time synchronization issues
            if device.verify_otp(otp):
                login(self.request, user)
                messages.success(self.request, "Login successful!")
                
                # Clean up session
                if 'otp_user_id' in self.request.session:
                    del self.request.session['otp_user_id']
                
                return super().form_valid(form)
            else:
                messages.error(self.request, "Invalid or expired OTP.")
                return self.form_invalid(form)
                
        except User.DoesNotExist:
            messages.error(self.request, "User account not found. Please try again.")
            return redirect('login')



class ResendOTPView(View):
    def post(self, request, *args, **kwargs):
        user_id = request.session.get('otp_user_id')
        if not user_id:
            return JsonResponse({'success': False, 'error': 'Session expired, please log in again'})
        
        try:
            user = User.objects.get(id=user_id)
            send_otp_email(user)
            return JsonResponse({'success': True})
        except User.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'User not found'})



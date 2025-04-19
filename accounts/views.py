from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate
from django.contrib import messages
from django.views.generic import CreateView, FormView
from django.urls import reverse_lazy
from django.contrib.auth.views import LoginView, LogoutView

from .forms import CustomUserCreationForm, CustomAuthenticationForm, CustomPasswordResetForm

from django.contrib.auth.views import PasswordResetView, PasswordResetDoneView, PasswordResetConfirmView, PasswordResetCompleteView

from .models import EncryptedEmailField

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


# class CustomLoginView(LoginView):
#     form_class = CustomAuthenticationForm
#     template_name = 'registration/login.html'
#     redirect_authenticated_user = True
    
#     def form_invalid(self, form):
#         messages.error(self.request, "Invalid email or password. Please try again.")
#         return super().form_invalid(form)


# class CustomLoginView(FormView):
#     form_class = CustomAuthenticationForm
#     template_name = 'registration/login.html'
#     success_url = reverse_lazy('verify_otp')
    
#     def form_valid(self, form):
#         email = form.cleaned_data.get('username')  # Assuming email is used as username
#         password = form.cleaned_data.get('password')
        
#         user = authenticate(self.request, username=email, password=password)
        
#         if user is not None:
#             # Store the user ID in session for the next step
#             self.request.session['otp_user_id'] = user.id
            
#             # Send OTP via email
#             send_otp_email(user)
            
#             messages.success(self.request, "OTP has been sent to your email.")
#             return super().form_valid(form)
#         else:
#             messages.error(self.request, "Invalid email or password. Please try again.")
#             return self.form_invalid(form)
    
#     def form_invalid(self, form):
#         messages.error(self.request, "Invalid email or password. Please try again.")
#         return super().form_invalid(form)

class CustomLoginView(FormView):
    form_class = CustomAuthenticationForm
    template_name = 'registration/login.html'
    success_url = reverse_lazy('verify_otp')
    
    def form_valid(self, form):
        email = form.cleaned_data.get('username')  # Email is used as username
        password = form.cleaned_data.get('password')
        
        try:
            # First check if user exists with this email hash
            email_hash = EncryptedEmailField.hash_email(email)
            user = User.objects.get(email_hash=email_hash)
            
            # Then authenticate
            user = authenticate(self.request, username=email, password=password)
            
            if user is not None:
                # Store the user ID in session for the next step
                self.request.session['otp_user_id'] = user.id
                
                # Send OTP via email
                send_otp_email(user)
                
                messages.success(self.request, "OTP has been sent to your email.")
                return super().form_valid(form)
            else:
                messages.error(self.request, "Invalid email or password. Please try again.")
                return self.form_invalid(form)
                
        except User.DoesNotExist:
            # We don't want to reveal if the email exists or not (security best practice)
            messages.error(self.request, "Invalid email or password. Please try again.")
            return self.form_invalid(form)





class CustomLogoutView(LogoutView):
    next_page = 'login'  
    
    def dispatch(self, request, *args, **kwargs):
        messages.success(request, "You have been successfully logged out.")
        return super().dispatch(request, *args, **kwargs)




# class CustomPasswordResetView(PasswordResetView):
#     template_name = 'registration/password_reset.html'
#     email_template_name = 'registration/reset_email.html'
#     subject_template_name = 'registration/reset_subject.txt'
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






# api_views
from rest_framework import generics, status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from rest_framework_simplejwt.views import TokenObtainPairView

from .serializers import (
    UserSerializer, RegisterSerializer, LoginSerializer, OTPVerificationSerializer
    # PasswordResetSerializer,PasswordResetConfirmSerializer, ChangePasswordSerializer
)

User = get_user_model()

class RegisterAPIView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        
        # Create token for the user
        refresh = RefreshToken.for_user(user)
        
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'user': UserSerializer(user).data
        }, status=status.HTTP_201_CREATED)
# class RegisterAPIView(generics.CreateAPIView):
#     queryset = User.objects.all()
#     serializer_class = RegisterSerializer
#     permission_classes = [permissions.AllowAny]

#     def create(self, request, *args, **kwargs):
#         serializer = self.get_serializer(data=request.data)
#         try:
#             serializer.is_valid(raise_exception=True)
#             user = serializer.save()
            
#             # Create token for the user
#             refresh = RefreshToken.for_user(user)
            
#             return Response({
#                 'refresh': str(refresh),
#                 'access': str(refresh.access_token),
#                 'user': UserSerializer(user).data
#             }, status=status.HTTP_201_CREATED)
#         except serializers.ValidationError as e:
#             # Return validation errors in a more user-friendly format
#             return Response({
#                 'status': 'error',
#                 'message': 'Registration failed',
#                 'errors': e.detail
#             }, status=status.HTTP_400_BAD_REQUEST)



# class LoginAPIView(TokenObtainPairView):
#     serializer_class = LoginSerializer
#     permission_classes = [permissions.AllowAny]
class LoginInitiateAPIView(APIView):
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        return Response({
            'user_id': serializer.validated_data['user_id'],
            'message': serializer.validated_data['message']
        }, status=status.HTTP_200_OK)

class VerifyOTPAPIView(APIView):
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        serializer = OTPVerificationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = serializer.validated_data['user']
        
        # Generate tokens
        refresh = RefreshToken.for_user(user)
        
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'user': UserSerializer(user).data
        }, status=status.HTTP_200_OK)
    
class ResendOTPAPIView(APIView):
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        user_id = request.data.get('user_id')
        
        if not user_id:
            return Response(
                {'error': 'User ID is required'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            user = User.objects.get(id=user_id)
            send_otp_email(user)
            return Response({
                'message': 'OTP has been sent to your email'
            }, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response(
                {'error': 'User not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )    

class UserProfileAPIView(generics.RetrieveUpdateAPIView):
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user


class LogoutAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception:
            return Response(status=status.HTTP_400_BAD_REQUEST)



# views.py - Add to your existing views
from django.shortcuts import render, redirect
from django.contrib.auth import login, get_user_model
from django.contrib import messages
from django.views.generic import FormView
from django.urls import reverse_lazy
from django.contrib.auth.mixins import UserPassesTestMixin

from .forms import CustomAuthenticationForm, OTPVerificationForm
from .models import OTPDevice
from .utils import send_otp_email

User = get_user_model()

# class RequestOTPView(FormView):
#     form_class = CustomAuthenticationForm
#     template_name = 'registration/login.html'
#     success_url = reverse_lazy('verify_otp')
    
#     def form_valid(self, form):
#         email = form.cleaned_data.get('username')  # Assuming email is used as username
#         password = form.cleaned_data.get('password')
        
#         user = authenticate(self.request, username=email, password=password)
        
#         if user is not None:
#             # Store the email in session for the next step
#             self.request.session['otp_email'] = email
            
#             # Send OTP via email
#             send_otp_email(user)
            
#             messages.success(self.request, "OTP has been sent to your email.")
#             return super().form_valid(form)
#         else:
#             messages.error(self.request, "Invalid credentials.")
#             return self.form_invalid(form)


# class VerifyOTPView(FormView):
#     form_class = OTPVerificationForm
#     template_name = 'registration/verify_otp.html'
#     success_url = reverse_lazy('dashboard')  # Redirect to home page after successful login
    
#     def get_initial(self):
#         initial = super().get_initial()
#         initial['email'] = self.request.session.get('otp_email', '')
#         return initial
    
#     def form_valid(self, form):
#         email = form.cleaned_data.get('email')
#         otp = form.cleaned_data.get('otp')
        
#         try:
#             user = User.objects.get(email=email)
#             device = OTPDevice.objects.get(user=user)
            
#             if device.verify_otp(otp):
#                 login(self.request, user)
#                 messages.success(self.request, "Login successful!")
                
#                 # Clean up session
#                 if 'otp_email' in self.request.session:
#                     del self.request.session['otp_email']
                
#                 return super().form_valid(form)
#             else:
#                 messages.error(self.request, "Invalid or expired OTP.")
#                 return self.form_invalid(form)
                
#         except (User.DoesNotExist, OTPDevice.DoesNotExist):
#             messages.error(self.request, "Something went wrong. Please try again.")
#             return self.form_invalid(form)
# class VerifyOTPView(FormView):
#     form_class = OTPVerificationForm
#     template_name = 'registration/verify_otp.html'
#     success_url = reverse_lazy('dashboard')  # Redirect to dashboard after successful login
    
#     def dispatch(self, request, *args, **kwargs):
#         # Check if user came from login page with a session
#         if 'otp_user_id' not in request.session:
#             messages.error(request, "Please log in first.")
#             return redirect('login')
#         return super().dispatch(request, *args, **kwargs)
    
#     def get_form_kwargs(self):
#         kwargs = super().get_form_kwargs()
#         # Pass the user_id to the form
#         kwargs['user_id'] = self.request.session.get('otp_user_id')
#         return kwargs
    
#     def form_valid(self, form):
#         otp = form.cleaned_data.get('otp')
#         user_id = self.request.session.get('otp_user_id')
        
#         try:
#             user = User.objects.get(id=user_id)
#             device = OTPDevice.objects.get(user=user)
            
#             if device.verify_otp(otp):
#                 # Log the user in only after OTP verification
#                 login(self.request, user)
#                 messages.success(self.request, "Login successful!")
                
#                 # Clean up session
#                 if 'otp_user_id' in self.request.session:
#                     del self.request.session['otp_user_id']
                
#                 return super().form_valid(form)
#             else:
#                 messages.error(self.request, "Invalid or expired OTP.")
#                 return self.form_invalid(form)
                
#         except (User.DoesNotExist, OTPDevice.DoesNotExist):
#             messages.error(self.request, "Something went wrong. Please try again.")
#             return redirect('login')

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


from django.views import View
from django.http import JsonResponse
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




# class PasswordResetAPIView(APIView):
#     permission_classes = [permissions.AllowAny]

#     def post(self, request):
#         serializer = PasswordResetSerializer(data=request.data)
#         if serializer.is_valid():
#             email = serializer.validated_data['email']
#             try:
#                 user = User.objects.get(email=email)
                
#                 # Generate token and UID
#                 token = default_token_generator.make_token(user)
#                 uid = urlsafe_base64_encode(force_bytes(user.pk))
                
#                 # reset URL (this would be your Flutter app's deep link)
#                 current_site = get_current_site(request)
#                 reset_url = f"accounts://password-reset-confirm/{uid}/{token}/"
                
#                 # Send email
#                 mail_subject = 'Reset your password'
#                 message = render_to_string('registration/reset_email.html', {
#                     'user': user,
#                     'reset_url': reset_url,
#                 })
#                 email = EmailMessage(mail_subject, message, to=[user.email])
#                 email.send()
                
#                 return Response(
#                     {"detail": "Password reset email has been sent."},
#                     status=status.HTTP_200_OK
#                 )
#             except User.DoesNotExist:
#                 # Don't reveal whether a user exists or not for security
#                 pass
                
#         return Response(
#             {"detail": "Password reset email has been sent if the email exists."},
#             status=status.HTTP_200_OK
#         )

# class PasswordResetAPIView(APIView):
#     permission_classes = [permissions.AllowAny]

#     def post(self, request):
#         serializer = PasswordResetSerializer(data=request.data)
#         if serializer.is_valid():
#             email = serializer.validated_data['email']
            
#             # Calculate the email hash
#             email_hash = EncryptedEmailField.hash_email(email)
            
#             try:
#                 # Look up user by email_hash
#                 user = User.objects.get(email_hash=email_hash)
                
#                 # Generate token and UID
#                 token = default_token_generator.make_token(user)
#                 uid = urlsafe_base64_encode(force_bytes(user.pk))
                
#                 # Get current site details
#                 current_site = get_current_site(request)
#                 protocol = 'https' if request.is_secure() else 'http'
#                 domain = current_site.domain
                
#                 # Generate reset URL path (without protocol and domain)
#                 reset_path = f"accounts/password-reset-confirm/{uid}/{token}/"
                
#                 # Full reset URL that will be used in the template
#                 full_reset_url = f"{protocol}://{domain}/{reset_path}"
                
#                 # Send email
#                 mail_subject = 'OnTap - Password Reset Request'
#                 message = render_to_string('registration/reset_email.html', {
#                     'user': user,
#                     'reset_url': full_reset_url,  # Pass the full URL directly
#                     'uid': uid,
#                     'token': token,
#                     'protocol': protocol,
#                     'domain': domain,
#                 })
                
#                 email_message = EmailMessage(mail_subject, message, to=[user.email])
#                 email_message.send()
                
#                 return Response(
#                     {"detail": "Password reset email has been sent."},
#                     status=status.HTTP_200_OK
#                 )
#             except User.DoesNotExist:
#                 # Don't reveal whether a user exists
#                 pass
#             except Exception as e:
#                 # Log the error
#                 import logging
#                 logger = logging.getLogger(__name__)
#                 logger.error(f"Password reset error: {str(e)}")
                
#         return Response(
#             {"detail": "Password reset email has been sent if the email exists."},
#             status=status.HTTP_200_OK
#         )


# class PasswordResetConfirmAPIView(APIView):
#     permission_classes = [permissions.AllowAny]

#     def post(self, request):
#         serializer = PasswordResetConfirmSerializer(data=request.data)
#         if serializer.is_valid():
#             try:
#                 uid = force_str(urlsafe_base64_decode(serializer.validated_data['uidb64']))
#                 user = User.objects.get(pk=uid)
                
#                 # Check if token is valid
#                 if default_token_generator.check_token(user, serializer.validated_data['token']):
#                     user.set_password(serializer.validated_data['new_password'])
#                     user.save()
#                     return Response(
#                         {"detail": "Password has been reset successfully."},
#                         status=status.HTTP_200_OK
#                     )
#                 return Response(
#                     {"detail": "Invalid token."},
#                     status=status.HTTP_400_BAD_REQUEST
#                 )
#             except (TypeError, ValueError, OverflowError, User.DoesNotExist):
#                 return Response(
#                     {"detail": "Invalid user ID."},
#                     status=status.HTTP_400_BAD_REQUEST
#                 )
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# class ChangePasswordAPIView(APIView):
#     permission_classes = [permissions.IsAuthenticated]

#     def post(self, request):
#         serializer = ChangePasswordSerializer(data=request.data)
#         if serializer.is_valid():
#             user = request.user
#             if not user.check_password(serializer.validated_data['old_password']):
#                 return Response(
#                     {"old_password": ["Wrong password."]},
#                     status=status.HTTP_400_BAD_REQUEST
#                 )
            
#             user.set_password(serializer.validated_data['new_password'])
#             user.save()
#             return Response(
#                 {"detail": "Password updated successfully."},
#                 status=status.HTTP_200_OK
#             )
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)





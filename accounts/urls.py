from django.urls import path
from .views import SignUpView, CustomLoginView, CustomLogoutView 

from .views import CustomPasswordResetView, CustomPasswordResetDoneView, CustomPasswordResetConfirmView, CustomPasswordResetCompleteView

# Import API views
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenVerifyView
from .views import (
    RegisterAPIView, UserProfileAPIView, LogoutAPIView,
    PasswordResetAPIView, PasswordResetConfirmAPIView, ChangePasswordAPIView
)


urlpatterns = [
    path('signup/', SignUpView.as_view(), name='signup'),
    path('login/', CustomLoginView.as_view(), name='login'),
    path('logout/', CustomLogoutView.as_view(), name='logout'),
    
path('password-reset/', CustomPasswordResetView.as_view(), name='password_reset'),
path('password-reset/done/', CustomPasswordResetDoneView.as_view(), name='password_reset_done'),
path('password-reset-confirm/<uidb64>/<token>/', CustomPasswordResetConfirmView.as_view(), name='password_reset_confirm'),
path('password-reset-complete/', CustomPasswordResetCompleteView.as_view(), name='password_reset_complete'),



# JWT Auth endpoints
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    
    # User management endpoints
    path('api/register/', RegisterAPIView.as_view(), name='api_register'),
    path('api/profile/', UserProfileAPIView.as_view(), name='api_profile'),
    path('api/logout/', LogoutAPIView.as_view(), name='api_logout'),
    
    # Password management
    path('api/password/reset/', PasswordResetAPIView.as_view(), name='api_password_reset'),
    path('api/password/reset/confirm/', PasswordResetConfirmAPIView.as_view(), name='api_password_reset_confirm'),
    path('api/password/change/', ChangePasswordAPIView.as_view(), name='api_password_change'),
]
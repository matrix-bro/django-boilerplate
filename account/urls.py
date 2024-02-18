from django.urls import path
from account.api import account
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

urlpatterns = [
    path('register/', account.RegisterView.as_view(), name='register'),
    path('login/', TokenObtainPairView.as_view(), name='login'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('activate-account/<str:uidb64>/<str:token>/', account.ActivateUserAccount.as_view(), name='activate_user_account'),
    path('logout/', account.LogoutView.as_view(), name='logout'),
    path('forgot-password/', account.ForgotPassword.as_view(), name='forgot_password'),
    path('verify-reset-token/<str:uidb64>/<str:token>/', account.VerifyPasswordResetToken.as_view(), name='verify_reset_token'),
    path('reset-password/<str:uidb64>/<str:token>/', account.ResetPassword.as_view(), name='reset_password'),
]

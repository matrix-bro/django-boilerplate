from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import serializers, status, permissions
from django.contrib.auth import get_user_model
from account.services.account_services import create_user_account, send_reset_password_email, check_token_validity
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
User = get_user_model()
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from django.utils import dateparse, timezone
from django.http import JsonResponse
from account.services.account_services import token_generator
from rest_framework_simplejwt.tokens import RefreshToken

class RegisterView(APIView):
    class InputSerializer(serializers.ModelSerializer):
        class Meta:
            model = User
            fields = ('first_name', 'last_name', 'email', 'password', 'confirm_password')

        password = serializers.CharField(write_only=True)
        confirm_password = serializers.CharField(write_only=True)

        def validate(self, attrs):
            if attrs['password'] != attrs['confirm_password']:
                raise serializers.ValidationError({
                    'password': "Password fields didn't match."
                })
            
            attrs.pop('confirm_password')   # Removing confirm_password from validated_data

            return attrs
        
    """
        POST: Creates user account
    """
    def post(self, request):
        serializer = self.InputSerializer(data=request.data)

        serializer.is_valid(raise_exception=True)

        password = serializer.validated_data['password']

        try:
            validate_password(password, request.user)
        except ValidationError as e:
            return Response({
                'password': e.messages
            }, status=status.HTTP_400_BAD_REQUEST)

        user = create_user_account(**serializer.validated_data)

        response = self.InputSerializer(user)

        return Response({
            'success': 'Account created successfully.',
            'data': response.data,
            'status': status.HTTP_201_CREATED,
        }, status=status.HTTP_201_CREATED)

class ActivateUserAccount(APIView):
    
    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            token, expiry_date = token.split("_")
            token = force_str(urlsafe_base64_decode(token))
            expiry_date = force_str(urlsafe_base64_decode(expiry_date))
            expiry_date = dateparse.parse_datetime(expiry_date)

            if (not token) or (not expiry_date):
                raise Exception
            
            current_time = timezone.now()

            if current_time > expiry_date:
                return JsonResponse(
                    {
                        "success": False,
                        "message": "Token has expired.",
                        "code": status.HTTP_400_BAD_REQUEST,
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
            
            user = User.objects.get(pk=uid)

        except Exception as e:
            user = None

        if not token_generator.check_token(user, token):
            return JsonResponse(
                {
                    "success": False,
                    "message": "Token is invalid or expired.",
                    "code": status.HTTP_400_BAD_REQUEST,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        if user and token_generator.check_token(user, token):
            user.is_active = True
            user.save()

            return JsonResponse(
                {
                    "success": True,
                    "message": "Email verification completed successfully.",
                    "code": status.HTTP_200_OK,
                },
                status=status.HTTP_200_OK,
            )

        return JsonResponse(
            {
                "success": False,
                "message": "Email verification failed.",
                "code": status.HTTP_400_BAD_REQUEST,
            },
            status=status.HTTP_400_BAD_REQUEST,
        )
    
class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        try:
            # Get the refresh_token and blacklist it
            refresh_token = request.data['refresh_token']
            token = RefreshToken(refresh_token)
            token.blacklist()

            return Response(status=status.HTTP_205_RESET_CONTENT)
        except:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        
class ForgotPassword(APIView):
    class InputSerializer(serializers.Serializer):
        email = serializers.EmailField()
    
    def post(self, request):
        serializer = self.InputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        validated_email = serializer.validated_data['email']

        try:
            user = User.objects.get(email=validated_email)
        except:
            return Response({
                'success': 'User not found.',
                'status': status.HTTP_400_BAD_REQUEST,
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Send email
        send_reset_password_email(user)

        return Response({
            'success': f'A reset password link has been sent to {validated_email}',
            'status': status.HTTP_200_OK,
        }, status=status.HTTP_200_OK)
    
class VerifyPasswordResetToken(APIView):
    def get(self, request, uidb64, token):
        
        check_token_validity(uidb64, token)

        return Response({
            'success': 'A token has been verified.',
            'status': status.HTTP_200_OK,
        }, status=status.HTTP_200_OK)
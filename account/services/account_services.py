from django.contrib.auth import get_user_model
User = get_user_model()
from django.template.loader import render_to_string
from django.contrib.auth.tokens import PasswordResetTokenGenerator
import six
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.utils import timezone, dateparse
from datetime import timedelta
from django.core.mail import EmailMultiAlternatives
from rest_framework import serializers

class TokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return (
            six.text_type(user.pk)
            + six.text_type(timestamp)
            + six.text_type(user.is_active)
        )
    
token_generator = TokenGenerator()

def create_user_account(first_name, last_name, email, password):
    user = User.objects.create_user(first_name=first_name, last_name=last_name, email=email, password=password)

    # generate token and send email
    token = token_generator.make_token(user)
    send_activation_email(user.first_name, user.email, user.pk, token)

    return user

def send_activation_email(first_name, email, user_id, token):
    expiry_date = timezone.now() + timedelta(hours=1)
    subject = "Activate your account"
    email_body = render_to_string(
        "account/activate_email.html",
        {
            "first_name": first_name,
            "domain": "http://localhost:8000/",
            "uid": urlsafe_base64_encode(force_bytes(user_id)),
            "token": urlsafe_base64_encode(force_bytes(token))
            + "_"
            + urlsafe_base64_encode(force_bytes(str(expiry_date))),
        }
    )

    email = EmailMultiAlternatives(
        subject=subject,
        from_email="admin@site.com",
        to=[email]
    )

    email.attach_alternative(email_body, "text/html")
    email.send()

def send_reset_password_email(user):
    token = token_generator.make_token(user)
    expiry_date = timezone.now() + timedelta(minutes=30)
    subject = "Reset your password"
    email_body = render_to_string(
        "account/reset_password_email.html",
        {
            "first_name": user.first_name,
            "domain": "http://localhost:8000/",
            "uid": urlsafe_base64_encode(force_bytes(user.pk)),
            "token": urlsafe_base64_encode(force_bytes(token))
            + "_"
            + urlsafe_base64_encode(force_bytes(str(expiry_date))),
        }
    )

    email = EmailMultiAlternatives(
        subject=subject,
        from_email="admin@site.com",
        to=[user.email]
    )

    email.attach_alternative(email_body, "text/html")
    email.send()

def check_token_validity(uidb64, token):
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
            raise serializers.ValidationError("Token has expired.")
        
        user = User.objects.get(pk=uid)

    except Exception as e:
        user = None

    if not token_generator.check_token(user, token):
        raise serializers.ValidationError("Token is invalid or expired.")
    
    return user
from django.urls import path
from account.api import account

urlpatterns = [
    path('register/', account.RegisterView.as_view(), name='register'),

]

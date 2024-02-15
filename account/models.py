from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser, PermissionsMixin

class UserAccountManager(BaseUserManager):
    def create_user(self, first_name, last_name, email, password=None):
        if not email:
            raise ValueError('Email field required')
        
        email = self.normalize_email(email)
        email = email.lower()

        user = self.model(first_name=first_name, last_name=last_name, email=email)

        user.set_password(password)

        user.save(using=self._db)

        return user
    
    def create_superuser(self, first_name, last_name, email, password=None):

        user = self.create_user(first_name, last_name, email, password=password)

        user.is_staff = True
        user.is_superuser = True

        user.save(using=self._db)

        return user
    
class UserAccount(AbstractBaseUser, PermissionsMixin):
    first_name = models.CharField(max_length=100)    
    last_name = models.CharField(max_length=100)    
    email = models.EmailField(max_length=200, unique=True)
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)

    objects = UserAccountManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    def __str__(self):
        return self.email

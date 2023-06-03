from django.contrib.auth.models import AbstractBaseUser
from django.contrib.auth.base_user import BaseUserManager
from django.db import models
from django.urls import reverse
from django.conf import settings
from hashlib import sha3_512, md5
from os import path
import random


class CustomUserManager(BaseUserManager):
    def create_user(self, username, password=None, **extra_fields):
        if not username:
            raise ValueError('The username field must be set')
        username = username
        user = self.model(username=username, **extra_fields)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, username, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(username, password, **extra_fields)


class CustomUser(AbstractBaseUser):
    username = models.CharField(unique=True, max_length=30)
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    security_q1 = models.CharField(max_length=128)
    security_q2 = models.CharField(max_length=128)
    security_q3 = models.CharField(max_length=128)
    failed_login_attempts = models.IntegerField(default=0)
    address = models.CharField(max_length=50)
    joined_at = models.DateTimeField(auto_now_add=True)
    image = models.ImageField(
        upload_to='DockCloud/templates/static/assets/images/users_profiles', blank=True, null=True)
    # To get all instances of CustomUser, you will use CustomUser.objects.all()
    objects = CustomUserManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        return True

    def has_module_perms(self, app_label):
        return True
        # existing methods

    def increment_failed_login_attempts(self):
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 10:
            self.is_active = False
        self.save()

    def reset_failed_login_attempts(self):
        self.failed_login_attempts = 0
        self.save()

    def check_security_answers(self, answer1, answer2, answer3):
        """
        Check if the user's security question answers match the provided answers.
        """
        # Hash the provided answers using the SHA256 algorithm
        hashed_answer1 = sha3_512(answer1.encode('utf-8')).hexdigest()
        hashed_answer2 = sha3_512(answer2.encode('utf-8')).hexdigest()
        hashed_answer3 = sha3_512(answer3.encode('utf-8')).hexdigest()
        # get the user object from the database
        user = CustomUser.objects.get(id = self.id)
        # Compare the hashed answers with the stored hashed answers
        if hashed_answer1 == user.security_q1 and hashed_answer2 == user.security_q2 and hashed_answer3 == user.security_q3:
            return True
        else:
            return False

    def get_image_name(self):
        if self.image:
            return path.basename(self.image.name)
        else:
            return "default.png"

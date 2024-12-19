# backend/files/models.py
from django.db import models
from django.conf import settings
from cryptography.fernet import Fernet
from django.contrib.auth.models import AbstractUser
import os
import uuid
from django.utils.timezone import now

class CustomUser(AbstractUser):
    ROLE_CHOICES = (
        ('admin', 'Admin'),
        ('user', 'User'),
       ('guest','Guest'), 
    )

    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='user')
    phone = models.CharField(max_length = 30, null = False, blank = False, default = '11111')
    is_loggedin = models.BooleanField(default = False)

    user_permissions = models.ManyToManyField(
        'auth.Permission', 
        related_name='customuser_permissions',  # New related_name to avoid clash
        blank=True,
    )

    groups = models.ManyToManyField(
        'auth.Group',
        related_name='customuser_set',  # Use a custom related name to avoid clashes
        blank=True
    )

    def __str__(self):
        return self.username

class File(models.Model):
    owner = models.ForeignKey(CustomUser, on_delete=models.CASCADE, null = True)
    file = models.FileField(upload_to='files/')
    key = models.CharField(max_length=256)  # Encryption key
    shared_with = models.ManyToManyField(CustomUser, related_name='shared_files', blank=True)
    created_at = models.DateTimeField(auto_now_add = True)
    updated_at = models.DateTimeField(auto_now = True)

    def encrypt(self, file_path):
        # Generate a key for encryption
        key = Fernet.generate_key()
        cipher_suite = Fernet(key)

        # Read and encrypt the file
        with open(file_path, 'rb') as f:
            encrypted_data = cipher_suite.encrypt(f.read())

        # Write the encrypted data back to the file
        with open(file_path, 'wb') as f:
            f.write(encrypted_data)

        # Store the key in the database
        self.key = key.decode()
        self.save()

    def decrypt(self, file_path):
        # Get the stored encryption key
        cipher_suite = Fernet(self.key.encode())

        # Read and decrypt the file
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
            decrypted_data = cipher_suite.decrypt(encrypted_data)

        return decrypted_data


    
class ShareableLink(models.Model):
    file = models.ForeignKey(File, on_delete = models.CASCADE)
    token = models.UUIDField(default = uuid.uuid4, unique = True)
    expires_at = models.DateTimeField()

    def is_valid(self):
        return self.expires_at > now()

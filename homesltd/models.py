from django.db import models

# Create your models here.
class User(models.Model):
    fullname = models.CharField(max_length= 200)
    email_address = models.EmailField(max_length=200)
    phone_number = models.CharField(max_length=100)
    message = models.CharField(max_length=500)

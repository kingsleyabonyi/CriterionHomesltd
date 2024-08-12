from rest_framework import serializers, validators
from .models import User



class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['fullname', 'email_address', 'phone_number', 'message']
        # fields = '__all__'


class EmailSerializer(serializers.Serializer):
    email_address = serializers.EmailField()

    
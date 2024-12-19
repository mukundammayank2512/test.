from rest_framework import serializers
from .models import CustomUser

class CustomUserSerializer(serializers.ModelSerializer):
    password1 = serializers.CharField(write_only=True, required=True)
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = CustomUser
        fields = ['username', 'password1', 'password2', 'phone', 'role']

    def validate(self, data):
        # Ensure passwords match
        if data['password1'] != data['password2']:
            raise serializers.ValidationError({"password": "Passwords do not match."})
        return data

    def create(self, validated_data):
        # Remove password fields from validated data
        password = validated_data.pop('password1')
        validated_data.pop('password2')

        # Create the user
        user = CustomUser.objects.create(**validated_data)
        user.set_password(password)
        user.save()
        return user

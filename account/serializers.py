from account.models import *
from rest_framework import serializers
from django.core.validators import validate_email
from django.core.exceptions import ValidationError

class LoginSerializer(serializers.Serializer):
    identifier = serializers.CharField(required=True, write_only=True)
    password = serializers.CharField(write_only=True, required=True)

    def validate_identifier(self, value):
        try:
            # Attempt to validate the value as an email
            if "@" in value:  # Simplistic check to assume it's an email
                validate_email(value)  # Will raise a ValidationError if invalid
        except ValidationError as e:
            raise serializers.ValidationError("Invalid email address") from e
        return value

class UserSerializer(serializers.ModelSerializer):
    user_permissions = serializers.SerializerMethodField()
    image = serializers.ImageField(required=False)

    class Meta:
        model = User
        fields = (
            'id', 'name', 'email', 'phone_number', 'national_id', 'gender', 'date_of_birth',
            'country', 'district', 'sector', 'cell', 'village', 'status', 'role', 'image',
            'bio', 'password', 'user_permissions'
        )
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def get_user_permissions(self, obj):
        """Retrieve the user's direct permissions."""
        if hasattr(obj, 'get_all_permissions'):
            return obj.get_all_permissions()
        return []

    def create(self, validated_data):
        """
        Create a new user with a hashed password and handle optional image upload.
        """
        password = validated_data.pop('password', None)
        user = User.objects.create(**validated_data)
        if password:
            user.set_password(password)
        user.save()
        return user

    def update(self, instance, validated_data):
        """
        Update user details and hash the password if provided.
        """
        # Handle image upload separately if provided
        instance.image = validated_data.pop('image', instance.image)

        # If a password is provided, hash it using set_password
        password = validated_data.pop('password', None)
        if password:
            instance.set_password(password)

        # Update the remaining fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        instance.save()
        return instance
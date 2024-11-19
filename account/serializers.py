import re
from account.models import *
from datetime import timedelta
from django.db.models import Q
from rest_framework import serializers
from django.core.validators import validate_email
from django.core.exceptions import ValidationError

class LoginSerializer(serializers.Serializer):
    identifier = serializers.CharField(required=True, write_only=True)
    password = serializers.CharField(write_only=True, required=True)
    
    def validate_identifier(self, value):
        """
        Validate that the identifier is either a valid email or a valid phone number.
        """
        # Check if it's an email
        if "@" in value:
            try:
                validate_email(value)
            except ValidationError as e:
                raise serializers.ValidationError("Invalid email address.") from e
        else:
            # Validate phone number (simple regex for demonstration)
            phone_regex = re.compile(r'^\+?1?\d{9,15}$')
            if not phone_regex.match(value):
                raise serializers.ValidationError("Invalid phone number format.")
        return value

    def validate_password(self, value):
        """
        Add password validations if needed (e.g., minimum length).
        """
        if len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long.")
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

    def validate_email(self, value):
        """
        Validate that the email is unique.
        """
        if value:
            if User.objects.filter(email=value).exists():
                raise serializers.ValidationError("A user with this email already exists.")
        return value

    def validate_phone_number(self, value):
        """
        Validate that the phone number is unique and follows a specific format.
        """
        phone_regex = re.compile(r'^\+?1?\d{9,15}$')  # Example: +12345678901
        if not phone_regex.match(value):
            raise serializers.ValidationError("Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed.")
        if User.objects.filter(phone_number=value).exists():
            raise serializers.ValidationError("A user with this phone number already exists.")
        return value

    def validate_national_id(self, value):
        """
        Validate that the national ID is unique and follows a specific format.
        """
        nid_regex = re.compile(r'^\d{10}$')  # Example: 10-digit number
        if not nid_regex.match(value):
            raise serializers.ValidationError("National ID must be a 10-digit number.")
        if User.objects.filter(national_id=value).exists():
            raise serializers.ValidationError("A user with this National ID already exists.")
        return value

    def validate_password(self, value):
        """
        Validate password strength.
        """
        if len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long.")
        if not re.search(r'[A-Z]', value):
            raise serializers.ValidationError("Password must contain at least one uppercase letter.")
        if not re.search(r'[a-z]', value):
            raise serializers.ValidationError("Password must contain at least one lowercase letter.")
        if not re.search(r'\d', value):
            raise serializers.ValidationError("Password must contain at least one digit.")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
            raise serializers.ValidationError("Password must contain at least one special character.")
        return value

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

class PasswordResetRequestSerializer(serializers.Serializer):
    email_or_phone = serializers.CharField()

    def validate_email_or_phone(self, value):
        if not User.objects.filter(Q(email=value) | Q(phone_number=value)).exists():
            raise serializers.ValidationError('User with this email or phone number does not exist.')
        return value

class PasswordResetConfirmSerializer(serializers.Serializer):
    email_or_phone = serializers.CharField()
    otp = serializers.CharField(max_length=7)
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        email_or_phone = attrs.get('email_or_phone')
        otp = attrs.get('otp')

        try:
            user = User.objects.get(
                Q(email=email_or_phone) | Q(phone_number=email_or_phone),
                reset_otp=otp,
                otp_created_at__gte=timezone.now() - timedelta(minutes=10)
            )
        except User.DoesNotExist:
            raise serializers.ValidationError('Invalid OTP or OTP has expired.')

        self.context['user'] = user
        return attrs

    def save(self):
        user = self.context['user']
        password = self.validated_data['password']

        # Set the new password
        user.set_password(password)

        # Clear OTP fields
        user.reset_otp = None
        user.otp_created_at = None
        user.save()

        return user
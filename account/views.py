import logging
from account.utils import *
from account.models import *
from django.db.models import Q
from account.serializers import *
from google.oauth2 import id_token
from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth import authenticate
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated
from rest_framework import generics, permissions, status
from google.auth.transport import requests as google_requests

logger = logging.getLogger(__name__)

class LoginView(generics.GenericAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            # Log the serializer errors
            logger.warning(f"Login failed due to serializer errors: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        identifier = serializer.validated_data['identifier']
        password = serializer.validated_data['password']

        # Determine if the identifier is an email or phone number
        user = None
        if "@" in identifier:
            user = authenticate(username=identifier, password=password)
            if not user:
                logger.warning(f"Login failed for email: {identifier}")
        else:
            try:
                user = User.objects.get(phone_number=identifier)
                if not user.check_password(password):
                    user = None
                    logger.warning(f"Login failed for phone number: {identifier} due to incorrect password.")
            except User.DoesNotExist:
                logger.warning(f"Login failed: No user found with phone number: {identifier}")

        if user:
            # Delete old token and generate a new one
            Token.objects.filter(user=user).delete()
            token, created = Token.objects.get_or_create(user=user)

            logger.info(f"User {user.email or user.phone_number} logged in successfully.")

            return Response({
                'token': token.key,
                'user': UserSerializer(user).data,
                'message': 'Login successful.'
            }, status=status.HTTP_200_OK)
        
        # For security, do not specify if it's the identifier or password that's wrong
        return Response({'error': 'Invalid credentials.'}, status=status.HTTP_400_BAD_REQUEST)

class GoogleAuthView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        token = request.data.get('token')
        if not token:
            return Response({'message': 'Token is required.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            # Specify the CLIENT_ID of the app that accesses the backend:
            idinfo = id_token.verify_oauth2_token(token, google_requests.Request(), GOOGLE_CLIENT_ID)

            # ID token is valid. Get the user's Google Account ID from the decoded token.
            userid = idinfo['sub']
            email = idinfo.get('email')
            name = idinfo.get('name')

            # Check if user exists
            try:
                user = User.objects.get(email=email)
                # Update Google ID if necessary
                user.google_id = userid
                user.save()
            except User.DoesNotExist:
                # Create a new user
                user = User.objects.create_user(
                    name=name,
                    email=email,
                    google_id=userid,
                    password=User.objects.make_random_password()  # Generate a random password
                )

            # Create or get token
            token_obj, created = Token.objects.get_or_create(user=user)

            logger.info(f"User {user.email} authenticated via Google.")

            return Response({
                'user': UserSerializer(user).data,
                'token': token_obj.key,
                'message': 'Google authentication successful.'
            }, status=status.HTTP_200_OK)

        except ValueError:
            # Invalid token
            logger.error('Invalid Google token.')
            return Response({'message': 'Invalid token.'}, status=status.HTTP_400_BAD_REQUEST)

class RegisterView(generics.CreateAPIView):
    """
    View to register a new user. Accessible to any user.
    """
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            try:
                user = serializer.save()
                token, created = Token.objects.get_or_create(user=user)
                logger.info(f"New user registered: {user.email or user.phone_number}")
                return Response({
                    "user": UserSerializer(user, context=self.get_serializer_context()).data,
                    "token": token.key,
                    "message": "User registered successfully."
                }, status=status.HTTP_201_CREATED)
            except ValidationError as ve:
                logger.error(f"Validation error during user registration: {ve}")
                return Response({
                    "message": "User registration failed.",
                    "errors": ve.detail
                }, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                logger.error(f"Unexpected error during user registration: {e}")
                return Response({
                    "message": "User registration failed due to an unexpected error.",
                    "errors": str(e)
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            logger.warning(f"User registration failed with errors: {serializer.errors}")
            return Response({
                "message": "User registration failed.",
                "errors": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        try:
            if hasattr(request.user, 'auth_token'):
                request.user.auth_token.delete()
            return Response({
                "message": "Logout successful."
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "error": f"An error occurred during logout: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UpdateUserView(generics.UpdateAPIView):
    queryset = User.objects.all()
    permission_classes = [IsAuthenticated]
    serializer_class = UserSerializer

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', True)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        if serializer.is_valid():
            try:
                user = serializer.save()
                logger.info(f"User updated: {user.email or user.phone_number}")
                return Response({
                    "user": serializer.data,
                    "message": "Account updated successfully."
                }, status=status.HTTP_200_OK)
            except ValidationError as ve:
                logger.error(f"Validation error during user update: {ve}")
                return Response({
                    "message": "Account update failed.",
                    "errors": ve.detail
                }, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                logger.error(f"Unexpected error during user update: {e}")
                return Response({
                    "message": "Account update failed due to an unexpected error.",
                    "errors": str(e)
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            logger.warning(f"User update failed with errors: {serializer.errors}")
            return Response({
                "message": "Account update failed.",
                "errors": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetRequestView(generics.GenericAPIView):
    serializer_class = PasswordResetRequestSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            email_or_phone = serializer.validated_data['email_or_phone']
            user = User.objects.filter(Q(email=email_or_phone) | Q(phone_number=email_or_phone)).first()

            if not user:
                logger.warning(f"Password reset requested for non-existent identifier: {email_or_phone}")
                return Response(
                    {'error': 'User with this email or phone number does not exist.'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Generate a 7-digit OTP
            otp = generate_otp()
            user.reset_otp = otp
            user.otp_created_at = timezone.now()
            user.save()

            # Send OTP via Email or SMS
            if user.email and user.email == email_or_phone:
                # Send Email
                subject = 'Password Reset OTP'
                message = f'Your password reset OTP is: {otp}'
                recipient_list = [user.email]
                email_sent = send_email(subject, message, recipient_list)
                if email_sent:
                    logger.info(f"Password reset OTP sent to email: {user.email}")
                    return Response(
                        {'message': 'OTP has been sent to your email.'},
                        status=status.HTTP_200_OK
                    )
                else:
                    logger.error(f"Failed to send OTP email to {user.email}")
                    return Response(
                        {'error': 'Failed to send OTP email. Please try again later.'},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR
                    )
            elif user.phone_number and user.phone_number == email_or_phone:
                # Send SMS
                message = f'Your password reset OTP is: {otp}'
                sms_sent = send_sms(user.phone_number, message)
                if sms_sent:
                    logger.info(f"Password reset OTP sent to phone number: {user.phone_number}")
                    return Response(
                        {'message': 'OTP has been sent to your phone number.'},
                        status=status.HTTP_200_OK
                    )
                else:
                    logger.error(f"Failed to send OTP SMS to {user.phone_number}")
                    return Response(
                        {'error': 'Failed to send OTP SMS. Please try again later.'},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR
                    )
            else:
                logger.warning(f"Provided contact information does not match for user ID: {user.id}")
                return Response(
                    {'error': 'Provided contact information does not match our records.'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        else:
            logger.warning(f"Password reset request failed with errors: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetConfirmView(generics.GenericAPIView):
    serializer_class = PasswordResetConfirmSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            try:
                user = serializer.save()
                logger.info(f"Password reset successful for user: {user.email or user.phone_number}")
                return Response({'message': 'Password has been reset successfully.'}, status=status.HTTP_200_OK)
            except ValidationError as ve:
                logger.error(f"Validation error during password reset confirmation: {ve}")
                return Response({
                    "message": "Password reset failed.",
                    "errors": ve.detail
                }, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                logger.error(f"Unexpected error during password reset confirmation: {e}")
                return Response({
                    "message": "Password reset failed due to an unexpected error.",
                    "errors": str(e)
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            logger.warning(f"Password reset confirmation failed with errors: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
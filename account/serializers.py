from rest_framework import serializers
from account.models import User
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from account.utils import Util
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password


# =================================== User Registration =======================================================

class UserRegistrationSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
            required=True,
            validators=[UniqueValidator(queryset=User.objects.all())]
            )

    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    confirm_password = serializers.CharField(write_only=True, required=True)
    class Meta:
        model = User
        fields = ('name', 'password', 'confirm_password', 'email', 'phone', 'birth_date','user_type', 'address')
        

    def validate(self, attrs):

        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        

        return attrs

    def create(self, validated_data):
        user = User.objects.create(
            name=validated_data['name'],
            email=validated_data['email'],
            phone=validated_data['phone'],
            birth_date=validated_data['birth_date'],
            user_type=validated_data['user_type'],
            address=validated_data['address'],
            

        )


        user.set_password(validated_data['password'])
        user.save()

        return user

# ============================= User Login  ======================================

class UserLoginSerializer(serializers.ModelSerializer):
  email = serializers.EmailField(max_length=255)
  class Meta:
    model = User
    fields = ['email', 'password']


# =============================  Profile  ======================================

class UserGetSerializer(serializers.ModelSerializer):
      birth_date = serializers.DateField(format="%d-%m-%Y", allow_null=True)
      class Meta:
            
       model = User
       fields = ['id', 'user_type','email', 'name', 'phone', 'birth_date', 'created_by', 'deleted', 'created_at', 'address']

# ============================= User Change Password  ======================================

class UserChangePasswordSerializer(serializers.Serializer):
  password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
  confirm_password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
  class Meta:
    fields = ['password', 'confirm_password']

  def validate(self, attrs):
    password = attrs.get('password')
    confirm_password = attrs.get('confirm_password')
    user = self.context.get('user')
    if password != confirm_password:
      raise serializers.ValidationError("Password and Confirm Password doesn't match")
    user.set_password(password)
    user.save()
    return attrs

# ============================= Send Password link  on email  ======================================

# class SendPasswordResetEmailSerializer(serializers.Serializer):
#   email = serializers.EmailField(max_length=255)
#   class Meta:
#     fields = ['email']

#   def validate(self, attrs):
#     email = attrs.get('email')
#     if User.objects.filter(email=email).exists():
#       user = User.objects.get(email = email)
#       uid = urlsafe_base64_encode(force_bytes(user.id))
#       print('Encoded UID', uid)
#       token = PasswordResetTokenGenerator().make_token(user)
#       print('Password Reset Token', token)
#       link = 'http://localhost:3000/user/reset/'+uid+'/'+token
#       print('Password Reset Link', link)
#       # Send EMail
     
#       body = 'Click Following Link to Reset Your Password '+link
#       data = {
#         'subject':'Reset Your Password',
#         'body':body,
#         'to_email':user.email
#       }
#       # Util.send_email(data)
#       return attrs
#     else:
#       raise serializers.ValidationError('You are not a Registered User')
          

# class UserPasswordResetSerializer(serializers.Serializer):
#   password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
#   confirm_password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
#   class Meta:
#     fields = ['password', 'confirm_password']

#   def validate(self, attrs):
#     try:
#       password = attrs.get('password')
#       confirm_password = attrs.get('confirm_password')
#       uid = self.context.get('uid')
#       token = self.context.get('token')
#       if password != confirm_password:
#         raise serializers.ValidationError("Password and Confirm Password doesn't match")
#       id = smart_str(urlsafe_base64_decode(uid))
#       user = User.objects.get(id=id)
#       if not PasswordResetTokenGenerator().check_token(user, token):
#         raise serializers.ValidationError('Token is not Valid or Expired')
#       user.set_password(password)
#       user.save()
#       return attrs
#     except DjangoUnicodeDecodeError as identifier:
#       PasswordResetTokenGenerator().check_token(user, token)
#       raise serializers.ValidationError('Token is not Valid or Expired')

# ============================= User Profile  ======================================

# class UserProfileSerializer(serializers.ModelSerializer):
#   class Meta:
#     model = User
#     fields = ['id', 'email']

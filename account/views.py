from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.decorators import api_view
from account.models import User
from account.serializers import  UserChangePasswordSerializer, UserLoginSerializer, UserRegistrationSerializer, UserGetSerializer
from django.contrib.auth import authenticate
from account.renderers import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import logout


# =============================== Generate Token Manually ==============================
def get_tokens_for_user(user):
  refresh = RefreshToken.for_user(user)
  return {
      'refresh': str(refresh),
      'access': str(refresh.access_token),
  }

# ============================= User Registration ======================================

class UserRegistrationView(APIView):
  renderer_classes = [UserRenderer]
  def post(self, request, format=None):
    user = User()
    serializer = UserRegistrationSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    user = serializer.save()


    token = get_tokens_for_user(user)
    return Response({'token':token, 'msg':'Registration Successful'}, status=status.HTTP_201_CREATED)

# ============================= User Login  ======================================

class UserLoginView(APIView):
  renderer_classes = [UserRenderer]
  def post(self, request, format=None):
    serializer = UserLoginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    email = serializer.data.get('email')
    password = serializer.data.get('password')
    user = authenticate(email=email, password=password)
    if user is not None:
      token = get_tokens_for_user(user)
      return Response({'token':token, 'msg':'Login Success'}, status=status.HTTP_200_OK)
    else:
      return Response({'errors':{'non_field_errors':['Email or Password is not Valid']}}, status=status.HTTP_404_NOT_FOUND)


 # ============================= All User ======================================

@api_view(['GET'])
def get_user(request, id=None):
      # query_string = request.query_params

      data = {}
      try:
          if id:
                user = User.objects.filter(pk=id, deleted=0)
          else:
                user = User.objects.filter(deleted=0)

          data["total_record"] = len(user)
           
      except User.DoesNotExist:
        data["succes"] = False
        data["msg"] = "User Does not exist"
        data["data"] = []
        return Response(status=status.HTTP_401_UNAUTHORIZED)

      if request.method == "GET":
        serializer = UserGetSerializer(user, many=True) 
        data["succes"] = True
        data["msg"] = "OK" 

        # if "fields" in query_string:
        #       if query_string["fields"]:
                    
        data["data"] = serializer.data
        return Response(data=data, status=status.HTTP_200_OK)


# ============================= User Change Password ======================================

class UserChangePasswordView(APIView):
  renderer_classes = [UserRenderer]
  permission_classes = [IsAuthenticated]
  def post(self, request, format=None):
    serializer = UserChangePasswordSerializer(data=request.data, context={'user':request.user})
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Changed Successfully'}, status=status.HTTP_200_OK)

# ============================= Update User  ======================================

@api_view(['POST'])
def update_user(request, pk):
    data={}
    user = User.objects.get(id=pk)
    serializer = UserGetSerializer(instance=user, data=request.data)

    if User.objects.filter(**request.data).exists():
        raise serializer.ValidationError('This User is Already exists')
        
    if serializer.is_valid():
        serializer.save()
        data["success"] = True
        data["msg"] = "Data upload Successfully"
        data["data"] = serializer.data
        return Response(data=data, status=status.HTTP_201_CREATED)


    data["success"] = False
    data["msg"] = {err_obj: str(serializer.errors[err_obj][0]) for err_obj in serializer.errors}
    data["data"] = serializer.data
    return Response(data=data, status=status.HTTP_400_BAD_REQUEST)

# ============================= Log Out  ======================================

@api_view(["POST"])
def user_logout(request):
  if request.method == "POST":
    logout(request)
    return Response({'msg':'LogOut Successfully'}, status=status.HTTP_200_OK)


# ===========================Delete Record================================

@api_view(['DELETE'])
def delete_user(request, pk):
    user = User.objects.get(id=pk)
    user.delete()

    return Response('User is Delete Succefully')


# ============================= Send Password Rest on Email  ======================================

# class SendPasswordResetEmailView(APIView):
#   renderer_classes = [UserRenderer]
#   def post(self, request, format=None):
#     serializer = SendPasswordResetEmailSerializer(data=request.data)
#     serializer.is_valid(raise_exception=True)
#     return Response({'msg':'Password Reset link send. Please check your Email'}, status=status.HTTP_200_OK)

# # =============================  Rest via  Email  ======================================

# class UserPasswordResetView(APIView):
#   renderer_classes = [UserRenderer]
#   def post(self, request, uid, token, format=None):
#     serializer = UserPasswordResetSerializer(data=request.data, context={'uid':uid, 'token':token})
#     serializer.is_valid(raise_exception=True)
#     return Response({'msg':'Password Reset Successfully'}, status=status.HTTP_200_OK)
   
# ============================= User Profile ======================================

# class UserProfileView(APIView):
#   # renderer_classes = [UserRenderer]
#   # permission_classes = [IsAuthenticated]
#   def get(self, request, format=None):
#     serializer = UserProfileSerializer(request.user)

#     return Response(serializer.data, status=status.HTTP_200_OK)
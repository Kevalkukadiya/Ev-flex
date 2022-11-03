from django.urls import path
from . import views
from account.views import  UserChangePasswordView, get_user, UserRegistrationView, UserLoginView


urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),
   path('get/', get_user),
    path('changepassword/', UserChangePasswordView.as_view(), name='changepassword'),
    path('update/<str:pk>/', views.update_user, name='update_user'),
    path('logout/', views.user_logout, name='user_logout'),
     path('delete/<str:pk>/', views.delete_user, name='delete_user'),
    
]
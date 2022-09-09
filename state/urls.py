from django.urls import path
from . import views


urlpatterns = [

     path('get/', views.view_state, name='view_state'),
     path('get/<int:id>/', views.view_state, name='view_state'),
     path('create/', views.create_state, name='create_state'),
     path('update/<str:pk>/', views.update_state, name='update_state'), 
     path('delete/<str:pk>/', views.delete_state, name='delete_state'),
]
from django.urls import path
from . import views


urlpatterns = [

     path('get/', views.view_area, name='view_area'),
     path('get/<int:id>/', views.view_area, name='view_area'),
     path('create/', views.create_area, name='create_area'),
     path('update/<str:pk>/', views.update_area, name='update_area'), 
     path('delete/<str:pk>/', views.delete_area, name='delete_area'),
]
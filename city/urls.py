from django.urls import path
from . import views


urlpatterns = [
     path('get/', views.view_city, name='view_city'),
     path('get/<int:id>/', views.view_city, name='view_city'),
     path('create/', views.create_city, name='create_city'),
     path('update/<str:pk>/', views.update_city, name='update_city'), 
     path('delete/<str:pk>/', views.delete_city, name='delete_city'),
]

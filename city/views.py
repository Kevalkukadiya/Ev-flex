from rest_framework import serializers
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import City
from .serializers import CitySerializer

# ===========================Create New Record================================

@api_view(['POST'])
def create_city(request):
    data = {}
    if request.method == "POST":
        city = City()
        serializer = CitySerializer(city, data=request.data)

        if City.objects.filter(**request.data).exists():
            raise serializers.ValidationError('This City is Already exists')
        
        
        if serializer.is_valid():
            serializer.save()
            data["success"] = True
            data["msg"] = "Data upload Successfully"
            data["data"] = serializer.data
            return Response(data=data, status=status.HTTP_201_CREATED)

        data["success"] = False
        data["msg"] = {err_obj: str(serializer.errors[err_obj][0]) for err_obj in serializer.error}
        data["data"] = serializer.data
        return Response(data=data, status=status.HTTP_400_BAD_REQUEST)

    
# ===========================List of All Record================================

@api_view(['GET'])
def view_city(request, id=None):
    data = {}
    try:
        if id:
            city = City.objects.filter(pk=id, deleted=0)
        else:
            city = City.objects.filter(deleted=0)
        data["total_record"] = len(city)
        
    except City.DoesNotExist:
        data["succes"] = False
        data["msg"] = "Record Does not exist"
        data["data"] = []
        return Response(data=data, status=status.HTTP_401_UNAUTHORIZED)

    if request.method == "GET":   
        serializer = CitySerializer(city, many=True)
        data["succes"] = True
        data["msg"] = "OK"
        data["data"] = serializer.data
        return Response(data=data, status=status.HTTP_200_OK)


# ===========================Update Record================================

@api_view(['POST'])
def update_city(request, pk):
    data={}
    city = City.objects.get(city_id=pk)
    serializer = CitySerializer(instance=city, data=request.data)

    if City.objects.filter(**request.data).exists():
        raise serializers.ValidationError('This City is Already exists')
        
    if serializer.is_valid():
        serializer.save()
        data["success"] = True
        data["msg"] = "Data upload Successfully"
        data["data"] = serializer.data
        return Response(data=data, status=status.HTTP_201_CREATED)


    data["success"] = False
    data["msg"] = {err_obj: str(serializer.errors[err_obj][0]) for err_obj in serializer.error}
    data["data"] = serializer.data
    return Response(data=data, status=status.HTTP_400_BAD_REQUEST)

# ===========================Delete Record================================

@api_view(['DELETE'])
def delete_city(request, pk):
    city = City.objects.get(city_id=pk)
    city.delete()

    return Response('City is Delete Succefully')

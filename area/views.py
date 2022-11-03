from rest_framework import serializers
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import Area
from .serializers import AreaSerializer

# ===========================Create New Record================================

@api_view(['POST'])
def create_area(request):
    data = {}
    if request.method == "POST":
        area = Area()
        serializer = AreaSerializer(area, data=request.data)

        if Area.objects.filter(**request.data).exists():
            raise serializers.ValidationError('This Area is Already exists')
        
        
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

    
# ===========================List of All Record================================

@api_view(['GET'])
def view_area(request, id=None):
    data = {}
    try:
        if id:
            area = Area.objects.filter(pk=id, deleted=0)
        else:
            area = Area.objects.filter(deleted=0)
        data["total_record"] = len(area)
        
    except Area.DoesNotExist:
        data["succes"] = False
        data["msg"] = "Record Does not exist"
        data["data"] = []
        return Response(data=data, status=status.HTTP_401_UNAUTHORIZED)

    if request.method == "GET":   
        serializer = AreaSerializer(area, many=True)
        data["succes"] = True
        data["msg"] = "OK"
        data["data"] = serializer.data
        return Response(data=data, status=status.HTTP_200_OK)


# ===========================Update Record================================

@api_view(['POST'])
def update_area(request, pk):
    data={}
    area = Area.objects.get(area_id=pk)
    serializer = AreaSerializer(instance=area, data=request.data)

    if Area.objects.filter(**request.data).exists():
        raise serializers.ValidationError('This Area is Already exists')
        
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

# ===========================Delete Record================================

@api_view(['DELETE'])
def delete_area(request, pk):
    area = Area.objects.get(area_id=pk)
    area.delete()

    return Response('Area is Delete Succefully')

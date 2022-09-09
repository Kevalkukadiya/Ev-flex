from rest_framework import serializers
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import State
from .serializers import StateSerializer

# ===========================Create New Record================================
@api_view(['POST'])
def create_state(request):
    data = {}
    if request.method == "POST":
        state = State()
        serializer = StateSerializer(state, data=request.data)

        if State.objects.filter(**request.data).exists():
            raise serializers.ValidationError('This State is Already exists')
        
        
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
def view_state(request, id=None):
    data = {}
    try:
        if id:
            state = State.objects.filter(pk=id, deleted=0)
        else:
            state = State.objects.filter(deleted=0)
        data["total_record"] = len(state)
        
    except State.DoesNotExist:
        data["succes"] = False
        data["msg"] = "Record Does not exist"
        data["data"] = []
        return Response(data=data, status=status.HTTP_401_UNAUTHORIZED)

    if request.method == "GET":   
        serializer = StateSerializer(state, many=True)
        data["succes"] = True
        data["msg"] = "OK"
        data["data"] = serializer.data
        return Response(data=data, status=status.HTTP_200_OK)


# ===========================Update Record================================
@api_view(['POST'])
def update_state(request, pk):
    data={}
    state = State.objects.get(state_id=pk)
    serializer = StateSerializer(instance=state, data=request.data)

    if State.objects.filter(**request.data).exists():
        raise serializers.ValidationError('This State is Already exists')
        
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
def delete_state(request, pk):
    state = State.objects.get(state_id=pk)
    state.delete()

    return Response('State is Delete Succefully')

from django.db.models import fields
from rest_framework import serializers
from .models import Area
from city.serializers import CitySerializer
from state.serializers import StateSerializer

class AreaSerializer(serializers.ModelSerializer):
    def to_representation(self, instance):
        ret = super(AreaSerializer,self).to_representation(instance)

        if "city" in ret:
            ret["city_name"] = CitySerializer(instance.city).data["city_name"]
        
        if "state" in ret:
            ret["state_name"] = StateSerializer(instance.state).data["state_name"]


        return ret
    
        
    class Meta:
        model = Area
        fields = '__all__'



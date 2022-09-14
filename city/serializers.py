from django.db.models import fields
from rest_framework import serializers
from .models import City
from state.serializers import StateSerializer


class CitySerializer(serializers.ModelSerializer):
    def to_representation(self, instance):
        ret = super(CitySerializer,self).to_representation(instance)

        if "state" in ret:
            ret["state_name"] = StateSerializer(instance.state).data["state_name"]

        return ret
        
    class Meta:
        model = City
        fields = '__all__'



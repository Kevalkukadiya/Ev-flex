from django.db import models
from state.models import State


class City(models.Model):
    state = models.ForeignKey(State, on_delete=models.CASCADE)    
    city_id = models.AutoField(primary_key=True)
    city_name = models.CharField(max_length=100)
    deleted = models.IntegerField(default=0, unique=False)


    def __str__(self):
        return self


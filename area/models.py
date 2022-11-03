
from django.db import models
from state.models import State
from city.models import City

# Create your models here.

class Area(models.Model):
    state = models.ForeignKey(State, on_delete=models.CASCADE)
    city = models.ForeignKey(City, on_delete=models.CASCADE)
    area_id = models.AutoField(primary_key=True)
    area_name = models.CharField(max_length=100)
 
    deleted = models.IntegerField(default=0, unique=False)

    def __str__(self):
        return self
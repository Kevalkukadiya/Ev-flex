from django.db import models

# Create your models here.
class State(models.Model):
    state_id = models.AutoField(primary_key=True)
    state_name = models.CharField(max_length=100)
    deleted = models.IntegerField(default=0, unique=False)

    def __str__(self):
        return f"({self.state_id},{self.state_name})"
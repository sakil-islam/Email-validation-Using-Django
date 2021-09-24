from django.db import models

# Create your models here.


class Input_data(models.Model):
    input_values = models.CharField(max_length=255)
    timestamp = models.DateTimeField(auto_now_add=True)

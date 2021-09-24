from rest_framework import serializers
from .models import Input_data


class Input_dataSerializer(serializers.ModelSerializer):
    class Meta:
        model = Input_data
        fields = ['timestamp', 'input_values']

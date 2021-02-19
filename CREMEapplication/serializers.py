""" Serializers convert complex data to native Python datatypes that
    can easily rendered into JSON, XML,... It also provide de-serializer
    to convert back parsed data to complex types.
"""
from .models import ProgressData
from rest_framework import serializers


class ProgressDataSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = ProgressData
        fields = ('url', 'stage', 'status', 'detail')
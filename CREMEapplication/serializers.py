""" Serializers convert complex data to native Python datatypes that
    can easily rendered into JSON, XML,... It also provide de-serializer
    to convert back parsed data to complex types.
"""
from .models import ProgressData
from rest_framework import serializers


class ProgressDataSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = ProgressData
        fields = ('url', 'scenario', 'stage_1_status', 'stage_1_detail', 'stage_2_status', 'stage_2_detail',
                  'stage_3_status', 'stage_3_detail', 'stage_4_status', 'stage_4_detail',
                  'stage_5_status', 'stage_5_detail', 'stage_6_status', 'stage_6_detail',
                  'stage_7_status', 'stage_7_detail')

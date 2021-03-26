from django.urls import path, include
from . import views
from rest_framework import routers

router = routers.SimpleRouter()
router.register(r'progressdata', views.ProgressDataViewSet)

urlpatterns = [
    path('', views.new_testbed, name='new_testbed'),
    path('new_testbed', views.new_testbed, name='new_testbed'),
    path('new_testbed_information', views.new_testbed_information, name='new_testbed_information'),
    path('dashboard', views.dashboard, name='dashboard'),
    path('api/', include(router.urls))
]

from django.urls import path
from . import views


urlpatterns = [
    path('', views.new_testbed, name='new_testbed'),
    path('new_testbed_information/', views.new_testbed_information, name='new_testbed_information'),
    path('dashboard', views.dashboard, name='dashboard'),
]

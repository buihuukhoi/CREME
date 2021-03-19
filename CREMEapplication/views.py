from django.shortcuts import render
from .models import Testbed, Controller, DataLoggerServer, TargetServer, BenignServer, VulnerableClient, \
    NonVulnerableClient, AttackerServer, MaliciousClient, AttackScenario, ProgressData
from .forms import TestbedForm, ControllerForm, DataLoggerServerForm, TargetServerForm, BenignServerForm, \
    VulnerableClientForm, NonVulnerableClientForm, AttackerServerForm, MaliciousClientForm, AttackScenarioForm
from django.shortcuts import redirect

from .serializers import ProgressDataSerializer
from rest_framework import viewsets

from .tasks import execute_toolchain
from django.contrib import messages
import os
import socket


# Create your views here.


DASHBOARD = 'dashboard'
NEW_TESTBED = 'new_testbed'
NEW_TESTBED_INFORMATION = 'new_testbed_information'


# ---------- API ----------
class ProgressDataViewSet(viewsets.ModelViewSet):
    queryset = ProgressData.objects.all()
    serializer_class = ProgressDataSerializer
    # permission_classes = [permissions.IsAuthenticated]


def is_running_testbed():
    # check whether the testbed is running or not?
    testbeds = Testbed.objects.all()
    if testbeds:
        first_testbed = testbeds.first()
        if first_testbed.status == 2:
            return True


def not_exist_testbed():
    testbeds = Testbed.objects.all()
    if not testbeds:
        return True


def create_progress_data_if_not_exist():
    progress_datas = ProgressData.objects.all()
    if not progress_datas:
        ProgressData.objects.create()


def validate_ips(hostname_ip_map):
    errors = []
    all_valid = True
    for hostname, ip in hostname_ip_map.items():
        if ' ' in ip:
            all_valid = False
            errors.append("({0}) {1} is not a valid IP address".format(hostname, ip))
        else:
            HOST_UP = False
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((ip, 22))
            if result == 0:
                HOST_UP = True
            else:
                HOST_UP = False
            sock.close()

            if not HOST_UP:
                all_valid = False
                errors.append("Cannot connect with {0} ({1})".format(ip, hostname))
    return all_valid, errors


def dashboard(request):
    create_progress_data_if_not_exist()
    return render(request, 'testbed/dashboard.html', {})


def new_testbed(request):
    if is_running_testbed():
        return redirect(DASHBOARD)

    if request.method == "POST":
        form_testbed = TestbedForm(request.POST)
        form_attack_scenario = AttackScenarioForm(request.POST)

        if form_testbed.is_valid():
            testbeds = Testbed.objects.all()
            if testbeds:  # update first object if it exists, otherwise --> create new one
                first_testbed = testbeds.first()
                form_testbed = TestbedForm(request.POST, instance=first_testbed)
            testbed = form_testbed.save(commit=False)
            testbed.number_of_controller = 1
            testbed.number_of_data_logger_server = 1
            testbed.number_of_target_server = 1
            testbed.number_of_benign_server = 1
            testbed.number_of_attacker_server = 1
            testbed.number_of_malicious_client = 1
            testbed.save()

        if form_attack_scenario.is_valid():
            attack_scenarios = AttackScenario.objects.all()
            if attack_scenarios:  # update first object if it exists, otherwise --> create new one
                first_attack_scenario = attack_scenarios.first()
                form_attack_scenario = AttackScenarioForm(request.POST, instance=first_attack_scenario)
            form_attack_scenario.save()

        return redirect(NEW_TESTBED_INFORMATION)

    else:
        form_testbed = TestbedForm()
        form_attack_scenario = AttackScenarioForm()
    return render(request, 'testbed/new_testbed.html', {'form_testbed': form_testbed,
                                                        'form_attack_scenario': form_attack_scenario})


def new_testbed_information(request):
    if not_exist_testbed():
        return redirect(NEW_TESTBED)
    if is_running_testbed():
        return redirect(DASHBOARD)

    testbed = Testbed.objects.all().first()
    num_of_c = testbed.number_of_controller
    num_of_dls = testbed.number_of_data_logger_server
    num_of_target_server = testbed.number_of_target_server
    num_of_benign_server = testbed.number_of_benign_server
    num_of_vulnerable_client = testbed.number_of_vulnerable_client
    num_of_non_vulnerable_client = testbed.number_of_non_vulnerable_client
    num_of_attacker_server = testbed.number_of_attacker_server
    num_of_malicious_client = testbed.number_of_malicious_client

    if request.method == "POST":
        # clear all existing objects
        Controller.objects.all().delete()
        DataLoggerServer.objects.all().delete()
        TargetServer.objects.all().delete()
        BenignServer.objects.all().delete()
        VulnerableClient.objects.all().delete()
        NonVulnerableClient.objects.all().delete()
        AttackerServer.objects.all().delete()
        MaliciousClient.objects.all().delete()

        dict_hostname_ip = {}

        form_c = ControllerForm(request.POST, prefix='c')
        if form_c.is_valid():
            form_c = form_c.save(commit=False)
            dict_hostname_ip[form_c.hostname] = form_c.ip
            form_c.save()

        form_dls = DataLoggerServerForm(request.POST, prefix='dls')
        if form_dls.is_valid():
            form_dls = form_dls.save(commit=False)
            dict_hostname_ip[form_dls.hostname] = form_dls.ip
            form_dls.save()

        form_ts = TargetServerForm(request.POST, prefix='ts')
        if form_ts.is_valid():
            form_ts = form_ts.save(commit=False)
            dict_hostname_ip[form_ts.hostname] = form_ts.ip
            form_ts.save()

        form_bs = BenignServerForm(request.POST, prefix='bs')
        if form_bs.is_valid():
            form_bs = form_bs.save(commit=False)
            dict_hostname_ip[form_bs.hostname] = form_bs.ip
            form_bs.save()

        for i in range(num_of_vulnerable_client):
            form_vc = VulnerableClientForm(request.POST, prefix='vc{0}'.format(i+1))
            if form_vc.is_valid():
                form_vc = form_vc.save(commit=False)
                dict_hostname_ip[form_vc.hostname] = form_vc.ip
                form_vc.save()

        for i in range(num_of_non_vulnerable_client):
            form_nvc = NonVulnerableClientForm(request.POST, prefix='nvc{0}'.format(i+1))
            if form_nvc.is_valid():
                form_nvc = form_nvc.save(commit=False)
                dict_hostname_ip[form_nvc.hostname] = form_nvc.ip
                form_nvc.save()

        form_as = AttackerServerForm(request.POST, prefix='as')
        if form_as.is_valid():
            attacker_server = form_as.save(commit=False)
            attacker_server.number_of_new_bots = num_of_vulnerable_client
            dict_hostname_ip[attacker_server.hostname] = attacker_server.ip
            attacker_server.save()

        form_mc = MaliciousClientForm(request.POST, prefix='mc')
        if form_mc.is_valid():
            form_mc = form_mc.save(commit=False)
            dict_hostname_ip[form_mc.hostname] = form_mc.ip
            form_mc.save()

        # validate ip addresses
        all_valid, errors = validate_ips(dict_hostname_ip)
        if not all_valid:
            for error in errors:
                messages.error(request, error)

            dict_machines = dict()
            dict_machines['Controller'] = ControllerForm(request.POST, prefix='c')
            dict_machines['Data Logger Server'] = DataLoggerServerForm(request.POST, prefix='dls')
            dict_machines['Target Server'] = TargetServerForm(request.POST, prefix='ts')
            dict_machines['Benign Server'] = BenignServerForm(request.POST, prefix='bs')
            for i in range(num_of_vulnerable_client):
                dict_machines['Vulnerable Client {0}'.format(i + 1)] = VulnerableClientForm(request.POST,
                                                                                            prefix='vc{0}'.format(
                                                                                                i + 1))
            for i in range(num_of_non_vulnerable_client):
                dict_machines['Non-Vulnerable Client {0}'.format(i + 1)] = \
                    NonVulnerableClientForm(request.POST, prefix='nvc{0}'.format(i + 1))
            dict_machines['Attacker Server'] = AttackerServerForm(request.POST, prefix='as')
            dict_machines['Malicious Client'] = MaliciousClientForm(request.POST, prefix='mc')

            return render(request, 'testbed/new_testbed_information.html', {'dict_machines': dict_machines})

        create_progress_data_if_not_exist()

        execute_toolchain.delay()

        return redirect(DASHBOARD)
    else:
        dict_machines = dict()
        dict_machines['Controller'] = ControllerForm(prefix='c')
        dict_machines['Data Logger Server'] = DataLoggerServerForm(prefix='dls')
        dict_machines['Target Server'] = TargetServerForm(prefix='ts')
        dict_machines['Benign Server'] = BenignServerForm(prefix='bs')
        for i in range(num_of_vulnerable_client):
            dict_machines['Vulnerable Client {0}'.format(i+1)] = VulnerableClientForm(prefix='vc{0}'.format(i+1))
        for i in range(num_of_non_vulnerable_client):
            dict_machines['Non-Vulnerable Client {0}'.format(i+1)] = NonVulnerableClientForm(prefix='nvc{0}'.format(i+1))
        dict_machines['Attacker Server'] = AttackerServerForm(prefix='as')
        dict_machines['Malicious Client'] = MaliciousClientForm(prefix='mc')

    return render(request, 'testbed/new_testbed_information.html', {'dict_machines': dict_machines})

from django.shortcuts import render
from .models import Testbed, Controller, DataLoggerServer, TargetServer, BenignServer, VulnerableClient, \
    NonVulnerableClient, AttackerServer, MaliciousClient, AttackScenario, ProgressData, MachineLearningModel
from .forms import TestbedForm, ControllerForm, DataLoggerServerForm, TargetServerForm, BenignServerForm, \
    VulnerableClientForm, NonVulnerableClientForm, AttackerServerForm, MaliciousClientForm, AttackScenarioForm, \
    MachineLearningModelForm
from django.shortcuts import redirect

from .serializers import ProgressDataSerializer
from rest_framework import viewsets

from .tasks import execute_toolchain
from django.contrib import messages
import os
import socket
import json
import pandas as pd
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
            try:
                sock.settimeout(1)
                result = sock.connect_ex((ip, 22))
                if result == 0:
                    HOST_UP = True
                else:
                    HOST_UP = False
            except socket.error as exc:
                print("Caught exception socket.error : {0}".format(exc))
            finally:
                sock.close()

            if not HOST_UP:
                all_valid = False
                errors.append("Cannot connect with IP address {0} ({1})".format(ip, hostname))
    return all_valid, errors


def dashboard(request):
    create_progress_data_if_not_exist()
    testbeds = Testbed.objects.all()
    out = [[]]
    headers = []
    context = {}
    if testbeds:
        first_testbed = testbeds.first()
        if first_testbed.status == 3:
            # Ref : https://www.geeksforgeeks.org/rendering-data-frame-to-html-template-in-table-view-using-django-framework/
            file_dir = os.path.dirname(__file__)
            accuracy_dir =  os.path.join(file_dir, '../CREME_backend_execution/evaluation_results/accuracy')
            data_sources = ['accounting','syslog','traffic']
            
            
            for i, source in enumerate(data_sources):
                data = []
                csv_path = os.path.join(accuracy_dir, 'accuracy_for_{}.csv'.format(source))
                df = pd.read_csv(csv_path) 
                json_records = df.reset_index().to_json(orient ='records')
                data.append([])
                data = json.loads(json_records)
                
                context["d_{}".format(source)] =  data 
                
                
    return render(request, 'testbed/dashboard.html', context)


def new_testbed(request):
    if is_running_testbed():
        return redirect(DASHBOARD)

    if request.method == "POST":
        form_testbed = TestbedForm(request.POST)
        form_attack_scenario = AttackScenarioForm(request.POST)
        form_machine_learning_model = MachineLearningModelForm(request.POST)

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
            testbed.number_of_non_vulnerable_client = max(2, testbed.number_of_non_vulnerable_client)
            testbed.save()

        scenario_valid = False  # at least one scenario must be selected
        if form_attack_scenario.is_valid():
            # must select at least one attack scenario
            for field_name in form_attack_scenario.fields:
                value = form_attack_scenario.cleaned_data[field_name]
                scenario_valid = scenario_valid or value
            attack_scenarios = AttackScenario.objects.all()
            # update first object if it exists, otherwise --> create new one
            if attack_scenarios:
                first_attack_scenario = attack_scenarios.first()
                form_attack_scenario = AttackScenarioForm(request.POST, instance=first_attack_scenario)
            form_attack_scenario.save()

        ml_model_valid = False  # at least one ml model must be selected
        if form_machine_learning_model.is_valid():
            # must select at least one ml model
            for field_name in form_machine_learning_model.fields:
                value = form_machine_learning_model.cleaned_data[field_name]
                ml_model_valid = ml_model_valid or value
            machine_learning_models = MachineLearningModel.objects.all()
            # update first object if it exists, otherwise --> create new one
            if machine_learning_models:
                first_machine_learning_model = machine_learning_models.first()
                form_machine_learning_model = MachineLearningModelForm(request.POST,
                                                                       instance=first_machine_learning_model)
            form_machine_learning_model.save()

        # if not valid --> re-fill the form
        if not scenario_valid or not ml_model_valid:
            if not scenario_valid:
                error = "Must select at least one attack scenario"
                messages.error(request, error)
            if not ml_model_valid:
                error = "Must select at least one machine learning model"
                messages.error(request, error)

            dict_forms = dict()
            dict_forms['Number of machines:'] = TestbedForm(request.POST)
            dict_forms['Scenario:'] = AttackScenarioForm(request.POST)
            dict_forms['Machine Learning model:'] = MachineLearningModelForm(request.POST)

            return render(request, 'testbed/new_testbed.html', {'dict_forms': dict_forms})

        return redirect(NEW_TESTBED_INFORMATION)

    else:
        dict_forms = dict()
        dict_forms['Number of machines:'] = TestbedForm()
        dict_forms['Scenario:'] = AttackScenarioForm()
        dict_forms['Machine Learning model:'] = MachineLearningModelForm()
    return render(request, 'testbed/new_testbed.html', {'dict_forms': dict_forms})


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

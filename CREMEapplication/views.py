from django.shortcuts import render
from .models import Testbed, DataLoggerServer, TargetServer, BenignServer, VulnerableClient, NonVulnerableClient,\
    AttackerServer, MaliciousClient, AttackScenario
from .forms import TestbedForm, DataLoggerServerForm, TargetServerForm, BenignServerForm, VulnerableClientForm,\
    NonVulnerableClientForm, AttackerServerForm, MaliciousClientForm, AttackScenarioForm
from django.shortcuts import redirect

# Create your views here.


DASHBOARD = 'dashboard'
NEW_TESTBED = 'new_testbed'
NEW_TESTBED_INFORMATION = 'new_testbed_information'


def is_running():
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


def dashboard(request):
    return render(request, 'testbed/dashboard.html', {})


def new_testbed(request):
    if is_running():
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
    if is_running():
        return redirect(DASHBOARD)

    testbed = Testbed.objects.all().first()
    num_of_dls = testbed.number_of_data_logger_server
    num_of_target_server = testbed.number_of_target_server
    num_of_benign_server = testbed.number_of_benign_server
    num_of_vulnerable_client = testbed.number_of_vulnerable_client
    num_of_non_vulnerable_client = testbed.number_of_non_vulnerable_client
    num_of_attacker_server = testbed.number_of_attacker_server
    num_of_malicious_client = testbed.number_of_malicious_client

    if request.method == "POST":
        # clear all existing objects
        DataLoggerServer.objects.all().delete()
        TargetServer.objects.all().delete()
        BenignServer.objects.all().delete()
        VulnerableClient.objects.all().delete()
        NonVulnerableClient.objects.all().delete()
        AttackerServer.objects.all().delete()
        MaliciousClient.objects.all().delete()

        form_dls = DataLoggerServerForm(request.POST, prefix='dls')
        if form_dls.is_valid():
            form_dls.save()

        form_ts = TargetServerForm(request.POST, prefix='ts')
        if form_ts.is_valid():
            form_ts.save()

        form_bs = BenignServerForm(request.POST, prefix='bs')
        if form_bs.is_valid():
            form_bs.save()

        form_as = AttackerServerForm(request.POST, prefix='as')
        if form_as.is_valid():
            form_as.save()

        form_mc = MaliciousClientForm(request.POST, prefix='mc')
        if form_mc.is_valid():
            form_mc.save()

        for i in range(num_of_vulnerable_client):
            form_vc = VulnerableClientForm(request.POST, prefix='vc{0}'.format(i+1))
            if form_vc.is_valid():
                form_vc.save()

        for i in range(num_of_non_vulnerable_client):
            form_nvc = NonVulnerableClientForm(request.POST, prefix='nvc{0}'.format(i+1))
            if form_nvc.is_valid():
                form_nvc.save()
        return redirect(DASHBOARD)
    else:
        dict_machines = dict()
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

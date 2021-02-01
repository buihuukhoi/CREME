from django.shortcuts import render
from .models import Testbed, Controller, DataLoggerServer, TargetServer, BenignServer, VulnerableClient, \
    NonVulnerableClient, AttackerServer, MaliciousClient, AttackScenario
from .forms import TestbedForm, ControllerForm, DataLoggerServerForm, TargetServerForm, BenignServerForm, \
    VulnerableClientForm, NonVulnerableClientForm, AttackerServerForm, MaliciousClientForm, AttackScenarioForm
from django.shortcuts import redirect
import threading
from CREME_backend_execution.classes import machines
from CREME_backend_execution.classes.CREME import Creme

# Create your views here.


DASHBOARD = 'dashboard'
NEW_TESTBED = 'new_testbed'
NEW_TESTBED_INFORMATION = 'new_testbed_information'


def update_running_testbed():
    testbeds = Testbed.objects.all()
    if testbeds:
        first_testbed = testbeds.first()
        first_testbed.status = 2
        first_testbed.save()


def load_testbed_information():
    # ===> Load testbed's information from database <===
    info_controller = Controller.objects.all().first()
    info_dls = DataLoggerServer.objects.all().first()
    info_ts = TargetServer.objects.all().first()
    info_bs = BenignServer.objects.all().first()
    info_list_vc = VulnerableClient.objects.all()
    info_list_nvc = NonVulnerableClient.objects.all()
    info_as = AttackerServer.objects.all().first()
    info_mc = MaliciousClient.objects.all().first()

    info_attack_scenario = AttackScenario.objects.all().first()
    mirai = info_attack_scenario.mirai
    ransomware = info_attack_scenario.ransomware
    resource_hijacking = info_attack_scenario.resource_hijacking
    disk_wipe = info_attack_scenario.disk_wipe
    end_point_dos = info_attack_scenario.end_point_dos

    # ===> prepare machine's information for a Creme object <===
    machines.Machine.controller_hostname = info_controller.hostname
    machines.Machine.controller_ip = info_controller.ip
    machines.Machine.controller_username = info_controller.username
    machines.Machine.controller_password = info_controller.password
    machines.Machine.controller_path = info_controller.path

    dls = machines.DataLoggerServer(info_dls.hostname, info_dls.ip, info_dls.username, info_dls.password,
                                    info_dls.path, info_dls.network_interface, atop_interval=info_dls.atop_interval)
    machines.DataLoggerClient.dls = dls  # load dls to Data Logger Client, use to centralize data from clients
    target_server = machines.TargetServer(info_ts.hostname, info_ts.ip, info_ts.username, info_ts.password,
                                          info_ts.path, attacker_server_ip=info_as.ip)
    benign_server = machines.BenignServer(info_bs.hostname, info_bs.ip, info_bs.username, info_bs.password,
                                          info_bs.path, attacker_server_ip=info_as.ip)

    vulnerable_clients = []
    for info_vc in info_list_vc:
        vulnerable_client = machines.VulnerableClient(info_vc.hostname, info_vc.ip, info_vc.username, info_vc.password,
                                                      info_vc.path, server=target_server)
        vulnerable_clients.append(vulnerable_client)

    non_vulnerable_clients = []
    for info_nvc in info_list_nvc:
        non_vulnerable_client = machines.NonVulnerableClient(info_nvc.hostname, info_nvc.ip, info_nvc.username,
                                                             info_nvc.password, info_nvc.path, server=benign_server)
        non_vulnerable_clients.append(non_vulnerable_client)

    machines.AttackerServer.data_logger_server_ip = info_dls.ip
    attacker_server = machines.AttackerServer(info_as.hostname, info_as.ip, info_as.username, info_as.password,
                                              info_as.path)
    machines.MaliciousClient.data_logger_server_ip = info_dls.ip
    malicious_client = machines.MaliciousClient(info_mc.hostname, info_mc.ip, info_mc.username, info_mc.password,
                                                info_mc.path)

    # ===> create a Creme object <===
    creme = Creme(dls, target_server, benign_server, vulnerable_clients, non_vulnerable_clients, attacker_server,
                  malicious_client, mirai, ransomware, resource_hijacking, disk_wipe, end_point_dos)
    creme.test_print_information()


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


def execute_toolchain():
    update_running_testbed()
    load_testbed_information()
    print("the toolchain is executing...............")
    pass


def dashboard(request):
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

        form_c = ControllerForm(request.POST, prefix='c')
        if form_c.is_valid():
            form_c.save()

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
            attacker_server = form_as.save(commit=False)
            attacker_server.number_of_new_bots = num_of_vulnerable_client
            attacker_server.save()

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

        # execute the main task
        t = threading.Thread(target=execute_toolchain(), args=())
        t.start()

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

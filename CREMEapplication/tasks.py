from CREME.celery import app
from .models import Testbed, Controller, DataLoggerServer, TargetServer, BenignServer, VulnerableClient, \
    NonVulnerableClient, AttackerServer, MaliciousClient, AttackScenario, ProgressData, MachineLearningModel
from CREME_backend_execution.classes import machines
from CREME_backend_execution.classes.CREME import Creme


def update_testbed_status(id_status):
    """
    use to update status of testbed
    :param id_status: 1 off, 2 running, 3 finished
    :return:
    """
    testbeds = Testbed.objects.all()
    if testbeds:
        first_testbed = testbeds.first()
        first_testbed.status = id_status
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

    models_name = []
    info_machine_learning_model = MachineLearningModel.objects.all().first()
    if info_machine_learning_model.decision_tree:
        models_name.append("decision_tree")
    if info_machine_learning_model.naive_bayes:
        models_name.append("naive_bayes")
    if info_machine_learning_model.extra_tree:
        models_name.append("extra_tree")
    if info_machine_learning_model.knn:
        models_name.append("knn")
    if info_machine_learning_model.random_forest:
        models_name.append("random_forest")
    if info_machine_learning_model.XGBoost:
        models_name.append("XGBoost")

    # ===> prepare machine's information for a Creme object <===
    machines.Machine.controller_hostname = info_controller.hostname
    machines.Machine.controller_ip = info_controller.ip
    machines.Machine.controller_username = info_controller.username
    machines.Machine.controller_password = info_controller.password
    machines.Machine.controller_path = info_controller.path

    dls = machines.DataLoggerServer(info_dls.hostname, info_dls.ip, info_dls.username, info_dls.password,
                                    info_dls.path, info_dls.network_interface,
                                    atop_interval=info_dls.atop_interval)
    machines.DataLoggerClient.dls = dls  # load dls to Data Logger Client, use to centralize data from clients
    target_server = machines.TargetServer(info_ts.hostname, info_ts.ip, info_ts.username, info_ts.password,
                                          info_ts.path, attacker_server_ip=info_as.ip)
    benign_server = machines.BenignServer(info_bs.hostname, info_bs.ip, info_bs.username, info_bs.password,
                                          info_bs.path, attacker_server_ip=info_as.ip)

    vulnerable_clients = []
    for info_vc in info_list_vc:
        vulnerable_client = machines.VulnerableClient(info_vc.hostname, info_vc.ip, info_vc.username,
                                                      info_vc.password,
                                                      info_vc.path, server=target_server)
        vulnerable_clients.append(vulnerable_client)

    non_vulnerable_clients = []
    for info_nvc in info_list_nvc:
        non_vulnerable_client = machines.NonVulnerableClient(info_nvc.hostname, info_nvc.ip, info_nvc.username,
                                                             info_nvc.password, info_nvc.path, server=benign_server)
        non_vulnerable_clients.append(non_vulnerable_client)

    machines.TargetServer.vulnerable_clients = vulnerable_clients
    machines.TargetServer.non_vulnerable_clients = non_vulnerable_clients
    machines.BenignServer.vulnerable_clients = vulnerable_clients
    machines.BenignServer.non_vulnerable_clients = non_vulnerable_clients

    machines.AttackerServer.data_logger_server_ip = info_dls.ip
    machines.AttackerServer.DNS_server_ip = target_server.ip
    attacker_server = machines.AttackerServer(info_as.hostname, info_as.ip, info_as.username, info_as.password,
                                              info_as.path, number_of_new_bots=info_as.number_of_new_bots,
                                              targeted_DDoS=info_ts.ip, DDoS_type=info_as.DDoS_type,
                                              DDoS_duration=info_as.DDoS_duration)
    machines.MaliciousClient.data_logger_server_ip = info_dls.ip
    machines.MaliciousClient.attacker_server = info_as
    machines.MaliciousClient.DNS_server_ip = target_server.ip
    malicious_client = machines.MaliciousClient(info_mc.hostname, info_mc.ip, info_mc.username,
                                                info_mc.password, info_mc.path)

    # ===> create a Creme object <===
    Creme.models_name = models_name[:]
    creme = Creme(dls, target_server, benign_server, vulnerable_clients, non_vulnerable_clients, attacker_server,
                  malicious_client, mirai, ransomware, resource_hijacking, disk_wipe, end_point_dos)
    creme.run()
    # creme.test_print_information()
    # creme.configure()


@app.task
def execute_toolchain():
    print("the toolchain is executing...............")
    update_testbed_status(id_status=2)  # running
    load_testbed_information()
    update_testbed_status(id_status=3)  # finished
    pass

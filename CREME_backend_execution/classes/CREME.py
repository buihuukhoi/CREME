from .machines import *
from .helper import DownloadDataHelper


class Creme:
    mirai = True
    ransomware = True
    resource_hijacking = True
    disk_wipe = True
    end_point_dos = True

    def __init__(self, dls, target_server, benign_server, vulnerable_clients, non_vulnerable_clients,
                 attacker_server, malicious_client, mirai, ransomware, resource_hijacking, disk_wipe, end_point_dos):
        # self.stage = 0
        # self.status = 1
        # self.finishedTasks = []
        # self.messages = []
        # self.sizes = []
        # self.finishedStageList = []
        # Helper.clearProgressData()

        # Machines
        self.dls = dls
        self.target_server = target_server
        self.benign_server = benign_server
        self.vulnerable_clients = vulnerable_clients
        self.non_vulnerable_clients = non_vulnerable_clients
        self.attacker_server = attacker_server
        self.malicious_client = malicious_client

        # Attack scenarios. True/False
        Creme.mirai = mirai
        Creme.ransomware = ransomware
        Creme.resource_hijacking = resource_hijacking
        Creme.disk_wipe = disk_wipe
        Creme.end_point_dos = end_point_dos

    def configure(self):
        self.dls.configure()
        self.target_server.configure()
        self.benign_server.configure()
        for vulnerable_client in self.vulnerable_clients:
            vulnerable_client.configure()
        for non_vulnerable_client in self.non_vulnerable_clients:
            non_vulnerable_client.configure()
        self.attacker_server.configure()
        self.malicious_client.configure()

    # ---------- data collection ----------
    def start_collect_data(self):
        self.dls.start_collect_data()
        self.target_server.start_collect_data()
        self.benign_server.start_collect_data()
        for vulnerable_client in self.vulnerable_clients:
            vulnerable_client.start_collect_data()
        for non_vulnerable_client in self.non_vulnerable_clients:
            non_vulnerable_client.start_collect_data()

    def stop_collect_data(self):
        self.dls.stop_collect_data()
        self.target_server.stop_collect_data()
        self.benign_server.stop_collect_data()
        for vulnerable_client in self.vulnerable_clients:
            vulnerable_client.stop_collect_data()
        for non_vulnerable_client in self.non_vulnerable_clients:
            non_vulnerable_client.stop_collect_data()

    def centralize_data(self, contain_continuum_log=False):
        """
        using to centralize data from the data logger client to the data logger server
        :param contain_continuum_log: whether the attack scenario should collect log of apache continuum server or not
        """
        for vulnerable_client in self.vulnerable_clients:
            self.dls.centralize_data(vulnerable_client)
        for non_vulnerable_client in self.non_vulnerable_clients:
            self.dls.centralize_data(non_vulnerable_client)
        self.dls.centralize_data(self.target_server, contain_continuum_log)
        self.dls.centralize_data(self.benign_server, contain_continuum_log)

    def centralize_time_files(self, is_mirai=False):
        """
        using to centralize time files from the data logger client to the data logger server
        :param is_mirai: whether the scenario is mirai or not
        """
        if is_mirai:
            self.dls.mirai_centralize_time_files(self.attacker_server)
        # should implement for other scenario *******************************************************

    # ---------- benign behavior reproduction ----------
    def start_reproduce_benign_behavior(self):
        for vulnerable_client in self.vulnerable_clients:
            vulnerable_client.start_benign_behaviors()
        for non_vulnerable_client in self.non_vulnerable_clients:
            non_vulnerable_client.start_benign_behaviors()

    def stop_reproduce_benign_behavior(self):
        for vulnerable_client in self.vulnerable_clients:
            vulnerable_client.stop_benign_behaviors()
        for non_vulnerable_client in self.non_vulnerable_clients:
            non_vulnerable_client.stop_benign_behaviors()

    # ---------- attacks ----------
    def attack_mirai(self):
        self.attacker_server.mirai_start_cnc_and_login()
        self.malicious_client.mirai_start_malicious()
        self.attacker_server.mirai_wait_for_finished_scan()
        self.malicious_client.mirai_stop_malicious()
        self.attacker_server.mirai_transfer_and_start_malicious()
        self.attacker_server.mirai_wait_for_finished_transfer()
        self.attacker_server.mirai_wait_for_finished_ddos()

    # ---------- download data to controller ----------
    def download_data_to_controller(self, scenario_log_folder):
        """
        using to download data from the data logger server to controller, and save it to scenario_log_folder.
        :param scenario_log_folder: a folder of specific scenario insides the logs folder.
        """
        log_folder = Machine.controller_path
        tmp_folder_names = ["CREME", "CREME_backend_execution", "logs", scenario_log_folder]
        for folder in tmp_folder_names:
            log_folder = os.path.join(log_folder, folder)

        # ----- download pcap file -----
        traffic = "traffic"
        traffic_folder = os.path.join(log_folder, traffic)

        file_names = [self.dls.tcpFile]
        DownloadDataHelper.get_data(self.dls.ip, self.dls.username, self.dls.password, remote_folder=self.dls.path,
                                    file_names=file_names, local_folder=traffic_folder)

        # ----- download accounting files -----
        accounting = "accounting"
        accounting_folder = os.path.join(log_folder, accounting)

        file_names = []
        file_names.append(self.benign_server.atop_file)
        file_names.append(self.target_server.atop_file)
        for vulnerable_client in self.vulnerable_clients:
            file_names.append(vulnerable_client.atop_file)
        for non_vulnerable_client in self.non_vulnerable_clients:
            file_names.append(non_vulnerable_client.atop_file)

        DownloadDataHelper.get_data(self.dls.ip, self.dls.username, self.dls.password, remote_folder=self.dls.path,
                                    file_names=file_names, local_folder=accounting_folder)

        # ----- download accounting files -----
        syslog = "syslog"
        syslog_folder = os.path.join(log_folder, syslog)
        remote_folder = "/var/log/dataset_generation"
        file_names = ["dataset_generation.log"]

        DownloadDataHelper.get_data(self.dls.ip, self.dls.username, self.dls.password, remote_folder=remote_folder,
                                    file_names=file_names, local_folder=syslog_folder)

        # ----- download timestamp files -----
        # not yet implement ==> must implement this later

    def run_mirai(self):
        self.start_reproduce_benign_behavior()
        self.start_collect_data()
        self.attack_mirai()
        self.stop_collect_data()

        self.stop_reproduce_benign_behavior()
        self.attacker_server.clean_mirai()

        self.centralize_data()
        self.centralize_time_files(is_mirai=True)

        self.download_data_to_controller("mirai")

    def run(self):
        self.configure()

        if Creme.mirai:
            self.run_mirai()

        # process data
        # train ML
        # evaluation

    def test_print_information(self):
        """
        This function uses only for testing purpose.
        It will be removed later.
        """
        print("=====> Print Information <=====")
        print("controller: {0}, {1}, {2}, {3}, {4}".format(self.dls.controller_hostname, self.dls.controller_ip,
                                                           self.dls.controller_username, self.dls.controller_password,
                                                           self.dls.controller_path))
        print("<<<DLS>>> {0}".format(self.dls))
        print("<<<Target Server>>> {0}".format(self.target_server))
        print("<<<Benign Server>>> {0}".format(self.benign_server))
        for vulnerable_client in self.vulnerable_clients:
            print("<<<Vulnerable Client>>> {0}".format(vulnerable_client))
        for non_vulnerable_client in self.non_vulnerable_clients:
            print("<<<Non Vulnerable Client>>> {0}".format(non_vulnerable_client))
        print("<<<Attacker Server>>> {0}".format(self.attacker_server))
        print("<<<Malicious Client>>> {0}".format(self.malicious_client))

        print("mirai: {0}".format(self.mirai))
        print("ransomware: {0}".format(self.ransomware))
        print("resource_hijacking: {0}".format(self.resource_hijacking))
        print("disk_wipe: {0}".format(self.disk_wipe))
        print("end_point_dos: {0}".format(self.end_point_dos))
        print("===============================")

        # self.dls.configure_base()



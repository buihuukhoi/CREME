from .machines import *


class Creme:
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
        self.mirai = mirai
        self.ransomware = ransomware
        self.resource_hijacking = resource_hijacking
        self.disk_wipe = disk_wipe
        self.end_point_dos = end_point_dos

    def configure(self):
        pass

    def attack(self):
        pass

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



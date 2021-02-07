from interface import Interface


class IConfiguration(Interface):
    def configure(self):
        pass


class IConfigurationCommon(Interface):
    def configure_base(self):
        pass

    def configure_data_collection(self):
        pass


class IConfigurationAttack(Interface):
    def configure_mirai(self):
        pass

    def configure_ransomware(self):
        pass

    def configure_resource_hijacking(self):
        pass

    def configure_disk_wipe(self):
        pass

    def configure_end_point_dos(self):
        pass


class IDataCollection(Interface):
    def start_collect_data(self):
        pass

    def stop_collect_data(self):
        pass


class IConfigurationBenign(Interface):
    def configure_benign_services(self):
        pass


class IBenignReproduction(Interface):
    """
    defining actions for clients to generate benign behaviors to servers
    """
    def start_benign_behaviors(self):
        pass

    def stop_benign_behaviors(self):
        pass


class IAttack(Interface):
    """
    defining attack scenarios that should be implemented by Creme
    """
    def attack_mirai(self):
        pass

    def attack_ransomware(self):
        pass

    def attack_resource_hijacking(self):
        pass

    def attack_disk_wipe(self):
        pass

    def attack_end_point_dos(self):
        pass


class IMiraiAttackerServer(Interface):
    """
    defining actions of Mirai attack for the attacker server
    """
    def mirai_start_cnc_and_login(self):
        pass

    def mirai_wait_for_finished_scan(self):
        pass

    def mirai_transfer_and_start_malicious(self):
        pass

    def mirai_wait_for_finished_transfer(self):
        pass

    def mirai_wait_for_finished_ddos(self):
        pass


class IMiraiMaliciousClient(Interface):
    """
    defining actions of Mirai attack for the malicious client
    """
    def mirai_start_malicious(self):
        pass

    def mirai_stop_malicious(self):
        pass


from interface import Interface


# ---------- configuration ----------
class IConfiguration(Interface):
    def configure(self):
        """
        this function calls all of necessary configurations for each machine.
        """
        pass


class IConfigurationCommon(Interface):
    """
    defining common configurations that should be implemented by all cases of machines:
    including DataLoggerServer, DataLoggerClient, VulnerableClient, NonVulnerableClient, TargetServer, BenignServer,
    AttackerServer, MaliciousClient
    """
    def configure_base(self):
        pass

    def configure_data_collection(self):
        pass


class IConfigurationBenign(Interface):
    """
    defining configurations for benign services that should be implemented by clients and servers:
    including VulnerableClient, NonVulnerableClient, TargetServer, BenignServer
    """
    def configure_benign_services(self):
        pass


class IConfigurationAttack(Interface):
    """
    defining configurations for attack scenarios that should be implemented by clients and servers:
    including VulnerableClient, TargetServer, AttackerServer, MaliciousClient
    """
    def configure_mirai(self):
        pass

    def configure_pymetasploit(self):
        pass

    def configure_ransomware(self):
        pass

    def configure_resource_hijacking(self):
        pass

    def configure_disk_wipe(self):
        pass

    def configure_end_point_dos(self):
        pass


# ---------- data collection ----------
class IDataCollection(Interface):
    def start_collect_data(self):
        pass

    def stop_collect_data(self):
        pass


class IDataCentralization(Interface):
    """
    defining functions to centralize data that should be implemented by the data logger server:
    """
    def centralize_data(self, data_logger_client, contain_continuum_log=False):
        """
        using to centralize data from the data logger client to the data logger server
        :param data_logger_client: the machine which we want to centralize data from
        :param contain_continuum_log: whether the data logger client contains log of apache continuum server or not
        """
        pass

    def centralize_time_files(self, data_logger_client, time_files):
        """
        using to centralize time files from the data logger client to the data logger server
        :param data_logger_client: the machine which you want to centralize time files from
        :param time_files: name of time files you want to get from the remote machine
        """
        pass

    # def centralize_time_files(self, data_logger_client):
    #     pass


# ---------- benign behavior reproduction ----------
class IBenignReproduction(Interface):
    """
    defining actions for clients to generate benign behaviors to servers
    """
    def start_benign_behaviors(self):
        pass

    def stop_benign_behaviors(self):
        pass


# ---------- attacks ----------
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
        """
        starting cnc program and telnet login to cnc program to control bots
        """
        pass

    def mirai_wait_for_finished_scan(self):
        """
        waiting the malicious client to finish scanning new bots
        """
        pass

    def mirai_transfer_and_start_malicious(self):
        """
        cnc transfers malicious software (mirai) to new bots and run it (mirai)
        """
        pass

    def mirai_wait_for_finished_transfer(self):
        """
        cnc waits to finish transferring malicious software (mirai) to new bots.
        Then, cnc sends ddos commands to bots.
        """
        pass

    def mirai_wait_for_finished_ddos(self):
        """
        waiting to finish ddos attack.
        """
        pass


class IMiraiMaliciousClient(Interface):
    """
    defining actions of Mirai attack for the malicious client
    """
    def mirai_start_malicious(self):
        """
        starting the malicious software (mirai) at malicious client and scanning to find new bots.
        """
        pass

    def mirai_stop_malicious(self):
        """
        should stop the malicious software (mirai) before cnc transfers mirai to new bots.
        Otherwise, cnc may fail to telnet login to new bots. Because the ip range is small, the malicious client will
        continue to scan the bot even it already found the username and password.
        Contracting a list of existing bots may help to deal this problem.
        """
        pass


# ---------- process cleaning ----------
class ICleaningBenignReproduction(Interface):
    """
    defining actions for clients to clean benign reproduction.
    should be implemented by VulnerableClient and NonVulnerableClient.
    """
    def clean_benign_reproduction(self):
        pass


class ICleaningAttackReproduction(Interface):
    """
    defining actions for attacker server to clean attack reproduction.
    should be implemented by AttackerServer.
    """
    def clean_mirai(self):
        pass

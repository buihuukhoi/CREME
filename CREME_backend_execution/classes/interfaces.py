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


import os


class ScriptHelper:
    @staticmethod
    def get_del_known_hosts_path(scripts_path, del_script="./del_known_hosts.sh"):
        del_known_hosts_path = os.path.join(scripts_path, del_script)
        return del_known_hosts_path

    @staticmethod
    def get_script_cmd(file):
        scripts_path = os.path.join("CREME_backend_execution", "scripts")
        cmd = os.path.join(scripts_path, file)
        del_known_hosts_path = ScriptHelper.get_del_known_hosts_path(scripts_path, "./del_known_hosts.sh")
        return cmd, del_known_hosts_path




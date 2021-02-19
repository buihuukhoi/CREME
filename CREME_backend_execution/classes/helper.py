import os
import paramiko


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

    @staticmethod
    def execute_script(filename_path, parameters, show_cmd=False):
        cmd, del_known_hosts_path = ScriptHelper.get_script_cmd(filename_path)
        cmd += " {0}".format(del_known_hosts_path)
        for parameter in parameters:
            cmd += " {0}".format(parameter)
        print(cmd) if show_cmd else os.system(cmd)


class DownloadDataHelper:
    """
    this class supports to download data from machines to the Controller
    """
    @staticmethod
    def get_data(ip, username, password, remote_folder, file_names, local_folder):
        """
        using to get files that have a name existing in file_names at remote_folder from ip,
        and save them to local_folder.
        """
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(hostname=ip, username=username, password=password)

        ftp_client = ssh_client.open_sftp()

        for file_name in file_names:
            remote_file = os.path.join(remote_folder, file_name)
            local_file = os.path.join(local_folder, file_name)
            ftp_client.get(remote_file, local_file)

        ftp_client.close()

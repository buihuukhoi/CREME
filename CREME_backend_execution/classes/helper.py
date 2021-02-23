import os
import paramiko
from CREMEapplication.models import ProgressData


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


class ProgressHelper:
    """
    this class supports to update progress data that used to display progress on the dashboard
    """
    scenario = "scenario"
    status_fields = {1: "stage_1_status", 2: "stage_2_status", 3: "stage_3_status", 4: "stage_4_status",
                     5: "stage_5_status", 6: "stage_6_status", 7: "stage_7_status"}
    detail_fields = {1: "stage_1_detail", 2: "stage_2_detail", 3: "stage_3_detail", 4: "stage_4_detail",
                     5: "stage_5_detail", 7: "stage_6_detail", 7: "stage_7_detail"}
    messages = []

    @staticmethod
    def update_scenario(scenario):
        """
        use to update displayed scenario on the dashboard
        """
        progress_data_all = ProgressData.objects.all()
        progress_data = progress_data_all.first()
        setattr(progress_data, ProgressHelper.scenario, scenario)
        progress_data.save()

    @staticmethod
    def clean_attack_stages():
        """
        use to clean attack stages when moving to other attack scenario.
        it is called by update_stage() function
        """
        progress_data_all = ProgressData.objects.all()
        progress_data = progress_data_all.first()

        off_status = 1
        off_detail = "None"
        for i in range(2, 5):
            status_field = ProgressHelper.status_fields[i]
            detail_field = ProgressHelper.detail_fields[i]
            setattr(progress_data, status_field, off_status)
            setattr(progress_data, detail_field, off_detail)
        progress_data.save()

    @staticmethod
    def update_messages(message, size, finished_task, override_pre_message, finished_stage, new_stage):
        """
        use to update messages in the detail part of stage.
        it is called by update_stage() function
        """
        if new_stage:
            ProgressHelper.messages = []

        running_icon = '<i class="fa fa-refresh" aria-hidden="true"></i>'
        success_icon = '<i class="fa fa-check" aria-hidden="true"></i>'
        if finished_task:
            icon = success_icon
        else:
            icon = running_icon
        message = f'<h{size}>{icon} {message}</h{size}>'
        # message += "<br>"

        if override_pre_message:
            ProgressHelper.messages[-1] = message
        else:
            ProgressHelper.messages.append(message)

        if finished_stage:
            finished_message = "Finished Stage"
            class_finish_stage = ' class="alert alert-success" role="alert"'
            finished_message = f'<h{size}{class_finish_stage}>{icon} {finished_message}</h{size}>'
            ProgressHelper.messages.append(finished_message)

    @staticmethod
    def update_stage(stage, message, size, finished_task=False, override_pre_message=False, finished_stage=False,
                     new_stage=False):
        """
        use to update status and detail of stages on the dashboard
        """
        if new_stage and stage == 2:
            ProgressHelper.clean_attack_stages()

        ProgressHelper.update_messages(message, size, finished_task, override_pre_message, finished_stage, new_stage)
        detail = ""
        for message in ProgressHelper.messages:
            detail += message

        # update progress object
        progress_data_all = ProgressData.objects.all()
        progress_data = progress_data_all.first()

        status_field = ProgressHelper.status_fields[stage]
        if new_stage:
            setattr(progress_data, status_field, 2)
        if finished_stage:
            setattr(progress_data, status_field, 3)
        detail_field = ProgressHelper.detail_fields[stage]
        setattr(progress_data, detail_field, detail)
        progress_data.save()



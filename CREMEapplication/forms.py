from django import forms

from .models import Testbed, Controller, DataLoggerServer, TargetServer, BenignServer, VulnerableClient,\
    NonVulnerableClient, AttackerServer, MaliciousClient, AttackScenario, MachineLearningModel, SkipStage


class TestbedForm(forms.ModelForm):

    class Meta:
        model = Testbed
        fields = ('number_of_controller', 'number_of_data_logger_server', 'number_of_target_server',
                  'number_of_benign_server', 'number_of_vulnerable_client', 'number_of_non_vulnerable_client',
                  'number_of_attacker_server', 'number_of_malicious_client')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['number_of_controller'].disabled = True
        self.fields['number_of_data_logger_server'].disabled = True
        self.fields['number_of_target_server'].disabled = True
        self.fields['number_of_benign_server'].disabled = True
        self.fields['number_of_attacker_server'].disabled = True
        self.fields['number_of_malicious_client'].disabled = True


class ControllerForm(forms.ModelForm):
    class Meta:
        model = Controller
        fields = ('hostname', 'ip', 'username', 'password', 'path')


class DataLoggerServerForm(forms.ModelForm):
    class Meta:
        model = DataLoggerServer
        fields = ('hostname', 'ip', 'username', 'password', 'path', 'network_interface', 'atop_interval')


class TargetServerForm(forms.ModelForm):
    class Meta:
        model = TargetServer
        fields = ('hostname', 'ip', 'username', 'password', 'path')


class BenignServerForm(forms.ModelForm):
    class Meta:
        model = BenignServer
        fields = ('hostname', 'ip', 'username', 'password', 'path')


class VulnerableClientForm(forms.ModelForm):
    class Meta:
        model = VulnerableClient
        fields = ('hostname', 'ip', 'username', 'password', 'path')


class NonVulnerableClientForm(forms.ModelForm):
    class Meta:
        model = NonVulnerableClient
        fields = ('hostname', 'ip', 'username', 'password', 'path')


class AttackerServerForm(forms.ModelForm):
    class Meta:
        model = AttackerServer
        fields = ('hostname', 'ip', 'username', 'password', 'path', 'DDoS_type', 'DDoS_duration')


class MaliciousClientForm(forms.ModelForm):
    class Meta:
        model = MaliciousClient
        fields = ('hostname', 'ip', 'username', 'password', 'path')


class AttackScenarioForm(forms.ModelForm):
    class Meta:
        model = AttackScenario
        fields = ('mirai', 'ransomware', 'resource_hijacking', 'disk_wipe', 'end_point_dos', 'data_theft',
                  'rootkit_ransomware')


class MachineLearningModelForm(forms.ModelForm):
    class Meta:
        model = MachineLearningModel
        fields = ("decision_tree", "naive_bayes", "extra_tree", "knn", "random_forest", "XGBoost")

class SkipStageForm(forms.ModelForm):
    class Meta:
        model = SkipStage
        fields = {"skip configuration","skip reproduction","skip data processing","skip ML training","skip evaluation"}
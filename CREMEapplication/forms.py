from django import forms

from .models import Testbed, DataLoggerServer, TargetServer, BenignServer, VulnerableClient, NonVulnerableClient,\
    AttackerServer, MaliciousClient


class TestbedForm(forms.ModelForm):

    class Meta:
        model = Testbed
        fields = ('number_of_data_logger_server', 'number_of_target_server', 'number_of_benign_server',
                  'number_of_vulnerable_client', 'number_of_non_vulnerable_client', 'number_of_attacker_server',
                  'number_of_malicious_client')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['number_of_data_logger_server'].disabled = True
        self.fields['number_of_target_server'].disabled = True
        self.fields['number_of_benign_server'].disabled = True
        self.fields['number_of_attacker_server'].disabled = True
        self.fields['number_of_malicious_client'].disabled = True


class DataLoggerServerForm(forms.ModelForm):

    class Meta:
        model = DataLoggerServer
        fields = ('hostname', 'ip', 'username', 'password', 'network_interface')


class TargetServerForm(forms.ModelForm):

    class Meta:
        model = TargetServer
        fields = ('hostname', 'ip', 'username', 'password')


class BenignServerForm(forms.ModelForm):

    class Meta:
        model = BenignServer
        fields = ('hostname', 'ip', 'username', 'password')


class VulnerableClientForm(forms.ModelForm):

    class Meta:
        model = VulnerableClient
        fields = ('hostname', 'ip', 'username', 'password')


class NonVulnerableClientForm(forms.ModelForm):

    class Meta:
        model = NonVulnerableClient
        fields = ('hostname', 'ip', 'username', 'password')


class AttackerServerForm(forms.ModelForm):

    class Meta:
        model = AttackerServer
        fields = ('hostname', 'ip', 'username', 'password', 'path', 'number_of_new_bots')


class MaliciousClientForm(forms.ModelForm):

    class Meta:
        model = MaliciousClient
        fields = ('hostname', 'ip', 'username', 'password')

import os
import subprocess
import shlex
import pwd
import json
from pathlib import Path

from inspection_task import InspectionTask

DEPLOY_CONFIG_FILE = str(Path('/opt/cantian/config/deploy_param.json'))
DIR_NAME, _ = os.path.split(os.path.abspath(__file__))
INSPECTION_JSON_FILE = str(Path('{}/inspection_config.json'.format(DIR_NAME)))


class CantianInspection(InspectionTask):
    def __new__(cls, *args, **kwargs):
        cls.inspection_json_file = INSPECTION_JSON_FILE
        return super().__new__(cls)

    def __init__(self, _input_value, _use_smartkit=False):
        super().__init__(_input_value, _use_smartkit)
        self.check_executor()

    @staticmethod
    def get_depoly_user():
        """
        obtain deploy user name from config file
        :return:
            string: deploy user name
        """
        return "cantian"

    @staticmethod
    def get_node_ip():
        """
        obtain node id from config file
        :return:
            string: node id
        """
        with open(DEPLOY_CONFIG_FILE, encoding='utf-8') as file:
            deploy_info = json.load(file)
            node_id = deploy_info.get('node_id').split(':')[0]
            cms_ip = deploy_info.get('cms_ip').split(';')
        node_ip = cms_ip[int(node_id)]
        return "cantian_" + node_ip

    def check_executor(self):
        executor = pwd.getpwuid(os.getuid())[0]
        if executor != self.deply_user:
            raise ValueError(f"inspection must be executed by {self.deply_user}")

    def task_execute_single(self, inspection_detail, name_pwd, ip_port):
        echo_sentence = ''
        _ip = ''
        _port = ''
        inspection_item_file = inspection_detail.get('inspection_file_path')
        inspection_item_input = inspection_detail.get('script_input')
        component_belong = inspection_detail.get('component')
        time_out = int(inspection_detail.get('time_out'))

        if name_pwd:
            echo_sentence = f'echo -e "{name_pwd[0]}\n{name_pwd[1]}"'

        if ip_port:
            _ip = ip_port[0]
            _port = ip_port[1]

        if component_belong not in self.user_map.keys():
            raise Exception(f'Module {component_belong} not exist')

        if inspection_item_input:
            if echo_sentence:
                echo_cmd = shlex.split(echo_sentence)
                echo_popen = subprocess.Popen(echo_cmd, stdout=subprocess.PIPE, shell=False)
                single_inspection_popen = subprocess.Popen([f'/usr/bin/python3', inspection_item_file,
                                                            inspection_item_input, _ip, _port], stdin=echo_popen.stdout,
                                                           stdout=subprocess.PIPE, shell=False)
            else:
                single_inspection_popen = subprocess.Popen([f'{echo_sentence}/usr/bin/python3', inspection_item_file,
                                                            inspection_item_input, _ip, _port],
                                                           stdout=subprocess.PIPE, shell=False)
        else:
            if echo_sentence:
                echo_cmd = shlex.split(echo_sentence)
                echo_popen = subprocess.Popen(echo_cmd, stdout=subprocess.PIPE, shell=False)
                single_inspection_popen = subprocess.Popen([f'/usr/bin/python3', inspection_item_file,
                                                            _ip, _port], stdin=echo_popen.stdout,
                                                           stdout=subprocess.PIPE, shell=False)
            else:
                single_inspection_popen = subprocess.Popen([f'/usr/bin/python3', inspection_item_file,
                                                            _ip, _port],
                                                           stdout=subprocess.PIPE, shell=False)

        single_inspection_result = single_inspection_popen.communicate(timeout=time_out)[0].decode('utf-8')

        return single_inspection_result
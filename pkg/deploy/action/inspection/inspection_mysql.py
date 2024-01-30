import logging
import os
import subprocess
import pwd
import socket
from pathlib import Path

from inspection_task import InspectionTask


DIR_NAME, _ = os.path.split(os.path.abspath(__file__))
INSPECTION_JSON_FILE = str(Path('{}/mysql_inspection_config.json'.format(DIR_NAME)))
DEPLOY_UID = 5000
LOCALHOST = "127.0.0.1"


class MysqlInspection(InspectionTask):
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
        # 通过uid获取用户名
        return pwd.getpwuid(DEPLOY_UID)[0]

    @staticmethod
    def get_node_ip():
        """
        To mark the home of the inspection result.
        :return:
            string: mysql
        """
        try:
            manage_ip = socket.gethostbyname(socket.gethostname())
        except Exception as err:
            manage_ip = LOCALHOST
        return 'mysql_' + str(manage_ip)

    @staticmethod
    def check_executor():
        if os.getuid() != 0:
            raise ValueError(f"inspection must be executed by root")

    def task_execute_single(self, inspection_detail, name_pwd=None, ip_port=None):
        inspection_item_file = inspection_detail.get('inspection_file_path')
        inspection_item_input = inspection_detail.get('script_input')
        component_belong = inspection_detail.get('component')
        time_out = int(inspection_detail.get('time_out'))

        if component_belong not in self.user_map.keys():
            raise ValueError(f'Module {component_belong} not exist')

        if inspection_item_input:
            single_inspection_popen = subprocess.Popen(['/usr/bin/python3', inspection_item_file,
                                                        inspection_item_input], stdout=subprocess.PIPE, shell=False)
        else:
            single_inspection_popen = subprocess.Popen(['/usr/bin/python3', inspection_item_file],
                                                       stdout=subprocess.PIPE, shell=False)

        single_inspection_result = single_inspection_popen.communicate(timeout=time_out)[0].decode('utf-8')

        return single_inspection_result

import os
import re
import sys
import atexit
import getpass
import shutil
from pathlib import Path
from datetime import datetime
from datetime import timezone
import json

CUR_PATH = os.path.dirname(os.path.realpath(__file__))
sys.path.append(CUR_PATH)
import log_tool
from generate_html_results import GenHtmlRes

LOG = log_tool.setup('om')

MAX_AUDIT_NUM = 10
DIR_NAME, _ = os.path.split(os.path.abspath(__file__))
INSPECTION_PATH = str(Path('{}/inspections_log'.format(DIR_NAME)))
FAIL = 'fail'
SUCCESS = 'success'
SUCCESS_ENUM = [0, '0']
ZSQL_IP = "127.0.0.1"
ZSQL_PORT = "1611"
LOG_DIRECTORY = f'{CUR_PATH}/inspection_task_log'


class InspectionTask:

    def __init__(self, _input_value):
        self.input_param = 'all'
        self.inspection_map = self.read_inspection_config()

        try:
            self.inspection_items = self.get_input(_input_value)
        except ValueError as val_err:
            raise ValueError(str(val_err)) from val_err

        self.inspection_result = []
        self.audit_path = INSPECTION_PATH
        self.output_data = []
        self.success_list = []
        self.fail_list = []
        self.deploy_user = self.get_depoly_user()
        self.user_map = {
            'cantian': self.deploy_user,
            'cms': self.deploy_user,
            'dbstor': self.deploy_user,
            'mysql': self.deploy_user,
            'ctmgr': 'ctmgruser',
            'ct_om': 'root'
        }

    @staticmethod
    def get_depoly_user():
        return ""

    @staticmethod
    def get_node_ip():
        return ""

    @staticmethod
    def get_deploy_mode():
        return ""

    @staticmethod
    def format_single_inspection_result(inspection_item, inspection_detail, execute_result, inspection_result):
        return_value = {
            'inspection_item': inspection_item,
            'description_zn': inspection_detail.get("description_zn"),
            'description_en': inspection_detail.get("description_en"),
            'component': inspection_detail.get("component"),
            'inspection_result': execute_result,
            'inspection_detail': inspection_result.get('data'),
            'resource_en': inspection_detail.get("resource_en"),
            'resource_zh': inspection_detail.get("resource_zh")
        }
        if inspection_result and isinstance(inspection_result, dict):
            err_info = inspection_result.get('error', {})
            error_code = err_info.get('code')
            if error_code is None:
                return return_value

            if error_code not in SUCCESS_ENUM:
                return_value['inspection_result'] = FAIL
                return_value['inspection_detail'] = {
                    'error': inspection_result.get('error')
                }

        return return_value

    @staticmethod
    def param_check_single(inspection_item, inspection_detail):
        if not inspection_detail:
            raise ValueError("[error]: inspection item %s not exist" % inspection_item)

        if not os.path.exists(inspection_detail.get('inspection_file_path')):
            raise ValueError("[error]: inspection file: "
                             "%s not exist" % str(inspection_detail.get('inspection_file_path')))

    @staticmethod
    def res_format_check(res_output):
        """
        check component inspection result is legal or not
        :param res_output: component inspection out put
        :return:
            True: legal
            False: illegal
        """
        if not isinstance(res_output, dict):
            return False

        if 'data' not in res_output or 'error' not in res_output:
            return False

        if isinstance(res_output.get('error'), dict) and 'code' in res_output.get('error'):
            return True

        return False

    @staticmethod
    def user_name_reg(user_name):
        """
        determine whether the input username is legal
        :return:
            True: the input username is legal
            False: the input username is illegal
        """
        reg_pattern = r'^\w+$'
        reg_match_res = re.findall(reg_pattern, user_name)
        if not reg_match_res or len(reg_match_res) >= 2:
            return False

        return True

    def read_inspection_config(self):
        """
        reading inspection config file to obtain inspection component details
        :return:
        """
        with open(self.inspection_json_file, encoding='utf-8') as file:
            inspection_map = json.load(file)

        deploy_mode = self.get_deploy_mode()
        if deploy_mode == "--nas":
            del inspection_map["dbs_redundant_links_check"]
        return inspection_map

    def get_input(self, _input_value):
        """
        get input (inspection components
        :param _input_value: all or [component names]
        :return:
        """
        if _input_value == 'all':
            return list(self.inspection_map.keys())

        if not _input_value.startswith('[') or not _input_value.endswith(']'):
            LOG.error(f'input_value is: {_input_value}, format error')
            raise ValueError('[error]: Input value is not correct; should be "all" or "[component1, component2, ...]".')

        return _input_value[1:-1].split(',')

    def task_execute_single(self, inspection_detail, name_pwd, ip_port):
        """
        execute single inspection component
        :param inspection_detail: inspection component detail, check value of the inspection_config.json
        :param name_pwd: () or (name, password)
        :param ip_port: () or (ip, port)
        :return:
        """
        return ""

    def write_audit(self):
        """
        write overall inspection result to file
        :return:
        """
        utc_now = datetime.utcnow()
        cur_time = utc_now.replace(tzinfo=timezone.utc).astimezone(tz=None)
        node_info = self.get_node_ip()
        audit_file = 'inspection_{}_{}'.format(node_info, str(cur_time.strftime("%Y%m%d%H%M%S")))
        audit_file_path = str(Path(self.audit_path + '/' + audit_file))

        if not os.path.exists(self.audit_path):
            os.mkdir(self.audit_path)

        if not os.path.exists(audit_file_path):
            os.mkdir(audit_file_path)
            os.chmod(audit_file_path, 0o700)

        audit_list = sorted(os.listdir(self.audit_path))
        while len(audit_list) >= MAX_AUDIT_NUM:
            temp_path = str(Path(self.audit_path + "/" + str(audit_list[0])))
            shutil.rmtree(temp_path)
            audit_list.pop(0)
        # 生成html格式巡检结果
        GenHtmlRes(self.inspection_result, audit_file_path, node_info).generate_html_zh()
        GenHtmlRes(self.inspection_result, audit_file_path, node_info).generate_html_en()

        return audit_file

    def get_user_pwd(self):
        """
        if there is one inspection need user or pwd, request user input user and name
        :return:
            required is True: tuple (user, pwd)
            required is False: empty tuple ()
        """
        for inspection_item in self.inspection_items:
            if self.inspection_map.get(inspection_item, {}).get('need_pwd'):
                user_name = input('Please input user: ')
                system_pwd = getpass.getpass("Please input password: ")
                if not self.user_name_reg(user_name):
                    raise ValueError(f"[error] the input username '{user_name}' is illegal, "
                                     f"please enter a correct username.")
                return user_name, system_pwd

        return ()

    def get_ip_port(self):
        """
        get ip and port from user
        :return:
            required is True: tuple (ip, port)
            required is False: empty tuple ()
        """
        for inspection_item in self.inspection_items:
            if self.inspection_map.get(inspection_item, {}).get('need_ip'):
                return ZSQL_IP, ZSQL_PORT

        return ()

    def task_execute(self):
        """
        main enter of the inspection
        """
        name_pwd = self.get_user_pwd()
        ip_port = self.get_ip_port()

        for inspection_item in self.inspection_items:
            inspection_detail = self.inspection_map.get(inspection_item)
            try:
                self.param_check_single(inspection_item, inspection_detail)
            except ValueError as val_err:
                raise ValueError(str(val_err)) from val_err

            try:
                single_inspection_result = json.loads(self.task_execute_single(inspection_detail, name_pwd, ip_port))
            except Exception as _err:
                LOG.error(f'execute item: {inspection_item} with {str(_err.__class__)} error: {str(_err)}')
                print(f'[error]: inspection component: {inspection_item} execute it\'s inspection script failed')
                formated_inspection_result = self.format_single_inspection_result(inspection_item,
                                                                                  inspection_detail, FAIL, {})
                self.inspection_result.append(formated_inspection_result)
                self.fail_list.append(inspection_item)
                continue

            if not self.res_format_check(single_inspection_result):
                print(f'[error]: inspection component: {inspection_item} obtain an unexpected result')
                formated_inspection_result = self.format_single_inspection_result(inspection_item,
                                                                                  inspection_detail, FAIL, {})
                self.inspection_result.append(formated_inspection_result)
                self.fail_list.append(inspection_item)
                continue

            formated_inspection_result = self.format_single_inspection_result(inspection_item, inspection_detail,
                                                                              SUCCESS, single_inspection_result)

            if formated_inspection_result.get('inspection_result') == FAIL:
                self.inspection_result.append(formated_inspection_result)
                self.fail_list.append(inspection_item)
                continue

            self.inspection_result.append(formated_inspection_result)
            self.success_list.append(inspection_item)

        log_name = self.write_audit()
        log_full_path = str(Path(f'{self.audit_path}/{log_name}'))

        if not self.fail_list:
            raise ValueError(f'All components inspection execute success; \ninspection result file is {log_full_path}')

        if not self.success_list:
            raise ValueError(f'All components inspection execute failed; \ninspection result file is {log_full_path}')

        raise ValueError(f'Component: [{", ".join(self.success_list)}] inspection execute success, '
                         f'\ncomponent: [{", ".join(self.fail_list)} ]inspection execute failed; '
                         f'\ninspection result file is {log_full_path}')


def change_mode_back():
    os.chmod(LOG_DIRECTORY, 0o700)


def main(input_val):
    # 运行期间修改日志路径为777，确保各模块可以在日志路径内创建日志文件
    os.chmod(LOG_DIRECTORY, 0o777)
    from declear_env import DeclearEnv
    # 获取执行当前进程的用户名
    from inspection_cantian import CantianInspection
    cantian_inspection = CantianInspection(input_val)
    cantian_inspection.task_execute()


if __name__ == '__main__':
    input_value = None
    try:
        input_value = sys.argv[1]
    except Exception as err:
        _ = err
        exit('[error]: Input format is not correct, missing input value;'
             ' Input value could be "all" or "[component1,component2,...]".')

    sys.dont_write_bytecode = True
    atexit.register(change_mode_back)
    try:
        main(input_value)
    except Exception as err:
        exit(str(err))

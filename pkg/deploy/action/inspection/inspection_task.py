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
CTSQL_IP = "127.0.0.1"
CTSQL_PORT = "1611"
LOG_DIRECTORY = f'{CUR_PATH}/inspection_task_log'


class InspectionTask:

    def __init__(self, _input_value, _use_smartkit=False):
        self.input_param = 'all'
        self.inspection_map = self.read_inspection_config()
        self.use_smartkit = _use_smartkit

        try:
            self.inspection_items = self.get_input(_input_value)
        except ValueError as val_err:
            raise ValueError(str(val_err)) from val_err

        self.inspection_result = []
        self.audit_path = INSPECTION_PATH
        self.output_data = []
        self.success_list = []
        self.fail_list = []
        self.deply_user = self.get_depoly_user()
        self.user_map = {
            'cantian': self.deply_user,
            'cms': self.deply_user,
            'dbstor': self.deply_user,
            'mysql': self.deply_user,
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

    @staticmethod
    def decrypt_password():
        primary_keystore = "/opt/cantian/common/config/primary_keystore_bak.ks"
        standby_keystore = "/opt/cantian/common/config/standby_keystore_bak.ks"
        sys.path.append("/opt/cantian/action/dbstor")
        from kmc_adapter import CApiWrapper
        ctsql_ini_path = '/mnt/dbdata/local/cantian/tmp/data/cfg/ctsql.ini'
        kmc_decrypt = CApiWrapper(primary_keystore=primary_keystore, standby_keystore=standby_keystore)
        kmc_decrypt.initialize()
        ctsql_ini_data = file_reader(ctsql_ini_path)
        encrypt_pwd = ctsql_ini_data[ctsql_ini_data.find('=') + 1:].strip()
        try:
            kmc_decrypt_pwd = kmc_decrypt.decrypt(encrypt_pwd)
        except Exception as error:
            raise Exception('[result] decrypt ctsql passwd failed') from error
        finally:
            kmc_decrypt.finalize()
        split_env = os.environ['LD_LIBRARY_PATH'].split(":")
        filtered_env = [single_env for single_env in split_env if "/opt/cantian/dbstor/lib" not in single_env]
        os.environ['LD_LIBRARY_PATH'] = ":".join(filtered_env)
        return kmc_decrypt_pwd

    def read_inspection_config(self):
        """
        reading inspection config file to obtain inspection component details
        :return:
        """
        with open(self.inspection_json_file, encoding='utf-8') as file:
            inspection_map = json.load(file)

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

    def check_smartkit(self):
        if self.use_smartkit:
            user_name = "sys"
            system_pwd = self.decrypt_password()
        else:
            user_name = input('Please input user:')
            system_pwd = getpass.getpass("Please input password:")
            if not self.user_name_reg(user_name):
                raise ValueError(f"[error] the input username '{user_name}' is illegal, "
                                 f"please enter a correct username.")
        return system_pwd, user_name

    def get_user_pwd(self):
        """
        if there is one inspection need user or pwd, request user input user and name
        :return:
            required is True: tuple (user, pwd)
            required is False: empty tuple ()
        """
        for inspection_item in self.inspection_items:
            if self.inspection_map.get(inspection_item, {}).get('need_pwd'):
                system_pwd, user_name = self.check_smartkit()
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
                return CTSQL_IP, CTSQL_PORT

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


def file_reader(file_path):
    with open(file_path, 'r') as file:
        return file.read()


def change_mode_back():
    os.chmod(LOG_DIRECTORY, 0o700)


def main(input_val):
    # 运行期间修改日志路径为777，确保各模块可以在日志路径内创建日志文件
    os.chmod(LOG_DIRECTORY, 0o777)
    from declear_env import DeclearEnv
    # 获取当前为参天还是mysql容器
    current_env = DeclearEnv().get_env_type()
    # 获取执行当前进程的用户名
    current_executor = DeclearEnv().get_executor()
    if current_env == "cantian":
        from inspection_cantian import CantianInspection
        cantian_inspection = CantianInspection(input_val, use_smartkit)
        cantian_inspection.task_execute()

    else:
        from inspection_mysql import MysqlInspection
        mysql_inspection = MysqlInspection(input_val, use_smartkit)
        mysql_inspection.task_execute()


if __name__ == '__main__':
    input_value = None
    use_smartkit = False
    try:
        input_value = sys.argv[1]
    except Exception as err:
        _ = err
        exit('[error]: Input format is not correct, missing input value;'
             ' Input value could be "all" or "[component1,component2,...]".')
    if len(sys.argv) == 3 and sys.argv[2] == "smartkit":
        use_smartkit = True
    sys.dont_write_bytecode = True
    atexit.register(change_mode_back)
    try:
        main(input_value)
    except Exception as err:
        exit(str(err))

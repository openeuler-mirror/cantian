import os
import sys
import re
import json
import stat
import pathlib
from datetime import datetime
from datetime import timezone
import requests

CUR_PATH, _ = os.path.split(os.path.abspath(__file__))
sys.path.append(str(pathlib.Path(CUR_PATH).parent.parent))

from utils.config.rest_constant import Constant as RestElemConstant
from utils.client.response_parse import ResponseParse
from utils.config.rest_constant import Constant
from om_log import REST_LOG as LOG

NORMAL_STATE, ABNORMAL_STATE = 0, 1


def get_cur_timestamp():
    utc_now = datetime.utcnow()
    return utc_now.replace(tzinfo=timezone.utc).astimezone(tz=None).strftime('%Y%m%d%H%M%S')


class ExecutionError(Exception):
    pass


class RestClient:
    def __init__(self, login_tuple: object) -> object:
        self.ip_addr, self.user_name, self.passwd = login_tuple
        self.device_id = None
        self.token = None
        self.ism_session = None
        self.session = None
        self.res_login = None

    @staticmethod
    def gen_timestamp():
        utc_now = datetime.utcnow()
        cur_time = utc_now.replace(tzinfo=timezone.utc).astimezone(tz=None)
        return str(cur_time.strftime('%Y%m%d%H%M%S'))

    @staticmethod
    def exception_handler(err_msg=None, cur_mode=None):
        err_info = '[current_mode] {}, [err_info] {}'.format(cur_mode, err_msg)
        LOG.error(err_info)
        raise ExecutionError(err_info)

    @staticmethod
    def response_parse(res_data):
        status_code = res_data.status_code
        err_code, err_details = -1, 'failed'

        if status_code == 200:
            exec_res = res_data.json()
            err_code, err_details = \
                exec_res.get('error').get('code'), exec_res.get('error').get('description')

        return status_code, int(err_code), err_details

    def update_cookies(self, res):
        res_body, set_cookie = res.json().get('data'), res.headers.get('Set-Cookie')

        self.token, self.device_id = res_body.get('iBaseToken'), res_body.get('deviceid')

        match_res = re.findall(r'session=ismsession=\w+;', set_cookie)
        if match_res:
            self.ism_session = match_res[0][:-1]

    def make_header(self, content_type='application/json'):
        header = {'Content-type': content_type}
        if self.token:
            header['iBaseToken'] = self.token
        if self.ism_session:
            header['Cookie'] = self.ism_session

        return header

    def login(self, keep_session=False):
        url = '{}{}:{}{}'.format(RestElemConstant.HTTPS, self.ip_addr, RestElemConstant.PORT, RestElemConstant.LOGIN)
        user_info = {
            'username': self.user_name,
            'password': self.passwd,
            'scope': 0,
            'loginMode': 3,
            'timeConversion': 0,
            'isEncrypt': 'false'
        }

        login_header = {
            'Content-type': 'application/json',
            'Cookie': '__LANGUAGE_KEY__=zh-CN; __IBASE_LANGUAGE_KEY__=zh-CN'
        }

        requests.packages.urllib3.disable_warnings()
        with requests.session() as session:
            res = session.post(url, data=json.dumps(user_info), headers=login_header, verify=False)
            status_code, err_code, err_details = self.response_parse(res)
            if err_code:
                err_msg = ('Login DM failed {}, status_code: {}, err_code: {}, '
                           'err_details: {}'.format(self.ip_addr, status_code, err_code, err_details))
                raise Exception(err_msg)

            self.update_cookies(res)

            if keep_session:
                self.session = session
                self.res_login = res.json()
            else:
                res.close()

        return NORMAL_STATE, 'success'

    def logout(self):
        url = RestElemConstant.LOGOUT.format(deviceId=self.device_id)
        res = self.normal_request(url, 'delete')
        result = ResponseParse(res)
        status_code, error_code, error_des = result.get_res_code()
        if status_code != 200 or error_code != 0:
            err_msg = "Failed to logout, details:%s" % error_des
            LOG.error(err_msg)
            raise ExecutionError(err_msg)
        LOG.info("Log out success.")

    def normal_request(self, url, method, data=None, **kwargs):
        """

        :rtype: object
        """
        if data:
            data = json.dumps(data)
        requests.packages.urllib3.disable_warnings()
        timeout, keep_session = kwargs.get("timeout"), kwargs.get("keepsession")
        url = Constant.HTTPS + self.ip_addr + ":" + Constant.PORT + url
        if keep_session:
            req = self.session
            self.token = self.res_login.get('data').get('ibasetoken')
        else:
            req = requests.session()

        headers = self.make_header()
        with req as session:
            if method == 'put':
                res = session.put(url, data=data, headers=headers, verify=False, timeout=timeout)
            elif method == 'post':
                res = session.post(url, data=data, headers=headers, verify=False, timeout=timeout)
            elif method == 'get':
                res = session.get(url, data=data, headers=headers, verify=False, timeout=timeout)
            elif method == 'delete':
                res = session.delete(url, data=data, headers=headers, verify=False, timeout=timeout)

            res.close()
        return res


def read_helper(file_path):
    with open(file_path, 'r', encoding='utf-8') as f_handler:
        deploy_data = f_handler.read()
        return deploy_data


def write_helper(file_path, data):
    modes = stat.S_IWRITE | stat.S_IRUSR
    flags = os.O_WRONLY | os.O_TRUNC | os.O_CREAT
    if data:
        with os.fdopen(os.open(file_path, flags, modes), 'w', encoding='utf-8') as file:
            file.write(json.dumps(data, indent=4))
    else:
        with os.fdopen(os.open(file_path, flags, modes), 'w', encoding='utf-8') as file:
            file.truncate()

import re
import json
from datetime import datetime
from datetime import timezone
import requests
from om_log import SNAPSHOT_LOGS as LOG

NORMAL_STATE, ABNORMAL_STATE = 0, 1


def get_cur_timestamp():
    utc_now = datetime.utcnow()
    return utc_now.replace(tzinfo=timezone.utc).astimezone(tz=None).strftime('%Y%m%d%H%M%S')


class RestElemConstant:
    PORT = '8088'
    HTTPS = 'https://'
    LOGIN = '/deviceManager/rest/xxx/login'


class ExecutionError(Exception):
    pass


class RestClient:
    def __init__(self, login_tuple, processed_fs):
        self.ip_addr, self.user_name, self.passwd = login_tuple
        self.upgrade_version = get_cur_timestamp()
        self.processed_fs = processed_fs

        self.device_id = None
        self.token = None
        self.ism_session = None
        self.session = None
        self.res_login = None

        self.handler = {'create': self.create_snapshots,
                        'rollback': self.rollback_snapshots}

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

    @staticmethod
    def get_data(res_data):
        exec_res = res_data.json()
        data = exec_res.get("data")
        return data

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

    def login(self, fs_name, keep_session=False):
        url = '{}{}:{}{}'.format(RestElemConstant.HTTPS, self.ip_addr, RestElemConstant.PORT, RestElemConstant.LOGIN)
        user_info = {'username': self.user_name,
                     'password': self.passwd,
                     'scope': 0,
                     'loginMode': 3,
                     'timeConversion': 0,
                     'isEncrypt': 'false'}

        login_header = {'Content-type': 'application/json',
                        'Cookie': '__LANGUAGE_KEY__=zh-CN; __IBASE_LANGUAGE_KEY__=zh-CN'}

        requests.packages.urllib3.disable_warnings()
        with requests.session() as session:
            res = session.post(url, data=json.dumps(user_info), headers=login_header, verify=False)
            status_code, err_code, err_details = self.response_parse(res)
            if err_code:
                err_msg = ('Login {} failed before taking the snapshot of {}, status_code: {}, err_code: {}, '
                           'err_details: {}'.format(fs_name, self.ip_addr, status_code, err_code, err_details))
                return err_code, err_msg

            self.update_cookies(res)

            if keep_session:
                self.session = session
                self.res_login = res.json()
            else:
                res.close()

        return NORMAL_STATE, 'success'

    def normal_request(self, url, method, data=None, **kwargs):
        requests.packages.urllib3.disable_warnings()
        timeout, keep_session = kwargs.get("timeout"), kwargs.get("keepsession")

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

    def get_file_system_id(self, fs_name):
        url = '{}{}:{}/deviceManager/rest/{}/filesystem?filter=NAME::{}'.format(RestElemConstant.HTTPS,
                                                                                self.ip_addr,
                                                                                RestElemConstant.PORT,
                                                                                str(self.device_id),
                                                                                fs_name)
        res = self.normal_request(url, 'get')
        status_code, err_code, err_details = self.response_parse(res)
        if err_code:
            err_msg = 'Get file system id of {} failed, status_code: {}, err_code: {}, ' \
                      'err_details: {}'.format(fs_name, status_code, err_code, err_details)
            return ABNORMAL_STATE, err_msg

        file_system_id = res.json().get('data')[0].get('ID')
        return NORMAL_STATE, file_system_id

    def create_snapshots(self, fs_name):
        if self.processed_fs.get(fs_name):
            return NORMAL_STATE

        work_state, res_details = self.get_file_system_id(fs_name)
        if work_state:
            return self.exception_handler(err_msg=res_details, cur_mode='create')

        url = '{}{}:{}/deviceManager/rest/{}/fssnapshot'.format(RestElemConstant.HTTPS,
                                                                self.ip_addr,
                                                                RestElemConstant.PORT,
                                                                self.device_id)
        reg_version = '{}_{}'.format(fs_name, self.upgrade_version).replace('.', '_')
        snapshot_name = '{}_{}'.format(reg_version, self.gen_timestamp())
        data = {'NAME': snapshot_name,
                'PARENTID': int(res_details),
                'PARENTTYPE': 40}
        res = self.normal_request(url, 'post', data=json.dumps(data))
        status_code, err_code, err_details = self.response_parse(res)
        if err_code:
            err_msg = 'Take snapshot of {} failed, status_code: {}, ' \
                      'err_code: {}, err_details: {}'.format(fs_name, status_code, err_code, err_details)
            return self.exception_handler(err_msg=err_msg, cur_mode='create')

        snapshot_id = res.json().get('data').get('ID')
        self.processed_fs[fs_name] = snapshot_id
        return NORMAL_STATE

    def rollback_snapshots(self, fs_name):
        # 若该fs_name的快照未成功创建则无需回退
        if not self.processed_fs.get(fs_name):
            return NORMAL_STATE

        url = '{}{}:{}/deviceManager/rest/{}/fssnapshot/rollback_fssnapshot'.format(RestElemConstant.HTTPS,
                                                                                    self.ip_addr,
                                                                                    RestElemConstant.PORT,
                                                                                    self.device_id)
        data = {'ID': self.processed_fs.get(fs_name)}
        res = self.normal_request(url, 'put', data=json.dumps(data))
        status_code, err_code, err_details = self.response_parse(res)
        if err_code:
            err_msg = 'Rollback snapshot of {} failed, status_code: {}, ' \
                      'err_code: {}, err_details: {}'.format(fs_name, status_code, err_code, err_details)
            return self.exception_handler(err_msg=err_msg, cur_mode='rollback')

        return NORMAL_STATE

    def query_rollback_snapshots_process(self, fs_name):
        """
        查询文件系统快照回滚进度
        文件系统回滚状态：
            0：空闲状态；
            1：运行状态；
            2：暂停状态；
            3：完成状态；
            4：终止状态；
        文件系统回滚进度：0-99,回滚成功后，无该字段
        :param fs_name: 文件系统名称
        :return: rollback_rate：回顾进度， rollback_status：回滚状态
        """
        if not self.processed_fs.get(fs_name):
            return NORMAL_STATE, NORMAL_STATE
        url = '{}{}:{}/deviceManager/rest/{}/FSSNAPSHOT/query_fs_snapshot_rollback?PARENTNAME={}'\
            .format(RestElemConstant.HTTPS,
                    self.ip_addr,
                    RestElemConstant.PORT,
                    self.device_id,
                    fs_name)

        res = self.normal_request(url, 'get')
        status_code, err_code, err_details = self.response_parse(res)
        if err_code:
            err_msg = 'Query rollback snapshot process of {} failed, status_code: {}, ' \
                      'err_code: {}, err_details: {}'.format(fs_name, status_code, err_code, err_details)
            return self.exception_handler(err_msg=err_msg, cur_mode='rollback')
        data = self.get_data(res)
        rollback_rate, rollback_status = data.get("rollbackRate"), data.get("rollbackStatus")
        LOG.info("Rollback snapshot process of %s details:rollback_rate[%s] rollback_status[%s]",
                 fs_name, rollback_rate, rollback_status)
        return rollback_rate, rollback_status

    def execute(self, fs_name, mode):
        if isinstance(self.processed_fs, str):
            self.processed_fs = json.loads(self.processed_fs)

        if not self.token:
            work_state, res_details = self.login(fs_name)
            if work_state:
                return self.exception_handler(err_msg=res_details, cur_mode='get login token')

        return self.handler.get(mode)(fs_name)

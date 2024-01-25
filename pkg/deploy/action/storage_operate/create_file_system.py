# coding=utf-8
import json
import argparse
import re
import traceback
import sys
import os
import pathlib
import ipaddress


CUR_PATH, _ = os.path.split(os.path.abspath(__file__))

sys.path.append(str(pathlib.Path(CUR_PATH).parent))

from logic.storage_operate import StorageInf
from utils.client.rest_client import read_helper, write_helper
from utils.client.ssh_client import SshClient
from utils.client.response_parse import ResponseParse
from om_log import REST_LOG as LOG

FS_PARAM_PATH = str(pathlib.Path(CUR_PATH, "../../config/file_system_info.json"))
DEPLOY_PARAM_PATH = str(pathlib.Path(CUR_PATH, "../../config/deploy_param.json"))
FS_TYPE_LIST = [
    "storage_dbstore_fs", "storage_dbstore_page_fs",
    "storage_share_fs", "storage_archive_fs",
    "storage_metadata_fs"
]
SHARE_FS_TYPE_LIST = [
    "storage_share_fs", "storage_archive_fs",
    "storage_metadata_fs"
]


def is_valid_string(string):
    """
    文件系统名 只支持数字、字母、下划线和中文字符，特殊字符支持“.”、“-”.长度：1-255
    定义正则表达式模式，匹配数字、字母、下划线、中文字符、特殊字符 . 和 -
    :param string:
    :return:
    """
    pattern = r'^[\w\u4e00-\u9fa5.-]{1,255}$'
    match = re.match(pattern, string)
    return match is not None


def is_valid_ip_range(ip_range):
    if ip_range == "*":
        return True
    try:
        ipaddress.IPv4Network(ip_range, strict=False)
        return True
    except ipaddress.AddressValueError:
        return False


class CreateFS(object):
    def __init__(self, login_tuple):
        self.ip_addr, self.user_name, self.passwd = login_tuple
        self.storage_opt = StorageInf(login_tuple)
        self.ssh_client = SshClient(*login_tuple)
        self.fs_info = self._init_params()
        self.pre_check_result = list()

    @staticmethod
    def handle_error_msg(err_msg):
        LOG.error(err_msg)
        raise Exception(err_msg)

    @staticmethod
    def check_capacity(capacity):
        """
        检查容量填写是否符合要求
        :param capacity: 容量,exp:300GB/30TB/3PB
        :return: bool
        """
        if capacity.endswith(("GB", "TB", "PB")):
            capacity_digit = re.findall(r"\d+", capacity)
            if capacity_digit:
                return capacity_digit[0].isnumeric()
        return False

    @staticmethod
    def compute_capacity(capacity):
        """
        计算容量，返回单位为sectors的容量，扇区大小是512bytes
        :param capacity: 容量GB/TB/PB
        :return: sectors
        """
        capacity_digit = re.findall(r"\d+", capacity)[0]
        capacity_unit = re.findall(r"[A-Z]+", capacity)[0]
        convert_dict = {
            "GB": 1,
            "TB": 1000,
            "PB": 1000 ** 2
        }
        return convert_dict.get(capacity_unit) * int(capacity_digit) * 1024 * 1024 * 2

    @staticmethod
    def _init_params():
        fs_info = json.loads(read_helper(FS_PARAM_PATH))
        deploy_info = json.loads(read_helper(DEPLOY_PARAM_PATH))
        for fs_type in FS_TYPE_LIST:
            fs_info[fs_type]["NAME"] = deploy_info.get(fs_type)
        return fs_info

    @classmethod
    def _result_parse(cls, err_msg, res):
        result = ResponseParse(res)
        rsp_code, rsp_result, rsp_data = result.get_rsp_data()
        error_code = rsp_result.get('code')
        if rsp_code != 0 or error_code != 0:
            error_des = rsp_result.get('description')
            error_sgt = rsp_result.get('suggestion')
            err_msg = err_msg % (error_code, error_des, error_sgt)
            cls.handle_error_msg(err_msg)
        return rsp_data

    def pre_check(self):
        """
        check fs info before create
        step:
            1. check param type correct
            2. check user_name, pass_wd correct
            3. check fs exists
            4. check vstore exists
        :return:
        """
        def _check_func():
            pool_id = self.fs_info.get("PARENTID")
            self._check_vstore_exists()
            self._check_storage_pool_exists(pool_id)
            self._check_fs_exists()
        LOG.info("Check file system params start.")
        self._check_param_type()
        self._check_vstore_id()
        self.storage_opt.login()
        try:
            _check_func()
        finally:
            self.storage_opt.logout()
        LOG.info("Check file system params success.")

    def create(self):
        """
        auto create file system.
        step:
            1. query the file system name from deploy_param.json
            2. query fs info from DM; if exists, return ERROR
            3. create fs by OM restfull interface, record fs info
            4. create nfs share, recorde nfs share info
            5. add nfs client
        :return:
        """
        def _create_func():
            fs_info = {}
            for fs_type in FS_TYPE_LIST:
                nfs_share_id = None
                nfs_share_client_id = None
                _fs_info = self.fs_info.get(fs_type)
                _fs_name = _fs_info.get("NAME")
                LOG.info("Begin to create fs [%s] name: %s", fs_type, _fs_name)
                vstore_id = self.fs_info.get(fs_type).get("vstoreId")
                LOG.info("Begin to create fs [%s] name: %s, vstore id:[%s]",
                         fs_type, _fs_name, vstore_id)
                _fs_info = self.storage_opt.query_file_system_info(_fs_name, vstore_id)
                if _fs_info:
                    err_msg = "The file system[%s] already exists." % _fs_name
                    self.handle_error_msg(err_msg)
                fs_id = self._create_fs(fs_type)
                if fs_type in SHARE_FS_TYPE_LIST:
                    nfs_share_id = self._create_nfs_share(fs_id, fs_type)
                    nfs_share_client_id = self._add_nfs_client(nfs_share_id, fs_type)
                fs_info[fs_type] = {
                    "fs_id": fs_id,
                    "nfs_share_id": nfs_share_id,
                    "nfs_share_client_id": nfs_share_client_id
                }
                LOG.info("Create fs [%s] success, detail:name[%s], info:%s", fs_type, _fs_name, fs_info)
                if fs_type == "storage_share_fs":
                    self._config_mandatory_lock_switch(vstore_id)
        LOG.info("Create fs start.")
        self.storage_opt.login()
        try:
            _create_func()
        finally:
            self.storage_opt.logout()
        LOG.info("Create fs end.")

    def delete(self):
        """
        auto delete fs info
        step:
            1. query the file system name from deploy_param.json
            2. query fs info from DM, if not exists, break
            3. query nfs share info, if not exists, continue, else del
            4. delete fs info
        :return:
        """
        def _delete_func():
            for fs_type in FS_TYPE_LIST:
                _fs_info = self.fs_info.get(fs_type)
                _fs_name = _fs_info.get("NAME")
                LOG.info("Begin to del fs [%s] name: %s", fs_type, _fs_name)
                vstore_id = self.fs_info.get(fs_type).get("vstoreId")
                fs_info = self.storage_opt.query_file_system_info(_fs_name, vstore_id)
                if not fs_info:
                    LOG.info("fs [%s] name %s is not exist", fs_type, _fs_name)
                    continue
                fs_id = fs_info.get("ID")
                nfs_share_info = self.storage_opt.query_nfs_info(fs_id, vstore_id)
                if nfs_share_info:
                    nfs_share_id = nfs_share_info[0].get("ID")
                    self.storage_opt.delete_nfs_share(nfs_share_id, vstore_id)
                else:
                    LOG.info("The nfs share of fs [%s] name %s is not exist", fs_type, _fs_name)
                self.storage_opt.delete_file_system(fs_id)
        LOG.info("Delete fs info start.")
        self.storage_opt.login()
        try:
            _delete_func()
        finally:
            self.storage_opt.logout()
        LOG.info("Delete fs info end.")

    def _check_vstore_id(self):
        deploy_info = json.loads(read_helper(DEPLOY_PARAM_PATH))
        deploy_info_vstore_id = deploy_info.get("vstore_id")
        deploy_info_dbstore_fs_vstore_id = deploy_info.get("dbstore_fs_vstore_id")
        fs_info_share_vstore_id = self.fs_info.get("storage_share_fs").get("vstoreId")
        fs_info_dbstore_fs_vstore_id = self.fs_info.get("storage_dbstore_fs").get("vstoreId")
        if int(deploy_info_vstore_id) != int(fs_info_share_vstore_id) or \
                int(deploy_info_dbstore_fs_vstore_id) != int(fs_info_dbstore_fs_vstore_id):
            err_msg = "dbstore_fs_vstore_id or vstore_id of config_params.json is " \
                      "different from file_system_info.json,details:vstore_id:(%s, %s)," \
                      " dbstore_fs_vstore_id:(%s, %s)" % (deploy_info_vstore_id,
                                                          deploy_info_dbstore_fs_vstore_id,
                                                          fs_info_share_vstore_id,
                                                          fs_info_dbstore_fs_vstore_id)
            LOG.error(err_msg)
            raise Exception(err_msg)

    def _check_param_type(self):
        """
        check create fs params type
        PARENTID: storage pool id, type: int
        SNAPSHOTRESERVEPER: snapshot reserve percentage, type: int, range: 0-50
        CAPACITYTHRESHOLD: total space alarm threshold, type: int, range: 50-99
        CAPACITY: file system capacity, type: int
        vstoreId: vstore id, type: int
        :return:bool
        """
        err_dict = {}
        name_err = []
        digit_err = []
        range_err = []
        range_check = {
            "SNAPSHOTRESERVEPER": (0, 51),
            "CAPACITYTHRESHOLD": (50, 99)
        }
        digit_check = ["SNAPSHOTRESERVEPER", "CAPACITYTHRESHOLD"]
        pool_id = self.fs_info.get("PARENTID")
        if not isinstance(pool_id, int):
            digit_err.append("PARENTID")
        client_ip = self.fs_info.get("client_ip")
        if not is_valid_ip_range(client_ip):
            range_err.append({"client_ip": client_ip})
        for fs_type in FS_TYPE_LIST:
            fs_name = self.fs_info.get(fs_type).get("NAME")
            fs_info = self.fs_info.get(fs_type)
            vstore_id = self.fs_info.get(fs_type).get("vstoreId")
            if not isinstance(vstore_id, int):
                digit_err.append({fs_type: "vstoreId"})
            if not is_valid_string(fs_name):
                name_err.append({fs_type: fs_name})
            for key, value in fs_info.items():
                if key in digit_check and not isinstance(value, int):
                    digit_err.append({fs_type: key})
                if key in list(range_check.keys()) and value not in range(*range_check.get(key)):
                    range_err.append({fs_type: key})
                if key == "CAPACITY" and not self.check_capacity(value):
                    digit_err.append({fs_type: key})
        if name_err:
            err_dict["name_err"] = name_err
        if digit_err:
            err_dict["type_err"] = digit_err
        if range_err:
            err_dict["range_err"] = range_err
        if err_dict:
            err_msg = "Before create fs check error, details:%s" % err_dict
            self.handle_error_msg(err_msg)

    def _check_fs_exists(self):
        """
        check fs exists before create
        :return: None
        """
        check_fail = []
        for fs_type in FS_TYPE_LIST:
            _fs_name = self.fs_info.get(fs_type).get("NAME")
            vstore_id = self.fs_info.get(fs_type).get("vstoreId")
            _fs_info = self.storage_opt.query_file_system_info(_fs_name, vstore_id)
            if _fs_info:
                check_fail.append(_fs_name)
        if check_fail:
            err_msg = "File system%s exists" % check_fail
            self.handle_error_msg(err_msg)

    def _check_storage_pool_exists(self, pool_id):
        """
        check storage pool id exists
        :param pool_id: pool id
        :return: None
        """
        resp_data = self.storage_opt.query_storage_pool_info(pool_id)
        if not resp_data:
            err_msg = "Pool id[%s] not exists" % pool_id
            self.handle_error_msg(err_msg)

    def _check_vstore_exists(self):
        """
        check vstore id exists
        :return: bool
        """
        check_fail = []
        for fs_type in FS_TYPE_LIST:
            _fs_name = self.fs_info.get(fs_type).get("NAME")
            vstore_id = self.fs_info.get(fs_type).get("vstoreId")
            try:
                self.storage_opt.query_vstore_info(vstore_id)
            except Exception as _err:
                err_msg = "Vstore id[%s] not exists" % vstore_id
                check_fail.append(err_msg)
        if check_fail:
            err_msg = "Vstore_id %s is not exists" % check_fail
            self.handle_error_msg(err_msg)

    def _get_fs_info(self, fs_type):
        data = {
            "PARENTID": self.fs_info.get("PARENTID"),
            "workloadTypeId": 1038,
        }
        capacity = self.compute_capacity(self.fs_info[fs_type].get("CAPACITY"))
        data.update(self.fs_info.get(fs_type))
        data["CAPACITY"] = capacity
        return data

    def _get_nfs_share_info(self, fs_type, fs_id):
        data = {
            "SHAREPATH": f"/{ self.fs_info.get(fs_type).get('NAME')}/",
            "vstoreId":  self.fs_info.get(fs_type).get("vstoreId"),
            "FSID": fs_id
        }
        data.update(self.fs_info.get(fs_type))
        return data

    def _get_share_client_info(self, parent_id, fs_type):
        data = {
            "ACCESSVAL": 1,
            "ALLSQUASH": 1,
            "ROOTSQUASH": 1,
            "PARENTID": parent_id,
            "vstoreId": self.fs_info.get(fs_type).get("vstoreId"),
            "NAME": self.fs_info.get("client_ip")
        }
        return data

    def _recorde_fs_info(self, fs_info):
        recorde_info = self.fs_info
        for fs_type in FS_TYPE_LIST:
            recorde_info.get(fs_type).update(fs_info.get(fs_type))
        write_helper(FS_PARAM_PATH, recorde_info)

    def _create_fs(self, fs_type):
        """
        param fs_type: storage_dbstore_fs、storage_share_fs、storage_archive_fs、storage_metadata_fs
        :return:the file system id
        """
        data = self._get_fs_info(fs_type)
        return self.storage_opt.create_file_system(data)

    def _create_nfs_share(self, fs_id, fs_type):
        """
        add nfs share
        :param fs_id: the file system id
        :param fs_type: storage_dbstore_fs、storage_share_fs、storage_archive_fs、storage_metadata_fs
        :return: nfs share id
        """
        data = self._get_nfs_share_info(fs_type, fs_id)
        return self.storage_opt.create_nfs_share(data)

    def _add_nfs_client(self, nfs_share_id, fs_type):
        """
        add nfs client
        :param nfs_share_id: 共享id
        :return: nfs client id
        """
        data = self._get_share_client_info(nfs_share_id, fs_type)
        return self.storage_opt.add_nfs_client(data)

    def _config_mandatory_lock_switch(self, vstore_id):
        """
        配置租户强制锁

        :param vstore_id: 租户ID
        :return:
        """
        def _exec_cmd():
            _cmd = f"change vstore view id={vstore_id}"
            res = self.ssh_client.execute_cmd(_cmd, expect=":/>", timeout=10)
            if "Command executed successfully." in res:
                LOG.info("Execute cmd[%s] success", _cmd)
            else:
                err_msg = "Execute cmd[%s], details:%s" % (_cmd, res)
                LOG.error(err_msg)
                raise Exception(err_msg)
            _cmd = "change service nfs_config nfsv4_mandatory_lock_switch=enable"
            self.ssh_client.execute_cmd(_cmd, expect="(y/n)", timeout=10)
            _cmd = "y"
            self.ssh_client.execute_cmd(_cmd, expect=":/>", timeout=10)
            if "Command executed successfully." in res:
                LOG.info("Execute cmd[%s] success", _cmd)
            else:
                err_msg = "Execute cmd[%s], details:%s" % (_cmd, res)
                LOG.error(err_msg)
                raise Exception(err_msg)
        self.ssh_client.create_client()
        try:
            _exec_cmd()
        finally:
            self.ssh_client.close_client()


def main():
    create_parser = argparse.ArgumentParser()
    create_parser.add_argument('--action', choices=["create", "delete", "pre_check"], dest="action", required=True)
    create_parser.add_argument('--ip', dest="ip_addr", required=True)
    args = create_parser.parse_args()
    action = args.action
    ip_addr = args.ip_addr
    user_name = input()
    passwd = input()
    login_param = (ip_addr, user_name, passwd)
    create_fs = CreateFS(login_param)
    getattr(create_fs, action)()


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        LOG.error("Execute create fs failed, details:%s, traceback:%s", str(err), traceback.format_exc())
        exit(1)

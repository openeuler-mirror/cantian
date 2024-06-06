# -*- coding: UTF-8 -*-
import abc
import os
import re
import subprocess
import shlex
import socket
import sys
import stat
import json
import collections
from pathlib import Path
from logic.common_func import exec_popen
from om_log import LOGGER as LOG

INSTALL_PATH = "/opt/cantian"
NEEDED_SIZE = 20580  # M
NEEDED_MEM_SIZE = 16 * 1024  # M

dir_name, _ = os.path.split(os.path.abspath(__file__))
CANTIAND_INI_FILE = "/mnt/dbdata/local/cantian/tmp/data/cfg/cantiand.ini"

ip_check_element = {
    'cantian_vlan_ip',
    'storage_vlan_ip',
    'cms_ip'
}

ping_check_element = {
    'cantian_vlan_ip',
    'storage_vlan_ip',
    'cms_ip',
    'share_logic_ip',
    'archive_logic_ip',
    'metadata_logic_ip',
    'storage_logic_ip'
}

kernel_element = {
    'TEMP_BUFFER_SIZE',
    'DATA_BUFFER_SIZE',
    'SHARED_POOL_SIZE',
    'LOG_BUFFER_SIZE'
}
UnitConversionInfo = collections.namedtuple('UnitConversionInfo', ['tmp_gb', 'tmp_mb', 'tmp_kb', 'key', 'value',
                                                                   'sga_buff_size', 'temp_buffer_size',
                                                                   'data_buffer_size', 'shared_pool_size',
                                                                   'log_buffer_size'])

class ConfigChecker:
    """
    对参天安装的配置文件中内容进行校验的反射类
    * 方法名：与配置文件中的key一致
    """

    @staticmethod
    def node_id(value):
        node_id_enum = {'0', '1'}
        if value not in node_id_enum:
            return False

        return True

    @staticmethod
    def install_type(value):
        install_type_enum = {'override', 'reserve'}
        if value not in install_type_enum:
            return False

        return True

    @staticmethod
    def link_type(value):
        link_type_enum = {'1', '0', '2'}  # 1为rdma 0为tcp 2为rdma 1823
        if value not in link_type_enum:
            return False

        return True

    @staticmethod
    def db_type(value):
        db_type_enum = {'0', '1', '2'}
        if value not in db_type_enum:
            return False

        return True

    @staticmethod
    def mysql_in_container(value):
        mysql_in_container_enum = {'0', '1'}
        if value not in mysql_in_container_enum:
            return False

        return True

    @staticmethod
    def kerberos_key(value):
        kerberos_key_enum = {"krb5", "krb5i", "krb5p", "sys"}
        if value not in kerberos_key_enum:
            return False

        return True

    @staticmethod
    def deploy_mode(value):
        deploy_mode_enum = {"nas", "dbstore", "dbstore_unify"}
        if value not in deploy_mode_enum:
            return False

        return True
    
    @staticmethod
    def cantian_in_container(value):
        cantian_in_container_enum = {'0', '1', '2'}
        if value not in cantian_in_container_enum:
            return False
        
        return True

    @staticmethod
    def cluster_id(value):
        try:
            value = int(value)
        except Exception as error:
            LOG.error('cluster id type must be int : %s', str(error))
            return False

        if value < 0 or value > 255:
            LOG.error('cluster id cannot be less than 0 or more than 255')
            return False

        return True

    @staticmethod
    def cluster_name(value):
        if len(value) > 64 or not value:
            LOG.error('cluster name cannot be more than 64 or less than 1 in length')
            return False
        return True

    @staticmethod
    def mes_type(value):
        if value not in ["UC", "TCP"]:
            return False
        return True
    
    @staticmethod
    def mes_ssl_switch(value):
        if not isinstance(value, bool):
            return False
        return True

    @staticmethod
    def mysql_metadata_in_cantian(value):
        if not isinstance(value, bool):
            return False

        return True

    @staticmethod
    def redo_num(value):
        try:
            if int(value) <= 0:
                return False
        except Exception as error:
            LOG.error('redo_num type must be int : %s', str(error))
            return False
        if int(value) < 3 or int(value) > 256:
            LOG.error('redo_num cannot be less than 3 or more than 256')
            return False
        return True

    @staticmethod
    def redo_size(value):
        if not value.endswith("G"):
            return False
        int_value = value.strip("G")
        try:
            if int(int_value) <= 0:
                return False
        except Exception as error:
            LOG.error('redo_size type must be int : %s', str(error))
            return False
        return True

    @staticmethod
    def ca_path(value):
        return os.path.exists(value)

    @staticmethod
    def crt_path(value):
        return os.path.exists(value)

    @staticmethod
    def key_path(value):
        return os.path.exists(value)

    @staticmethod
    def mes_type(value):
        mes_type_enum = {"TCP", "UC"}
        if value not in mes_type_enum:
            return False

        return True

    @staticmethod
    def dbstore_fs_vstore_id(value):
        try:
            value = int(value)

        except Exception as error:
            LOG.error('dbstore_fs_vstore id type must be int : %s', str(error))
            return False
        return True


class CheckBase(metaclass=abc.ABCMeta):
    def __init__(self, check_name, suggestion):
        self.check_name = check_name
        self.suggestion = suggestion

    def check(self, *args, **kwargs):
        LOG.info("[Check Item]-[%s]: begin", self.check_name)
        check_result = False
        try:
            check_result = self.get_result(*args, **kwargs)
        except Exception as error:
            LOG.error("[Check Item]-[%s]: error: %s", self.check_name, str(error))
        LOG.info("[Check Item]-[%s]: result: %s", self.check_name, str(check_result))
        return check_result, [self.check_name, self.suggestion]

    @abc.abstractmethod
    def get_result(self, *args, **kwargs):
        """
        子类实现
        """
        return True


class CheckMem(CheckBase):
    def __init__(self):
        super().__init__('memory available size smaller than {}M'.format(NEEDED_MEM_SIZE),
                         'current memory size {}M'.format(self.get_mem_available()))

    @staticmethod
    def get_mem_available():
        """
        获取可用内存
        return:单位M
        """
        res = 0
        with open('/proc/meminfo') as file_path:
            for line in file_path.readlines():
                if "MemFree:" in line:
                    mem_free = line.split(':')[1].strip()
                    mem_free = mem_free.split(" ")[0]
                    res += int(mem_free) // 1024

                if "MemAvailable" in line:
                    mem_avail = line.split(':')[1].strip()
                    mem_avail = mem_avail.split(" ")[0]
                    res += int(mem_avail) // 1024

        return res

    def get_result(self, *args, **kwargs):
        return self.get_mem_available() >= NEEDED_MEM_SIZE


class CheckDisk(CheckBase):
    def __init__(self):
        super().__init__('disk capacity available size smaller than {}M'.format(NEEDED_SIZE),
                         'current disk capacity {}M'.format(self.get_disk_available()))

    @staticmethod
    def find_dir_path():
        """
        获取最上级目录
        """
        _path = INSTALL_PATH
        while not os.path.isdir(_path):
            _path = os.path.dirname(_path)
        return _path

    def get_disk_available(self):
        """
        获取可用磁盘剩余容量
        return:单位M
        """
        fs_info = os.statvfs(self.find_dir_path())
        avail = fs_info.f_bavail * fs_info.f_frsize
        return avail / (1024 * 1024)

    def get_result(self, *args, **kwargs):
        return self.get_disk_available() >= NEEDED_SIZE


class CheckInstallPath(CheckBase):
    def __init__(self):
        super().__init__("check install path is right.", "please check install path")

    def get_result(self, *args, **kwargs):
        """
        当安装路径已存在，且不是文件夹是报错
        """
        return not (os.path.exists(INSTALL_PATH) and not os.path.isdir(INSTALL_PATH))


class CheckInstallConfig(CheckBase):
    def __init__(self, config_path=None):
        super().__init__("check config param", 'please check params in json file {}'.format(config_path))
        self.config_path = config_path
        self.value_checker = ConfigChecker
        self.config_key = {
            'deploy_user', 'node_id', 'cms_ip', 'storage_dbstore_fs', 'storage_share_fs', 'storage_archive_fs',
            'storage_metadata_fs', 'share_logic_ip', 'archive_logic_ip', 'metadata_logic_ip', 'db_type',
            'MAX_ARCH_FILES_SIZE', 'mysql_in_container', 'mysql_metadata_in_cantian', 'storage_logic_ip', 'deploy_mode',
            'mes_ssl_switch', 'cantian_in_container', 'dbstore_demo'
        }
        self.dbstore_config_key = {
            'cluster_name', 'cantian_vlan_ip', 'storage_vlan_ip', 'link_type', 'storage_dbstore_page_fs',
            'kerberos_key', 'cluster_id', 'mes_type', "vstore_id", "dbstore_fs_vstore_id"
        }
        self.file_config_key = {
            "redo_num", "redo_size"
        }
        self.mes_type_key = {"ca_path", "crt_path", "key_path"}
        self.config_params = {}
        self.cluster_name = None
        self.ping_timeout = 3

    @staticmethod
    def check_ipv4(_ip):
        """
        ipv4合法校验
        """
        try:
            socket.inet_pton(socket.AF_INET, _ip)
        except AttributeError:
            try:
                socket.inet_aton(_ip)
            except socket.error:
                return False
            return _ip.count('.') == 3
        except socket.error:
            return False
        return True

    @staticmethod
    def check_ipv6(_ip):
        """
        ipv6合法校验.
        """
        try:
            socket.inet_pton(socket.AF_INET6, _ip)
        except socket.error:
            return False
        return True

    @staticmethod
    def execute_cmd(cmd):
        cmd_list = cmd.split("|")
        process_list = []
        for index, cmd in enumerate(cmd_list):
            if index == 0:
                _p = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
            else:
                _p = subprocess.Popen(shlex.split(cmd), stdin=process_list[index - 1].stdout,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
            process_list.append(_p)
        try:
            stdout, stderr = process_list[-1].communicate(timeout=30)
        except Exception as err:
            return -1, str(err), -1
        return stdout.decode().strip("\n"), stderr.decode().strip("\n"), process_list[-1].returncode

    def read_install_config(self):
        try:
            with open(self.config_path, 'r', encoding='utf8') as file_path:
                json_data = json.load(file_path)
                return json_data
        except Exception as error:
            LOG.error('load %s error, error: %s', self.config_path, str(error))

        return {}

    def check_install_config_params(self, install_config_keys):
        not_in_either = install_config_keys ^ self.config_key
        # 如果 config_key中存在的关键字install_config.json中没有，报错。
        for element in not_in_either:
            if element != 'dbstore_demo' and element not in install_config_keys:
                LOG.error('config_params.json need param %s', element)
                return False
        return True

    def check_install_config_param(self, key, value):
        if hasattr(self.value_checker, key):
            target_checker = getattr(self.value_checker, key)
            if not target_checker(value):
                return False

        if key in ip_check_element:
            ip_list = re.split(r"[;,]", value)
            for single_ip in ip_list:
                if not self.check_ipv4(single_ip) and not self.check_ipv6(single_ip):
                    return False

        # 适配域名部署方式检查当前域名是否能ping通
        if key in ping_check_element:
            ip_list = re.split(r"[;,]", value)
            for node_ip in ip_list:
                cmd = "%s %s -i 1 -c 3 | grep ttl | wc -l"
                ping_cmd = cmd % ("ping", node_ip)
                ping6_cmd = cmd % ("ping6", node_ip)
                try:
                    ping_ret, _, ping_code = self.execute_cmd(ping_cmd)
                except Exception as err:
                    _ = err
                    ping_ret = -1
                try:
                    ping6_ret, _, ping6_code = self.execute_cmd(ping6_cmd)
                except Exception as err:
                    _ = err
                    ping6_ret = -1
                if ping_ret != "3" and ping6_ret != "3":
                    return False
        return True

    def write_result_to_json(self):
        modes = stat.S_IRWXU | stat.S_IROTH | stat.S_IRGRP
        flag = os.O_RDWR | os.O_CREAT | os.O_TRUNC
        with os.fdopen(os.open(str(Path('{}/deploy_param.json'.format(dir_name))), flag, modes), 'w') as file_path:
            config_params = json.dumps(self.config_params, indent=4)
            file_path.write(config_params)

    def update_config_params(self):
        # 使用域名部署场景，share_logic_ip、archive_logic_ip、metadata_logic_ip为空时需要更新字段为cluster_name

        if self.config_params.get("share_logic_ip") == "" and \
                self.config_params.get("archive_logic_ip") == "" and \
                self.config_params.get("metadata_logic_ip") == "":
            self.config_params["share_logic_ip"] = self.config_params.get("cluster_name")
            self.config_params["archive_logic_ip"] = self.config_params.get("cluster_name")
            self.config_params["metadata_logic_ip"] = self.config_params.get("cluster_name")
            modes = stat.S_IRWXU | stat.S_IROTH | stat.S_IRGRP
            flag = os.O_RDWR | os.O_CREAT | os.O_TRUNC
            config_params = json.dumps(self.config_params, indent=4)
            with os.fdopen(os.open(self.config_path, flag, modes), 'w') as file_path:
                file_path.write(config_params)

    def do_unit_conversion(self, get_unit_conversion_info):
        tmp_gb, tmp_mb, tmb_kb, key, value,\
        sga_buff_size, temp_buffer_size, data_buffer_size,\
        shared_pool_size, log_buffer_size = get_unit_conversion_info
        if value[0: -1].isdigit() and value[-1:] in ["G", "M", "K"]:
            unit_map = {
                "G": tmp_gb,
                "M": tmp_mb,
                "K": tmb_kb,
            }
            size_unit = unit_map.get(value[-1:])
            sga_buff_size += int(value[0:-1]) * size_unit
        
        if key == "TEMP_BUFFER_SIZE":
            sga_buff_size -= temp_buffer_size
        if key == "DATA_BUFFER_SIZE":
            sga_buff_size -= data_buffer_size
        if key == "SHARED_POOL_SIZE":
            sga_buff_size -= shared_pool_size
        if key == "LOG_BUFFER_SIZE":
            sga_buff_size -= log_buffer_size
        
        return sga_buff_size

    def check_sga_buff_size(self):
        LOG.info("Checking sga buff size.")
        # GB MB KB
        tmp_gb = 1024 * 1024 * 1024
        tmp_mb = 1024 * 1024
        tmp_kb = 1024
        # The size of database
        log_buffer_size = 4 * tmp_mb
        shared_pool_size = 128 * tmp_mb
        data_buffer_size = 128 * tmp_mb
        temp_buffer_size = 32 * tmp_mb
        sga_buff_size = (log_buffer_size + shared_pool_size + data_buffer_size + temp_buffer_size)

        # parse the value of kernel parameters
        modes = stat.S_IWUSR | stat.S_IRUSR
        flags = os.O_RDONLY
        with os.fdopen(os.open(CANTIAND_INI_FILE, flags, modes), 'r') as fp:
            for line in fp:
                if line == "\n":
                    continue
                (key, value) = line.split(" = ")
                if key in kernel_element:
                    # Unit consersion
                    get_unit_conversion_info = UnitConversionInfo(tmp_gb ,tmp_mb, tmp_kb, key, value.strip(),
                                                                  sga_buff_size, temp_buffer_size, data_buffer_size,
                                                                  shared_pool_size, log_buffer_size)
                    sga_buff_size = self.do_unit_conversion(get_unit_conversion_info)
        
        # check sga buff size
        cmd = "cat /proc/meminfo |grep -wE 'MemFree:|Buffers:|Cached:|SwapCached' |awk '{sum += $2};END {print sum}'"
        ret_code, cur_avi_memory, stderr = exec_popen(cmd)
        if ret_code:
            LOG.error("cannot get shmmax parameters, command: %s, err: %s" % (cmd, stderr))
        if sga_buff_size < 114 * tmp_mb:
            LOG.error("sga buffer size should not less than 114MB, please check it!")
        
        try:
            if sga_buff_size > int(cur_avi_memory) * tmp_kb:
                LOG.error("sga buffer size should less than shmmax, please check it!")
        except ValueError as ex:
            LOG.error("check sga buffer size failed: " + str(ex))
        
        LOG.info("End check sga buffer size")

    def get_result(self, *args, **kwargs):
        if not self.config_path:
            LOG.error('path of config file is not entered, example: sh install.sh xxx/xxx/xxx')
            return False

        install_config_params = self.read_install_config()

        if install_config_params['cantian_in_container'] != '0':
            ip_check_element.remove('cms_ip')

        self.install_config_params_init(install_config_params)

        self.cluster_name = install_config_params.get("cluster_name")
        # 不开启归档时不检查归档连通性
        if install_config_params.get("storage_archive_fs") == "":
            ping_check_element.remove("archive_logic_ip")

        if install_config_params['deploy_mode'] != "nas":
            self.config_key.remove("storage_logic_ip")
            self.config_key.update(self.dbstore_config_key)
            ping_check_element.remove("storage_logic_ip")
            if install_config_params['deploy_mode'] == "dbstore_unify":
                ping_check_element.remove("share_logic_ip")
                install_config_params['share_logic_ip'] = "127.0.0.1"
        else:
            self.config_params['cluster_id'] = "0"
            self.config_params['mes_type'] = "TCP"
            self.config_key.update(self.file_config_key)

        if install_config_params['cantian_in_container'] != '0':
            ping_check_element.remove("cms_ip")
            ip_check_element.remove("cantian_vlan_ip")
            ping_check_element.remove("cantian_vlan_ip")

        if install_config_params['archive_logic_ip'] == "" \
                and install_config_params['share_logic_ip'] == "" \
                and install_config_params['metadata_logic_ip'] == "":
            install_config_params['archive_logic_ip'] = self.cluster_name
            install_config_params['share_logic_ip'] = self.cluster_name
            install_config_params['metadata_logic_ip'] = self.cluster_name

        max_arch_files_size = install_config_params.get('MAX_ARCH_FILES_SIZE', "")
        if not max_arch_files_size:
            install_config_params['MAX_ARCH_FILES_SIZE'] = '300G'

        if not self.check_install_config_params(install_config_params.keys()):
            return False
        for key, value in install_config_params.items():
            if key in self.config_key:
                checked_result = self.check_install_config_param(key, value)
                if not checked_result:
                    LOG.error('check %s with value: %s failed', str(key), str(value))
                    return False
                self.config_params[key] = value
        try:
            self.update_config_params()
        except Exception as error:
            LOG.error('write config param to config_param.json failed, error: %s', str(error))
            return False
        if install_config_params['cantian_in_container'] == '0':
            try:
                self.write_result_to_json()
            except Exception as error:
                LOG.error('write config param to deploy_param.json failed, error: %s', str(error))
                return False
        if install_config_params['cantian_in_container'] != '0':
            self.check_sga_buff_size()
        return True

    def install_config_params_init(self, install_config_params):
        if 'link_type' not in install_config_params.keys():
            install_config_params['link_type'] = '1'
        if 'storage_archive_fs' not in install_config_params.keys():
            install_config_params['storage_archive_fs'] = ''
        if 'archive_logic_ip' not in install_config_params.keys():
            install_config_params['archive_logic_ip'] = ''
        if 'mes_type' not in install_config_params.keys():
            install_config_params['mes_type'] = 'UC'
        if 'mes_ssl_switch' not in install_config_params.keys():
            install_config_params['mes_ssl_switch'] = False
        if 'deploy_mode' not in install_config_params.keys():
            install_config_params['deploy_mode'] = "dbstore"
        if 'dbstore_fs_vstore_id' not in install_config_params.keys():
            install_config_params['dbstore_fs_vstore_id'] = "0"
        if install_config_params.get("mes_ssl_switch") == True and install_config_params.get("cantian_in_container", -1) == "0":
            self.config_key.update(self.mes_type_key)
        if 'db_type' not in install_config_params.keys():
            install_config_params['db_type'] = '0'
        if 'mysql_metadata_in_cantian' not in install_config_params.keys():
            install_config_params['mysql_metadata_in_cantian'] = True


class PreInstall:
    def __init__(self, install_model, config_path):
        self.config_path = config_path
        self.install_model = install_model
        self.result = []

    def check_main(self):
        """
        存在，但是不是目录
        """
        if self.install_model == "override":
            check_items = [CheckMem, CheckDisk, CheckInstallPath, CheckInstallConfig]
        else:
            check_items = [CheckMem, CheckDisk, CheckInstallPath]

        for item in check_items:
            check_result = True
            if item is CheckInstallConfig:
                res = item(self.config_path).get_result()
                if not res:
                    check_result = False
            else:
                res = item().get_result()
                if not res:
                    check_result = False

            if not check_result:
                LOG.error('failed: %s, suggestion: %s', item().check_name, item().suggestion)
                return 1

        return 0


if __name__ == '__main__':
    config_file = None
    install_type = sys.argv[1]
    if install_type == 'override':
        config_file = sys.argv[2]

    pre_install = PreInstall(install_type, config_file)
    exit(pre_install.check_main())

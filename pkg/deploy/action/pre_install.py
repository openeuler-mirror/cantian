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
PKG_DIR = os.path.abspath(os.path.join(dir_name, ".."))
CANTIAN_MEM_SPEC_FILE = os.path.join(dir_name, "config", "container_conf", "init_conf", "mem_spec")
CANTIAND_INI_FILE = "/mnt/dbdata/local/cantian/tmp/data/cfg/cantiand.ini"

SINGLE_DOUBLE_PROCESS_MAP = {
    "0": "cantiand_in_cluster",
    "1": "cantiand_with_mysql_in_cluster"
}

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
    'LOG_BUFFER_SIZE',
    'SESSIONS',
    'VARIANT_MEMORY_AREA_SIZE',
    '_INDEX_BUFFER_SIZE'
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
        deploy_mode_enum = {"file", "combined", "dbstor"}
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
        if value not in ["UC", "TCP", "UC_RDMA"]:
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
        mes_type_enum = {"TCP", "UC", "UC_RDMA"}
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
            'mes_ssl_switch', 'cantian_in_container', 'deploy_policy'
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

    @staticmethod
    def check_cantian_mem_spec():
        if os.path.exists(CANTIAN_MEM_SPEC_FILE):
            with open(CANTIAN_MEM_SPEC_FILE, encoding="utf-8") as f:
                mem_spec = json.load(f)
            if mem_spec not in ["1", "2", "3"]:
                LOG.error("Check mem spec failed, current value[%s], " \
                          "value range [\"1\", \"2\", \"3\"]", mem_spec)
                return False
        return True

    @staticmethod
    def check_storage_cantian_vlan_ip_scale(install_config_params):
        """
        检查storage_vlan_ip 与 cantian_vlan_ip对个数是否符合要求
        exp:
            storage_vlan_ip: item1|item2|item3
            cantian_vlan_ip: item3|item4|item5
            item :127.0.0.1;127.0.0.2
            scale: len(storage_vlan_ip.split("|")) == len(cantian_vlan_ip.split("|"))
                   sum = len(item1.split(";") * len(item3.split(";")) + ...
                   sum <= 32
        :param install_config_params:
        :return:
        """
        cantian_vlan_ips = install_config_params.get("cantian_vlan_ip").split("|")
        storage_vlan_ips = install_config_params.get("storage_vlan_ip").split("|")
        if len(cantian_vlan_ips) != len(storage_vlan_ips):
            LOG.error("cantian_vlan_ip and storage_vlan_ip should have same length.")
            return False
        scale = 0
        for i in range(len(cantian_vlan_ips)):
            scale += len(cantian_vlan_ips[i].split(";")) * len(storage_vlan_ips[i].split(";"))
        if scale > 32:
            LOG.error("cantian_vlan_ip and storage_vlan_ip scale should be less than 32.")
            return False
        return True

    def read_install_config(self):
        try:
            with open(self.config_path, 'r', encoding='utf8') as file_path:
                json_data = json.load(file_path)
                return json_data
        except Exception as error:
            LOG.error('load %s error, error: %s', self.config_path, str(error))

        return {}

    def check_install_config_params(self, install_config):
        install_config_keys = install_config.keys()
        not_in_either = install_config_keys ^ self.config_key
        # 如果 config_key中存在的关键字install_config.json中没有，报错。
        for element in not_in_either:
            # 去nas忽略部分参数
            dbstor_ignore_params = {"storage_metadata_fs", "share_logic_ip",
                                    "archive_logic_ip", "metadata_logic_ip", "vstore_id"}
            combined_ignore_params = {"share_logic_ip", "vstore_id"}
            if element in dbstor_ignore_params and install_config['deploy_mode'] == "dbstor":
                continue
            if element in combined_ignore_params and install_config['deploy_mode'] == "combined":
                continue
            if element not in install_config_keys:
                LOG.error('config_params.json need param %s', element)
                return False
        return True

    def check_install_config_param(self, key, value):
        if hasattr(self.value_checker, key):
            target_checker = getattr(self.value_checker, key)
            if not target_checker(value):
                return False

        if key in ip_check_element:
            ip_list = re.split(r"[;,|]", value)
            for single_ip in ip_list:
                if not self.check_ipv4(single_ip) and not self.check_ipv6(single_ip):
                    return False

        # 适配域名部署方式检查当前域名是否能ping通
        if key in ping_check_element:
            ip_list = re.split(r"[;,|]", value)
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
        if key == "SESSIONS":
            buff_size_pre_session = 5.5 * tmp_gb / 1024
            sga_buff_size += int(value) * buff_size_pre_session
        
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
                    get_unit_conversion_info = UnitConversionInfo(tmp_gb, tmp_mb, tmp_kb, key, value.strip(),
                                                                  sga_buff_size, temp_buffer_size, data_buffer_size,
                                                                  shared_pool_size, log_buffer_size)
                    sga_buff_size = self.do_unit_conversion(get_unit_conversion_info)
        
        # check sga buff size
        cmd = "cat /proc/meminfo |grep -wE 'MemFree:|Buffers:|Cached:|SwapCached' |awk '{sum += $2};END {print sum}'"
        ret_code, cur_avi_memory, stderr = exec_popen(cmd)
        if ret_code:
            LOG.error("cannot get shmmax parameters, command: %s, err: %s" % (cmd, stderr))
            return False
        if sga_buff_size < 114 * tmp_mb:
            LOG.error("sga buffer size should not less than 114MB, please check it!")
            return False
        
        # memory for Mysql, share memory, Dbstor, and CMS
        sga_buff_size += 12.2 * tmp_gb
        if int(sga_buff_size) > int(cur_avi_memory) * tmp_kb:
            LOG.error("sga buffer size(%.2f GB) should less than availble memory(%.2f GB), please check it!" % (int(sga_buff_size) / tmp_gb, int(cur_avi_memory) / tmp_mb))
            return False

        cmd = r"cat /proc/1/environ | tr '\0' '\n' | grep MY_MEMORY_SIZE | cut -d= -f2"
        ret_code, container_memory_limit, stderr = exec_popen(cmd)
        if ret_code:
            LOG.error("cannot get memory limit, command: %s, err: %s" % (cmd, stderr))
            return False
        if container_memory_limit and (int(container_memory_limit) / tmp_gb) < 60:
            LOG.error("container memory limit(%.2f GB) cannot be less than 60GB, please check it!" % (int(container_memory_limit) / tmp_gb))
            return False
        if container_memory_limit and int(sga_buff_size) > int(container_memory_limit):
            LOG.error("sga buffer size(%.2f GB) should less than container memory limit(%.2f GB), please check it!" % (int(sga_buff_size) / tmp_gb, int(container_memory_limit) / tmp_gb))
            return False
        
        LOG.info("End check sga buffer size")
        return True

    def get_result(self, *args, **kwargs):
        if not self.config_path:
            LOG.error('path of config file is not entered, example: sh install.sh xxx/xxx/xxx')
            return False

        install_config_params = self.read_install_config()
        ret = self.init_config_by_deploy_policy(install_config_params)
        if not ret:
            LOG.error("init deploy policy failed")
            return False

        self.install_config_params_init(install_config_params)

        self.cluster_name = install_config_params.get("cluster_name")
        # 不开启归档时不检查归档连通性
        if install_config_params.get("storage_archive_fs") == "":
            ping_check_element.remove("archive_logic_ip")

        if install_config_params['deploy_mode'] != "file":
            self.config_key.remove("storage_logic_ip")
            self.config_key.update(self.dbstore_config_key)
            ping_check_element.remove("storage_logic_ip")
            if install_config_params['deploy_mode'] == "dbstor":
                if not install_config_params['mysql_metadata_in_cantian']:
                    LOG.error('Failed to check. deploy_mode is dbstor, mysql_metadata_in_cantian must be true')
                    return False
                ping_check_element.remove("share_logic_ip")
                install_config_params['share_logic_ip'] = "127.0.0.1"
                # 去nas防止报错，后续版本删除
                install_config_params['archive_logic_ip'] = "127.0.0.1"
                install_config_params['metadata_logic_ip'] = "127.0.0.1"
        else:
            self.config_params['cluster_id'] = "0"
            self.config_params['mes_type'] = "TCP"
            self.config_key.update(self.file_config_key)

        if install_config_params['cantian_in_container'] != '0':
            ip_check_element.remove('cms_ip')
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

        if not self.check_install_config_params(install_config_params):
            return False
        if (install_config_params['deploy_mode'] != "file" and
                not self.check_storage_cantian_vlan_ip_scale(install_config_params)):
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
            if not self.check_cantian_mem_spec():
                return False

            if not self.check_sga_buff_size():
                return False
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
            install_config_params['deploy_mode'] = "combined"
        if 'dbstore_fs_vstore_id' not in install_config_params.keys():
            install_config_params['dbstore_fs_vstore_id'] = "0"
        if install_config_params.get("mes_ssl_switch") == True and install_config_params.get("cantian_in_container", "-1") == "0":
            self.config_key.update(self.mes_type_key)
        if 'db_type' not in install_config_params.keys():
            install_config_params['db_type'] = '0'
        if 'mysql_metadata_in_cantian' not in install_config_params.keys():
            install_config_params['mysql_metadata_in_cantian'] = True

    def parse_policy_config_file(self):
        policy_path = os.path.join(dir_name, "deploy_policy_config.json")
        try:
            with open(policy_path, 'r', encoding='utf8') as file_path:
                json_data = json.load(file_path)
                return json_data
        except Exception as error:
            LOG.error('load %s error, error: %s', policy_path, str(error))
            return False
    
    def parse_cantian_config_file(self):
        cantian_config_path = os.path.join(dir_name, "cantian")
        cantian_config_path = os.path.join(cantian_config_path, "install_config.json")
        try:
            with open(cantian_config_path, 'r', encoding='utf8') as file_path:
                json_data = json.load(file_path)
                return json_data
        except Exception as error:
            LOG.error('load %s error, error: %s', cantian_config_path, str(error))
            return False
    
    def init_config_by_deploy_policy(self, install_config_params):
        deploy_policy_json = self.parse_policy_config_file()
        if deploy_policy_json is False:
            LOG.error("parse deploy_policy_config.json failed")
            return False

        cantian_config_json = self.parse_cantian_config_file()
        if cantian_config_json is False:
            LOG.error("parse cantian/install_config.json failed")
            return False
        # 根据配置文件获取配置方案
        deploy_policy_key = install_config_params.get("deploy_policy", "")
        # 如果配置方案为空或者默认走原安装流程，直接返回
        if deploy_policy_key == "" or deploy_policy_key == "default":
            LOG.info("deploy policy is default")
            # 如果未配置套餐参数，初始化套餐参数
            install_config_params["deploy_policy"] = "default"
            return True
        LOG.info("deploy policy is %s" % deploy_policy_key)       
        # 如果配置方案未配置则返回失败，安装结束
        deploy_policy_value = deploy_policy_json.get(deploy_policy_key, {})
        if deploy_policy_value == {}:
            LOG.error("can not find the deploy policy(%s)" % deploy_policy_key)
            return False
            
        # 如果配置方案合法则将方案中的参数写入配置文件
        is_single_process = deploy_policy_value.get("single_process", "0")
        if SINGLE_DOUBLE_PROCESS_MAP.get(is_single_process, "") != cantian_config_json.get("M_RUNING_MODE"):
            LOG.error("The package type does not match the configuration parameters.")
            return False
        tmp_config = deploy_policy_value.get("config", {})

        for item in tmp_config.keys():
            if item in self.config_key:
                install_config_params[item] = tmp_config.get(item, "")
            else:
                LOG.error("deploy policy has invalid params %s" % item)
                return False
        return True


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

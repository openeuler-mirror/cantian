#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Perform hot backups of CantianDB100 databases.
# Copyright © Huawei Technologies Co., Ltd. 2010-2018. All rights reserved.

import sys

sys.dont_write_bytecode = True

try:
    import glob
    import getopt
    import getpass
    import grp
    import os
    import platform
    import pwd
    import re
    import shutil
    import socket
    import stat
    import subprocess
    import time
    import tarfile
    import copy
    import json
    import sys
    import collections
    from get_config_info import get_value
    from cantian_funclib import CommonValue, SingleNodeConfig, ClusterNode0Config, \
        ClusterNode1Config, DefaultConfigValue
    from Common import CommonPrint
    from options import Options
    from exception import NormalException
    from log import LOGGER
    sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "dbstor"))
    from kmc_adapter import CApiWrapper

    PYTHON242 = "2.4.2"
    PYTHON3 = "3.0"
    gPyVersion = platform.python_version()

    if gPyVersion < PYTHON3:
        print_str = CommonPrint()
        print_str.common_log("This install script can not support python version: %s"
                             % gPyVersion)
        raise ValueError("This install script can not support python version: %s"
                         % gPyVersion)

    sys.path.append(os.path.split(os.path.realpath(__file__))[0])
    sys.dont_write_bytecode = True
except ImportError as err:
    raise ValueError("Unable to import module: %s." % str(err)) from err

CURRENT_OS = platform.system()

CANTIAND = "cantiand"
CANTIAND_WITH_MYSQL = "cantiand_with_mysql"
CANTIAND_WITH_MYSQL_ST = "cantiand_with_mysql_st"  # single process mode with mysql llt
CANTIAND_IN_CLUSTER = "cantiand_in_cluster"
CANTIAND_WITH_MYSQL_IN_CLUSTER = "cantiand_with_mysql_in_cluster"
MYSQLD = "mysqld"

INSTALL_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "installdb.sh")

VALID_RUNNING_MODE = {CANTIAND, CANTIAND_WITH_MYSQL, CANTIAND_WITH_MYSQL_ST, CANTIAND_IN_CLUSTER,
                      CANTIAND_WITH_MYSQL_IN_CLUSTER, MYSQLD}

VALID_SINGLE_MYSQL_RUNNING_MODE = {CANTIAND_WITH_MYSQL_IN_CLUSTER, CANTIAND_WITH_MYSQL_ST, CANTIAND_WITH_MYSQL}

CLUSTER_SIZE = 2  # default to 2, 4 node cluster mode need add parameter to specify this

INSTALL_SCPRIT_DIR = os.path.dirname(os.path.abspath(__file__))
PKG_DIR = os.path.abspath(os.path.join(INSTALL_SCPRIT_DIR, "../.."))

JS_CONF_FILE = os.path.join(PKG_DIR, "action", "cantian", "install_config.json")
CANTIAN_CONF_FILE = os.path.join("/opt/cantian/cantian", "cfg", "cantian_config.json")
CONFIG_PARAMS_FILE = os.path.join(PKG_DIR, "config", "deploy_param.json")
CANTIAN_START_STATUS_FILE = os.path.join("/opt/cantian/cantian", "cfg", "start_status.json")
CANTIAN_INSTALL_LOG_FILE = "/opt/cantian/cantian/log/cantian_deploy.log"
CANTIAND_INI_FILE = "/mnt/dbdata/local/cantian/tmp/data/cfg/cantiand.ini"
CTSQL_INI_FILE = '/mnt/dbdata/local/cantian/tmp/data/cfg/*sql.ini'

MYSQL_CODE_DIR = "/opt/cantian/image/cantian_connector/cantian-connector-mysql"
MYSQL_BIN_DIR = "/opt/cantian/mysql/install/mysql"
MYSQL_DATA_DIR = ""
MYSQL_LOG_FILE = ""

g_opts = Options()
CheckPathsInfo = collections.namedtuple('CheckPathsInfo', ['path_len', 'path_type_in', 'a_ascii',
                                                           'z_ascii', 'a_cap_ascii', 'z_cap_ascii',
                                                           'num0_ascii', 'num9_ascii', 'char_check_list'])

UnitConversionInfo = collections.namedtuple('UnitConversionInfo', ['tmp_gb', 'tmp_mb', 'tmp_kb', 'key', 'value',
                                                                   'sga_buff_size', 'temp_buffer_size',
                                                                   'data_buffer_size', 'shared_pool_size',
                                                                   'log_buffer_size'])


def check_kernel_parameter(para):
    """Is kernel parameter invalid?"""
    pattern = re.compile("^[A-Z_][A-Z0-9_]+$")
    if not pattern.match(para.upper().strip()):
        print_str_1 = CommonPrint()
        print_str_1.common_log("The kernel parameter '%s' is invalid." % para)
        raise ValueError("The kernel parameter '%s' is invalid." % para)


def check_invalid_symbol(para):
    """
    If there is invalid symbol in parameter?
    :param para: parameter's value
    :return: NA
    """
    symbols = ["|", "&", "$", ">", "<", "\"", "'", "`"]
    for symbol in symbols:
        if para.find(symbol) > -1:
            print_str_1 = CommonPrint()
            print_str_1.common_log("There is invalid symbol \"%s\" in %s" % (symbol, para))
            raise ValueError("There is invalid symbol \"%s\" in %s" % (symbol, para))


def all_zero_addr_after_ping(node_ip):
    """
    check ip is all 0
    :param node_ip: ip addr
    :return: bool
    """
    if not node_ip:
        return False
    allowed_chars = set('0:.')
    if set(node_ip).issubset(allowed_chars):
        return True
    else:
        return False


def check_path(path_type_in):
    """
    Check the validity of the path.
    :param path_type_in: path
    :return: weather validity
    """
    path_len = len(path_type_in)
    a_ascii = ord('a')
    z_ascii = ord('z')
    a_cap_ascii = ord('A')
    z_cap_ascii = ord('Z')
    num0_ascii = ord('0')
    num9_ascii = ord('9')
    blank_ascii = ord(' ')
    sep1_ascii = ord(os.sep)
    sep2_ascii = ord('_')
    sep3_ascii = ord(':')
    sep4_ascii = ord('-')
    sep5_ascii = ord('.')
    char_check_list1 = [blank_ascii,
                        sep1_ascii,
                        sep2_ascii,
                        sep4_ascii,
                        sep5_ascii
                        ]

    char_check_list2 = [blank_ascii,
                        sep1_ascii,
                        sep2_ascii,
                        sep3_ascii,
                        sep4_ascii
                        ]
    if CURRENT_OS == "Linux":
        get_check_path_linux_info = CheckPathsInfo(path_len, path_type_in, a_ascii, z_ascii, a_cap_ascii,
                                                   z_cap_ascii, num0_ascii, num9_ascii, char_check_list1)
        return check_path_linux(get_check_path_linux_info)
    elif CURRENT_OS == "Windows":
        get_check_path_windows_info = CheckPathsInfo(path_len, path_type_in, a_ascii, z_ascii, a_cap_ascii,
                                                     z_cap_ascii, num0_ascii, num9_ascii, char_check_list2)
        return check_path_windows(get_check_path_windows_info)
    else:
        print_str_1 = CommonPrint()
        print_str_1.common_log("Error: Can not support this platform.")
        raise ValueError("Error: Can not support this platform.")


def check_path_linux(get_check_path_linux_info):
    path_len, path_type_in, a_ascii, z_ascii, a_cap_ascii, \
        z_cap_ascii, num0_ascii, num9_ascii, char_check_list1 = get_check_path_linux_info
    for i in range(0, path_len):
        char_check = ord(path_type_in[i])
        if (not (a_ascii <= char_check <= z_ascii
                 or a_cap_ascii <= char_check <= z_cap_ascii
                 or num0_ascii <= char_check <= num9_ascii
                 or char_check in char_check_list1)):
            return False
    return True


def check_path_windows(get_check_path_windows_info):
    path_len, path_type_in, a_ascii, z_ascii, a_cap_ascii, \
        z_cap_ascii, num0_ascii, num9_ascii, char_check_list2 = get_check_path_windows_info
    for i in range(0, path_len):
        char_check = ord(path_type_in[i])
        if (not (a_ascii <= char_check <= z_ascii
                 or a_cap_ascii <= char_check <= z_cap_ascii
                 or num0_ascii <= char_check <= num9_ascii
                 or char_check in char_check_list2)):
            return False
    return True


def _exec_popen(cmd, values=None):
    """
    subprocess.Popen in python2 and 3.
    :param cmd: commands need to execute
    :return: status code, standard output, error output
    """
    if not values:
        values = []
    bash_cmd = ["bash"]
    pobj = subprocess.Popen(bash_cmd, shell=False, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if gPyVersion[0] == "3":
        pobj.stdin.write(cmd.encode())
        pobj.stdin.write(os.linesep.encode())
        for value in values:
            pobj.stdin.write(value.encode())
            pobj.stdin.write(os.linesep.encode())
        try:
            stdout, stderr = pobj.communicate(timeout=3600)
        except subprocess.TimeoutExpired as err_cmd:
            pobj.kill()
            return -1, "Time Out.", str(err_cmd)
        stdout = stdout.decode()
        stderr = stderr.decode()
    else:
        pobj.stdin.write(cmd)
        pobj.stdin.write(os.linesep)
        for value in values:
            pobj.stdin.write(value)
            pobj.stdin.write(os.linesep)
        try:
            stdout, stderr = pobj.communicate(timeout=1800)
        except subprocess.TimeoutExpired as err_cmd:
            pobj.kill()
            return -1, "Time Out.", str(err_cmd)
    if stdout[-1:] == os.linesep:
        stdout = stdout[:-1]
    if stderr[-1:] == os.linesep:
        stderr = stderr[:-1]

    return pobj.returncode, stdout, stderr


def _get_input(msg):
    """
    Packaged function about user input which dialect with Python 2
    and Python 3.
    :param msg: input function's prompt message
    :return: the input value of user
    """
    if gPyVersion[0] == "3":
        return input(msg)
    return raw_input(msg)


def check_platform():
    """
    check platform

    Currently only supports Linux platforms.
    """
    if CURRENT_OS is None or not CURRENT_OS.strip():
        print_str_1 = CommonPrint()
        print_str_1.common_log("Can not get platform information.")
        raise ValueError("Can not get platform information.")
    if CURRENT_OS == "Linux":
        pass
    else:
        print_str_2 = CommonPrint()
        print_str_2.common_log("This install script can not support %s platform." % CURRENT_OS)
        raise ValueError("This install script can not support %s platform." % CURRENT_OS)


def usage():
    print_str_1 = CommonPrint()
    print_str_1.common_log(usage.__doc__)


def load_config_param(json_data):
    g_opts.node_id = int(json_data.get('node_id'))
    if json_data.get('link_type', '0').strip() == '0':
        g_opts.link_type = "TCP"
    elif json_data.get('link_type', '0').strip() == '1':
        g_opts.link_type = "RDMA"
    elif json_data.get('link_type', '0').strip() == '2':
        g_opts.link_type = "RDMA_1823"
    if json_data.get('cantian_in_container', 0) == '1':
        g_opts.cantian_in_container = True
    g_opts.db_type = json_data.get('db_type', '').strip()
    g_opts.storage_dbstore_fs = json_data.get("storage_dbstore_fs").strip()
    g_opts.storage_share_fs = json_data['storage_share_fs'].strip()
    g_opts.namespace = json_data.get('cluster_name', 'test1').strip()
    g_opts.share_logic_ip = json_data.get('share_logic_ip', '').strip()
    g_opts.archive_logic_ip = json_data.get('archive_logic_ip', '').strip()
    g_opts.mes_type = json_data.get("mes_type", "UC").strip()
    g_opts.archive_location = "location=/mnt/dbdata/remote/archive_" + json_data['storage_archive_fs'].strip()
    metadata_str = "metadata_" + json_data.get('storage_metadata_fs', '').strip()
    node_str = "node" + str(g_opts.node_id)
    global MYSQL_DATA_DIR
    MYSQL_DATA_DIR = os.path.join("/mnt/dbdata/remote", metadata_str, node_str)
    global MYSQL_LOG_FILE
    MYSQL_LOG_FILE = os.path.join(MYSQL_DATA_DIR, "mysql.log")
    g_opts.max_arch_files_size = json_data['MAX_ARCH_FILES_SIZE'].strip()
    g_opts.cluster_id = json_data['cluster_id'].strip()
    g_opts.use_dbstor = True if json_data.get("deploy_mode", "").strip() != "nas" else False


def parse_parameter():
    try:
        # Parameters are passed into argv. After parsing, they are stored
        # in opts as binary tuples. Unresolved parameters are stored in args.
        opts, args = getopt.getopt(sys.argv[1:],
                                   "h:s:t:", ["help", "sys_password=", "isencrept="])
        if args:
            print_str_1 = CommonPrint()
            print_str_1.common_log("Parameter input error: " + str(args[0]))
            raise ValueError("Parameter input error: " + str(args[0]))

        for _key, _value in opts:
            if _key == "-s":
                g_opts.password = _get_input("please input pwd: ").strip()
                g_opts.cert_encrypt_pwd = _get_input("please input cert_encrypt_pwd:").strip()
            if _key == "-t":
                if _value.strip() == 'reserve':
                    g_opts.isencrept = False

        flags = os.O_RDONLY
        modes = stat.S_IWUSR | stat.S_IRUSR
        with os.fdopen(os.open(JS_CONF_FILE, flags, modes), 'r') as fp:
            json_data = json.load(fp)
            g_opts.log_file = json_data['l_LOG_FILE'].strip()  # -I
            g_opts.running_mode = json_data['M_RUNING_MODE'].strip()  # -M
            g_opts.ignore_pkg_check = True  # -p

        flags = os.O_RDONLY
        modes = stat.S_IWUSR | stat.S_IRUSR
        with os.fdopen(os.open(CONFIG_PARAMS_FILE, flags, modes), 'r') as fp:
            json_data = json.load(fp)
            load_config_param(json_data)
        g_opts.opts = opts
    except getopt.GetoptError as error:
        print_str_2 = CommonPrint()
        print_str_2.common_log("Parameter input error: " + error.msg)
        raise ValueError(str(error)) from error


def is_mlnx():
    """
    is_mlnx
    """
    ret_code, stdout, stderr = _exec_popen("which ofed_info")
    if ret_code:
        log("no ofed_info cmd found."
            "ret_code : %s, stdout : %s, stderr : %s" % (ret_code, stdout, stderr))
        return False

    ret_code, stdout, stderr = _exec_popen("ofed_info -s")
    if ret_code:
        log("exec ofed_info cmd failed."
            "ret_code : %s, stdout : %s, stderr : %s" % (ret_code, stdout, stderr))
        return False

    if 'MLNX_OFED_LINUX-5.5' in stdout:
        log("Is mlnx 5.5")
        return True

    ret_code, os_arch, stderr = _exec_popen("uname -i")
    aarch_mlnx_version_list = ['OFED-internal-5.8-2.0.3', 'MLNX_OFED_LINUX-5.8', 'MLNX_OFED_LINUX-5.9']
    aarch_version_check_result = any(mlnx_version if mlnx_version in stdout else False
                                     for mlnx_version in aarch_mlnx_version_list)
    if os_arch == "aarch64" and aarch_version_check_result == True:
        log("Is mlnx 5.8~5.9"
            " ret_code : %s, stdout : %s, stderr : %s" % (ret_code, os_arch, stderr))
        return True

    log("Not mlnx 5.5")
    return False


def is_hinicadm3():
    ret_code, _, sterr = _exec_popen("whereis hinicadm3")
    if ret_code:
        log("can not find hinicadm3")
        return False
    return True


def is_rdma_startup():
    """
    is_rdma_startup
    """
    return g_opts.link_type == "RDMA" and is_mlnx()


def is_rdma_1823_startup():
    return g_opts.link_type == "RDMA_1823" and is_hinicadm3()


def check_parameter():
    """
    check parameter
    """
    print_str_7 = CommonPrint()
    check_log_path()
    # Use the default log path.
    if not g_opts.log_file:
        use_default_log_path()
    check_logfile_path(print_str_7)
    check_running_mode(print_str_7)


def check_running_mode(print_str_7):
    # Check running mode
    if len(g_opts.running_mode) == 0 or g_opts.running_mode.lower() not in VALID_RUNNING_MODE:
        print_str_7.common_log("Invalid running mode: " + g_opts.running_mode)
        raise ValueError("Invalid running mode: " + g_opts.running_mode)
    if g_opts.node_id not in [0, 1]:
        print_str_7.common_log("Invalid node id: " + g_opts.node_id)
        raise ValueError("Invalid node id: " + g_opts.node_id)
    if g_opts.running_mode.lower() in [CANTIAND, CANTIAND_WITH_MYSQL, CANTIAND_WITH_MYSQL_ST] and g_opts.node_id == 1:
        print_str_7.common_log("Invalid node id: " + g_opts.node_id + ", this node id can only run in cluster mode")
        raise ValueError("Invalid node id: " + g_opts.node_id + ", this node id can only run in cluster mode")


def check_logfile_path(print_str_7):
    # Check the legitimacy of the path logfile
    if not check_path(g_opts.log_file):
        print_str_7.common_log("Error: There is invalid character in specified log file.")
        raise ValueError("Error: There is invalid character in specified log file.")


def init_start_status_file():
    print_str_7 = CommonPrint()
    try:
        flags = os.O_WRONLY | os.O_TRUNC | os.O_CREAT
        modes = stat.S_IWUSR | stat.S_IRUSR
        start_parameters = {'start_status': 'default', 'db_create_status': 'default', 'ever_started': False}
        with os.fdopen(os.open(CANTIAN_START_STATUS_FILE, flags, modes), 'w') as load_fp:
            json.dump(start_parameters, load_fp)
    except IOError as ex:
        print_str_7.common_log("Error: Can not create or write file: " + CANTIAN_START_STATUS_FILE)
        print_str_7.common_log(str(ex))
        raise ValueError(str(ex)) from ex


def check_log_path():
    if g_opts.log_file:
        g_opts.log_file = os.path.realpath(os.path.normpath(g_opts.log_file))
        base_name = os.path.basename(g_opts.log_file)
        dir_path = os.path.dirname(g_opts.log_file)

        if not os.path.isdir(dir_path):
            g_opts.log_file = ""
            print_str_1 = CommonPrint()
            print_str_1.common_log("Specified log path: \"%s\" does not exist, "
                                   "choose the default path instead." % dir_path)
        elif not base_name:
            g_opts.log_file = ""
            print_str_2 = CommonPrint()
            print_str_2.common_log("Log file does not been specified, "
                                   "choose the default logfile instead.")


def use_default_log_path():
    # The default log is ~/cantian_deploy.log
    if not os.path.exists(CANTIAN_INSTALL_LOG_FILE):
        print_str_1 = CommonPrint()
        print_str_1.common_log("The cantian_deploy.log is not exist.")
        raise ValueError("The cantian_deploy.log is not exist.")
    g_opts.log_file = CANTIAN_INSTALL_LOG_FILE


def log(msg, is_screen=False):
    """
    Print log
    :param msg: log message
    :return: NA
    """
    if is_screen:
        print_str_1 = CommonPrint()
        print_str_1.common_log(msg)
    LOGGER.info(msg)


def log_exit(msg):
    """
    Print log and exit
    :param msg: log message
    :return: NA
    """
    LOGGER.error(msg)
    raise ValueError("Execute cantian_install.py failed")


def cantian_check_share_logic_ip_isvalid(nodeip):
    """
    function: Check the nfs logic ip is valid
    input : ip
    output: NA
    """

    def ping_execute(p_cmd):
        cmd = "%s %s -i 1 -c 3 | grep ttl | wc -l" % (p_cmd, nodeip)
        ret_code, stdout, stderr = _exec_popen(cmd)
        if ret_code or stdout != '3':
            return False
        return True

    log("check nfs logic ip address or domain name.")
    if not ping_execute("ping") and not ping_execute("ping6"):
        log_exit("checked the node IP address or domain name failed: %s" % nodeip)

    log("checked the node IP address or domain name success: %s" % nodeip)


def file_reader(file_path):
    with open(file_path, 'r') as file:
        return file.read()


class Platform(object):
    """
    get dist name/version/id from /etc/*release
    """

    def __init__(self):
        pass

    SUPPORTED_DISTS = ('suse', 'debian', 'fedora', 'redhat', 'centos',
                       'mandrake', 'mandriva', 'rocks', 'slackware',
                       'yellowdog', 'gentoo', 'unitedlinux',
                       'turbolinux', 'arch', 'mageia', 'openeuler',
                       'neokylin', 'euleros', 'kylin')
    UNIXCONFDIR = '/etc'

    @staticmethod
    def _parse_release_file(firstline, version='', dst_id=''):
        """
        function: parse first line of /etc/*release
        input: string
        output: tuple(string, string, string)
        """
        lsb_release_version_re = r'(.+) release ([\d.]+)[^(]*(?:\((.+)\))?'
        release_version_re = (r'([^0-9]+)(?: release )?([\d.]+)[^(]*'
                              r'(?:\((.+)\))?')

        try:
            lsb_release_version = re.compile(lsb_release_version_re,
                                             re.ASCII)
            release_version = re.compile(release_version_re,
                                         re.ASCII)
        except AttributeError:
            lsb_release_version = re.compile(lsb_release_version_re)
            release_version = re.compile(release_version_re)

        # parse the first line
        lsb_matcher = lsb_release_version.match(firstline)
        if lsb_matcher is not None:
            # lsb eg: "distro release x.x (codename)"
            return tuple(lsb_matcher.groups())

        # pre-lsb eg: "distro x.x (codename)"
        pre_lsb_matcher = release_version.match(firstline)
        if pre_lsb_matcher is not None:
            return tuple(pre_lsb_matcher.groups())

        # take the first two words when unknown format
        line_list = firstline.strip().split()
        if line_list:
            version = line_list[0]
            if len(line_list) > 1:
                dst_id = line_list[1]

        return '', version, dst_id

    @staticmethod
    def dist():
        """
        function: obtain the operating system version information from
                  the /etc directory.
        input: NA
        output: distname, version, id
        """
        try:
            # traverse the /etc directory
            etc = os.listdir(Platform.UNIXCONFDIR)
            etc.sort()
        except OSError:
            # Probably not a Unix system
            return "", "", ""

        try:
            release_re = re.compile(r'(\w+)[-_](release|version)', re.ASCII)
        except AttributeError:
            release_re = re.compile(r'(\w+)[-_](release|version)')

        for etc_file in etc:
            tmp_m = release_re.match(etc_file)
            # regular expression matched
            if tmp_m is None:
                continue
            _distname, dummy = tmp_m.groups()

            # read the first line
            try:
                etc_file_name = os.path.join(Platform.UNIXCONFDIR, etc_file)
                flags = os.O_RDONLY
                modes = stat.S_IWUSR | stat.S_IRUSR
                with os.fdopen(os.open(etc_file_name, flags, modes), 'r') as f:
                    firstline = f.readline()
            except Exception as error:
                log("read first line exception: %s." % str(error))
                continue

            # when euler, has centos-release
            if (_distname.lower() == "centos" and
                    _distname.lower() not in firstline.lower()):
                continue

            if _distname.lower() in Platform.SUPPORTED_DISTS:
                distname = _distname
                break
        else:
            _dists_str = ", ".join(Platform.SUPPORTED_DISTS)
            raise Exception("Unsupported OS. Supported only: %s." % _dists_str)

        # get (distname, version, id) from /etc/*release
        _, dist_version, dist_id = Platform._parse_release_file(firstline)

        # _distname is /etc/*release context, distname is file name context
        if not dist_version:
            dist_version = ""
        if not dist_id:
            dist_id = ""

        return distname, dist_version, dist_id


class ParameterContainer(object):
    IFILE = "IFILE"

    def __init__(self):
        self.ifiles = []
        self.parameters = []
        self.map = {}

    def __len__(self):
        return len(self.parameters)

    def __setitem__(self, key, value):
        if key == self.IFILE:
            # Only duplicate IFILE are allowed.
            # But same value of IFILE are not allowed.
            if value in self.ifiles:
                index = self.ifiles.index(value)
                para_index = 0
                for _ in range(index + 1):
                    para_index = self.parameters.index(self.IFILE,
                                                       para_index + 1)
                self.parameters.pop(para_index)
                self.ifiles.pop(index)
            self.parameters.append(key)
            self.ifiles.append(value)
        else:
            # Remove the key-value set before.
            if key in self.parameters:
                self.parameters.remove(key)
            # Record the key-value
            self.parameters.append(key)
            self.map[key] = value

    def __getitem__(self, key):
        if key not in self.parameters:
            raise KeyError(key)
        if key == self.IFILE:
            return self.ifiles
        else:
            return self.map.get(key, "")

    def __contains__(self, item):
        return item in self.parameters

    def keys(self):
        for key in self.parameters:
            yield key

    def items(self):
        index = 0
        for key in self.parameters:
            if key == self.IFILE:
                yield key, self.ifiles[index]
                index += 1
            else:
                yield key, self.map[key]


def skip_execute_in_node_1():
    if g_opts.running_mode in [CANTIAND_IN_CLUSTER, CANTIAND_WITH_MYSQL_IN_CLUSTER] and g_opts.node_id == 1:
        return True
    return False


def create_dir_if_needed(condition, directory_addr):
    if condition:
        return
    os.makedirs(dir, CommonValue.KEY_DIRECTORY_PERMISSION)


class Installer:
    """ This is Cantiand installer. """

    # Defining a constant identifies which step the installer failed to take.
    # For roll back.
    failed_init = "0"
    DECOMPRESS_BIN_FAILED = "1"
    SET_ENV_FAILED = "2"
    PRE_DATA_DIR_FAILED = "3"
    INIT_DB_FAILED = "4"
    CREATE_DB_FAILED = "5"
    # Define the installation mode constant identifier
    INS_ALL = "all"
    INS_PROGRAM = "program"
    # Record the steps for the current operation to fail
    failed_pos = failed_init
    # Record running version number information
    # Initial value is "CANTIANDB100-V300R001C00-RUN"
    RUN_VERSION_A = "Cantian-RUN"

    # other version: CantianDB_100
    RUN_VERSION_B = "CantianDB_100_1.0.0-RUN"

    # start mode
    NOMOUNT_MODE = "nomount"
    MOUNT_MODE = "mount"
    OPEN_MODE = "open"
    # configure file
    CANTIAND_CONF_FILE = "cantiand.ini"
    CTSQL_CONF_FILE = "ctsql.ini"
    CMS_CONF_FILE = "cms.ini"
    CLUSTER_CONF_FILE = "cluster.ini"
    CANTIAND_HBA_FILE = "cthba.conf"
    DEFAULT_INSTANCE_NAME = "cantian"
    # backup cantiand install log dir
    backup_log_dir = ""

    login_ip = ""
    ipv_type = "ipv4"

    def __init__(self, user, group):
        """ Constructor for the Installer class. """
        log("Begin init...")
        log("Installer runs on python version : " + gPyVersion)

        os.umask(0o27)

        # User
        self.user = user
        # Sysdba login enabled by default
        self.enable_sysdba_login = False
        # Group
        self.group = group
        self.user_info = "%s:%s" % (self.user, self.group)
        # Install path
        self.install_path = ""
        # Option for installing program only or all.
        self.option = "program"
        self.flag_option = 0
        # old pgdata path
        self.old_data_path = ""
        # Data path
        self.data = ""
        # gcc home path
        self.gcc_home = ""
        # DB config parameters
        self.cantiand_configs = {}
        self.cms_configs = {}
        self.gss_configs = {}
        self.dn_conf_dict = ParameterContainer()
        # run file
        self.run_file = ""
        # run package name
        self.run_pkg_name = ""
        # run MDf file
        self.run_sha256_file = ""

        self.login_ip = "127.0.0.1"
        self.lsnr_addr = ""
        self.lsnr_port = 1611
        self.instance_name = self.DEFAULT_INSTANCE_NAME

        self.user_home_path = ""
        # dir path
        self.dir_name = ""
        self.pid = 0

        # create database sql that user specify
        self.create_db_file = ""

        # user profile
        self.user_profile = ""
        # flag for creating program dir
        self.is_mkdir_prog = False
        # flag for creating data dir
        self.is_mkdir_data = False

        # flag for close ssl
        self.close_ssl = False
        self.ssl_path = ""
        # REPL_AUTH
        self.repl_auth = False
        # REPL_SCRAM_AUTH
        self.repl_scram_auth = True
        # ENABLE_ACCESS_DC
        self.enable_access_dc = False

        # replace_password_verify
        self.replace_password_verify = True

        # The running mode
        self.running_mode = ""

        # log dirs
        self.backup_log_dir = ""
        self.status_log = ""

        self.factor_key = ""

        self.ctsql_conf = {}

        log("End init")

    @staticmethod
    def set_sql_redo_size_and_num(db_data_path, create_database_sql):
        """
        开源场景纯file部署，redo size和num用户可配置
        """
        redo_num = int(get_value("redo_num"))
        redo_size = get_value("redo_size")
        sql_file = os.path.join(db_data_path, create_database_sql)
        with open(sql_file, "r") as file:
            sql_content = file.read()
        pattern = r"logfile (\(.*\n{0,}.*\))"
        replace_content = re.findall(pattern, sql_content)
        for item in replace_content:
            sql_content = sql_content.replace(item, "(%s)")
        s = []
        for i in range(1, redo_num * 2 + 1):
            redo_index = "{:02d}".format(i)
            if i == 10:
                redo_index = "0a"
            s.append("'dbfiles3/redo%s.dat' size %s" % (redo_index, redo_size))
        node0_redo = ", ".join(s[:redo_num])
        node1_redo = ", ".join(s[redo_num:])
        data = sql_content % (node0_redo, node1_redo)
        modes = stat.S_IWRITE | stat.S_IRUSR
        flags = os.O_WRONLY | os.O_TRUNC | os.O_CREAT
        with os.fdopen(os.open(sql_file, flags, modes), 'w', encoding='utf-8') as file:
            file.write(data)

    def get_decompress_tarname(self, tar_file):
        '''
        decompress a.tar.gz, then get file name
        :return:
        '''
        # get real directory name in tar file
        tars = tarfile.open(tar_file)
        basename = tars.getnames()[0]
        tars.close()
        return basename

    def is_readable(self, file_name, user):
        '''
        :param path:
        :param user:
        :return:
        '''
        user_info = pwd.getpwnam(user)
        uid = user_info.pw_uid
        gid = user_info.pw_gid
        s = os.stat(file_name)
        mode = s[stat.ST_MODE]
        return (
                ((s[stat.ST_UID] == uid) and (mode & stat.S_IRUSR > 0)) or
                ((s[stat.ST_GID] == gid) and (mode & stat.S_IRGRP > 0)) or
                (mode & stat.S_IROTH > 0)
        )

    def check_createdb_file(self):
        '''
        check it is a file; user has read permission,
        :return:
        '''
        # check -f parameter
        if self.option != self.INS_ALL:
            raise Exception("Error: -f parameter should be used without"
                            " -O parameter ")
        # check it is a file
        if not os.path.isfile(self.create_db_file):
            raise Exception("Error: %s does not exists or is not a file"
                            " or permission is not right."
                            % self.create_db_file)
        if not check_path(self.create_db_file):
            raise Exception("Error: %s file path invalid: "
                            % self.create_db_file)
        # if execute user is root, check common user has read permission
        file_path = os.path.dirname(self.create_db_file)

        # check path of create db sql file that user can cd
        permission_ok, _ = self.check_permission(file_path, True)
        if not permission_ok:
            raise Exception("Error: %s can not access %s"
                            % (self.user, file_path))

        # check create db file is readable for user
        if not self.is_readable(self.create_db_file, self.user):
            raise Exception("Error: %s is not readable for user %s"
                            % (self.create_db_file, self.user))
        # change file to a realpath file
        self.create_db_file = os.path.realpath(self.create_db_file)

    def parse_default_config(self):
        """
        Parse cantiand, cms, gss default config
        :return: cantiand config, cms config, gss config
        """
        # 获取默认值
        if g_opts.running_mode in [CANTIAND, CANTIAND_WITH_MYSQL, CANTIAND_WITH_MYSQL_ST]:
            self.cantiand_configs = SingleNodeConfig.get_config(g_opts.cantian_in_container)
        if g_opts.running_mode in [CANTIAND_IN_CLUSTER, CANTIAND_WITH_MYSQL_IN_CLUSTER] and g_opts.node_id == 0:
            self.cantiand_configs = ClusterNode0Config.get_config(g_opts.cantian_in_container)
        if g_opts.running_mode in [CANTIAND_IN_CLUSTER, CANTIAND_WITH_MYSQL_IN_CLUSTER] and g_opts.node_id == 1:
            self.cantiand_configs = ClusterNode1Config.get_config(g_opts.cantian_in_container)

    def check_parameter(self):
        """
        Detect the legality of input parameters,
        and return process if not legal.
        :return: NA
        """
        log("Checking parameters.")
        self.parse_default_config()
        self.parse_key_and_value()
        if len(self.cantiand_configs.get("INTERCONNECT_ADDR")) == 0:
            log_exit("Database INTERCONNECT_ADDR must input, need -Z parameter.")
        # Check database user
        if g_opts.db_user and g_opts.db_user.lower() != "sys":
            log_exit("Database connector's name must be [sys].")
        if not self.install_path:
            log_exit("Parameter input error, need -R parameter.")
        self.install_path = os.path.normpath(self.install_path)
        if not self.data:
            log_exit("Parameter input error, need -D parameter.")
        self.data = os.path.normpath(self.data)
        # Check user
        if not self.user:
            log_exit("Parameter input error, need -U parameter.")
        os.environ['cantiand_user'] = str(self.user)
        # User must be exist.
        str_cmd = "id -u ${cantiand_user}"
        ret_code, stdout, stderr = _exec_popen(str_cmd)
        if ret_code:
            log_exit("%s : no such user, command: %s"
                     "ret_code : %s, stdout : %s, stderr : %s" % (self.user, str_cmd, ret_code, stdout, stderr))
        if self.option == self.INS_ALL:
            # App data and inst data can't be the same one.
            if self.install_path == self.data:
                log_exit("Program path should not equal to data path!")
            elif self.install_path.find(self.data + os.sep) == 0:
                log_exit("Can not install program under data path!")
            elif self.data.find(self.install_path + os.sep) == 0:
                log_exit("Can not install data under program path!")
            else:
                log("Program path is separated with data path!")
        # Check the app path
        real_path = os.path.realpath(self.install_path)
        if not check_path(real_path):
            log_exit("Install program path invalid: " + self.install_path)
        # Check the data path
        real_path = os.path.realpath(self.data)
        if not check_path(real_path):
            log_exit("Install data path invalid: " + self.data)
        if len(self.cantiand_configs.get("LOG_HOME")) == 0:
            self.cantiand_configs["LOG_HOME"] = os.path.join(self.data, "log")
        if len(self.cantiand_configs.get("SHARED_PATH")) == 0:
            self.cantiand_configs["SHARED_PATH"] = os.path.join(self.data, "data")
        self.cantiand_configs["ARCHIVE_DEST_1"] = g_opts.archive_location
        self.cantiand_configs["MAX_ARCH_FILES_SIZE"] = g_opts.max_arch_files_size
        self.cantiand_configs["CLUSTER_ID"] = g_opts.cluster_id
        self.add_config_for_dbstore()
        self.ssl_path = os.path.join(self.install_path, "sslkeys")
        self.show_parse_result()

    def show_parse_result(self):
        # Print the result of parse.
        log("Using %s:%s to install database" % (self.user, self.group))
        log("Using install program path : %s" % self.install_path)
        log("Using option : " + self.option)
        log("Using install data path : %s" % self.data)

        conf_parameters = copy.deepcopy(self.cantiand_configs)
        for key in conf_parameters.keys():
            # Ignore the values of some parameters. For example,
            # _SYS_PASSWORD and SSL_KEY_PASSWORD.
            if key.endswith("PASSWORD") or key.endswith("PASSWD"):
                conf_parameters[key] = "*"
            elif key.endswith("KEY") and key != "SSL_KEY":
                conf_parameters[key] = "*"
        log("Using set cantiand config parameters : " + str(conf_parameters))
        log("End check parameters.")

    def add_config_for_dbstore(self):
        self.cantiand_configs["CONTROL_FILES"] = "{0}, {1}, {2}".format(os.path.join(self.data, "data/ctrl1"),
                                                                        os.path.join(self.data, "data/ctrl2"),
                                                                        os.path.join(self.data, "data/ctrl3"))
        if g_opts.use_dbstor:
            self.cantiand_configs["CONTROL_FILES"] = "(-ctrl1, -ctrl2, -ctrl3)"
            self.cantiand_configs["SHARED_PATH"] = "-"
            self.cantiand_configs["ENABLE_DBSTOR"] = "TRUE"
            self.cantiand_configs["DBSTOR_NAMESPACE"] = g_opts.namespace
        else:
            self.cantiand_configs["ENABLE_DBSTOR"] = "FALSE"
            self.cantiand_configs["SHARED_PATH"] = \
                '/mnt/dbdata/remote/storage_{}/data'.format(g_opts.storage_dbstore_fs)

    def parse_key_and_value(self):
        flags = os.O_RDONLY
        modes = stat.S_IWUSR | stat.S_IRUSR
        with os.fdopen(os.open(CONFIG_PARAMS_FILE, flags, modes), 'r') as fp:
            json_data = json.load(fp)
            _value = json_data.get('cms_ip', '0').strip()
            self.cantiand_configs['INTERCONNECT_ADDR'] = _value
            node_addr = _value.split(";")[g_opts.node_id]
            self.cantiand_configs['LSNR_ADDR'] += "," + node_addr
            _value = json_data.get('mysql_metadata_in_cantian', 'True')
            self.cantiand_configs['MYSQL_METADATA_IN_CANTIAN'] = str(_value).upper()

        flags = os.O_RDONLY
        modes = stat.S_IWUSR | stat.S_IRUSR
        with os.fdopen(os.open(JS_CONF_FILE, flags, modes), 'r') as fp:
            json_data = json.load(fp)
            self.install_path = json_data['R_INSTALL_PATH'].strip()  # -R
            self.data = json_data['D_DATA_PATH'].strip()  # -D
            self.option = self.INS_ALL
            for tmp_num in range(100):
                tmp_word = 'Z_KERNEL_PARAMETER' + str(tmp_num)
                if json_data.get(tmp_word, '') != '':
                    _value = json_data.get(tmp_word, '').strip().split('=')
                    self.cantiand_configs[_value[0].strip().upper()] = _value[1].strip()
            if g_opts.password:
                self.cantiand_configs["_SYS_PASSWORD"] = g_opts.password
            if g_opts.cert_encrypt_pwd:
                self.cantiand_configs["MES_SSL_KEY_PWD"] = g_opts.cert_encrypt_pwd
            self.close_ssl = True

    def check_runner(self):
        """
        The user currently running the script must be root or in root group,
        if not exit.
        :return: NA
        """

        log("Checking runner.")
        gid = os.getgid()
        uid = os.getuid()
        log("Check runner user id and group id is : %s, %s"
            % (str(uid), str(gid)))
        if (gid != 0 and uid != 0):
            log_exit("Only user with root privilege can run this script")

        log("End check runner is root")

    def chown_log_file(self):
        """
        chmod and chown log file
        :return:
        """
        try:
            if os.path.exists(g_opts.log_file):
                uid = pwd.getpwnam(self.user).pw_uid
                gid = grp.getgrnam(self.group).gr_gid
                os.chown(g_opts.log_file, uid, gid)
        except Exception as ex:
            log_exit("Can not change log file's owner. Output:%s" % str(ex))

    def chown_data_dir(self):
        """
        chown data and gcc dirs
        :return:
        """
        cmd = "chown %s:%s -hR \"%s\";" % (self.user, self.group, self.data)
        log("Change owner cmd: %s" % cmd)
        ret_code, _, stderr = _exec_popen(cmd)
        if ret_code:
            raise Exception(
                "chown to %s:%s return: %s%s%s" % (self.user, self.group, str(ret_code), os.linesep, stderr))

    ###########################################################################
    # Is there a database installed by the user? If right, raise error
    # and exit. Because each user is only allowed install one database by
    # this script.
    ###########################################################################
    def check_old_install(self):
        """
        Is there a database installed by the user?
        :return: NA
        """

        log("Checking old install.")

        # Check $CTDB_HOME.
        str_cmd = "echo ~"
        ret_code, stdout, stderr = _exec_popen(str_cmd)
        if ret_code:
            log_exit("Can not get user home."
                     "ret_code : %s, stdout : %s, stderr : %s" % (ret_code, stdout, stderr))
        # Get the profile of user.
        output = os.path.realpath(os.path.normpath(stdout))
        if (not check_path(output)):
            log_exit("The user home directory is invalid.")
        self.user_profile = os.path.join(output, ".bashrc")
        self.user_home_path = output
        log("Using user profile : " + self.user_profile)

        is_find = False
        try:
            flags = os.O_RDONLY
            modes = stat.S_IWUSR | stat.S_IRUSR
            with os.fdopen(os.open(self.user_profile, flags, modes), 'r') as _file:
                is_find = self.dealwith_gsdb(is_find, _file)
        except IOError as ex:
            log_exit("Can not read user profile: " + str(ex))
        except IndexError as ex:
            log_exit("Failed to read user profile: %s" % str(ex))

        if is_find:
            log_exit("Database has been installed already.")

        log("End check old install.")

    def dealwith_gsdb(self, is_find, _file):
        while True:
            str_line = _file.readline()
            if (not str_line):
                break
            str_line = str_line.strip()
            if (str_line.startswith("#")):
                continue
            user_info = str_line.split()
            self.dealwith_gsdb_data(user_info, str_line)
            if (len(user_info) >= 2 and user_info[0] == "export"
                    and user_info[1].startswith("CTDB_HOME_BAK=") > 0):
                is_find = True
                break
            else:
                continue
        return is_find

    def dealwith_gsdb_data(self, user_info, str_line):
        # deal with the CTDB_DATA with """
        if (len(user_info) >= 2 and user_info[0] == "export"
                and user_info[1].startswith('CTDB_DATA="') > 0):
            self.old_data_path = str_line[str_line.find("=") + 2:-1]
            self.old_data_path = os.path.normpath(self.old_data_path)
            real_path = os.path.realpath(self.old_data_path)
            if not check_path(real_path):
                log_exit("The Path specified by CTDB_DATA is invalid.")
            log("Old data path: " + self.old_data_path)
            if self.option == self.INS_ALL and self.old_data_path != self.data:
                log_exit("User CTDB_DATA is different from -D parameter value")
        # deal with the CTDB_DATA path without """
        elif (len(user_info) >= 2 and user_info[0] == "export"
              and user_info[1].startswith("CTDB_DATA=") > 0):
            self.old_data_path = str_line[str_line.find("=") + 1:]
            self.old_data_path = os.path.normpath(self.old_data_path)
            real_path = os.path.realpath(self.old_data_path)
            if (not check_path(real_path)):
                log_exit("The Path specified by CTDB_DATA is invalid.")
            log("Old data path: " + self.old_data_path)
            if self.option == self.INS_ALL and self.old_data_path != self.data:
                log_exit("User CTDB_DATA is different from -D parameter value")

    def check_permission(self, original_path, check_enter_only=False):
        """
        function:
            check if given user has operation permission for given path
        precondition:
            1.user should be exist
            2.original_path should be an absolute path
            3.caller should has root privilege
        postcondition:
            1.return True or False
        input : original_path,check_enter_only
        output: True/False
        """
        # check the user has enter the directory permission or not
        cmd = "cd %s" % original_path
        status, _, stderr = _exec_popen(cmd)
        if status:
            return False, stderr

        if check_enter_only:
            return True, ""

        # check the user has write permission or not
        test_file = os.path.join(original_path, "touch.tst")
        cmd = ("touch %s && chmod %s %s "
               % (test_file, CommonValue.KEY_FILE_MODE, test_file))

        status, _, stderr = _exec_popen(cmd)
        if status != 0:
            return False, stderr

        cmd = "echo aaa > %s " % test_file
        # delete tmp file
        status, _, stderr = _exec_popen(cmd)
        if status != 0:
            cmd = "rm -f %s " % test_file
            _exec_popen(cmd)
            return False, stderr

        cmd = "rm -f %s " % test_file
        status, _, stderr = _exec_popen(cmd)
        if status != 0:
            return False, stderr

        return True, ""

    ########################################################################
    # Check if the port is used in the installation parameters, and exit
    # if the port is used.
    ########################################################################
    def check_port(self, value):
        """
        Check if the port is used in the installation parameters, and exit
        if the port is used.
        :param value: port
        :return: NA
        """
        # the value can't be empty and must be a digit.
        # the value must > 1023 and <= 65535
        time_out, inner_port = self.check_inner_port(value)

        # Get the sokcet object
        if self.ipv_type == "ipv6":
            sk = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
            sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Test the socket connection.
        sk.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sk.settimeout(time_out)

        try:
            sk.bind((self.login_ip, inner_port))
            sk.close()
        except socket.error as error:
            sk.close()
            if gPyVersion >= PYTHON242:
                try:
                    # 98: Address already in use
                    # 95: Operation not supported
                    # 13: Permission denied
                    if (int(error.errno) == 98 or int(error.errno) == 95
                            or int(error.errno) == 13):
                        log("Error: port %s has been used,the detail"
                            " information is as follows:" % value)
                        str_cmd = "netstat -unltp | grep %s" % value
                        ret_code, stdout, stderr = _exec_popen(str_cmd)
                        if ret_code:
                            log_exit("can not get detail information of the"
                                     " port, command: %s."
                                     "ret_code : %s, stdout : %s, stderr : %s" % (str_cmd, ret_code, stdout, stderr))
                        log_exit(str(stdout))
                except ValueError as ex:
                    log_exit("check port failed: " + str(ex))
            else:
                log_exit("This install script can not support python version"
                         " : " + gPyVersion)

    def check_inner_port(self, value):
        time_out = 2
        if not value:
            log_exit("the number of port is null.")
        if not value.isdigit():
            log_exit("illegal number of port.")
        try:
            inner_port = int(value)
            if inner_port < 0 or inner_port > 65535:
                log_exit("illegal number of port.")
            if inner_port >= 0 and inner_port <= 1023:
                log_exit("system reserve port.")
        except ValueError as ex:
            log_exit("check port failed: " + str(ex))
        return time_out, inner_port

    #########################################################################
    # Check if the port is used in the installation parameters, and exit
    # if the port is used.
    #########################################################################
    def check_ip_is_vaild(self, node_ip):
        """
        function: Check the ip is valid
        input : ip
        output: NA
        """
        log("check the node IP address.")
        try:
            socket.inet_aton(node_ip)
            self.ipv_type = "ipv4"
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, node_ip)
                self.ipv_type = "ipv6"
            except socket.error:
                log_exit("The invalid IP address : %s is not ipv4 or ipv6 format." % node_ip)

        if self.ipv_type == "ipv6":
            ping_cmd = "ping6"
        else:
            ping_cmd = "ping"
        # use ping command to check the the ip, if no package lost,
        # the ip is valid
        cmd = "%s %s -i 1 -c 3 | grep ttl | wc -l" % (ping_cmd, node_ip)
        ret_code, stdout, stderr = _exec_popen(cmd)

        if ret_code or stdout != '3':
            log_exit("The invalid IP address is %s. "
                     "ret_code : %s, stdout : %s, stderr : %s" % (node_ip, ret_code, stdout, stderr))

        if all_zero_addr_after_ping(node_ip):
            ip_is_found = 1
        elif len(node_ip) != 0:
            ip_cmd = "/usr/sbin/ip addr | grep -w %s | wc -l" % node_ip
            ret_code, ip_is_found, stderr = _exec_popen(ip_cmd)
        else:
            ip_is_found = 0

        if ret_code or not int(ip_is_found):
            log_exit("The invalid IP address is %s. "
                     "ret_code : %s, ip_is_found : %s, stderr : %s" % (node_ip, ret_code, ip_is_found, stderr))

        log("checked the node IP address : %s" % node_ip)

    #########################################################################
    # Check the operating system kernel parameters and exit if they do
    # not meet the requirements of the database。
    #########################################################################
    def set_numa_config(self):
        if not os.path.exists('/usr/bin/lscpu'):
            log("Warning: lscpu path get error")
            return

        ret_code, result, stderr = _exec_popen('/usr/bin/lscpu | grep -i "NUMA node(s)"')
        if ret_code:
            log_exit("can not get numa node parameters, err: %s" % stderr)
        _result = result.strip().split(':')

        if len(_result) != 2:
            log("Warning: numa get error, result:%s" % result)
            return

        numa_num = 0
        numa_info = ""
        # 容器mysql实例支持最大个数12
        numa_cpu_num = 6
        # 判断_result[1].strip()
        if not _result[1].strip().isdigit():
            log("Warning: numa(s) size get error, result:%s" % result)
            return
        while numa_num < int(_result[1].strip()):
            err_code, ans, err_msg = _exec_popen('/usr/bin/lscpu | grep -i "NUMA node%s"' % numa_num)
            _ans = ans.strip().split(':')
            if len(_ans) != 2:
                log("Warning: numa node get error, ans:%s" % ans)
                return
            numa_str = _ans[1].strip()
            if platform.machine() == 'aarch64' and numa_num == 0:
                numa_id_str = _ans[1].strip().split('-')
                last_numa_id = numa_id_str[-1]
                if int(last_numa_id) >= 16:
                    numa_str = "0-1,6-11,16-" + str(last_numa_id)
            numa_info += numa_str + " "
            numa_num += 1

        if not numa_info.isspace():
            shm_mysql_cpu_group_info = (numa_info[:-1] + ";") * numa_cpu_num
            self.cantiand_configs["SHM_MYSQL_CPU_GROUP_INFO"] = shm_mysql_cpu_group_info[:-1]
            self.cantiand_configs["SHM_CPU_GROUP_INFO"] = numa_info

    def check_config_options(self):
        """
        Check the operating system kernel parameters and exit if they do
        not meet the requirements of the database。
        :return: NA
        """
        log("Checking kernel parameters.")
        # GB MB kB
        tmp_gb = 1024 * 1024 * 1024
        tmp_mb = 1024 * 1024
        tmp_kb = 1024
        # The size of database
        log_buffer_size = 4 * tmp_mb
        shared_pool_size = 128 * tmp_mb
        data_buffer_size = 128 * tmp_mb
        temp_buffer_size = 32 * tmp_mb
        sga_buff_size = (log_buffer_size + shared_pool_size + data_buffer_size
                         + temp_buffer_size)

        self.set_numa_config()
        # parse the value of kernel parameters
        for key, value in self.cantiand_configs.items():
            if not isinstance(value, str):
                value = str(value)
                self.cantiand_configs[key] = value
            try:
                check_kernel_parameter(key)
                check_invalid_symbol(value)
                # Unit conversion
                get_unit_conversion_info = UnitConversionInfo(tmp_gb, tmp_mb, tmp_kb, key, value,
                                                              sga_buff_size, temp_buffer_size, data_buffer_size,
                                                              shared_pool_size, log_buffer_size)
                sga_buff_size = self.do_unit_conversion(get_unit_conversion_info)
            except ValueError as ex:
                log_exit("check kernel parameter failed: " + str(ex))

        if self.lsnr_addr != "":
            _list = self.lsnr_addr.split(",")
            # Check the ip address
            for item in _list:
                if len(_list) != 1 and all_zero_addr_after_ping(item):
                    log_exit("lsnr_addr contains all-zero ip,"
                             " can not specify other ip.")
                self.check_ip_is_vaild(item)
        else:
            # If this parameter is empty, the IPv4 is used by default.
            # The default IP address is 127.0.0.1
            self.lsnr_addr = "127.0.0.1"
        self.check_sga_buff_size(sga_buff_size, tmp_mb, tmp_kb)

    def check_sga_buff_size(self, sga_buff_size, tmp_mb, tmp_kb):
        """
        check sga buffer size
        :param sga_buff_size:
        :param MB:
        :param KB:
        :return:
        """
        self.login_ip = self.lsnr_addr.split(",")[0]
        self.check_port(self.lsnr_port)
        self.lsnr_port = int(self.lsnr_port)
        # check sga_buff_size
        cmd = ("cat /proc/meminfo  |grep -wE 'MemFree:|Buffers:|Cached:"
               "|SwapCached' |awk '{sum += $2};END {print sum}'")
        ret_code, cur_avi_memory, stderr = _exec_popen(cmd)
        if ret_code:
            log_exit("can not get shmmax parameters, command: %s, err: %s" % (cmd, stderr))
        if sga_buff_size < 114 * tmp_mb:
            log_exit("sga_buff_size should bigger than or equal to 114*MB,"
                     " please check it!")
        try:
            if sga_buff_size > int(cur_avi_memory) * tmp_kb:
                log_exit("sga_buff_size should smaller than shmmax,"
                         " please check it!")
        except ValueError as ex:
            log_exit("check kernel parameter failed: " + str(ex))

        log("End check kernel parameters")

    @staticmethod
    def check_pare_bool_value(key, value):
        """Check the bool value and return it."""
        value = value.upper()
        if value == "TRUE":
            return True
        elif value == "FALSE":
            return False
        else:
            raise ValueError("The value of %s must in [True, False]." % key)

    @staticmethod
    def kmc_resovle_password(mode, plain_text):
        primary_keystore = DefaultConfigValue.PRIMARY_KEYSTORE
        standby_keystore = DefaultConfigValue.STANDBY_KEYSTORE
        kmc_adapter = CApiWrapper(primary_keystore, standby_keystore)
        kmc_adapter.initialize()
        try:
            if mode == "encrypted":
                ret_pwd = kmc_adapter.encrypt(plain_text)
            if mode == "decrypted":
                ret_pwd = kmc_adapter.decrypt(plain_text)
        except Exception as error:
            raise Exception("Failed to %s password of user [sys]. Error: %s" % (mode, str(error))) from error

        split_env = os.environ['LD_LIBRARY_PATH'].split(":")
        filtered_env = [single_env for single_env in split_env if "/opt/cantian/dbstor/lib" not in single_env]
        os.environ['LD_LIBRARY_PATH'] = ":".join(filtered_env)

        return ret_pwd

    @staticmethod
    def decrypt_db_passwd():
        file_list = glob.glob(CTSQL_INI_FILE)
        ctsql_ini_data = file_reader(file_list[0])
        encrypt_pwd = ctsql_ini_data[ctsql_ini_data.find('=') + 1:].strip()
        mode = "decrypted"
        g_opts.db_passwd = Installer.kmc_resovle_password(mode, encrypt_pwd)

    @staticmethod
    def set_cms_ini(passwd):
        cms_conf = "/opt/cantian/cms/cfg/cms.ini"
        str_cmd = f"sed -i '/_CMS_MES_SSL_KEY_PWD = None/d' {cms_conf}" \
                  f"&& echo '_CMS_MES_SSL_KEY_PWD = {passwd}' >> {cms_conf}"
        log("Copy config files cmd: " + str_cmd)
        ret_code, _, stderr = _exec_popen(str_cmd)
        if ret_code:
            log_exit("update cms.ini failed: " + str(ret_code) + os.linesep + stderr)

    def init_specify_kernel_para(self, key, value):
        """get the value of some kernel parameters."""
        if key == "LSNR_ADDR":
            self.lsnr_addr = value
        elif key == "INSTANCE_NAME":
            self.instance_name = value
        elif key == "LSNR_PORT":
            self.lsnr_port = value
        elif key == "ENABLE_SYSDBA_LOGIN":
            self.enable_sysdba_login = Installer.check_pare_bool_value(
                key, value)
        elif key == "REPL_AUTH":
            self.repl_auth = Installer.check_pare_bool_value(
                key, value)
        elif key == "REPL_SCRAM_AUTH":
            self.repl_scram_auth = Installer.check_pare_bool_value(
                key, value)
        elif key == "ENABLE_ACCESS_DC":
            self.enable_access_dc = Installer.check_pare_bool_value(
                key, value)
        elif key == "REPLACE_VERIFY_PASSWORD":
            self.replace_password_verify = Installer.check_pare_bool_value(
                key, value)
        else:
            return

    def do_unit_conversion(self, get_unit_conversion_info):
        tmp_gb, tmp_mb, tmp_kb, key, value, \
            sga_buff_size, temp_buffer_size, data_buffer_size, \
            shared_pool_size, log_buffer_size = get_unit_conversion_info
        if key in ["TEMP_BUFFER_SIZE", "DATA_BUFFER_SIZE",
                   "SHARED_POOL_SIZE", "LOG_BUFFER_SIZE"]:
            if value[0:-1].isdigit() and value[-1:] in ["G", "M", "K"]:
                unit_map = {
                    "G": tmp_gb,
                    "M": tmp_mb,
                    "K": tmp_kb,
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

        self.init_specify_kernel_para(key, value)
        return sga_buff_size

    def change_app_permission(self):
        """
        function: after decompression install package, change file permission
        input : NA
        output: NA
        """
        # change install path privilege to 700
        str_cmd = "chmod %s %s -R" % (CommonValue.KEY_DIRECTORY_MODE,
                                      self.install_path)
        # chmod add-ons/ file 500
        str_cmd += ("&& find '%s'/add-ons -type f | xargs chmod %s "
                    % (self.install_path, CommonValue.MID_FILE_MODE))
        # chmod admin/ file 600
        str_cmd += ("&& find '%s'/admin -type f | xargs chmod %s "
                    % (self.install_path, CommonValue.KEY_FILE_MODE))
        # chmod admin/scripts/fetch_cls_stat.py file 550
        str_cmd += ("&& find '%s'/admin -type f | grep fetch_cls_stat.py | xargs chmod %s "
                    % (self.install_path, CommonValue.MAX_FILE_MODE))
        # chmod lib/ file 500
        str_cmd += ("&& find '%s'/lib -type f | xargs chmod %s"
                    % (self.install_path, CommonValue.MID_FILE_MODE))
        # chmod bin/ file 500
        str_cmd += ("&& find '%s'/bin -type f | xargs chmod %s "
                    % (self.install_path, CommonValue.MID_FILE_MODE))
        str_cmd += ("&& find '%s'/cfg -type f | xargs chmod %s "
                    % (self.install_path, CommonValue.KEY_FILE_MODE))
        package_xml = os.path.join(self.install_path, "package.xml")
        if os.path.exists(package_xml):
            str_cmd += ("&& chmod %s '%s'/package.xml"
                        % (CommonValue.MIN_FILE_MODE, self.install_path))

        log("Change app permission cmd: %s" % str_cmd)
        ret_code, _, stderr = _exec_popen(str_cmd)
        if ret_code:
            self.failed_pos = self.DECOMPRESS_BIN_FAILED
            log_exit("chmod %s return: " % CommonValue.KEY_DIRECTORY_MODE
                     + str(ret_code) + os.linesep + stderr)
        # 管控面使用
        str_cmd = "chmod %s %s " % (CommonValue.MAX_DIRECTORY_MODE,
                                    self.install_path)
        str_cmd += "&& chmod %s %s " % (CommonValue.MAX_DIRECTORY_MODE,
                                        os.path.join(self.install_path, "admin"))
        str_cmd += "&& chmod %s %s" % (CommonValue.MAX_DIRECTORY_MODE,
                                       os.path.join(self.install_path, "admin", "scripts"))
        log("Change app server/admin/scripts dir for om. cmd: %s" % str_cmd)
        ret_code, _, stderr = _exec_popen(str_cmd)
        if ret_code:
            self.failed_pos = self.DECOMPRESS_BIN_FAILED
            log_exit("chmod %s return: " % CommonValue.KEY_DIRECTORY_MODE
                     + str(ret_code) + os.linesep + stderr)

    def verify_new_passwd(self, passwd, shortest_len):
        """
        Verify new password.
        :return: NA
        """
        # eg 'length in [8-64]'
        if len(passwd) < shortest_len or len(passwd) > 64:
            raise ValueError("The length of password must be %s to 64."
                             % shortest_len)

        # Can't save with user name
        if passwd == self.user:
            raise ValueError("Error: Password can't be the same as username.")
        elif passwd == self.user[::-1]:
            raise ValueError("Error: Password cannot be the same as username "
                             "in reverse order")

        upper_cases = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        lower_cases = set("abcdefghijklmnopqrstuvwxyz")
        digits = set("1234567890")
        special_cases = set(r"""`~!@#$%^&*()-_=+\|[{}]:'",<.>/? """)

        # Contains at least three different types of characters
        types = 0
        passwd_set = set(passwd)
        for cases in [upper_cases, lower_cases, digits, special_cases]:
            if passwd_set & cases:
                types += 1
        if types < 3:
            raise ValueError("Error: Password must contains at least three"
                             " different types of characters.")

        # Only can contains enumerated cases
        all_cases = upper_cases | lower_cases | digits | special_cases
        un_cases = passwd_set - all_cases
        if un_cases:
            raise ValueError("Error: There are characters that are not"
                             " allowed in the password: '%s'"
                             % "".join(un_cases))

    def get_new_passwd(self, pw_prompt, user_prompt, shortest_len):
        """Get new passwd"""
        for _ in range(3):
            print_str_1 = CommonPrint()
            print_str_1.common_log("Please enter %s of %s: " % (pw_prompt, user_prompt))
            new_passwd = getpass.getpass()
            try:
                self.verify_new_passwd(new_passwd, shortest_len)
            except ValueError as error:
                print_str_2 = CommonPrint()
                print_str_2.common_log(str(error))
                continue

            print_str_3 = CommonPrint()
            print_str_3.common_log("Please enter %s of %s again: " % (pw_prompt, user_prompt))
            new_passwd2 = getpass.getpass()

            if new_passwd == new_passwd2:
                break
            print_str_3.common_log("Passwd not match.")
        else:
            raise ValueError("Failed to get new %s." % pw_prompt)

        if new_passwd:
            return new_passwd
        else:
            raise ValueError("Failed to get new %s." % pw_prompt)

    def check_sys_passwd(self):
        """
        Whether the password of the sys user has been specified. If not, raise
        :return: NA
        """
        # 0. "_SYS_PASSWORD" can't be set when ENABLE_SYSDBA_LOGIN is False
        sys_password = self.cantiand_configs["_SYS_PASSWORD"]
        if not self.enable_sysdba_login and len(sys_password) != 0:
            raise ValueError("Can't use _SYS_PASSWORD to set the password of "
                             "user [SYS] in the installation script when "
                             "ENABLE_SYSDBA_LOGIN is False.")

        # 1. Get passed from parameter -C
        # Set passwd of SYS in cantiand.ini by parameter -C
        if len(sys_password) != 0:
            return

        # 2. Get passwd from pipe and interactive input
        if sys.stdin.isatty():
            # If not pipe content, get passwd by interactive input
            g_opts.db_passwd = self.get_new_passwd(
                pw_prompt="database password",
                user_prompt="user [SYS]",
                shortest_len=8)
        else:
            try:
                # Get passwd from pipe
                g_opts.db_passwd = _get_input("")
            except EOFError as error:
                # Not find passwd from pipe
                raise ValueError("The content got from pipe not find passwd.") from error
            self.verify_new_passwd(g_opts.db_passwd, 8)

    def install_xnet_lib(self):
        if is_rdma_startup():
            str_cmd = "cp -rf %s/add-ons/mlnx/lib* %s/add-ons/" % (self.install_path, self.install_path)
        elif is_rdma_1823_startup():
            str_cmd = "cp -rf %s/add-ons/1823/lib* %s/add-ons/" % (self.install_path, self.install_path)
        else:
            str_cmd = "cp -rf %s/add-ons/nomlnx/lib* %s/add-ons/" % (self.install_path, self.install_path)

        log("Install xnet lib cmd: " + str_cmd)
        ret_code, _, stderr = _exec_popen(str_cmd)
        if ret_code:
            log_exit("Install xnet lib return: " + str(ret_code) + os.linesep + stderr)

    #########################################################################
    # Unzip the installation files to the installation directory.
    #########################################################################
    def decompress_bin(self):
        """
        Unzip the installation files to the installation directory.
        :return: NA
        """
        self.run_file = "/opt/cantian/image/cantian_connector/CantianKernel/Cantian-DATABASE-CENTOS-64bit/" \
                        "Cantian-RUN-CENTOS-64bit.tar.gz"
        self.run_pkg_name = self.get_decompress_tarname(self.run_file)

        log("Decompressing run file.")

        if g_opts.use_dbstor:
            os.makedirs("%s/dbstor/conf/dbs" % self.data, CommonValue.KEY_DIRECTORY_PERMISSION)
            os.makedirs("%s/dbstor/conf/infra/config" % self.data, CommonValue.KEY_DIRECTORY_PERMISSION)
            os.makedirs("%s/dbstor/data/logs" % self.data, CommonValue.KEY_DIRECTORY_PERMISSION)
            os.makedirs("%s/dbstor/data/ftds" % self.data, CommonValue.KEY_DIRECTORY_PERMISSION)
            if is_rdma_startup() or is_rdma_1823_startup():
                str_cmd = "cp %s/cfg/node_config_rdma.xml %s/dbstor/conf/infra/config/node_config.xml" % (
                    self.install_path, self.data)
            else:
                str_cmd = "cp %s/cfg/node_config_tcp.xml %s/dbstor/conf/infra/config/node_config.xml" % (
                    self.install_path, self.data)

            str_cmd += " && cp %s/cfg/osd.cfg %s/dbstor/conf/infra/config/osd.cfg" % (self.install_path, self.data)
            str_cmd += " && cp /opt/cantian/dbstor/tools/dbstor_config.ini %s/dbstor/conf/dbs/" % (self.data)
            str_cmd += " && echo 'DBSTOR_OWNER_NAME = cantian' >> %s/dbstor/conf/dbs/dbstor_config.ini" % (self.data)
            str_cmd += " && sed -i '/^\s*$/d' %s/dbstor/conf/dbs/dbstor_config.ini" % (self.data)
            str_cmd += " && chown -R %s:%s %s/dbstor" % (self.user, self.group, self.data)
            str_cmd += " && chmod 640 %s/dbstor/conf/dbs/dbstor_config.ini" % (self.data)
            log("Copy config files cmd: " + str_cmd)
            ret_code, _, stderr = _exec_popen(str_cmd)
            if ret_code:
                self.failed_pos = self.DECOMPRESS_BIN_FAILED
                log_exit("Decompress bin return: " + str(ret_code) + os.linesep + stderr)

        cantian_check_share_logic_ip_isvalid(g_opts.share_logic_ip)

        if g_opts.use_dbstor:
            self.install_xnet_lib()
        # change app permission
        self.change_app_permission()

        # change owner to user:group
        str_cmd = "chown %s:%s -hR %s " % (self.user, self.group,
                                           self.install_path)
        # Change the owner
        log("Change owner cmd: %s" % str_cmd)
        ret_code, _, stderr = _exec_popen(str_cmd)
        if ret_code:
            self.failed_pos = self.DECOMPRESS_BIN_FAILED
            log_exit("chown to %s: %s return: %s%s%s"
                     % (self.user, self.group, str(ret_code), os.linesep, stderr))

        log("End decompress bin file.")

    def export_user_env(self):
        try:
            flags = os.O_RDWR
            modes = stat.S_IWUSR | stat.S_IRUSR
            with os.fdopen(os.open(self.user_profile, flags, modes), 'a') as _file:
                _file.write("export CTDB_HOME=\"%s\"" % self.install_path)
                _file.write(os.linesep)
                _file.write("export PATH=\"%s\":$PATH"
                            % os.path.join(MYSQL_BIN_DIR, "bin"))
                _file.write(os.linesep)
                _file.write("export PATH=\"%s\":$PATH"
                            % os.path.join(self.install_path, "bin"))
                _file.write(os.linesep)
                if "LD_LIBRARY_PATH" in os.environ:
                    _file.write("export LD_LIBRARY_PATH=\"%s\":\"%s\""
                                ":$LD_LIBRARY_PATH"
                                % (os.path.join(self.install_path, "lib"),
                                   os.path.join(self.install_path, "add-ons")))
                else:
                    _file.write("export LD_LIBRARY_PATH=\"%s\":\"%s\""
                                % (os.path.join(self.install_path, "lib"),
                                   os.path.join(self.install_path, "add-ons")))
                _file.write(os.linesep)
                if self.old_data_path == "":
                    # set CTDB_DATA
                    _file.write("export CTDB_DATA=\"%s\"" % self.data)
                    _file.write(os.linesep)
                _file.flush()
        except IOError as ex:
            self.failed_pos = self.SET_ENV_FAILED
            log_exit("Can not set user environment variables: %s" % str(ex))

    def set_user_env(self):
        """
        Set the user's environment variables.

        The modification of Linux system:
            1. export PATH=the value of '-R'/bin:$PATH
            2. export LD_LIBRARY_PATH=the value of '-R'/lib:
               the value of '-R'/add-ons:$LD_LIBRARY_PATH
            3. export CTDB_DATA=the value of '-D'
            4. export CTDB_HOME=the value of '-R'
        :return: NA
        """
        log("Setting user env.")
        # set PATH, LD_LIBRARY_PATH
        self.export_user_env()
        # Avoid create database failed by the value of CTSQL_SSL_KEY_PASSWD
        self.clean_ssl_env()

        os.environ['PATH'] = (os.path.join(self.install_path, "bin")
                              + ":" + os.environ['PATH'])
        # in some system LD_LIBRARY_PATH is not set,
        #  so must check it, or excetion will be raise
        if 'LD_LIBRARY_PATH' in os.environ:
            os.environ['LD_LIBRARY_PATH'] = ("%s:%s:%s" % (
                os.path.join(self.install_path, "lib"), os.path.join(
                    self.install_path, "add-ons", ),
                os.environ['LD_LIBRARY_PATH']))
        else:
            os.environ['LD_LIBRARY_PATH'] = ("%s:%s" % (
                os.path.join(self.install_path, "lib"),
                os.path.join(self.install_path, "add-ons"),))
        os.environ["CTDB_HOME"] = self.install_path
        os.environ["CTDB_DATA"] = self.data

        # Clean the env about ssl cert
        # Avoid remaining environmental variables interfering
        # with the execution of subsequent ctsql
        os.environ["CTSQL_SSL_CA"] = ""
        os.environ["CTSQL_SSL_CERT"] = ""
        os.environ["CTSQL_SSL_KEY"] = ""
        os.environ["CTSQL_SSL_MODE"] = ""
        os.environ["CTSQL_SSL_KEY_PASSWD"] = ""
        log("End set user env.")

    def set_new_conf(self, param_dict, conf_file):
        """
        function: echo 'key:value' conf to given conf file
        input : parameter dict, conf file name
        output: NA
        """
        cmd = ""
        # make the command of write the parameter
        for key, value in param_dict.items():
            cmd += "echo '%s = %s' >> %s;" % (key, value, conf_file)

        if cmd:
            cmd = cmd.strip(";")
            ret_code, _, stderr = _exec_popen(cmd)
            if ret_code:
                raise Exception("Can not write the %s, command: %s,"
                                " output: %s" % (conf_file, cmd, stderr))

    def clean_old_conf(self, param_list, conf_file):
        """
        function: clean old conf in given conf file
        input : parameter list, conf file path
        output: NA
        """
        cmd = ""
        # make the command of delete the parameter
        for parameter in param_list:
            cmd += "sed -i '/^%s/d' %s;" % (parameter.replace('[', '\[').replace(']', '\]'), conf_file)

        if cmd:
            cmd = cmd.strip(";")
            ret_code, _, stderr = _exec_popen(cmd)
            if ret_code:
                raise Exception("Can not write the %s, command: %s,"
                                " output: %s"
                                % (conf_file, cmd, stderr))

    def generate_nomount_passwd(self, plain_passwd=""):
        cmd = "source ~/.bashrc && %s/bin/ctencrypt -e PBKDF2" % self.install_path
        g_opts.db_passwd = g_opts.db_passwd if len(plain_passwd.strip()) == 0 else plain_passwd.strip()
        values = [g_opts.db_passwd, g_opts.db_passwd]

        ret_code, stdout, stderr = _exec_popen(cmd, values)
        if ret_code:
            raise OSError("Failed to encrypt password of user [sys]."
                          " Error: %s" % (stderr + os.linesep + stderr))

        # Example of output:
        # Please enter password to encrypt:
        # *********
        # Please input password again:
        # *********
        # eg 'Cipher:         XXXXXXXXXXXXXXXXXXXXXXX'
        lines = stdout.split(os.linesep)
        cipher = lines[4].split(":")[1].strip()
        return cipher

    def set_conf(self, config, file, encrypt_passwd=False):
        """
        function: set cantian, cms, gss conf
        input : config data
        input : config file name
        input : should generate encrypt passwd
        output: NA
        """
        conf_file = os.path.join(self.data, "cfg", file)
        # Make sure this is a newline, when setting the first parameter
        cmd = "echo >> %s" % conf_file
        ret_code, _, stderr = _exec_popen(cmd)
        if ret_code:
            raise Exception("Can not write the  %s, command: %s,"
                            " output: %s" % (file, cmd, stderr))

        # Generate new kernel parameters
        common_parameters = copy.deepcopy(config)
        # Set password of NOMOUNT mode before create database.
        if encrypt_passwd:
            mode = "encrypted"
            self.ctsql_conf["SYS_PASSWORD"] = Installer.kmc_resovle_password(mode, common_parameters["_SYS_PASSWORD"])
            common_parameters["_SYS_PASSWORD"] = self.generate_nomount_passwd(common_parameters["_SYS_PASSWORD"])
            if g_opts.mes_type == "TCP":
                common_parameters["MES_SSL_KEY_PWD"] = Installer.kmc_resovle_password(mode, g_opts.cert_encrypt_pwd)

                self.set_cms_ini(common_parameters["MES_SSL_KEY_PWD"])
            g_opts.password = common_parameters["_SYS_PASSWORD"]
        else:
            self.ctsql_conf["SYS_PASSWORD"] = common_parameters["_SYS_PASSWORD"]

        if not g_opts.use_dbstor:
            common_parameters["FILE_OPTIONS"] = "FULLDIRECTIO"

        # 1.clean old conf
        self.clean_old_conf(list(common_parameters.keys()), conf_file)
        # 2.set new conf
        self.set_new_conf(common_parameters, conf_file)
        self.set_ctsql_conf()

    def set_ctsql_conf(self):
        conf_file = os.path.join(self.data, "cfg", self.CTSQL_CONF_FILE)
        cmd = ""
        for key, value in self.ctsql_conf.items():
            cmd += "echo '%s = %s' >> %s;" % (key, value, conf_file)
        if cmd:
            cmd = cmd.strip(";")
            ret_code, _, stderr = _exec_popen(cmd)
            if ret_code:
                raise Exception("Can not write the %s, command: %s,"
                                " output: %s" % (conf_file, cmd, stderr))

    def set_cluster_conf(self):
        """
        function: set cluster conf
        output: NA
        """
        conf_file = os.path.join(self.data, "cfg", self.CLUSTER_CONF_FILE)
        # Make sure this is a newline, when setting the first parameter
        cmd = "echo >> %s" % conf_file
        ret_code, _, stderr = _exec_popen(cmd)
        if ret_code:
            raise Exception("Can not write the %s, command: %s, output: %s" % (conf_file, cmd, stderr))
        size = CLUSTER_SIZE
        if g_opts.running_mode in [CANTIAND, CANTIAND_WITH_MYSQL, CANTIAND_WITH_MYSQL_ST]:
            size = 1
        if g_opts.node_id == 0 or g_opts.node_id == 1:
            node_ip = self.cantiand_configs["INTERCONNECT_ADDR"].split(",")
            if ";" in self.cantiand_configs["INTERCONNECT_ADDR"]:
                node_ip = self.cantiand_configs["INTERCONNECT_ADDR"].split(";")
        if len(node_ip) == 1:
            node_ip.append("127.0.0.1")
        # Generate new kernel parameters
        common_parameters = self.write_cluster_conf(node_ip, size)

        # 1.clean old conf
        self.clean_old_conf(list(common_parameters.keys()), conf_file)
        # 2.set new conf
        self.set_new_conf(common_parameters, conf_file)

    def write_cluster_conf(self, node_ip, size):
        common_parameters = {
            "REPORT_FILE": g_opts.log_file,
            "STATUS_LOG": os.path.join(self.data, "log", "cantianstatus.log"),
            "LD_LIBRARY_PATH": os.environ['LD_LIBRARY_PATH'],
            "USER_HOME": self.user_home_path,
            "USE_GSS": g_opts.use_gss,
            "USE_DBSTOR": g_opts.use_dbstor,
            "CLUSTER_SIZE": size,
            "NODE_ID": g_opts.node_id,
            "NODE_IP[0]": node_ip[0],
            "NODE_IP[1]": node_ip[1],
            "LSNR_NODE_IP[0]": node_ip[0],
            "LSNR_NODE_IP[1]": node_ip[1],
            "USER": self.user,
            "GROUP": self.group,
            "DATA": self.data,
            "CREAT_DB_FILE": self.create_db_file,
            "INSTALL_PATH": self.install_path,
            "RUNNING_MODE": g_opts.running_mode,
            "LOG_HOME": self.cantiand_configs["LOG_HOME"],
            "SYS_PASSWORD": g_opts.password,
            "MYSQL_CODE_DIR": MYSQL_CODE_DIR,
            "MYSQL_BIN_DIR": MYSQL_BIN_DIR,
            "MYSQL_DATA_DIR": MYSQL_DATA_DIR,
            "MYSQL_LOG_FILE": MYSQL_LOG_FILE,
        }

        if g_opts.use_dbstor:
            common_parameters["CONTROL_FILES"] = self.cantiand_configs["CONTROL_FILES"]
            common_parameters["SHARED_PATH"] = self.cantiand_configs["SHARED_PATH"],
            common_parameters["DBSTOR_NAMESPACE"] = self.cantiand_configs["DBSTOR_NAMESPACE"]

        common_parameters["ENABLE_DBSTOR"] = self.cantiand_configs["ENABLE_DBSTOR"]
        cantian_config_data = common_parameters
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        modes = stat.S_IWUSR | stat.S_IRUSR
        with os.fdopen(os.open(CANTIAN_CONF_FILE, flags, modes), 'w') as fp:
            json.dump(cantian_config_data, fp)

        return common_parameters

    def set_cthba_ssl(self):
        """Replace host to hostssl in cthba.conf"""
        cthba_file = os.path.join(self.data, "cfg", self.CANTIAND_HBA_FILE)
        cmd = "sed -i 's#^host #hostssl #g' %s" % cthba_file
        log("Set white list from host to hostssl.")
        ret_code, _, stderr = _exec_popen(cmd)
        if ret_code:
            err_msg = "Failed to set user white list from host to hostssl."
            log(err_msg + " Error: %s" % stderr)
            log_exit(err_msg)

    def add_cthba_item(self):
        """Add INTERCONNECT_ADDR and ip white list to cthba.conf"""
        addr_list = []
        if len(g_opts.white_list) != 0:
            addr_list = [_.strip() for _ in g_opts.white_list.split(",")]
        for item in re.split(r"[;,]", self.cantiand_configs["INTERCONNECT_ADDR"]):
            if item not in addr_list:
                addr_list.append(item)
        if "127.0.0.1" in addr_list:
            addr_list.remove("127.0.0.1")
        if "::1" in addr_list:
            addr_list.remove("::1")

        if addr_list:
            cthba_file = os.path.join(self.data, "cfg", self.CANTIAND_HBA_FILE)
            host_type = self.close_ssl and "host" or "hostssl"
            cmd = ""
            for addr in addr_list:
                cmd += "echo '%s * %s' >> %s; " % (host_type, addr, cthba_file)

            if cmd:
                cmd = cmd.strip(";")
                ret_code, _, stderr = _exec_popen(cmd)
                if ret_code:
                    raise Exception("Can not write the  %s, command: %s,"
                                    " output: %s" % (self.CANTIAND_HBA_FILE, cmd, stderr))

    def init_db_instance(self):
        """
        Modify the database configuration file cantiand.ini with the given
        parameters, which are specified by the -C parameter.
        :return: NA
        """

        log("Initialize db instance.")
        try:
            self.failed_pos = self.INIT_DB_FAILED
            # Set cthba.conf to hostssl
            if not self.close_ssl:
                self.set_cthba_ssl()
            self.add_cthba_item()
            # g_opts.isencrept默认加密
            self.set_conf(self.cantiand_configs, self.CANTIAND_CONF_FILE, g_opts.isencrept)
            self.set_cluster_conf()
        except Exception as error:
            log_exit(str(error))
            raise ValueError(str(error)) from error

        log("End init db instance")

    def genregstring(self, text):
        """
        Generates a regular expression string path return based on the
        passed string path.
        :param text: string path
        :return: NA
        """
        log("Begin gen regular string...")
        if not text:
            return ""
        ins_str = text
        ins_list = ins_str.split(os.sep)
        reg_string = ""
        for i in ins_list:
            if (i == ""):
                continue
            else:
                reg_string += r"\/" + i
        log("End gen regular string")
        return reg_string

    def __clean_env_cmd(self, cmds):
        # do clean
        for cmd in cmds:
            cmd = 'sed -i "%s" "%s"' % (cmd, self.user_profile)
            log("Clean environment variables cmd: %s" % cmd)
            ret_code, _, stderr = _exec_popen(cmd)
            if ret_code:
                log("Failed to clean environment variables."
                    " Error: %s" % stderr)
                log_exit("Failed to clean environment variables.")

    def clean_ssl_env(self):
        """
        Clear environment variables about ssl
        :return: NA
        """
        log("Begin clean user environment variables about ssl...")
        # Clear environment ssl cert
        ca_cmd = r"/^\s*export\s*CTSQL_SSL_CA=.*$/d"
        cert_cmd = r"/^\s*export\s*CTSQL_SSL_CERT=.*$/d"
        key_cmd = r"/^\s*export\s*CTSQL_SSL_KEY=.*$/d"
        mode_cmd = r"/^\s*export\s*CTSQL_SSL_MODE=.*$/d"
        cipher_cmd = r"/^\s*export\s*CTSQL_SSL_KEY_PASSWD=.*$/d"
        cmds = [ca_cmd, cert_cmd, key_cmd, mode_cmd, cipher_cmd]

        # do clean
        self.__clean_env_cmd(cmds)
        log("End clean user environment variables about ssl...")

    def clean_environment(self):
        """
        Clear environment variables
        :return: NA
        """
        log("Begin clean user environment variables...")

        # Clear environment variable CTDB_DATA
        data_cmd = r"/^\s*export\s*CTDB_DATA=.*$/d"
        # Clear environment variable PATH about database
        path_cmd = (r"/^\s*export\s*PATH=.*%s\/bin.*:\$PATH$/d"
                    % self.genregstring(self.install_path))
        # Clear environment variable LD_LIBRARY_PATH about database
        lib_cmd = (r"/^\s*export\s*LD_LIBRARY_PATH=.*%s\/lib.*"
                   r":.*%s\/add-ons*$/d"
                   % (self.genregstring(self.install_path),
                      self.genregstring(self.install_path)))
        # Clear environment variable CTDB_HOME
        home_cmd = r"/^\s*export\s*CTDB_HOME=.*$/d"
        # Clear environment variable CMS_HOME

        # Clear environment ssl cert
        ca_cmd = r"/^\s*export\s*CTSQL_SSL_CA=.*$/d"
        cert_cmd = r"/^\s*export\s*CTSQL_SSL_CERT=.*$/d"
        key_cmd = r"/^\s*export\s*CTSQL_SSL_KEY=.*$/d"
        mode_cmd = r"/^\s*export\s*CTSQL_SSL_MODE=.*$/d"
        cipher_cmd = r"/^\s*export\s*CTSQL_SSL_KEY_PASSWD=.*$/d"

        cmds = [path_cmd, lib_cmd, home_cmd,
                ca_cmd, cert_cmd, key_cmd, mode_cmd, cipher_cmd]
        if self.option == self.INS_ALL:
            cmds.insert(0, data_cmd)

        # do clean
        self.__clean_env_cmd(cmds)
        log("End clean user environment variables...")

    def rollback_data_dirs(self):
        if os.path.exists(self.data):
            shutil.rmtree(self.data)
            log("Roll back: " + self.data)

    def rollback_from_decompress(self):
        if os.path.exists(self.install_path):
            shutil.rmtree(self.install_path)
            log("Roll back: " + self.install_path)
        if self.option == self.INS_ALL:
            # Delete data
            self.rollback_data_dirs()

    def rollback_from_set_user_env(self):
        log("Using user profile: " + self.user_profile)
        # Delete program
        if os.path.exists(self.install_path):
            shutil.rmtree(self.install_path)
            log("Roll back: remove " + self.install_path)
        if self.option == self.INS_ALL:
            # Delete data
            self.rollback_data_dirs()
        # Delete env value
        self.clean_environment()

        log("Roll back: profile is updated ")

    def __kill_process(self, process_name):
        # root do install, need su - user kill process

        kill_cmd = (r"proc_pid_list=`ps ux | grep %s | grep -v grep"
                    r"|awk '{print $2}'` && " % process_name)
        kill_cmd += (r"(if [ X\"$proc_pid_list\" != X\"\" ];then echo "
                     r"$proc_pid_list | xargs kill -9; fi)")
        log("kill process cmd: %s" % kill_cmd)
        ret_code, stdout, stderr = _exec_popen(kill_cmd)
        if ret_code:
            log_exit("kill process %s faild."
                     "ret_code : %s, stdout : %s, stderr : %s" % (process_name, ret_code, stdout, stderr))

    #######################################################################
    # check datadir and prepare cfg/cantiand.ini,
    # mkdir datadir/data, datadir/log
    # The function fails to execute, the log is printed, and then exits
    #######################################################################
    def prepare_data_dir(self):
        """
        function: check datadir and prepare cfg/cantiand.ini,
                  mkdir datadir/data, datadir/log, datadir/trc
        input : NA
        output: NA
        """
        print_str_1 = CommonPrint()
        print_str_1.common_log("Checking data dir and config file")
        try:
            self.failed_pos = self.PRE_DATA_DIR_FAILED
            str_cmd = "chmod %s %s" % (CommonValue.KEY_DIRECTORY_MODE, self.data)
            log("Change privilege cmd: %s" % str_cmd)
            ret_code, _, stderr = _exec_popen(str_cmd)
            if ret_code:
                raise Exception(
                    "chmod %s return: " % CommonValue.KEY_DIRECTORY_MODE + str(ret_code) + os.linesep + stderr)

            # create data, cfg, log dir, trc
            data_dir = "%s/data" % self.data
            if not g_opts.use_dbstor:
                mount_storage_data = f"/mnt/dbdata/remote/storage_{g_opts.storage_dbstore_fs}/data"
                cmd = "ln -s %s %s;" % (mount_storage_data, self.data)
                ret_code, _, stderr = _exec_popen(cmd)
                if ret_code:
                    raise Exception("Can not link data dir, command: %s, output: %s" % (cmd, stderr))
            else:
                os.makedirs(data_dir, CommonValue.KEY_DIRECTORY_PERMISSION)
            os.makedirs("%s/log" % self.data, CommonValue.KEY_DIRECTORY_PERMISSION)
            os.makedirs("%s/archive_log" % self.data, CommonValue.KEY_DIRECTORY_PERMISSION)
            os.makedirs("%s/trc" % self.data, CommonValue.KEY_DIRECTORY_PERMISSION)
            os.makedirs("%s/tmp" % self.data, CommonValue.KEY_DIRECTORY_PERMISSION)

            if not self.close_ssl and self.option != self.INS_ALL:
                os.makedirs("%s/dbs" % self.data, CommonValue.KEY_DIRECTORY_PERMISSION)

            # move the config files about database.
            cmd = "mv -i %s/cfg %s;touch %s/cfg/%s" % (self.install_path, self.data, self.data, self.CTSQL_CONF_FILE)
            ret_code, _, stderr = _exec_popen(cmd)
            if ret_code:
                raise Exception("Can not create prepare data dir, command: %s, output: %s" % (cmd, stderr))

            # Change the mode of config files to 600
            cmd = "chmod {0} {1}/cfg/{2} {1}/cfg/{3} {1}/cfg/{4} {1}/cfg/{5}".format(
                CommonValue.KEY_FILE_MODE, self.data, self.CANTIAND_CONF_FILE,
                self.CMS_CONF_FILE, self.CANTIAND_HBA_FILE, self.CTSQL_CONF_FILE)
            ret_code, _, stderr = _exec_popen(cmd)
            if ret_code:
                raise Exception("chmod %s return: " % CommonValue.KEY_FILE_MODE + str(ret_code) + os.linesep + stderr)

            # Change the owner of config files
            self.chown_data_dir()
        except Exception as ex:
            log_exit(str(ex))

    def setcap(self):
        """
        function: setcap for binary files
        input: NA
        output: NA
        """
        if not g_opts.use_gss and not g_opts.use_dbstor:
            return

        cmd = "sh %s -P setcap >> %s 2>&1" % (INSTALL_SCRIPT, g_opts.log_file)
        ret_code, stdout, stderr = _exec_popen(cmd)
        if ret_code:
            output = stdout + stderr
            raise Exception("Failed to setcap.\ncmd: %s.\nOutput: %s" % (cmd, output))
        log("setcap successed")

    ##################################################################
    # start cantian instance
    ##################################################################
    def start_cantiand(self):
        """
        function:start cantian instacne
        input : start mode, start type
        output: NA
        """
        log("Starting cantiand...")
        # start cantian dn
        flags = os.O_RDONLY
        modes = stat.S_IWUSR | stat.S_IRUSR
        with os.fdopen(os.open(CANTIAN_START_STATUS_FILE, flags, modes), 'r') as load_fp:
            start_parameters = json.load(load_fp)
        self.chown_data_dir()
        status_success = False
        start_mode = self.NOMOUNT_MODE
        if g_opts.node_id == 1:
            start_mode = self.OPEN_MODE
        if g_opts.install_type == "reserve":
            start_mode = self.OPEN_MODE
        if start_parameters.setdefault('db_create_status', "default") == "done" and g_opts.node_id == 0:
            start_mode = self.OPEN_MODE

        # Start instance, according to running mode can point to cantiand or cantiand with mysql
        cmd = "echo -e '%s' | sh %s -P cantiand -M %s -T %s -C %s >> %s 2>&1" % (
            g_opts.db_passwd, INSTALL_SCRIPT, start_mode, g_opts.running_mode.lower(),
            g_opts.mysql_config_file_path, g_opts.log_file)

        status, stdout, stderr = _exec_popen(cmd)
        if status != 0:
            output = stdout + stderr
            if g_opts.db_passwd in output:
                output = "installdb.sh was killed"
            raise Exception("Can not start instance %s.\nOutput: %s" % (self.data, output))

        # In some condition cantian will take some time to start, so wait
        # it by checking the process cyclically after the start command
        # returned. If the cantiand process can't be found within the
        # expected time, it is considered that the startup failed.
        tem_log_info, status_success = self.init_some_condition(status_success, self.status_log)

        # the log file's permission is 600, change it
        if os.path.exists(self.status_log):
            uid = pwd.getpwnam(self.user).pw_uid
            gid = grp.getgrnam(self.group).gr_gid
            os.chown(self.status_log, uid, gid)
            os.chmod(self.status_log, CommonValue.KEY_FILE_PERMISSION)

        if not status_success:
            raise Exception("Can not get instance '%s' process pid,"
                            "The detailed information: '%s' " % (self.data, tem_log_info))
        log("cantiand has started")

    def get_invalid_parameter(self):
        log_home = self.cantiand_configs["LOG_HOME"]
        run_log = os.path.join(log_home, "run", "cantiand.rlog")
        cmd = "cat %s | grep 'ERROR' " % run_log
        ret_code, stdout, stderr = _exec_popen(cmd)
        output = stdout + stderr
        if ret_code:
            log("Failed to get the error message from '%s'. Output: %s" % (run_log, output))
            return ""
        else:
            return output

    def init_some_condition(self, status_success, status_log):
        start_time = 300
        tem_log_info = ""
        for i in range(0, start_time):
            time.sleep(3)

            cmd = ("ps aux | grep -v grep | grep %s | grep $ "
                   "|awk '{print $2}'" % (self.data))
            if g_opts.running_mode.lower() in [CANTIAND_WITH_MYSQL, CANTIAND_WITH_MYSQL_ST,
                                               CANTIAND_WITH_MYSQL_IN_CLUSTER]:
                cmd = "ps -ef | grep -v grep | grep mysqld"
                status_log = MYSQL_LOG_FILE

            ret_code, stdout, stderr = _exec_popen(cmd)
            if ret_code:
                status_success = False
                tem_log_info = ("Failed to execute cmd: %s.output:%s"
                                % (str(cmd), str(stderr)))
                break
            else:
                all_the_text = open(status_log).read()
                log("Instance start log output: %s, cmd: %s" % (str(all_the_text), str(cmd)))
                if all_the_text.find("instance started") >= 0:
                    if stdout:
                        status_success = True
                        self.pid = stdout.strip()
                        log("start instance successfully, pid = %s" % stdout)
                        break
                elif all_the_text.find("instance startup failed") > 0:
                    status_success = False
                    tem_log_info = all_the_text.strip()
                    # Get the error message from run log. After roll_back,
                    # all files and logs will be cleaned, so we must get
                    # the error message before roll_back.
                    run_log_info = self.get_invalid_parameter()
                    if run_log_info:
                        tem_log_info += os.linesep
                        tem_log_info += ("The run log error: %s%s" % (os.linesep, run_log_info))
                    break
            if (i + 1) == start_time:
                status_success = False
                tem_log_info = "Instance startup timeout, more than 900s"
            elif (i % 30) != 0:
                log("Instance startup in progress, please wait.")
        return tem_log_info, status_success

    def update_factor_key(self):
        if len(self.factor_key.strip()) == 0:
            return
        sql = "ALTER SYSTEM SET _FACTOR_KEY = '%s' " % self.factor_key
        self.execute_sql(sql, "set the value of _FACTOR_KEY")

    def execute_sql_file(self, sql_file):
        """
        function: execute sql file
        input : sql cmd
        output: NA
        """
        # root or normal user can execute install command, and can enable
        # or disable sysdba user, so the ctsql command have 4 condition
        # 1 root execute install.py and enable sysdba
        # 2 root execute install.py and disable sysdba
        # 3 normal user execute install.py and enable sysdba
        # 4 normal user execute install.py and disable sysdba
        if g_opts.install_type == "reserve":
            return "Install type is reserve."

        if self.enable_sysdba_login:
            cmd = "source ~/.bashrc && %s/bin/ctsql / as sysdba -q -D %s -f %s" % (self.install_path,
                                                                                  self.data, sql_file)
            return_code, stdout_data, stderr_data = _exec_popen(cmd)
        else:
            cmd = ("source ~/.bashrc && echo -e '%s' | %s/bin/ctsql %s@%s:%s -q -f %s" % (
                g_opts.db_passwd,
                self.install_path,
                g_opts.db_user,
                self.login_ip,
                self.lsnr_port,
                sql_file))
            return_code, stdout_data, stderr_data = _exec_popen(cmd)

        output = "%s%s" % (str(stdout_data), str(stderr_data))
        if g_opts.db_passwd in output:
            output = "execute ctsql file failed"
        log("Execute sql file %s output: %s" % (sql_file, output))
        if return_code:
            raise Exception("Failed to execute sql file %s, output:%s" % (sql_file, output))

        # return code is 0, but output has error info, CT-xxx, ZS-xxx
        result = output.replace("\n", "")
        if re.match(".*CT-\d{5}.*", result) or re.match(".*ZS-\d{5}.*", result):
            raise Exception("Failed to execute sql file %s, output:%s" % (sql_file, output))
        return stdout_data

    def execute_sql(self, sql, message):
        """
        function: execute sql string
        input : sql cmd
        output: NA
        """
        # root or normal user can execute install command, and can enable
        # or disable sysdba user, so the ctsql command have 4 condition
        # 1 root execute install.py and enable sysdba
        # 2 root execute install.py and disable sysdba
        # 3 normal user execute install.py and enable sysdba
        # 4 normal user execute install.py and disable sysdba
        ctsql_path = "%s/bin/*sql" % self.install_path
        ctsql_path = glob.glob(ctsql_path)[0]
        if self.enable_sysdba_login:
            cmd = ("source ~/.bashrc && %s / as sysdba "
                   "-q -D %s -c \"%s\""
                   % (ctsql_path, self.data, sql))
            return_code, stdout_data, stderr_data = _exec_popen(cmd)
        else:
            cmd = ("source ~/.bashrc && echo -e '%s' | %s %s@%s:%s -q"
                   " -c \"%s\"" % (
                       g_opts.db_passwd,
                       ctsql_path,
                       g_opts.db_user,
                       self.login_ip,
                       self.lsnr_port,
                       sql))
            return_code, stdout_data, stderr_data = _exec_popen(cmd)

        output = "%s%s" % (str(stdout_data), str(stderr_data))
        output.replace(g_opts.db_passwd, "*****")
        if return_code:
            raise Exception("Failed to %s by sql, output:%s"
                            % (message, output))

        # return code is 0, but output has error info, CT-xxx, ZS-xxx
        result = output.replace("\n", "")
        if re.match(".*CT-\d{5}.*", result) or re.match(".*ZS-\d{5}.*", result):
            raise Exception("Failed to execute sql %s, output:%s" % (sql, output))
        return stdout_data

    def deploy_cantian(self):
        """
        function:config cantian dn
                1. start dn
                2. create database guass
                3. create user
        input : NA
        output: NA
        """
        log("Creating database.")

        cantian_check_share_logic_ip_isvalid(g_opts.share_logic_ip)

        flags = os.O_RDONLY
        modes = stat.S_IWUSR | stat.S_IRUSR
        with os.fdopen(os.open(CANTIAN_CONF_FILE, flags, modes), 'r') as fp:
            json_data = json.load(fp)
            self.user = json_data['USER'].strip()
            self.group = json_data['GROUP'].strip()
            self.data = json_data['DATA'].strip()
            self.create_db_file = json_data['CREAT_DB_FILE'].strip()
            self.install_path = json_data['INSTALL_PATH'].strip()
            g_opts.running_mode = json_data['RUNNING_MODE'].strip()
            self.cantiand_configs["LOG_HOME"] = json_data.get('LOG_HOME', '').strip()
            self.cantiand_configs["ENABLE_DBSTOR"] = json_data.get('ENABLE_DBSTOR', '').strip()
            if g_opts.use_dbstor:
                self.cantiand_configs["SHARED_PATH"] = json_data.get('SHARED_PATH', '')
                self.cantiand_configs["CONTROL_FILES"] = json_data.get('CONTROL_FILES', '').strip()
                self.cantiand_configs["DBSTOR_NAMESPACE"] = json_data.get('DBSTOR_NAMESPACE', '').strip()
            else:
                self.cantiand_configs["SHARED_PATH"] = '/mnt/dbdata/remote/storage_{}/data'.format(
                    g_opts.storage_dbstore_fs)

        # clean old backup log
        # backup log file before rm data
        self.backup_log_dir = "/tmp/bak_log"
        if os.path.exists(self.backup_log_dir):
            shutil.rmtree(self.backup_log_dir)
            log("rm the backup log of cantiand " + self.backup_log_dir)

        # Clean the old status log
        self.status_log = "%s/log/cantianstatus.log" % self.data
        if os.path.exists(self.status_log):
            os.remove(self.status_log)

        if os.getuid() == 0:
            cmd = "chown %s:%s %s;" % (self.user, self.group, INSTALL_SCRIPT)
            ret_code, _, stderr = _exec_popen(cmd)
            if ret_code:
                raise Exception("chown to %s:%s return: %s%s%s"
                                % (self.user, self.group, str(ret_code),
                                   os.linesep, stderr))

        try:
            # 1.start dn process in nomount or mount mode
            self.failed_pos = self.CREATE_DB_FAILED
            cantian_check_share_logic_ip_isvalid(g_opts.share_logic_ip)
            self.start_cantiand()
            log("Creating cantian database...")
            cantian_check_share_logic_ip_isvalid(g_opts.share_logic_ip)
            self.create_db()
        except Exception as error:
            log_exit(str(error))
        self.check_db_status()
        log("Creating database succeed.")

    def create_db(self):
        if skip_execute_in_node_1():
            return
        flags = os.O_RDONLY
        modes = stat.S_IWUSR | stat.S_IRUSR
        with os.fdopen(os.open(CANTIAN_START_STATUS_FILE, flags, modes), 'r') as load_fp:
            start_parameters = json.load(load_fp)
        if (start_parameters.setdefault('db_create_status', "default") == "default"):
            self.update_factor_key()
            flags = os.O_WRONLY | os.O_TRUNC
            db_create_status_item = {'db_create_status': "creating"}
            start_parameters.update(db_create_status_item)
            with os.fdopen(os.open(CANTIAN_START_STATUS_FILE, flags, modes), 'w') as load_fp:
                json.dump(start_parameters, load_fp)
            self.execute_sql_file(self.get_database_file())
            db_create_status_item = {'db_create_status': "done"}
            start_parameters.update(db_create_status_item)
            with os.fdopen(os.open(CANTIAN_START_STATUS_FILE, flags, modes), 'w') as load_fp:
                json.dump(start_parameters, load_fp)

    def check_db_status(self):
        """
        参天启动后检查db状态，db状态为open状态后返回成功。超时设置为10min中，sql返回exp:

        Please enter password:
        ********
        connected.


        SQL>
        NAME                             STATUS               OPEN_STATUS
        -------------------------------- -------------------- --------------------
        dbstor                           OPEN                 READ WRITE

        1 rows fetched.


        """
        sql_cmd = "SELECT NAME, STATUS, OPEN_STATUS FROM DV_DATABASE"
        message = "check ctsql db status"
        db_status = ""
        timeout = 600
        while timeout:
            timeout -= 10
            time.sleep(10)
            try:
                res = self.execute_sql(sql_cmd, message)
            except Exception as _err:
                log(str(_err))
                continue
            if "1 rows fetched" not in res:
                continue
            db_status = re.split(r"\s+", re.split(r"\n+", res.strip())[-2].strip())[1].strip()
            log("ctsql db status: %s" % db_status)
            if db_status == "OPEN":
                log("Cantiand start success, db status: %s" % db_status)
                return
        else:
            log_exit("Cantiand start timeout, db status:%s" % db_status)

    def get_database_file(self):
        if self.create_db_file:
            # execute customized sql file, check -f parameter
            self.check_createdb_file()
            return self.create_db_file

        # execute default sql file
        # modify the sql file for create database
        sql_file_path = "%s/admin/scripts" % self.install_path
        file_name = "create_database.sample.sql"
        if g_opts.running_mode in [CANTIAND_IN_CLUSTER, CANTIAND_WITH_MYSQL_IN_CLUSTER]:
            file_name = "create_cluster_database.sample.sql"
        create_database_sql = os.path.join(sql_file_path, file_name)
        if g_opts.use_gss:
            self._sed_file("dbfiles1", "+vg1", create_database_sql)
            self._sed_file("dbfiles2", "+vg2", create_database_sql)
            self._sed_file("dbfiles3", "+vg3", create_database_sql)
        elif g_opts.use_dbstor:
            file_name = "create_dbstor_database.sample.sql"
            if g_opts.running_mode in [CANTIAND_IN_CLUSTER, CANTIAND_WITH_MYSQL_IN_CLUSTER]:
                file_name = "create_dbstor_cluster_database.sample.sql"
            create_database_sql = os.path.join(sql_file_path, file_name)
            file_name_0 = "create_dbstor_cluster_database.lun.sql"
            file_name_1 = "create_dbstor_cluster_database.sample.sql"
            file_name_2 = "create_dbstor_database.sample.sql"
            if g_opts.db_type in ['0', '1', '2']:
                create_database_sql_dic = {}
                create_database_sql_dic['0'] = file_name_0
                create_database_sql_dic['1'] = file_name_1
                create_database_sql_dic['2'] = file_name_2
                create_database_sql = os.path.join(sql_file_path, create_database_sql_dic.get(g_opts.db_type))
        else:
            create_database_sql = os.path.join(sql_file_path, file_name)
            file_name_0 = "create_cluster_database.lun.sql"
            file_name_1 = "create_cluster_database.sample.sql"
            file_name_2 = "create_database.sample.sql"
            if g_opts.db_type in ['0', '1', '2']:
                create_database_sql_dic = {}
                create_database_sql_dic['0'] = file_name_0
                create_database_sql_dic['1'] = file_name_1
                create_database_sql_dic['2'] = file_name_2
                create_database_sql = os.path.join(sql_file_path, create_database_sql_dic.get(g_opts.db_type))

            db_data_path = os.path.join(self.data, "data").replace('/', '\/')
            self.set_sql_redo_size_and_num(db_data_path, create_database_sql)
            self._sed_file("dbfiles1", db_data_path, create_database_sql)
            self._sed_file("dbfiles2", db_data_path, create_database_sql)
            self._sed_file("dbfiles3", db_data_path, create_database_sql)

        return create_database_sql

    def _sed_file(self, prefix, replace, file_name):
        fix_sql_file_cmd = ("sed -i 's/%s/%s/g' %s" % (prefix, replace, file_name))
        ret_code, _, _ = _exec_popen(fix_sql_file_cmd)
        if ret_code:
            raise Exception("sed %s failed, replace %s" % (file_name, replace))

    def _change_ssl_cert_owner(self):
        cmd = "chown -hR %s:%s %s; " % (self.user, self.group, self.ssl_path)
        ret_code, _, stderr = _exec_popen(cmd)
        if ret_code:
            raise Exception("chown to %s:%s return: %s%s%s"
                            % (self.user, self.group, str(ret_code), os.linesep, stderr))

    def get_ctencrypt_keys(self, skip_execute_sql=False):
        """Set the config about _FACTOR_KEY and LOCAL_KEY."""
        # Generate Key and WorkKey
        log("Generate encrypted keys.")
        cmd = "%s/bin/ctencrypt -g" % self.install_path
        ret_code, stdout, stderr = _exec_popen(cmd)
        if ret_code:
            raise OSError("Failed to generate encrypted keys. Error: %s"
                          % (stderr + os.linesep + stderr))

        # Example of output:
        # eg'Key:            XXXXXXXXXXXXXXXXXXXXXXX'
        # eg'WorkKey:        XXXXXXXXXXXXXXXXXXXXXXX'
        lines = stdout.split(os.linesep)
        key_ = lines[0].split(":")[1].strip()
        work_key = lines[1].split(":")[1].strip()

        # Set the value of _FACTOR_KEY
        if not skip_execute_sql:
            sql = "ALTER SYSTEM SET _FACTOR_KEY = '%s' " % key_
            self.execute_sql(sql, "set the value of _FACTOR_KEY")
            # Set the value of LOCAL_KEY
            sql = "ALTER SYSTEM SET LOCAL_KEY = '%s' " % work_key
            self.execute_sql(sql, "set the value of LOCAL_KEY")

        log("Generate encrypted keys successfully.")
        return key_, work_key

    def get_ctencrypt_keys_and_file(self):
        """Set the config about _FACTOR_KEY and LOCAL_KEY."""
        log("Generate encrypted keys.")
        f_factor1 = os.path.join(self.data, "dbs", "zenith_key1")
        f_factor2 = os.path.join(self.data, "dbs", "zenith_key2")

        # Generate Key and WorkKey
        #   This command will encrypt _FACTOR_KEY and write it into f_factor1.

        cmd = "%s/bin/ctencrypt -g -o '%s' " % (self.install_path, f_factor1)
        ret_code, stdout, stderr = _exec_popen(cmd)
        if ret_code:
            raise OSError("Failed to generate encrypted keys. Error: %s"
                          % (stderr + os.linesep + stderr))

        # Example of output:
        # eg'Key:            XXXXXXXXXXXXXXXXXXXXXXX'
        # eg'WorkKey:        XXXXXXXXXXXXXXXXXXXXXXX'
        lines = stdout.split(os.linesep)
        key_ = lines[0].split(":")[1].strip()
        work_key = lines[1].split(":")[1].strip()

        # Change own to user
        uid = pwd.getpwnam(self.user).pw_uid
        gid = grp.getgrnam(self.group).gr_gid
        os.chown(f_factor1, uid, gid)
        # Change mode to 600
        os.chmod(f_factor1, CommonValue.KEY_FILE_PERMISSION)
        # Copy f_factor1 to f_factor2
        shutil.copy(f_factor1, f_factor2)
        os.chown(f_factor2, uid, gid)
        os.chmod(f_factor2, CommonValue.KEY_FILE_PERMISSION)

        log("Generate encrypted keys successfully.")
        return key_, work_key

    def encrypt_ssl_key_passwd(self, key_, work_key, ssl_passwd, skip_execute_sql=False):
        """Encrypt ssl key password with _FACTOR_KEY and LOCAL_KEY."""
        log("Encrypt ssl key password.")

        cmd = ("%s/bin/ctencrypt -e AES256 -f %s -k %s"
               % (self.install_path, key_, work_key))

        values = [ssl_passwd, ssl_passwd]
        ret_code, stdout, stderr = _exec_popen(cmd, values)
        if ret_code:
            raise OSError("Failed to encrypt ssl key password. Error: %s"
                          % (stderr + os.linesep + stderr))

        # Example of output:
        # Please enter password to encrypt:
        # ***********
        # Please input password again:
        # ***********
        # eg'Cipher:         XXXXXXXXXXXXXXXXXXXXXXX'
        lines = stdout.split(os.linesep)
        cipher = lines[4].split(":")[1].strip()

        if self.option == self.INS_ALL and not skip_execute_sql:
            # Set SSL_KEY_PASSWORD
            sql = "ALTER SYSTEM SET SSL_KEY_PASSWORD = '%s'" % cipher
            self.execute_sql(sql, "set the value of SSL_KEY_PASSWORD")
        return cipher

    def set_ssl_conf(self, cipher="", factor_key="", work_key=""):
        """Set the config about ssl"""
        # Don't set SSL_CA and CTSQL_SSL_CA.
        # Avoid the need to copy files, env and kernel parameter
        # from the primary dn when installing the backup dn.
        cantian_conf_file = os.path.join(self.data, "cfg",
                                        self.CANTIAND_CONF_FILE)
        ssl_map = {
            "SSL_CERT": os.path.join(self.ssl_path, "server.crt"),
            "SSL_KEY": os.path.join(self.ssl_path, "server.key"),
            "SSL_VERIFY_PEER": "FALSE",
        }
        if cipher:
            ssl_map["SSL_KEY_PASSWORD"] = cipher
        if work_key:
            ssl_map["LOCAL_KEY"] = work_key
        if factor_key:
            self.factor_key = factor_key
        self.clean_old_conf(list(ssl_map.keys()), cantian_conf_file)
        self.clean_old_conf(["SSL_CA"], cantian_conf_file)
        self.set_new_conf(ssl_map, cantian_conf_file)

    def set_ssl_env(self, cipher):
        """
        1. export CTSQL_SSL_CERT = the path of client.crt
        2. export CTSQL_SSL_KEY = the path of client.key
        3. export CTSQL_SSL_MODE = required
        4. export CTSQL_SSL_KEY_PASSWD = {cipher}
        """
        # Don't set SSL_CA and CTSQL_SSL_CA.
        # Avoid the need to copy files, env and kernel parameter
        # from the primary dn when installing the backup dn.
        log("Set user environment variables about ssl.")
        try:
            flags = os.O_RDWR
            modes = stat.S_IWUSR | stat.S_IRUSR
            with os.fdopen(os.open(self.user_profile, flags, modes), 'a') as _file:
                _file.write("export CTSQL_SSL_CERT=\"%s\""
                            % os.path.join(self.ssl_path, "client.crt"))
                _file.write(os.linesep)
                _file.write("export CTSQL_SSL_KEY=\"%s\""
                            % os.path.join(self.ssl_path, "client.key"))
                _file.write(os.linesep)
                _file.write("export CTSQL_SSL_MODE=\"required\"")
                _file.write(os.linesep)
                _file.write("export CTSQL_SSL_KEY_PASSWD=\"%s\"" % cipher)
                _file.write(os.linesep)
                _file.flush()
        except IOError as ex:
            raise IOError("Failed Set user environment variables about ssl: %s"
                          % str(ex)) from ex

        os.environ["CTSQL_SSL_CERT"] = os.path.join(self.ssl_path, "client.crt")
        os.environ["CTSQL_SSL_KEY"] = os.path.join(self.ssl_path, "client.key")
        os.environ["CTSQL_SSL_MODE"] = "required"
        os.environ["CTSQL_SSL_KEY_PASSWD"] = cipher
        log("Set user environment variables about ssl successfully.")

    def stop_database(self):
        log("stop cantian instance.")
        # not specify -P parameter, password is empty, login by sysdba
        host_ip = self.lsnr_addr.split(",")[0]
        timeout = 1800

        if not g_opts.db_passwd:
            # connect database by sysdba
            cmd = ("%s/bin/shutdowndb.sh -h %s -p %s -w -m %s -D %s -T %d"
                   % (self.install_path, host_ip, self.lsnr_port,
                      "immediate", self.data, timeout))
            ret_code, _, stderr = _exec_popen(cmd)
        else:
            # connect database by username and password
            cmd = ("%s/bin/shutdowndb.sh -h"
                   " %s -p %s -U %s -m %s -W -D %s -T %d" %
                   (self.install_path,
                    host_ip, self.lsnr_port, g_opts.db_user, "immediate",
                    self.data, timeout))
            ret_code, _, stderr = _exec_popen(cmd, [g_opts.db_passwd])

        if ret_code:
            raise Exception("Failed to stop database. Error: %s"
                            % (stderr + os.linesep + stderr))
        log("stop cantian instance successfully.")

    def chmod_install_sqlfile(self):
        """
        function: when install finished, modify sql file permission to 400
        input : NA
        output: NA
        """
        try:
            str_cmd = ("find '%s'/admin -type f | xargs chmod %s "
                       % (self.install_path, CommonValue.MIN_FILE_MODE))
            ret_code, _, _ = _exec_popen(str_cmd)
            if ret_code:
                print_str_1 = CommonPrint()
                print_str_1.common_log("Change file permission to %s failed."
                                       " Please chmod %s filein directory %s/admin manually."
                                       % (CommonValue.MIN_FILE_MODE,
                                          CommonValue.MIN_FILE_MODE, self.install_path))
        except Exception as error:
            log_exit(str(error))

    def security_audit(self):
        """
        function:  security_audit, add oper if you needed
                1. chmod sql file permission
                2. ...
                3.
        input : NA
        output: NA
        """

        log("Changing file permission due to security audit.")
        # 1. chmod sql file permission
        self.chmod_install_sqlfile()

    ######################################################################
    # The main process of installation.
    # It is not necessary to check the return value of each function,
    # because there are check behavior them. If failed to execute code,
    # they will print the log and exit.
    #######################################################################
    def install(self):
        """
        install cantian app and create database
        the step of install for roll_back:
        1. init
        2. create database
        3. set user env
        4. decompress bin file
        the install process will save the install step in
        temp file, and when some step failed, the roll_back
        process read the install step and clean the files
        and directory created when install
        """

        self.verify_new_passwd(g_opts.password, 8)
        self.check_parameter()  # add cantiand, cms, gss config parameter check logic in this method
        self.chown_log_file()
        self.check_old_install()
        self.check_config_options()
        self.decompress_bin()
        self.set_user_env()
        self.prepare_data_dir()
        self.prepare_mysql_for_single()
        self.init_db_instance()  # init db config, including cantiand, cms, gss, ssl
        log("Successfully Initialize %s instance." % self.instance_name)

    def parse_cantiand_ini(self):
        cantiand_ini = {}
        modes = stat.S_IWUSR | stat.S_IRUSR
        flags = os.O_RDONLY
        with os.fdopen(os.open(CANTIAND_INI_FILE, flags, modes), 'r') as fp:
            for line in fp:
                if line == "\n":
                    continue
                (key, val) = line.split(" = ")
                val = val.replace('\n', '')
                cantiand_ini[key] = val
        self.enable_sysdba_login = Installer.check_pare_bool_value("ENABLE_SYSDBA_LOGIN",
                                                                   cantiand_ini.get("ENABLE_SYSDBA_LOGIN", "FALSE"))

    def install_start(self):
        self.parse_cantiand_ini()
        Installer.decrypt_db_passwd()
        self.deploy_cantian()
        self.security_audit()
        log("Successfully install %s instance." % self.instance_name)

    def check_parameter_mysql(self):
        if g_opts.mysql_config_file_path == "unset":
            g_opts.mysql_config_file_path = os.path.join(MYSQL_CODE_DIR, "scripts/my.cnf")
            log("no mysql config file assigned, set to %s" % g_opts.mysql_config_file_path)
        real_path = os.path.realpath(g_opts.mysql_config_file_path)
        if not os.path.isfile(real_path):
            log_exit("mysql config file {} not existed or it is not a file".format(real_path))
        if not self.is_readable(real_path, self.user):
            log_exit("mysql config file {} is not readable by {}".format(real_path, self.user))
        g_opts.mysql_config_file_path = real_path
        cmd = "chown {}:{} {};".format(self.user, self.group, real_path)
        cmd += "chmod {} {}".format(CommonValue.MAX_FILE_MODE, real_path)
        ret_code, _, stderr = _exec_popen(cmd)
        if ret_code:
            log_exit("Can not set mysql config mode, command: %s, output: %s" % (cmd, stderr))

    def clean_dir(self, dir_path):
        if not os.path.isdir(dir_path):
            return

        try:
            for filename in os.listdir(dir_path):
                file_path = os.path.join(dir_path, filename)
                # We can't remove file without permission write
                if os.path.isdir(file_path):
                    os.chmod(file_path, CommonValue.KEY_DIRECTORY_PERMISSION)
                    shutil.rmtree(file_path)
                else:
                    os.chmod(file_path, CommonValue.KEY_FILE_PERMISSION)
                    os.remove(file_path)
        except OSError:
            pass

    def prepare_given_path(self, one_path, check_empty=True):
        """
        function:
            make sure the path exist and user has private to access this path
        precondition:
            1.check_empty is True or False
            2.path list has been initialized
        input:
            1.path list
            2.check_empty
            3.path owner

        for each path in the path list
            save the path
            if path exist
                if need check empty
                    check empty
            else
                find the top path to be created
            create the path
            chown owner
            check permission
            check path size
        """
        log("Preparing path [%s]." % one_path)
        owner_path = one_path
        if (os.path.exists(one_path)):
            if (check_empty):
                file_list = os.listdir(one_path)
                if (len(file_list) != 0):
                    log_exit("Database path %s should be empty." % one_path)
        else:
            # create the given path
            log("Path [%s] does not exist. Please create it." % one_path)
            os.makedirs(one_path, 0o700)
            self.is_mkdir_prog = True

        # if the path already exist, just change the top path mode,
        # else change mode with -R
        # do not change the file mode in path if exist
        # found error: given path is /a/b/c, script path is /a/b/c/d,
        # then change mode with -R
        # will cause an error
        if owner_path != one_path:
            cmd = "chown -hR %s:%s %s; " % (self.user, self.group, owner_path)
            cmd += "chmod -R %s %s" % (CommonValue.KEY_DIRECTORY_MODE,
                                       owner_path)
        else:
            cmd = "chown %s:%s %s; " % (self.user, self.group, owner_path)
            cmd += "chmod %s %s" % (CommonValue.KEY_DIRECTORY_MODE, owner_path)

        log("cmd path %s" % cmd)
        ret_code, _, stderr = _exec_popen(cmd)
        if ret_code:
            log_exit(" Command: %s. Error:\n%s" % (cmd, stderr))

        # check permission
        log("check [%s] user permission" % one_path)
        permission_ok, stderr = self.check_permission(one_path)
        if not permission_ok:
            log_exit("Failed to check user [%s] path [%s] permission. Error: %s"
                     % (self.user, one_path, stderr))

    def prepare_mysql_data_dir(self):
        log("Preparing mysql data dir...")
        self.clean_dir(MYSQL_DATA_DIR)
        self.prepare_given_path(MYSQL_DATA_DIR, True)

    def prepare_mysql_bin_dir(self):
        log("Preparing mysql bin dir...")
        self.clean_dir(MYSQL_BIN_DIR)
        self.prepare_given_path(MYSQL_BIN_DIR, True)
        cmd = "cp -arf {} {};".format(os.path.join(MYSQL_CODE_DIR, "mysql_bin/mysql/*"), MYSQL_BIN_DIR)

        cmd += "cp %s/cfg/osd.cfg %s/bin/osd.cfg;" % (self.data, MYSQL_BIN_DIR)
        cmd += "chown -hR {}:{} {};".format(self.user, self.group, MYSQL_BIN_DIR)
        ret_code, _, stderr = _exec_popen(cmd)
        if ret_code:
            log_exit("Can not copy mysql bin, command: %s, output: %s" % (cmd, stderr))
        is_mysql_metadata_in_cantian = self.cantiand_configs.get("MYSQL_METADATA_IN_CANTIAN")
        if is_mysql_metadata_in_cantian == "TRUE":
            ctc_path = os.path.join(MYSQL_BIN_DIR, "lib/plugin/meta/ha_ctc.so")
        else:
            ctc_path = os.path.join(MYSQL_BIN_DIR, "lib/plugin/nometa/ha_ctc.so")
        if os.path.exists(ctc_path):
            mysql_plugin_path = os.path.join(MYSQL_BIN_DIR, "lib/plugin")
            shutil.copy(ctc_path, mysql_plugin_path)

    def set_mysql_env(self):
        log("Preparing mysql running env...")
        if 'LD_LIBRARY_PATH' in os.environ:
            os.environ['LD_LIBRARY_PATH'] = ("%s:%s:%s" % (
                os.path.join(MYSQL_BIN_DIR, "lib"),
                os.path.join(MYSQL_CODE_DIR, "daac_lib"),
                os.environ['LD_LIBRARY_PATH']))
        else:
            os.environ['LD_LIBRARY_PATH'] = ("%s:%s" % (
                os.path.join(MYSQL_BIN_DIR, "lib"), os.path.join(
                    MYSQL_CODE_DIR, "daac_lib")))
        cmd = "ldconfig -N %s %s" % (os.path.join(MYSQL_CODE_DIR, "daac_lib"), os.path.join(MYSQL_BIN_DIR, "lib"))
        ret_code, _, stderr = _exec_popen(cmd)
        if ret_code:
            log_exit("Can not link mysql lib, command: %s, output: %s" % (cmd, stderr))

    def prepare_mysql_for_single(self):
        if g_opts.running_mode.lower() not in VALID_SINGLE_MYSQL_RUNNING_MODE:
            return
        log("prepare_mysql_for_single")
        self.check_parameter_mysql()
        self.prepare_mysql_data_dir()
        self.prepare_mysql_bin_dir()
        self.set_mysql_env()


def check_archive_dir():
    if g_opts.db_type not in ['0', '1', '2']:
        log_exit("Invalid db_type : %s." % g_opts.db_type)
    if g_opts.db_type == '0' or g_opts.install_type == "reserve":
        return
    if g_opts.node_id == 1:
        return

    flags = os.O_RDONLY
    modes = stat.S_IWUSR | stat.S_IRUSR
    with os.fdopen(os.open(CANTIAN_START_STATUS_FILE, flags, modes), 'r') as load_fp:
        start_parameters = json.load(load_fp)
    if start_parameters.setdefault('db_create_status', "default") == "done":
        return

    cantian_check_share_logic_ip_isvalid(g_opts.archive_logic_ip)
    archive_dir = g_opts.archive_location.split("=")[1]
    if os.path.exists(archive_dir):
        files = os.listdir(archive_dir)
        for file in files:
            if (file[-4:] == ".arc" and file[:4] == "arch") or ("arch_file.tmp" in file):
                log_exit("archive dir %s is not empty, "
                         "history archive file or archive tmp file : %s." % (archive_dir, file))
    else:
        log_exit("archive dir %s is not exist." % archive_dir)
    log("checked the archive dir.")


class CanTian(object):
    g_opts.os_user, g_opts.os_group = get_value("deploy_user"), get_value("deploy_group")
    g_opts.install_type = get_value('install_type') if get_value('install_type') else "0"

    def cantian_pre_install(self):
        check_platform()
        parse_parameter()
        check_parameter()

    def cantian_install(self):
        parse_parameter()
        init_start_status_file()
        try:
            installer = Installer(g_opts.os_user, g_opts.os_group)
            installer.install()
            log("Install successfully, for more detail information see %s." % g_opts.log_file)
        except Exception as error:
            log_exit("Install failed: " + str(error))
            raise ValueError(str(error)) from error

    def cantian_start(self):
        try:
            flags = os.O_RDWR | os.O_CREAT
            modes = stat.S_IWUSR | stat.S_IRUSR
            with os.fdopen(os.open(CANTIAN_START_STATUS_FILE, flags, modes), 'w+') as load_fp:
                start_parameters = json.load(load_fp)
                start_status_item = {'start_status': "starting"}
                start_parameters.update(start_status_item)
                load_fp.seek(0)
                load_fp.truncate()
                json.dump(start_parameters, load_fp)

            parse_parameter()
            check_archive_dir()
            installer = Installer(g_opts.os_user, g_opts.os_group)
            installer.install_start()
            log("Start successfully, for more detail information see %s." % g_opts.log_file)

            flags = os.O_RDWR | os.O_CREAT
            with os.fdopen(os.open(CANTIAN_START_STATUS_FILE, flags, modes), 'w+') as load_fp:
                start_parameters = json.load(load_fp)
                start_status_item = {'start_status': "started"}
                start_parameters.update(start_status_item)
                ever_started_item = {'ever_started': True}
                start_parameters.update(ever_started_item)
                load_fp.seek(0)
                load_fp.truncate()
                json.dump(start_parameters, load_fp)

            sep_mark = os.path.sep
            cmd = "pidof cantiand"
            if g_opts.running_mode.lower() in [CANTIAND_WITH_MYSQL, CANTIAND_WITH_MYSQL_ST,
                                               CANTIAND_WITH_MYSQL_IN_CLUSTER]:
                cmd = "pidof mysqld"
            ret_code, cantiand_pid, stderr = _exec_popen(cmd)
            if ret_code:
                log_exit("can not get pid of cantiand or mysqld, command: %s, err: %s" % (cmd, stderr))
            cantiand_pid = cantiand_pid.strip(" ")
            if cantiand_pid is not None and len(cantiand_pid) > 0:
                cmd = "echo 0x6f > " + sep_mark + "proc" + sep_mark + str(cantiand_pid) + \
                      sep_mark + "coredump_filter"
                ret_code, cantiand_pid, stderr = _exec_popen(cmd)
                if ret_code:
                    log_exit("can not set coredump_filter, command: %s, err: %s" % (cmd, stderr))
                log("Set coredump_filter successfully")

        except Exception as error:
            log("Start failed: " + str(error))
            log("Please refer to install log \"%s\" for more detailed information." % g_opts.log_file)
            raise ValueError(str(error)) from error

    def post_check(self):
        log("Post upgrade check start.")
        installer = Installer(g_opts.os_user, g_opts.os_group)
        installer.decrypt_db_passwd()
        flags = os.O_RDONLY
        modes = stat.S_IWUSR | stat.S_IRUSR
        with os.fdopen(os.open(JS_CONF_FILE, flags, modes), 'r') as fp:
            json_data = json.load(fp)
            installer.install_path = json_data['R_INSTALL_PATH'].strip()
        installer.check_db_status()
        log("Post upgrade check success.")


if __name__ == "__main__":
    Func = CanTian()
    try:
        Func.cantian_install()
    except ValueError as err:
        exit(str(err))
    except Exception as err:
        exit(str(err))
    exit(0)

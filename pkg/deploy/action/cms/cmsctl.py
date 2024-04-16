#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Perform hot backups of CantianDB100 databases.
# Copyright © Huawei Technologies Co., Ltd. 2010-2018. All rights reserved.
import sys
import re
import grp
import os
import platform
import pwd
import shutil
import socket
import stat
import subprocess
import time
import copy
import json
import glob
from log import LOGGER
from get_config_info import get_value
sys.path.append('../')
try:
    from obtains_lsid import LSIDGenerate
except Exception as err:
    pass

PYTHON242 = "2.4.2"
PYTHON25 = "2.5"
gPyVersion = platform.python_version()
CUR_PATH, _ = os.path.split(os.path.abspath(__file__))
LOG_FILE = "/opt/cantian/cms/log/cms_deploy.log"

sys.dont_write_bytecode = True
FORCE_UNINSTALL = None
CHECK_MAX_TIMES = 7


class CommonValue(object):
    """
    common value for some variables
    """

    def __init__(self):
        pass

    MAX_FILE_MODE = 640
    MIN_FILE_MODE = 400
    KEY_FILE_MODE = 600
    MID_FILE_MODE = 500

    KEY_DIRECTORY_MODE = 700
    MAX_DIRECTORY_MODE = 750
    MIN_DIRECTORY_MODE = 550

    KEY_DIRECTORY_MODE_STR = '0700'

    MIN_FILE_PERMISSION = 0o400
    MID_FILE_PERMISSION = 0o500
    KEY_FILE_PERMISSION = 0o600
    KEY_DIRECTORY_PERMISSION = 0o700
    MAX_DIRECTORY_PERMISSION = 0o750
    MIN_DIRECTORY_PERMISSION = 0o550


CURRENT_OS = platform.system()

CANTIAND = "cantiand"
CANTIAND_WITH_MYSQL = "cantiand_with_mysql"
CANTIAND_WITH_MYSQL_ST = "cantiand_with_mysql_st"  # single process mode with mysql llt
CANTIAND_IN_CLUSTER = "cantiand_in_cluster"
CANTIAND_WITH_MYSQL_IN_CLUSTER = "cantiand_with_mysql_in_cluster"
MYSQLD = "mysqld"
CANTIAN_USER = get_value("deploy_user")
CANTIAN_GROUP = get_value("deploy_user")

VALID_RUNNING_MODE = {CANTIAND, CANTIAND_WITH_MYSQL, CANTIAND_WITH_MYSQL_ST, CANTIAND_IN_CLUSTER,
                      CANTIAND_WITH_MYSQL_IN_CLUSTER, MYSQLD}

VALID_SINGLE_MYSQL_RUNNING_MODE = {CANTIAND_WITH_MYSQL_IN_CLUSTER, CANTIAND_WITH_MYSQL_ST, CANTIAND_WITH_MYSQL}

CLUSTER_SIZE = 2  # default to 2, 4 node cluster mode need add parameter to specify this
CMS_TOOL_CONFIG_COUNT = 4

PKG_DIR = "/opt/cantian/image/cantian_connector"  # no use
MYSQL_CODE_DIR = os.path.join(PKG_DIR, "cantian-connector-mysql")
MYSQL_BIN_DIR = "/opt/cantian/mysql/install/mysql"
MYSQL_DATA_DIR = ""
MYSQL_LOG_FILE = ""

a_ascii = ord('a')
z_ascii = ord('z')
aa_ascii = ord('A')
zz_ascii = ord('Z')
num0_ascii = ord('0')
num9_ascii = ord('9')
blank_ascii = ord(' ')
sep1_ascii = ord(os.sep)
sep2_ascii = ord('_')
sep3_ascii = ord(':')
sep4_ascii = ord('-')
sep5_ascii = ord('.')
SEP_SED = r"\/"


def log(msg):
    """
    :param msg: log message
    :return: NA
    """
    LOGGER.info(msg)


def log_exit(msg):
    """
    :param msg: log message
    :return: NA
    """
    LOGGER.error(msg)
    if FORCE_UNINSTALL != "force":
        raise ValueError("FORCE_UNINSTALL is not force.")


def check_runner():
    """Check whether the user and owner of the script are the same."""
    owner_uid = os.stat(__file__).st_uid
    runner_uid = os.getuid()
    log("check runner and owner uid: %d %d" % (owner_uid, runner_uid))

    if owner_uid == 0:
        if runner_uid != 0:
            runner = pwd.getpwuid(runner_uid).pw_name
            log_exit("the owner of *.sh has root privilege,can't run it by user [%s]." % runner)
    else:
        if runner_uid == 0:
            owner = pwd.getpwuid(owner_uid).pw_name
            log_exit("the owner of *.sh is [%s],can't run it by root." % owner)
        elif runner_uid != owner_uid:
            runner = pwd.getpwuid(runner_uid).pw_name
            owner = pwd.getpwuid(owner_uid).pw_name
            log_exit("the owner of *.sh [%s] is different with the executor [%s]." % (owner, runner))


def _exec_popen(cmd, values=None):
    """
    subprocess.Popen in python2 and 3.
    param cmd: commands need to execute
    return: status code, standard output, error output
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
            stdout, stderr = pobj.communicate(timeout=1800)
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


def run_cmd(str_cmd, wrong_info):
    ret_code, stdout, stderr = _exec_popen(str_cmd)
    if ret_code:
        output = stdout + stderr
        log_exit("%s.\ncommand: %s.\noutput: %s" % (wrong_info, str_cmd, output))
    return stdout


def check_platform():
    """
    check platform
    Currently only supports Linux platforms.
    """
    log("check current os: %s" % CURRENT_OS)
    if CURRENT_OS is None or not CURRENT_OS.strip():
        log_exit("failed to get platform information.")
    if CURRENT_OS == "Linux":
        pass
    else:
        log_exit("this install script can not support %s platform." % CURRENT_OS)


def check_user(user, group):
    """Verify user legitimacy"""
    log("check user and group: %s:%s" % (user, group))
    try:
        user_ = pwd.getpwnam(user)
    except KeyError:
        log_exit("parameter input error: -U, the user does not exists.")

    try:
        group_ = grp.getgrnam(group)
    except KeyError:
        log_exit("parameter input error: -U, the group does not exists.")

    if user_.pw_gid != group_.gr_gid:
        log_exit("parameter input error: -U, the user does not match the group.")
    elif user == "root" or user_.pw_uid == 0:
        log_exit("parameter input error: -U, can not install program to"
                 " root user.")
    elif group == "root" or user_.pw_gid == 0:
        log_exit("parameter input error: -U, can not install program to"
                 " user with root privilege.")

    runner_uid = os.getuid()
    if runner_uid != 0 and runner_uid != user_.pw_uid:
        runner = pwd.getpwuid(runner_uid).pw_name
        log_exit("Parameter input error: -U, has to be the same as the"
                 " executor [%s]" % runner)


def check_path(path_type_in):
    """
    Check the validity of the path.
    :param path_type_in: path
    :return: weather validity
    """
    path_len = len(path_type_in)
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
        return check_path_linux(path_len, path_type_in, char_check_list1)
    elif CURRENT_OS == "Windows":
        return check_path_windows(path_len, path_type_in, char_check_list2)
    else:
        log("can not support this platform.")
        return False


def check_path_linux(path_len, path_type_in, char_check_list):
    for i in range(0, path_len):
        char_check = ord(path_type_in[i])
        if (not (a_ascii <= char_check <= z_ascii
                 or aa_ascii <= char_check <= zz_ascii
                 or num0_ascii <= char_check <= num9_ascii
                 or char_check in char_check_list)):
            return False
    return True


def check_path_windows(path_len, path_type_in, char_check_list):
    for i in range(0, path_len):
        char_check = ord(path_type_in[i])
        if (not (a_ascii <= char_check <= z_ascii
                 or aa_ascii <= char_check <= zz_ascii
                 or num0_ascii <= char_check <= num9_ascii
                 or char_check in char_check_list)):
            return False
    return True


def create_directory(needed, dir_name):
    if needed:
        return
    if not os.path.exists(dir_name):
        os.makedirs(dir_name, CommonValue.KEY_DIRECTORY_PERMISSION)


def genreg_string(text):
    """
    process text string
    param: text string
    output: new text string
    """
    if not text:
        return ""
    ins_str = text
    ins_list = ins_str.split(os.sep)
    reg_string = ""
    for i in ins_list:
        if (i == ""):
            continue
        else:
            reg_string += SEP_SED + i
    return reg_string

deploy_mode = get_value("deploy_mode")
cantian_in_container = get_value("cantian_in_container")
mes_type = get_value("mes_type") if deploy_mode != "nas" else "TCP"
mes_ssl_switch = get_value("mes_ssl_switch")
node_id = get_value("node_id")
storage_share_fs = get_value("storage_share_fs")

CMS_CONFIG = {
    "NODE_ID": 0,
    "GCC_HOME": "",  # generate by installer
    "GCC_DIR": "",  # generate by installer
    "GCC_TYPE": "",
    "_PORT": 14587,
    "_IP": "",  # input by user in command line parameter, same as CANTIAND_CONFIG#LSNR_ADDR
    "_LOG_LEVEL": 7,
    "_SPLIT_BRAIN": "TRUE",
    "_LOG_MAX_FILE_SIZE": "60M",
    "_DETECT_DISK_TIMEOUT": 100,
    "_DISK_DETECT_FILE": "gcc_file_detect_disk,",
    "_STOP_RERUN_CMS_SCRIPT": "/opt/cantian/action/cms/cms_reg.sh",
    "_EXIT_NUM_COUNT_FILE": "/opt/cantian/cms/cfg/exit_num.txt",
    "_CMS_NODE_FAULT_THRESHOLD": "6",
    "_CMS_MES_THREAD_NUM": "5",
    "_CMS_MES_MAX_SESSION_NUM": "40",
    "_CMS_MES_MESSAGE_POOL_COUNT": "1",
    "_CMS_MES_MESSAGE_QUEUE_COUNT": "1",
    "_CMS_MES_MESSAGE_BUFF_COUNT": "4096",
    "_CMS_MES_MESSAGE_CHANNEL_NUM": "1",
    "_CMS_GCC_BAK": "",  # generate by installer
    "_CLUSTER_ID": 0,
    "_USE_DBSTOR": "", # generate by installer
    "_DBSTOR_NAMESPACE": "", # generate by installer
    "_CMS_MES_PIPE_TYPE": mes_type
}
PRIMARY_KEYSTORE = "/opt/cantian/common/config/primary_keystore_bak.ks"
STANDBY_KEYSTORE = "/opt/cantian/common/config/standby_keystore_bak.ks"

MES_CONFIG = {
        "_CMS_MES_SSL_SWITCH": mes_ssl_switch,
        "_CMS_MES_SSL_KEY_PWD": None,
        "_CMS_MES_SSL_CRT_KEY_PATH": "/opt/cantian/common/config/certificates",
        "KMC_KEY_FILES": f"({PRIMARY_KEYSTORE}, {STANDBY_KEYSTORE})"
}

CMS_CONFIG.update(MES_CONFIG)


class NormalException(Exception):
    """
        Exception for exit(0)
    """


class CmsCtl(object):
    user = ""
    group = ""
    node_id = 0
    cluster_id = 0
    port = "14587"
    ip_addr = ""
    ip_cluster = "192.168.86.1;192.168.86.2"
    cluster_name = ""

    ipv_type = "ipv4"
    install_type = ""
    uninstall_type = ""
    cms_new_config = "/opt/cantian/cms/cfg/cms.json"
    cms_old_config = "/opt/cantian/backup/files/cms.json"
    cluster_config = "cluster.ini"

    gcc_home = ""
    gcc_dir = ""
    gcc_type = "NFS" if deploy_mode != "dbstore_unify" else "DBS"
    running_mode = "cantiand_in_cluster"
    install_config_file = "/root/tmp/install_ct_node0/config/deploy_param.json"
    link_type = "RDMA"
    cms_gcc_bak = ""

    install_step = 0
    storage_share_fs = ""
    storage_archive_fs = ""
    storage_metadata_fs = ""
    share_logic_ip = ""

    install_path = "/opt/cantian/cms/service"
    user_profile = ""
    cms_home = "/opt/cantian/cms"
    cms_scripts = "/opt/cantian/action/cms"
    user_home = ""
    use_gss = False
    use_dbstor = True if deploy_mode != "nas" else False
    mes_type = ""
    cluster_uuid = ""

    def __init__(self):
        install_config = "../../config/deploy_param.json"
        self.install_config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), install_config)

    @staticmethod
    def cms_check_share_logic_ip_isvalid(node_ip):
        """
        function: Check the nfs logic ip is valid
        input : ip
        output: NA
        """

        def ping_execute(p_cmd):
            cmd = "%s %s -i 1 -c 3 | grep ttl | wc -l" % (p_cmd, node_ip)
            ret_code, stdout, stderr = _exec_popen(cmd)
            if ret_code or stdout != '3':
                log("The invalid IP address is %s. "
                     "ret_code : %s, stdout : %s, stderr : %s" % (node_ip, ret_code, stdout, stderr))
                return False
            return True

        log("check the node IP address or domain name.")
        if not ping_execute("ping") and not ping_execute("ping6"):
            log_exit("checked the node IP address or domain name failed: %s" % node_ip)

        log("checked the node IP address or domain name success: %s" % node_ip)

    def load_path_config(self, load_dict):
        if "gcc_home" in load_dict:
            self.gcc_home = load_dict["gcc_home"]
        if "storage_share_fs" in load_dict:
            self.storage_share_fs = load_dict["storage_share_fs"]
        if "storage_archive_fs" in load_dict:
            self.storage_archive_fs = load_dict["storage_archive_fs"]
        if "storage_metadata_fs" in load_dict:
            self.storage_metadata_fs = load_dict["storage_metadata_fs"]
        if "user_profile" in load_dict:
            self.user_profile = load_dict["user_profile"]
        if "install_path" in load_dict:
            self.install_path = load_dict["install_path"]
        if "cms_home" in load_dict:
            self.cms_home = load_dict["cms_home"]
        if "user_home" in load_dict:
            self.user_home = load_dict["user_home"]
        if "install_config_file" in load_dict:
            self.install_config_file = load_dict["install_config_file"]
        if "cms_new_config" in load_dict:
            self.cms_new_config = load_dict["cms_new_config"]
        if "cms_gcc_bak" in load_dict:
            self.cms_gcc_bak = load_dict["cms_gcc_bak"]

    def load_cms_run_config(self, load_dict):
        if "cms_ip" in load_dict:
            self.ip_cluster = load_dict["cms_ip"]
        if "ip_cluster" in load_dict:
            self.ip_cluster = load_dict["ip_cluster"]
        if "node_id" in load_dict:
            self.node_id = int(load_dict["node_id"])
        if "cluster_id" in load_dict:
            self.cluster_id = int(load_dict["cluster_id"])
        if "gcc_type" in load_dict:
            self.gcc_type = load_dict["gcc_type"]
        if "port" in load_dict:
            self.port = load_dict["port"]
        if "ip_addr" in load_dict:
            self.ip_addr = load_dict["ip_addr"]
        if "running_mode" in load_dict:
            self.running_mode = load_dict["running_mode"]
        if "ipv_type" in load_dict:
            self.ipv_type = load_dict["ipv_type"]
        if "share_logic_ip" in load_dict:
            self.share_logic_ip = load_dict["share_logic_ip"]

    def load_user_config(self, load_dict):
        self.check_user_exist(load_dict)
        self.check_installation(load_dict)
        self.check_link_type(load_dict)
        if "cluster_name" in load_dict:
            self.cluster_name = load_dict["cluster_name"]
        if "mes_type" in load_dict:
            self.mes_type = mes_type

    def check_installation(self, load_dict):
        if "install_type" in load_dict and self.install_type != "reserve":
            self.install_type = load_dict["install_type"]
        if "install_step" in load_dict:
            self.install_step = load_dict["install_step"]

    def check_user_exist(self, load_dict):
        if "deploy_user" in load_dict:
            self.user, self.group = CANTIAN_USER, CANTIAN_GROUP
        if "user" in load_dict:
            self.user = load_dict["user"]
        if "group" in load_dict:
            self.group = load_dict["group"]

    def check_link_type(self, load_dict):
        if "link_type" in load_dict and (load_dict["link_type"] == "0" or load_dict["link_type"] == "TCP"):
            self.link_type = "TCP"
        if "link_type" in load_dict and (load_dict["link_type"] == "2" or load_dict["link_type"] == "RDMA_1823"):
            self.link_type = "RDMA_1823"

    def parse_parameters(self, config_file):
        if os.path.exists(config_file):
            flags = os.O_RDONLY | os.O_EXCL
            modes = stat.S_IWUSR | stat.S_IRUSR
            try:
                with os.fdopen(os.open(config_file, flags, modes), 'r') as load_f:
                    load_dict = json.load(load_f)
                    self.load_user_config(load_dict)
                    self.load_cms_run_config(load_dict)
                    self.load_path_config(load_dict)
                    node_str = "node" + str(self.node_id)
                    metadata_str = "metadata_" + self.storage_metadata_fs
                    global MYSQL_DATA_DIR
                    MYSQL_DATA_DIR = os.path.join("/mnt/dbdata/remote", metadata_str, node_str)
                    global MYSQL_LOG_FILE
                    MYSQL_LOG_FILE = os.path.join(MYSQL_DATA_DIR, "mysql.log")
            except OSError as ex:
                log_exit("get config file : %s" % str(ex))
        else:
            log_exit("the file does not exist : %s" % config_file)

    def set_cms_conf(self):
        conf_dict = {}
        conf_dict["user"] = self.user
        conf_dict["group"] = self.group
        conf_dict["node_id"] = self.node_id
        conf_dict["cluster_id"] = self.cluster_id
        conf_dict["gcc_home"] = self.gcc_home
        conf_dict["gcc_dir"] = self.gcc_dir
        conf_dict["gcc_type"] = self.gcc_type
        conf_dict["port"] = self.port
        conf_dict["ip_addr"] = self.ip_addr
        conf_dict["install_step"] = self.install_step
        conf_dict["user_profile"] = self.user_profile
        conf_dict["install_path"] = self.install_path
        conf_dict["running_mode"] = self.running_mode
        conf_dict["cms_home"] = self.cms_home
        conf_dict["user_home"] = self.user_home
        conf_dict["use_gss"] = self.use_gss
        conf_dict["use_dbstor"] = self.use_dbstor
        conf_dict["storage_share_fs"] = self.storage_share_fs
        conf_dict["storage_archive_fs"] = self.storage_archive_fs
        conf_dict["install_type"] = self.install_type
        conf_dict["uninstall_type"] = self.uninstall_type
        conf_dict["ipv_type"] = self.ipv_type
        conf_dict["link_type"] = self.link_type
        conf_dict["cms_new_config"] = self.cms_new_config
        conf_dict["ip_cluster"] = self.ip_cluster
        conf_dict["install_config_file"] = self.install_config_file
        conf_dict["share_logic_ip"] = self.share_logic_ip
        conf_dict["cluster_name"] = self.cluster_name
        conf_dict["cms_gcc_bak"] = self.cms_gcc_bak
        conf_dict["mes_type"] = self.mes_type

        log("set cms configs : %s" % (self.cms_new_config))
        flags = os.O_RDWR | os.O_CREAT | os.O_TRUNC
        modes = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP
        try:
            with os.fdopen(os.open(self.cms_new_config, flags, modes), "w") as file_object:
                json.dump(conf_dict, file_object)
        except OSError as ex:
            log_exit("failed to read config : %s" % str(ex))

    def set_conf(self, config, file):
        """
        function: set cantian, cms, gss conf
        input : config data
        input : config file name
        output: NA
        """
        conf_file = os.path.join(self.cms_home, "cfg", file)
        cmd = "echo >> %s" % conf_file
        run_cmd(cmd, "failed to write the %s" % file)

        config["_IP"] = self.ip_addr
        config["_PORT"] = self.port
        config["NODE_ID"] = self.node_id
        config["_CLUSTER_ID"] = self.cluster_id
        config["GCC_HOME"] = self.gcc_home  # generate by installer
        config["GCC_DIR"] = self.gcc_dir
        config["FS_NAME"] = self.storage_share_fs
        config["CLUSTER_NAME"] = self.cluster_name
        config["GCC_TYPE"] = self.gcc_type
        config["_CMS_GCC_BAK"] = self.cms_gcc_bak
        config["_USE_DBSTOR"] = self.use_dbstor
        config["_DBSTOR_NAMESPACE"] = self.cluster_name

        common_parameters = copy.deepcopy(config)

        if "GCC_TYPE" in common_parameters:
            common_parameters["GCC_DIR"] = common_parameters["GCC_HOME"]
            common_parameters["GCC_HOME"] = os.path.join(common_parameters["GCC_HOME"], "gcc_file")
        self.clean_old_conf(list(common_parameters.keys()), conf_file)
        self.set_new_conf(common_parameters, conf_file)

    def set_cluster_conf(self):
        """
        function: set cluster conf
        """
        conf_file = os.path.join(self.cms_home, "cfg", self.cluster_config)
        cmd = "echo >> %s" % conf_file
        run_cmd(cmd, "failed to write the %s" % conf_file)

        size = CLUSTER_SIZE
        if self.running_mode in [CANTIAND, CANTIAND_WITH_MYSQL, CANTIAND_WITH_MYSQL_ST]:
            size = 1
        node_ip = self.ip_cluster.split(";")
        if len(node_ip) == 1:
            node_ip.append("127.0.0.1")
        gcc_home = self.gcc_home
        gcc_dir = self.gcc_dir
        if self.gcc_type == "DBS" or self.gcc_type == "NFS":
            gcc_dir = gcc_home
            gcc_home = os.path.join(gcc_home, "gcc_file")
        if 'LD_LIBRARY_PATH' in os.environ:
            ld_library_path = ("%s:%s:%s" % (os.path.join(self.install_path, "lib"), os.path.join(
                    self.install_path, "add-ons",), os.environ['LD_LIBRARY_PATH']))
        else:
            ld_library_path = ("%s:%s" % (os.path.join(self.install_path, "lib"), os.path.join(
                self.install_path, "add-ons"),))
        common_parameters = {
            "GCC_HOME": gcc_home,
            "REPORT_FILE": LOG_FILE,
            "STATUS_LOG": os.path.join(self.cms_home, "log", "CmsStatus.log"),
            "LD_LIBRARY_PATH": ld_library_path,
            "USER_HOME": self.user_home,
            "USE_DBSTOR": self.use_dbstor,
            "USE_GSS": self.use_gss,
            "CLUSTER_SIZE": size,
            "NODE_ID": self.node_id,
            "NODE_IP[0]": node_ip[0],
            "NODE_IP[1]": node_ip[1],
            "CMS_PORT[0]": self.port,
            "CMS_PORT[1]": self.port,
            "LSNR_NODE_IP[0]": node_ip[0],
            "LSNR_NODE_IP[1]": node_ip[1],
            "USER": self.user,
            "GROUP": self.group,
            "MYSQL_CODE_DIR": MYSQL_CODE_DIR,
            "MYSQL_BIN_DIR": MYSQL_BIN_DIR,
            "MYSQL_DATA_DIR": MYSQL_DATA_DIR,
            "MYSQL_LOG_FILE": MYSQL_LOG_FILE,
        }
        self.clean_old_conf(list(common_parameters.keys()), conf_file)
        self.set_new_conf(common_parameters, conf_file)

    def set_new_conf(self, param_dict, conf_file):
        """
        function: echo 'key:value' conf to given conf file
        input : parameter dict, conf file name
        output: NA
        """
        cmd = ""
        for key, value in param_dict.items():
            cmd += "echo '%s = %s' >> %s;" % (key, value, conf_file)

        if cmd:
            cmd = cmd + "chmod 600 %s" % (conf_file)
            run_cmd(cmd, "failed to write the %s" % conf_file)

    def clean_old_conf(self, param_list, conf_file):
        """
        function: clean old conf in given conf file
        input : parameter list, conf file path
        output: NA
        """
        cmd = ""
        for parameter in param_list:
            cmd += "sed -i '/^%s/d' %s;" % (parameter.replace('[', '\[').replace(']', '\]'), conf_file)
        if cmd:
            cmd = cmd.strip(";")
            run_cmd(cmd, "failed to write the %s" % conf_file)

    def check_port(self, value, node_ip):
        """
        Check if the port is used in the installation parameters, and exit
        if the port is used.
        param value: port
        return: NA
        """
        log("check port: %s" % self.port)
        time_out, inner_port = self.check_inner_port(value)

        if self.ipv_type == "ipv6":
            socket_check = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
            socket_check = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        socket_check.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        socket_check.settimeout(time_out)
        if gPyVersion < PYTHON242:
            log_exit("this install script can not support python version"
                     " : " + gPyVersion)

        try:
            socket_check.bind((node_ip, inner_port))
        except socket.error as err_socket:
            socket_check.close()
            if (int(err_socket.errno) == 98 or int(err_socket.errno) == 95
                    or int(err_socket.errno) == 13):
                log("Error: port %s has been used,the detail"
                    " information is as follows:" % value)
                str_cmd = "netstat -unltp | grep %s" % value
                ret_code, stdout, stderr = _exec_popen(str_cmd)
                log_exit("can not get detail information of the"
                             " port, command:%s, output:%s, stderr:%s" % (str_cmd, str(stdout), stderr))

        socket_check.close()

    def check_inner_port(self, value):
        time_out = 2
        if not value:
            log_exit("the number of port is null.")
        if not value:
            log_exit("illegal number of port.")

        inner_port = int(value)
        if inner_port < 0 or inner_port > 65535:
            log_exit("illegal number of port.")
        if inner_port >= 0 and inner_port <= 1023:
            log_exit("system reserve port.")

        return time_out, inner_port

    def all_zero_addr_after_ping(self, nodeip):
        """
        check ip is all 0
        :param nodeip: ip addr
        :return: bool
        """
        if not nodeip:
            return False
        allowed_chars = set('0:.')
        if set(nodeip).issubset(allowed_chars):
            return True
        else:
            return False

    def check_ip_isvaild(self, nodeip):
        """
        function: Check the ip is valid
        input : ip
        output: NA
        """
        log("check the node IP address.")
        try:
            socket.inet_aton(nodeip)
        except socket.error:
            self.ipv_type = "ipv6"
            try:
                socket.inet_pton(socket.AF_INET6, nodeip)
            except socket.error:
                log_exit("the invalid IP address : %s is not ipv4 or ipv6 format." % nodeip)

        if self.ipv_type == "ipv6":
            ping_cmd = "ping6"
        else:
            ping_cmd = "ping"
        cmd = "%s %s -i 1 -c 3 | grep ttl | wc -l" % (ping_cmd, nodeip)
        ret_code, stdout, stderr = _exec_popen(cmd)

        if ret_code or stdout != '3':
            log_exit("The invalid IP address is %s. "
                     "ret_code : %s, stdout : %s, stderr : %s" % (nodeip, ret_code, stdout, stderr))

        ip_is_found = 1
        if nodeip in self.ip_addr:
            if self.all_zero_addr_after_ping(nodeip):
                ip_is_found = 1
            elif len(nodeip) != 0:
                ip_cmd = "/usr/sbin/ip addr | grep -w %s | wc -l" % nodeip
                ret_code, ip_is_found, stderr = _exec_popen(ip_cmd)
            else:
                ip_is_found = 0

        if ret_code or not int(ip_is_found):
            log_exit("The invalid IP address is %s. "
                     "ret_code : %s, ip_is_found : %s, stderr : %s" % (nodeip, ret_code, ip_is_found, stderr))

        log("checked the node IP address : %s" % nodeip)

    def change_app_permission(self):
        """
        function: after decompression install package, change file permission
        """
        str_cmd = "chmod %s %s -R" % (CommonValue.KEY_DIRECTORY_MODE,
                                      self.install_path)
        str_cmd += ("&& find '%s'/add-ons -type f | xargs chmod %s "
                    % (self.install_path, CommonValue.MID_FILE_MODE))
        str_cmd += ("&& find '%s'/admin -type f | xargs chmod %s "
                    % (self.install_path, CommonValue.MIN_FILE_MODE))
        str_cmd += ("&& find '%s'/lib -type f | xargs chmod %s"
                    % (self.install_path, CommonValue.MID_FILE_MODE))
        str_cmd += ("&& find '%s'/bin -type f | xargs chmod %s "
                    % (self.install_path, CommonValue.MID_FILE_MODE))
        str_cmd += ("&& find '%s'/cfg -type f | xargs chmod %s "
                    % (self.install_path, CommonValue.KEY_FILE_MODE))
        package_xml = os.path.join(self.install_path, "package.xml")
        if os.path.exists(package_xml):
            str_cmd += ("&& chmod %s '%s'/package.xml"
                        % (CommonValue.MIN_FILE_MODE, self.install_path))

        log("change app permission cmd: %s" % str_cmd)
        run_cmd(str_cmd, "failed to chmod %s" % CommonValue.KEY_DIRECTORY_MODE)
        if cantian_in_container == "0" and deploy_mode != "dbstore_unify":
            self.chown_gcc_dirs()

    def export_user_env(self):
        """
        set user environment values
        """
        flags = os.O_RDWR | os.O_EXCL
        modes = stat.S_IWUSR | stat.S_IRUSR
        try:
            with os.fdopen(os.open(self.user_profile, flags, modes), "a") as _file:
                _file.write("export CMS_HOME=\"%s\"" % self.cms_home)
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
                _file.flush()
                log("write export for cms_home, path, lib_path")
        except OSError as ex:
            log_exit("export user env : %s" % str(ex))

    def check_old_install(self):
        """
        is there a database installed by the user?
        :return: NA
        """
        log("check old install...")
        str_cmd = "echo ~"
        ret_code, stdout, stderr = _exec_popen(str_cmd)
        if ret_code:
            log_exit("failed to get user home."
                     "ret_code : %s, stdout : %s, stderr : %s" % (ret_code, stdout, stderr))
        output = os.path.realpath(os.path.normpath(stdout))
        if not check_path(output):
            log_exit("the user home directory is invalid.")
        self.user_profile = os.path.join(output, ".bashrc")
        self.user_home = output
        log("use user profile : " + self.user_profile)
        try:
            self.check_profile()
        except OSError as ex:
            log_exit("failed to check user profile : %s" % str(ex))
        log("end check old cms install.")

    def check_profile(self):
        """
        check cms_home value in user profile
        """
        is_find = False
        flags = os.O_RDWR | os.O_EXCL
        modes = stat.S_IWUSR | stat.S_IRUSR
        with os.fdopen(os.open(self.user_profile, flags, modes), "r") as _file:
            while True:
                str_line = _file.readline()
                if (not str_line):
                    break
                str_line = str_line.strip()
                if (str_line.startswith("#")):
                    continue
                user_info = str_line.split()
                if (len(user_info) >= 2 and user_info[0] == "export"
                        and user_info[1].startswith("CMS_HOME=") > 0):
                    is_find = True
                    break
                else:
                    continue
        if is_find:
            log_exit("CMS has been installed already.")

    def skip_execute_in_node_1(self):
        if self.running_mode in [CANTIAND_IN_CLUSTER, CANTIAND_WITH_MYSQL_IN_CLUSTER] and self.node_id == 1:
            return True
        return False

    def chown_gcc_dirs(self):
        """
        chown data and gcc dirs
        :return:
        """
        cmd = "chown %s:%s -hR \"%s\";" % (self.user, self.group, self.gcc_home)
        log("change owner cmd: %s" % cmd)
        self.cms_check_share_logic_ip_isvalid(self.share_logic_ip)
        log("if blocked here, please check if the network is normal")

        run_cmd(cmd, "failed to chown gcc dir: %s:%s" % (self.user, self.group))

    def prepare_gccdata_dir(self):
        log("prepare gcc home dir")
        self.cms_check_share_logic_ip_isvalid(self.share_logic_ip)
        log("if blocked here, please check if the network is normal")
        if deploy_mode != "dbstore_unify" and not os.path.exists(self.gcc_home):
            os.makedirs(self.gcc_home, CommonValue.KEY_DIRECTORY_PERMISSION)
            log("makedir for gcc_home %s" % (self.gcc_home))

    def install_xnet_lib(self):
        if self.is_rdma_startup():
            str_cmd = "cp -arf %s/add-ons/mlnx/lib* %s/add-ons/" % (self.install_path, self.install_path)
        elif self.is_rdma_1823_startup():
            str_cmd = "cp -arf %s/add-ons/1823/lib* %s/add-ons/" % (self.install_path, self.install_path)
        else:
            str_cmd = "cp -arf %s/add-ons/nomlnx/lib* %s/add-ons/" % (self.install_path, self.install_path)

        log("install xnet lib cmd: " + str_cmd)
        run_cmd(str_cmd, "failed to install xnet lib")

    def install_kmc_lib(self):
        str_cmd = "cp -arf %s/add-ons/kmc_shared/lib* %s/add-ons/" % (self.install_path, self.install_path)
        log("install kmc lib cmd: " + str_cmd)
        run_cmd(str_cmd, "failed to install kmc lib")

    def is_mlnx(self):
        """
        is_mlnx
        """
        ret_code, stdout, stderr = _exec_popen("which ofed_info")
        if ret_code:
            log("no ofed_info cmd found"
                "ret_code : %s, stdout : %s, stderr : %s" % (ret_code, stdout, stderr))
            return False

        ret_code, stdout, stderr = _exec_popen("ofed_info -s")
        if ret_code:
            log("exec ofed_info cmd failed"
                "ret_code : %s, stdout : %s, stderr : %s" % (ret_code, stdout, stderr))
            return False

        if 'MLNX_OFED_LINUX-5.5' in stdout:
            log("mlnx version 5.5")
            return True

        ret_code, os_arch, stderr = _exec_popen("uname -i")
        if ret_code:
            log_exit("failed to get linux release version."
                     "ret_code : %s, os_arch : %s, stderr : %s" % (ret_code, os_arch, stderr))
        aarch_mlnx_version_list = ['OFED-internal-5.8-2.0.3', 'MLNX_OFED_LINUX-5.8', 'MLNX_OFED_LINUX-5.9']
        aarch_version_check_result = any(mlnx_version if mlnx_version in stdout else False
            for mlnx_version in aarch_mlnx_version_list)
        if os_arch == "aarch64" and aarch_version_check_result == True:
            log("Is mlnx 5.8~5.9")
            return True

        log("Not mlnx 5.5")
        return False

    def is_hinicadm3(self):
        ret_code, _, sterr = _exec_popen("whereis hinicadm3")
        if ret_code:
            log("can not find hinicadm3")
            return False
        return True

    def is_rdma_startup(self):
        """
        is_rdma_startup
        """
        return self.link_type == "RDMA" and self.is_mlnx()

    def is_rdma_1823_startup(self):
        return self.link_type == "RDMA_1823" and self.is_hinicadm3()

    def check_parameter_install(self):
        if self.ip_cluster != "":
            _list = self.ip_cluster.split(';')
            self.ip_addr = _list[self.node_id]
            for item in re.split(r"[;,]", self.ip_cluster):
                if len(_list) != 1 and self.all_zero_addr_after_ping(item):
                    log_exit("ip contains all-zero ip,"
                             " can not specify other ip.")
                if cantian_in_container == "0":
                    self.check_ip_isvaild(item)
        else:
            self.ip_addr = "127.0.0.1"

        for _ip in self.ip_addr.split(","):
            self.check_port(self.port, _ip)

        if cantian_in_container == "0":
            self.cms_check_share_logic_ip_isvalid(self.share_logic_ip)

        log("check running mode: %s" % self.running_mode)
        if self.running_mode not in VALID_RUNNING_MODE:
            log_exit("Invalid running mode: " + str(self.node_id))
        log("check node id: %d" % self.node_id)
        if self.node_id not in [0, 1]:
            log_exit("invalid node id: " + str(self.node_id))

    def copy_app_files(self):
        """
        bin/lib files and script files
        """
        if not os.path.exists(self.install_path):
            os.makedirs(self.install_path, CommonValue.KEY_DIRECTORY_PERMISSION)
        cms_pkg_file = "/opt/cantian/image/Cantian-RUN-CENTOS-64bit"
        str_cmd = ("cp -arf %s/add-ons %s/admin %s/bin %s/cfg %s/lib %s/package.xml %s"
                   % (cms_pkg_file, cms_pkg_file, cms_pkg_file,
                      cms_pkg_file, cms_pkg_file, cms_pkg_file,
                      self.install_path))
        log("copy install files cmd: " + str_cmd)
        run_cmd(str_cmd, "failed to install cms lib files")

        if deploy_mode != "nas":
            self.install_xnet_lib()
            self.install_kmc_lib()

    def pre_install(self):

        check_platform()
        check_runner()

        if self.install_type not in ["override", "reserve"]:
            log_exit("wrong install type")
        if self.install_type != "override":
            log("check install type : reserve cms")
            self.parse_parameters(self.cms_old_config)
            self.__init__()
        else:
            log("check install type : override cms")
            self.parse_parameters(self.install_config_file)
            if deploy_mode == "dbstore_unify":
                self.gcc_home = os.path.join("/", self.storage_share_fs, str(self.cluster_name) + "_cms", "gcc_home")
            else:
                self.gcc_home = os.path.join("/mnt/dbdata/remote/share_" + self.storage_share_fs, "gcc_home")
            self.gcc_dir = self.gcc_home
            self.cms_gcc_bak = os.path.join("/mnt/dbdata/remote", "archive_" + self.storage_archive_fs)

        log("======================== begin to pre_install cms configs ========================")

        check_user(self.user, self.group)
        if deploy_mode != "dbstore_unify" and not check_path(self.gcc_home):
            log_exit("the gcc home directory is invalid.")

        self.check_parameter_install()
        self.check_old_install()
        self.install_step = 1
        self.set_cms_conf()
        log("======================== pre_install cms configs successfully ========================")

    def prepare_cms_tool_dbstor_config(self):
        for i in range(10, CMS_TOOL_CONFIG_COUNT + 10):
            file_num = i - 9
            uuid_generate = LSIDGenerate(2, self.cluster_id, i, self.node_id)
            inst_id, cms_tool_uuid = uuid_generate.execute()
            str_cmd = ("cp -raf /opt/cantian/dbstor/tools/dbstor_config.ini"
                       " %s/dbstor/conf/dbs/dbstor_config_tool_%s.ini" % (self.cms_home, str(file_num)))
            str_cmd += " && echo 'DBSTOR_OWNER_NAME = cms' >> %s/dbstor/conf/dbs/dbstor_config_tool_%s.ini" % (
                self.cms_home, str(file_num))
            str_cmd += " && echo 'CLUSTER_NAME = %s' >> %s/dbstor/conf/dbs/dbstor_config_tool_%s.ini" % (
                self.cluster_name, self.cms_home, str(file_num))
            str_cmd += " && echo 'CLUSTER_UUID = %s' >> %s/dbstor/conf/dbs/dbstor_config_tool_%s.ini" % (
                self.cluster_uuid, self.cms_home, str(file_num))
            str_cmd += (" && echo 'INST_ID = %s' >> %s/dbstor/conf/dbs/dbstor_config_tool_%s.ini"
                        % (inst_id, self.cms_home, str(file_num)))
            str_cmd += " && echo 'CMS_TOOL_UUID = %s' >> %s/dbstor/conf/dbs/dbstor_config_tool_%s.ini" % (
                cms_tool_uuid, self.cms_home, str(file_num))
            str_cmd += (" && sed -i '/^\s*$/d' %s/dbstor/conf/dbs/dbstor_config_tool_%s.ini"
                        % (self.cms_home, str(file_num)))
            str_cmd += " && chown -R %s:%s %s/dbstor" % (self.user, self.group, self.cms_home)
            str_cmd += " && chmod 640 %s/dbstor/conf/dbs/dbstor_config_tool_%s.ini" % (self.cms_home, str(file_num))
            ret_code, stdout, stderr = _exec_popen(str_cmd)
            if ret_code:
                log_exit("prepare cms tool dbstor config file failed, return: " +
                         str(ret_code) + os.linesep + stdout + os.linesep + stderr)

    def copy_dbstor_config(self):
        if os.path.exists(os.path.join(self.cms_home, "dbstor")):
            shutil.rmtree(os.path.join(self.cms_home, "dbstor"))

        os.makedirs("%s/dbstor/conf/dbs" % self.cms_home, CommonValue.KEY_DIRECTORY_PERMISSION)
        os.makedirs("%s/dbstor/conf/infra/config" % self.cms_home, CommonValue.KEY_DIRECTORY_PERMISSION)
        os.makedirs("%s/dbstor/data/logs" % self.cms_home, CommonValue.KEY_DIRECTORY_PERMISSION)
        os.makedirs("%s/dbstor/data/ftds" % self.cms_home, CommonValue.KEY_DIRECTORY_PERMISSION)
        if self.is_rdma_startup() or self.is_rdma_1823_startup():
            str_cmd = "cp -rfa %s/cfg/node_config_rdma_cms.xml %s/dbstor/conf/infra/config/node_config.xml" % (
                self.install_path, self.cms_home)
        else:
            str_cmd = "cp -raf %s/cfg/node_config_tcp_cms.xml %s/dbstor/conf/infra/config/node_config.xml" % (
                self.install_path, self.cms_home)

        generate_cluster_uuid = LSIDGenerate(0, self.cluster_id, 0, 0)
        generate_inst_id = LSIDGenerate(2, self.cluster_id, 0, self.node_id)
        _, self.cluster_uuid = generate_cluster_uuid.execute()
        inst_id, _ = generate_inst_id.execute()
        str_cmd += " && cp -raf %s/cfg/osd.cfg %s/dbstor/conf/infra/config/osd.cfg" % (self.install_path, self.cms_home)
        str_cmd += " && cp -raf /opt/cantian/dbstor/tools/dbstor_config.ini %s/dbstor/conf/dbs/" % (self.cms_home)
        str_cmd += " && echo 'DBSTOR_OWNER_NAME = cms' >> %s/dbstor/conf/dbs/dbstor_config.ini" % (self.cms_home)
        str_cmd += (" && echo 'CLUSTER_NAME = %s' >> %s/dbstor/conf/dbs/dbstor_config.ini"
                    % (self.cluster_name, self.cms_home))
        str_cmd += (" && echo 'CLUSTER_UUID = %s' >> %s/dbstor/conf/dbs/dbstor_config.ini"
                    % (self.cluster_uuid, self.cms_home))
        str_cmd += " && echo 'INST_ID = %s' >> %s/dbstor/conf/dbs/dbstor_config.ini" % (inst_id, self.cms_home)
        str_cmd += " && sed -i '/^\s*$/d' %s/dbstor/conf/dbs/dbstor_config.ini" % (self.cms_home)
        str_cmd += " && chown -R %s:%s %s/dbstor" % (self.user, self.group, self.cms_home)
        str_cmd += " && chmod 640 %s/dbstor/conf/dbs/dbstor_config.ini" % (self.cms_home)

        log("copy config files cmd: " + str_cmd)
        ret_code, stdout, stderr = _exec_popen(str_cmd)
        if ret_code:
            log_exit("copy dbstor config file failed, return: " +
                     str(ret_code) + os.linesep + stdout + os.linesep + stderr)

    def install(self):
        """
        install cms process, copy bin
        """
        log("======================== begin to install cms ========================")
        if self.install_step == 2:
            log("cms install already")
            log("======================== install cms module successfully ========================")
            return
        if self.install_step == 0:
            log_exit("please run pre_install previously")

        self.copy_app_files()

        if cantian_in_container == "0":
            self.prepare_gccdata_dir()
        self.export_user_env()
        self.change_app_permission()

        self.set_cluster_conf()
        self.set_conf(CMS_CONFIG, "cms.ini")
        if deploy_mode != "nas":
            self.copy_dbstor_config()
        if deploy_mode == "dbstore_unify":
            self.prepare_cms_tool_dbstor_config()

        cmd = "sh %s -P install_cms >> %s 2>&1" % (os.path.join(self.cms_scripts, "start_cms.sh"), LOG_FILE)
        run_cmd(cmd, "failed to set cms node information")

        self.install_step = 2
        self.set_cms_conf()

        log("======================== install cms module successfully ========================")

    def check_start_status(self):
        """
        cms启动后检查server和voting状态，确保在拉起cantiand前cms状态正常
        """
        server_status_cmd = "source ~/.bashrc && cms stat -server %s | grep -v \"NODE_ID\" | awk '{print $2}'" \
                            % self.node_id
        voting_status_cmd = "source ~/.bashrc && cms node -connected | awk '{print $1, $NF}' | grep -v \"VOTING\""
        timeout = 30
        while timeout:
            timeout -= 1
            try:
                server_status = run_cmd(server_status_cmd, "failed query cms server status")
            except ValueError as _err:
                time.sleep(1)
                continue
            if server_status == "TRUE":
                log("Current cms server status is %s" % server_status)
                break
            log("Current cms server status is %s" % server_status)
            time.sleep(1)
        else:
            log_exit("Query cms server status timeout")
        time.sleep(15)
        timeout = 30
        while timeout:
            timeout -= 1
            try:
                voting_status = run_cmd(voting_status_cmd, "failed to query voting status")
            except ValueError as _err2:
                time.sleep(1)
                continue
            if not voting_status:
                time.sleep(1)
                continue
            for node_voting_status in voting_status.strip().split("\n"):
                _node_id, status = node_voting_status.split(" ")
                if int(_node_id) == int(self.node_id) and status == "FALSE":
                    log("Current cms voting status is %s" % node_voting_status)
                    return
            log("Current cms voting status is %s" % voting_status)
            time.sleep(1)
        else:
            log_exit("Query cms voting status timeout")

    def start(self):
        """
        start cms process: check>>start>>change status
        """
        log("========================= begin to start cms process ========================")
        if self.install_step <= 1:
            log_exit("please run install previously")
        if self.install_step == 3:
            log("warning: cms started already")
            log("========================= start cms process successfully ========================")
            return
        cmd = "sh %s -P start_cms >> %s 2>&1" % (os.path.join(self.cms_scripts, "start_cms.sh"), LOG_FILE)
        run_cmd(cmd, "failed to start cms process")

        self.install_step = 3
        self.set_cms_conf()
        self.check_start_status()
        log("======================== start cms process successfully ========================")

    def check_status(self):
        """
        check cms process status
        """
        log("======================== begin to check cms process status ========================")
        if self.install_step <= 1:
            log_exit("please install cms previously")
        cmd = "source ~/.bashrc && %s/bin/cms stat -server 2>&1" % self.install_path
        stdout = run_cmd(cmd, "can not check cms process status")
        node_list = stdout.split("\n")[1:]
        for node_info in node_list:
            _node_id = node_info.split(" ")[0].strip(" ")
            if self.node_id == int(_node_id) and "TRUE" in node_info:
                log("======================== check cms process status successfully ========================")
                return
        log_exit("check cms process status failed")

    def stop(self):
        """
        stop cms process: kill>>change status
        """
        log("======================== begin to stop the cms process ========================")
        cms_processes = ["cms server", "cmsctl.py start", "cms/start.sh", "start_cms.sh"]
        for cms_process in cms_processes:
            self.kill_process(cms_process)
            self.check_process_status(cms_process)

        self.install_step = 2
        self.set_cms_conf()
        log("======================== stop the cms successfully ========================")

    def check_gcc_home_process(self):
        """
        删除gcc_home失败时，打印出当前暂用文件的进程
        :return:
        """
        if deploy_mode == "dbstore_unify":
            return
        gcc_home_path = "/mnt/dbdata/remote/share_%s/gcc_home/" % self.storage_share_fs
        remain_files = os.listdir(gcc_home_path)
        for file in remain_files:
            cmd = "lsof %s/%s | grep -v PID | awk '{print $2}'" % (gcc_home_path, file)
            ret_code, stdout, stderr = _exec_popen(cmd)
            if stdout:
                pid_list = stdout.split("\n")
                for pid in pid_list:
                    _cmd = "ps -ef | grep %s | grep -v grep" % pid
                    ret_code, _stdout, stderr = _exec_popen(cmd)
                    if _stdout:
                        log("gcc_home occupied by a process:%s" % _stdout)

    def uninstall(self):
        """
        uninstall cms: environment values and app files
        """
        log("======================== begin to uninstall cms module ========================")

        if deploy_mode != "dbstore_unify" and self.gcc_home == "":
            self.gcc_home = os.path.join("/mnt/dbdata/remote/share_" + self.storage_share_fs, "gcc_home")
        if self.node_id == 0:
            if cantian_in_container == "0":
                self.cms_check_share_logic_ip_isvalid(self.share_logic_ip)
                log("if blocked here, please check if the network is normal")
            if deploy_mode != "dbstore_unify":
                str_cmd = "rm -rf %s" % (self.gcc_home)
                ret_code, stdout, stderr = _exec_popen("timeout 10 ls %s" % self.gcc_home)
            else:
                str_cmd = "cms gcc -del"
                ret_code = 0
            if ret_code == 0:
                log("clean gcc home cmd : %s" % str_cmd)
                ret_code, stdout, stderr = _exec_popen(str_cmd)
                if ret_code and deploy_mode == "dbstore_unify" and self.install_step < 2:
                    log("cms install failed, no need to clean gcc file")
                elif ret_code:
                    output = stdout + stderr
                    self.check_gcc_home_process()
                    log_exit("failed to remove gcc home.\ncommand: %s.\noutput: %s \
                              \npossible reasons: \
                              \n1. user was using cms tool when uninstall. \
                              \n2. cms has not stopped. \
                              \n3. dbstor link was error. \
                              \n4. others, please contact the engineer to solve." % (str_cmd, output))
            elif FORCE_UNINSTALL != "force" and ret_code != 2:
                log_exit("can not connect to remote %s"
                         "ret_code : %s, stdout : %s, stderr : %s" % (self.gcc_home, ret_code, stdout, stderr))

        self.clean_environment()
        self.clean_install_path()

        str_cmd = "rm -rf {0}/cms_server.lck {0}/local {0}/gcc_backup {0}/cantian.ctd.cms*".format(
            self.cms_home)
        run_cmd(str_cmd, "failed to remove running files in cms home")
        log("======================== uninstall cms module successfully ========================")

    def backup(self):
        """
        save cms config
        """
        log("======================== begin to backup config files ========================")
        config_json = os.path.join(self.cms_home, "cfg/cms.json")
        if os.path.exists(config_json):
            str_cmd = ("cp -arf %s/cfg/* %s" % (self.cms_home, os.path.dirname(self.cms_old_config)))
            log("save cms json files cmd: " + str_cmd)
            run_cmd(str_cmd, "failed to save cms config files")
        else:
            log_exit("the file does not exist : %s" % config_json)
        log("======================== backup config files successfully ========================")

    def upgrade(self):
        log("======================== begin to upgrade cms dbstor config ========================")
        if deploy_mode == "dbstore_unify" and not glob.glob("%s/dbstor/conf/dbs/dbstor_config_tool*" % self.cms_home):
            self.copy_dbstor_config()
            self.prepare_cms_tool_dbstor_config()

        log("======================== upgrade cms dbstor config successfully ========================")

    def kill_process(self, process_name):
        """
        kill process
        input: process name
        output: NA
        """
        kill_cmd = (r"proc_pid_list=`ps ux | grep '%s' | grep -v grep"
                        r"|awk '{print $2}'` && " % process_name)
        kill_cmd += (r"(if [[ X\"$proc_pid_list\" != X\"\" ]];then echo "
                         r"$proc_pid_list | xargs kill -9; fi)")
        log("kill process cmd: %s" % kill_cmd)
        run_cmd(kill_cmd, "failed to kill process %s" % process_name)

    def get_pid(self, process_name):
        """
        get pid
        intput: process name
        output: pid
        """
        get_cmd = "ps ux | grep '%s' | grep -v grep | awk '{print $2}'" % process_name
        log("get process cmd: %s" % get_cmd)
        ret_code, stdout, stderr = _exec_popen(get_cmd)
        if ret_code:
            log_exit("Failed to get %s pid. cmd: %s. Error: %s" % (process_name, get_cmd, stderr))
        return stdout

    def check_process_status(self, process_name):
        """
        check process status
        intput: process_name
        output: NA
        """
        for i in range(CHECK_MAX_TIMES):
            pid = self.get_pid(process_name)
            if pid:
                log("checked %s times, %s pid is %s" % (i + 1, process_name, pid))
                if i != CHECK_MAX_TIMES - 1:
                    time.sleep(5)
            else:
                return
        log_exit("Failed to kill %s. It is still alive after 30s." % process_name)

    def clean_install_path(self):
        """
        clean install path
        input: NA
        output: NA
        """
        log("cleaning install path...")
        if os.path.exists(self.install_path):
            shutil.rmtree(self.install_path)
        if os.path.exists(os.path.join(self.cms_home, "cfg")):
            shutil.rmtree(os.path.join(self.cms_home, "cfg"))
        if os.path.exists(os.path.join(self.cms_home, "dbstor/conf")):
            shutil.rmtree(os.path.join(self.cms_home, "dbstor/conf"))
        if os.path.exists(os.path.join(self.cms_home, "dbstor/data/ftds")):
            shutil.rmtree(os.path.join(self.cms_home, "dbstor/data/ftds"))
        log("end clean install path")

    def clean_environment(self):
        """
        clean environment variable
        input: NA
        output: NA
        """
        log("cleaning user environment variables...")
        path_cmd = (r"/^\s*export\s*PATH=\"%s\/bin\":\$PATH$/d"
                    % genreg_string(self.install_path))
        lib_cmd = (r"/^\s*export\s*LD_LIBRARY_PATH=\"%s\/lib\":\"%s\/add-ons\".*$/d"
                   % (genreg_string(self.install_path),
                      genreg_string(self.install_path)))
        cms_cmd = r"/^\s*export\s*CMS_HOME=\".*\"$/d"

        cmds = [path_cmd, lib_cmd, cms_cmd]
        if self.user_profile == "":
            self.user_profile = os.path.join("/home", self.user, ".bashrc")
        for cmd in cmds:
            cmd = 'sed -i "%s" "%s"' % (cmd, self.user_profile)
            run_cmd(cmd, "failed to clean environment variables")
        log("end clean user environment variables")


def main():

    cms = CmsCtl()

    if len(sys.argv) > 3 and sys.argv[1] == "uninstall" and sys.argv[2] == "override":
        global FORCE_UNINSTALL
        FORCE_UNINSTALL = sys.argv[3]
    if len(sys.argv) > 1 and sys.argv[1]:
        arg = sys.argv[1]
        if arg == "pre_install":
            cms.parse_parameters(cms.install_config_file)
            cms.pre_install()
        if arg == "install":
            cms.parse_parameters(cms.cms_new_config)
            cms.install()

        if arg in {"start", "check_status", "stop", "uninstall", "backup", "upgrade"}:

            if os.path.exists("/opt/cantian/cms/cfg/cms.json"):
                install_cms_cfg = "/opt/cantian/cms/cfg/cms.json"
            else:
                install_cms_cfg = cms.install_config_file

            cms.parse_parameters(install_cms_cfg)
            if arg == "start":
                cms.start()
            if arg == "check_status":
                cms.check_status()
            if arg == "stop":
                cms.stop()
            if arg == "backup":
                cms.backup()
            if arg == "uninstall":
                cms.uninstall()
            if arg == "upgrade":
                cms.upgrade()


if __name__ == "__main__":
    try:
        main()
    except ValueError as err:
        exit(str(err))
    exit(0)

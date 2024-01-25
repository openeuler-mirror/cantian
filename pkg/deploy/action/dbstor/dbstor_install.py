#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Perform hot backups of CantianDB100 databases.
# Copyright © Huawei Technologies Co., Ltd. 2010-2018. All rights reserved.


import sys

sys.dont_write_bytecode = True
DBSTOR_WARN_TYPE = 0

try:
    import os
    import platform
    import copy
    import grp
    import pwd
    import time
    import json
    import sys
    import stat
    import tty
    import readline
    import termios
    import subprocess
    import logging
    import socket
    from configparser import ConfigParser
    from kmc_adapter import CApiWrapper

    DBSTORE_LOG_PATH = "/opt/cantian/dbstor"
    LOG_PATH = "/opt/cantian/dbstor/log"
    LOG_FILE = "/opt/cantian/dbstor/log/install.log"
    JS_CONF_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../config/deploy_param.json")
    DBSTOR_CONF_FILE = "/mnt/dbdata/remote/share_"
    DOCKER_DBSTOR_CONF_FILE = "/home/regress/cantian_data"
    BACKUP_CONF_FILE = "/opt/cantian/backup/files"
    SECTION = 'CLIENT'
    MAX_DIRECTORY_MODE = 0o755
    PYTHON242 = "2.4.2"
    PYTHON25 = "2.5"
    gPyVersion = platform.python_version()

    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger_handle = logging.FileHandler(LOG_FILE, 'a', "utf-8")

    logger_handle.setLevel(logging.DEBUG)
    logger_formatter = logging.Formatter('[%(asctime)s]-[%(filename)s]-[line:%(lineno)d]-[%(levelname)s]-'
                                '%(message)s-[%(process)s]')
    logger_handle.setFormatter(logger_formatter)
    logger.addHandler(logger_handle)
    logger.info("init logging success")

    if PYTHON242 <= gPyVersion < PYTHON25:
        import sha256
    elif gPyVersion >= PYTHON25:
        pass
    else:
        import_msg = "This install script can not support python version: %s" % gPyVersion
        logger.info(import_msg)
        raise ValueError(import_msg)
    sys.path.append(os.path.split(os.path.realpath(__file__))[0])
    sys.dont_write_bytecode = True
except ImportError as error_msg:
    raise ValueError("Unable to import module: %s." % str(error_msg)) from error_msg
CURRENT_OS = platform.system()
TIMEOUT_COUNT = 1800
GLOBAL_KMC_EXT = None


class ReadConfigParserNoCast(ConfigParser):
    "Inherit from built-in class: ConfigParser"
    def optionxform(self, optionstr):
        "Rewrite without lower()"
        return optionstr


def check_path(path_type_in):
    """
    Check the validity of the path.
    :param path_type_in: path
    :return: weather validity
    """
    path_len = len(path_type_in)
    ascii_map = {'a_ascii': ord('a'), 'z_ascii': ord('z'), 'a_upper_ascii': ord('A'), 'z_upper_ascii': ord('Z'),
                 'num0_ascii': ord('0'), 'num9_ascii': ord('9'), 'blank_ascii': ord(' '), 'sep1_ascii': ord(os.sep),
                 'sep2_ascii': ord('_'), 'sep3_ascii': ord(':'), 'sep4_ascii': ord('-'), 'sep5_ascii': ord('.')}
    char_check_list1 = [ascii_map.get('blank_ascii', 0),
                        ascii_map.get('sep1_ascii', 0),
                        ascii_map.get('sep2_ascii', 0),
                        ascii_map.get('sep4_ascii', 0),
                        ascii_map.get('sep5_ascii', 0)
                        ]

    char_check_list2 = [ascii_map.get('blank_ascii', 0),
                        ascii_map.get('sep1_ascii', 0),
                        ascii_map.get('sep2_ascii', 0),
                        ascii_map.get('sep3_ascii', 0),
                        ascii_map.get('sep4_ascii', 0)
                        ]
    if CURRENT_OS == "Linux":
        return check_path_linux(path_len, path_type_in, ascii_map, char_check_list1)
    elif CURRENT_OS == "Windows":
        return check_path_windows(path_len, path_type_in, ascii_map, char_check_list2)
    else:
        message = "Error: Can not support this platform."
        logger.info(message)
        raise ValueError(message)


def check_path_linux(path_len, path_type_in, ascii_map, char_check_list):
    for i in range(0, path_len):
        char_check = ord(path_type_in[i])
        if (not (ascii_map.get('a_ascii', 0) <= char_check <= ascii_map.get('z_ascii', 0)
                 or ascii_map.get('a_upper_ascii', 0) <= char_check <= ascii_map.get('z_upper_ascii', 0)
                 or ascii_map.get('num0_ascii', 0) <= char_check <= ascii_map.get('num9_ascii', 0)
                 or char_check in char_check_list)):
            return False
    return True


def check_path_windows(path_len, path_type_in, ascii_map, char_check_list):
    for i in range(0, path_len):
        char_check = ord(path_type_in[i])
        if (not (ascii_map.get('a_ascii', 0) <= char_check <= ascii_map.get('z_ascii', 0)
                 or ascii_map.get('a_upper_ascii', 0) <= char_check <= ascii_map.get('z_upper_ascii', 0)
                 or ascii_map.get('num0_ascii', 0) <= char_check <= ascii_map.get('num9_ascii', 0)
                 or char_check in char_check_list)):
            return False
    return True


def console_and_log(msg):
    """
    Print log
    :param msg: log message
    :param is_screen
    :return: NA
    """
    print(msg)
    logger.info(msg)


def log_exit(msg):
    """
    Print log and exit
    :param msg: log message
    :return: NA
    """
    console_and_log("Error: " + msg)
    print("Please refer to install log \"%s\" for more detailed information."
          % LOG_FILE)
    raise ValueError(str(msg))


def check_runner():
    """Check whether the user and owner of the script are the same."""
    owner_uid = os.stat(__file__).st_uid
    runner_uid = os.getuid()
    # Owner is root
    if owner_uid == 0:
        if runner_uid != 0:
            runner = pwd.getpwuid(runner_uid).pw_name
            log_exit("Error: The owner of install.py has root privilege,"
                  " can't run it by user [%s]." % runner)
    else:
        if runner_uid == 0:
            owner = pwd.getpwuid(owner_uid).pw_name
            log_exit("Error: The owner of install.py is [%s],"
                  " can't run it by root." % owner)
        elif runner_uid != owner_uid:
            runner = pwd.getpwuid(runner_uid).pw_name
            owner = pwd.getpwuid(owner_uid).pw_name
            log_exit("Error: The owner of install.py [%s] is different"
                  " with the executor [%s]." % (owner, runner))


def _exec_popen(cmd, values=None):
    """
    subprocess.Popen in python2 and 3.
    :param cmd: commands need to execute
    :return: status code, standard output, error output
    """
    if not values:
        values = []
    bash_cmd = ["bash"]
    p_obj = subprocess.Popen(bash_cmd, shell=False, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if gPyVersion[0] == "3":
        p_obj.stdin.write(cmd.encode())
        p_obj.stdin.write(os.linesep.encode())
        for value in values:
            p_obj.stdin.write(value.encode())
            p_obj.stdin.write(os.linesep.encode())
        stdout, stderr = p_obj.communicate(timeout=TIMEOUT_COUNT)
        stdout = stdout.decode()
        stderr = stderr.decode()
    else:
        p_obj.stdin.write(cmd)
        p_obj.stdin.write(os.linesep)
        for value in values:
            p_obj.stdin.write(value)
            p_obj.stdin.write(os.linesep)
        stdout, stderr = p_obj.communicate(timeout=TIMEOUT_COUNT)

    if stdout[-1:] == os.linesep:
        stdout = stdout[:-1]
    if stderr[-1:] == os.linesep:
        stderr = stderr[:-1]
    return p_obj.returncode, stdout, stderr


def check_user(user, group):
    """Verify user legitimacy"""
    try:
        user_ = pwd.getpwnam(user)
    except KeyError as key_error_msg:
        message = "Parameter input error: -U, the user does not exists.%s" % str(key_error_msg)
        logger.error(message)
        raise ValueError(message) from key_error_msg

    try:
        group_ = grp.getgrnam(group)
    except KeyError as key_error_msg:
        message = "Parameter input error: -U, the group does not exists.%s" % str(key_error_msg)
        logger.error(message)
        raise ValueError(message) from key_error_msg

    if user_.pw_gid != group_.gr_gid:
        message = "Parameter input error: -U, the user does not match the group."
        logger.error(message)
        raise ValueError(message)
    elif user == "root" or user_.pw_uid == 0:
        message = "Parameter input error: -U, can not install program to root user."
        logger.error(message)
        raise ValueError(message)
    elif group == "root" or user_.pw_gid == 0:
        message = "Parameter input error: -U, can not install program to user with root privilege."
        logger.error(message)
        raise ValueError(message)

    runner_uid = os.getuid()
    if runner_uid != 0 and runner_uid != user_.pw_uid:
        runner = pwd.getpwuid(runner_uid).pw_name
        message = "Parameter input error: -U, has to be the same as the executor [%s]" % runner
        logger.error(message)
        raise ValueError(message)


def dbstor_check_share_logic_ip_isvalid(node_ip):
    """
    function: Check the nfs logic ip is valid
    input : ip
    output: NA
    """
    def ping_execute(p_cmd):
        cmd = "%s %s -i 1 -c 3 | grep ttl | wc -l" % (p_cmd, node_ip)
        ret_code, stdout, _ = _exec_popen(cmd)
        if ret_code or stdout != '3':
            return False
        return True

    console_and_log("check nfs logic ip or domain name : %s" % node_ip)
    if not ping_execute("ping") and not ping_execute("ping6"):
        log_exit("checked the node IP address or domain name failed: %s" % node_ip)

    console_and_log("checked the node IP address or domain name success: %s" % node_ip)


class DBStor:
    """ This is DBStor installer. """

    def __init__(self):
        """ Constructor for the Installer class. """
        logger.info("Begin init...")
        logger.info("dbstor install runs on python version : %s", gPyVersion)

        os.umask(0o27)
        self.dbstor_config_tmp = {  # dbstor_config.ini default parameters
            "NAMESPACE_FSNAME": "",
            "NAMESPACE_PAGE_FSNAME": "",
            "DPU_UUID": "",
            "LINK_TYPE": "",
            "LOCAL_IP": "",
            "REMOTE_IP": "",
            "NODE_ID": "",
            "USER_NAME": "",
            "PASSWORD": "",
            "CLUSTER_ID": "",
        }
        self.conf_file_path = ""
        self.dbstor_conf_file = ""
        self.backup_conf_file = ""
        self.backup = ""
        self.dbstor_config = {}
        self.user = ""
        self.group = ""
        self.note_id = ""
        self.share_logic_ip = ""
        self.cluster_name = ""
        self.cluster_id = ""
        self.dbstore_fs_vstore_id = "0"
        self.dbstor_page_fs_vstore_id = "0"

    def check_ini(self):
        """
        check ini
        """
        # check the log path
        if not check_path(self.dbstor_conf_file):
            log_exit("Error: There is invalid character in specified dbstor config file.")
        if os.path.exists(self.dbstor_conf_file):
            try:
                os.remove(self.dbstor_conf_file)
            except OSError as ex:
                log_exit("Error: Can not remove dbstor config file: " + self.dbstor_conf_file)

    def check_log(self):
        """
        check log
        and the log for normal user is: ~/install.log
        """
        # check the log path
        flags = os.O_CREAT | os.O_EXCL
        modes = stat.S_IWUSR | stat.S_IRUSR | stat.S_IRGRP
        if not os.path.exists(LOG_FILE):
            try:
                with os.fdopen(os.open(LOG_FILE, flags, modes), "w", encoding="utf-8"):
                    pass
            except IOError as ex:
                log_exit("Error: Can not create or open log file: %s", LOG_FILE)

        try:
            os.chmod(LOG_FILE, modes)
        except OSError as ex:
            log_exit("Error: Can not chmod log file: %s", LOG_FILE)


    def read_dbstor_para(self):
        with os.fdopen(os.open(JS_CONF_FILE, os.O_RDONLY | os.O_EXCL, stat.S_IWUSR | stat.S_IRUSR), "r") as file_obj:
            json_data = json.load(file_obj)
            self.dbstor_config['NAMESPACE_FSNAME'] = json_data.get('storage_dbstore_fs', "").strip()
            self.dbstor_config['NAMESPACE_PAGE_FSNAME'] = json_data.get('storage_dbstore_page_fs', "").strip()
            self.dbstor_config['LOCAL_IP'] = json_data.get('cantian_vlan_ip', "").strip()
            self.dbstor_config['REMOTE_IP'] = json_data.get('storage_vlan_ip', "").strip()
            self.dbstor_config['NODE_ID'] = json_data.get('node_id', "").strip()
            self.dbstor_config['LINK_TYPE'] = json_data.get('link_type', "").strip()
            self.dbstor_config['LOG_VSTOR'] = json_data.get('dbstore_fs_vstore_id', "0").strip()
            self.dbstor_config['PAGE_VSTOR'] = json_data.get('dbstor_page_fs_vstore_id', "0").strip()
            if json_data.get('link_type', "").strip() != '0':
                self.dbstor_config['LINK_TYPE'] = '1'
            self.dbstor_config['CLUSTER_ID'] = json_data.get('cluster_id', "").strip()
            self.cluster_name = json_data.get('cluster_name', '')

    def check_dbstor_para(self):
        logger.info("Checking parameters.")
        if len(self.dbstor_config.get('NAMESPACE_FSNAME', "").strip()) == 0:
            message = "The storage_dbstore_fs parameter is not entered"
            console_and_log(message)
            raise ValueError(message)
        if len(self.dbstor_config.get('NAMESPACE_PAGE_FSNAME', "").strip()) == 0:
            message = "The storage_dbstore_page_fs parameter is not entered"
            console_and_log(message)
            raise ValueError(message)
        if len(self.dbstor_config.get('LOCAL_IP', "").strip()) == 0:
            message = "The cantian_vlan_ip parameter is not entered"
            console_and_log(message)
            raise ValueError(message)
        if len(self.dbstor_config.get('REMOTE_IP', "").strip()) == 0:
            message = "The storage_vlan_ip parameter is not entered"
            console_and_log(message)
            raise ValueError(message)
        if len(self.dbstor_config.get('NODE_ID', "").strip()) == 0:
            message = "The node_id parameter is not entered"
            console_and_log(message)
            raise ValueError(message)
        if len(self.dbstor_config.get('CLUSTER_ID', "").strip()) == 0:
            message = "The cluster_id parameter is not entered"
            console_and_log(message)
            raise ValueError(message)
        else:
            remote_ip_list = self.dbstor_config.get('REMOTE_IP', "").strip().split(';')
            link_cnt = 0
            global DBSTOR_WARN_TYPE
            for remote_ip in remote_ip_list:
                cmd = "ping -c 1 %s" % remote_ip.strip()
                logger.info(cmd)
                ret_code, stdout, stderr = _exec_popen(cmd)
                if ret_code:
                    console_and_log("Failed to ping remote ip. Error: %s" % remote_ip.strip())
                    DBSTOR_WARN_TYPE += 1
                else:
                    link_cnt += 1
            if link_cnt == 0:
                log_exit("Error: failed to ping all remote ip")

        if len(self.dbstor_config.get('DPU_UUID', "").strip()) == 0:
            cmd = "uuidgen"
            ret_code, stdout, stderr = _exec_popen(cmd)
            if ret_code:
                log_exit("Failed to get dpu uuid. Error: %s", stderr)
            self.dbstor_config['DPU_UUID'] = stdout.strip()

        if len(self.cluster_name) == 0:
            message = "The cluster_name parameter is not entered"
            console_and_log(message)
            raise ValueError(message)

    def verify_dbstor_usernm(self, in_type, passwd, shortest_len, longest_len):
        """
        Verify new password.
        :return: NA
        """

        if len(passwd) < shortest_len or len(passwd) > longest_len:
            console_and_log("The length of input must be %s to %s."
                             % (shortest_len, longest_len))
            raise ValueError("The length of input must be %s to %s."
                             % (shortest_len, longest_len))
        # Can't save with user name
        upper_cases = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        lower_cases = set("abcdefghijklmnopqrstuvwxyz")
        digits = set("1234567890")
        special_cases = set(r"""_""")

        if not ((passwd[0] in upper_cases) or (passwd[0] in lower_cases)):
            console_and_log("Error: UserName must start with a letter.")
            raise ValueError("Error: UserName must start with a letter.")

        # Contains at least three different types of characters
        passwd_set = set(passwd)
        # Only can contains enumerated cases
        all_cases = upper_cases | lower_cases | digits | special_cases
        un_cases = passwd_set - all_cases
        if un_cases:
            console_and_log("Error: There are characters that are not"
                             " allowed in the password: '%s'"
                             % "".join(un_cases))
            raise ValueError("Error: There are characters that are not"
                             " allowed in the password: '%s'"
                             % "".join(un_cases))
        logger.info("Successfully written user name.")

    def verify_dbstor_passwd(self, in_type, passwd, shortest_len, longest_len):
        """
        Verify new password.
        :return: NA
        """
        # eg 'length in [8-16]'
        if len(passwd) < shortest_len or len(passwd) > longest_len:
            console_and_log("The length of input must be %s to %s."
                             % (shortest_len, longest_len))
            raise ValueError("The length of input must be %s to %s."
                             % (shortest_len, longest_len))
        # Can't save with user name
        user_name = self.dbstor_config.get('USER_NAME', "")
        if user_name and passwd == user_name:
            console_and_log("Error: Password can't be the same as username.")
            raise ValueError("Error: Password can't be the same as username.")
        elif user_name and passwd == user_name[::-1]:
            console_and_log("Error: Password cannot be the same as username in reverse order")
            raise ValueError("Error: Password cannot be the same as username in reverse order")
        # The same character cannot appear three times consecutively
        for i in range(0, len(passwd) - 2):
            if passwd[i] == passwd[i + 1] and passwd[i + 1] == passwd[i + 2]:
                console_and_log("Error: The same character cannot appear three times consecutively ")
                raise ValueError("Error: The same character cannot appear three times consecutively")

        upper_cases = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        lower_cases = set("abcdefghijklmnopqrstuvwxyz")
        digits = set("1234567890")
        special_cases = set(r"""`~!@#$%^&*()-_=+\|[{}]:'",<.>/? """)

        # Password must contains at special characters
        passwd_set = set(passwd)
        if not passwd_set & special_cases:
            console_and_log("Error: Password must contains at special characters ")
            raise ValueError("Error: Password must contains at special characters")

        # Contains at least three different types of characters
        types = 0
        for cases in [upper_cases, lower_cases, digits, special_cases]:
            if passwd_set & cases:
                types += 1
        if types < 3:
            console_and_log("Error: Password must contains at least three different types of characters.")
            raise ValueError("Error: Password must contains at least three"
                             " different types of characters.")
        # Only can contains enumerated cases
        all_cases = upper_cases | lower_cases | digits | special_cases
        un_cases = passwd_set - all_cases
        if un_cases:
            console_and_log("Error: There are characters that are not"
                             " allowed in the password: '%s'"
                             % "".join(un_cases))
            raise ValueError("Error: There are characters that are not"
                             " allowed in the password: '%s'"
                             % "".join(un_cases))

    def getch(self):
        file_handle = sys.stdin.fileno()
        old_settings = termios.tcgetattr(file_handle)
        try:
            tty.setraw(sys.stdin.fileno())
            char = sys.stdin.read(1)
        finally:
            termios.tcsetattr(file_handle, termios.TCSADRAIN, old_settings)
        return char

    def getpass(self, input_prompt, maskchar="*"):
        password = ""
        logger.info("%s:", input_prompt)
        while True:
            char = self.getch()
            if char == "\r" or char == "\n":
                return password
            elif char == "\b" or ord(char) == 127:
                if len(password) > 0:
                    sys.stdout.write("\b \b")
                    sys.stdout.flush()
                    password = password[:-1]
            else:
                if char is not None:
                    sys.stdout.write(maskchar)
                    sys.stdout.flush()
                password += char

    def get_dbstor_usernm_passwd(self, input_prompt, file_prompt, shortest_len, longest_len):
        """Get new passwd"""
        flag = 0
        new_param = ""
        for _ in range(3):
            console_and_log("Please enter %s of %s: " % (input_prompt, file_prompt))
            try:
                if input_prompt == "UserName":
                    new_param = input("UserName: ")
                    self.verify_dbstor_usernm(input_prompt, new_param, shortest_len, longest_len)
                else:
                    new_param = input("PassWord: ")
                    self.verify_dbstor_passwd(input_prompt, new_param, shortest_len, longest_len)
                break
            except ValueError as error:
                logger.error(str(error))
                flag += 1
                continue
        if flag == 3:
            return 0
        return new_param

    def set_dbstor_conf(self, config, file, encrypt_passwd=False):
        """
        function: set dbstor conf
        input : config data
        input : config file name
        input : should generate encrypt passwd
        output: NA
        """
        dbstor_check_share_logic_ip_isvalid(self.share_logic_ip)
        self.check_ini()
        # Generate new kernel parameters
        conf = ReadConfigParserNoCast()
        # rewrite parameters
        conf.add_section(SECTION)
        # 对密码进行加密
        if encrypt_passwd:
            self.dbstor_config['PASSWORD'] = GLOBAL_KMC_EXT.encrypt(self.dbstor_config.get('PASSWORD', ""))
        for key in self.dbstor_config:
            conf.set(SECTION, key, self.dbstor_config[key])
        flags = os.O_CREAT | os.O_RDWR
        modes = stat.S_IWUSR | stat.S_IRUSR
        with os.fdopen(os.open(file, flags, modes), "w", encoding="utf-8") as file_obj:
            conf.write(file_obj)
        os.chmod(file, modes)

    def generate_db_config(self):
        """Generate DBstor Config parameter."""
        try:
            logger.info("Get username and password of dbstor config.")
            self.dbstor_config['USER_NAME'] = self.get_dbstor_usernm_passwd(input_prompt="UserName",
                                         file_prompt="dbstor config",
                                         shortest_len=6, longest_len=32)
            if self.dbstor_config.get('USER_NAME', 0) == 0:
                raise ValueError("create config file failed")
            self.dbstor_config['PASSWORD'] = self.get_dbstor_usernm_passwd(input_prompt="PassWord",
                                         file_prompt="dbstor config",
                                         shortest_len=8, longest_len=16)
            if self.dbstor_config.get('PASSWORD', 0) == 0:
                raise ValueError("create config file failed")
            logger.info("Successfully to get user name and password")
            logger.info("Generate DBstor Config File.")
            self.set_dbstor_conf(self.dbstor_config, self.dbstor_conf_file, True)
        except ValueError as error:
            log_exit(str(error))


    def read_old_dbstor_config(self):
        """read old DBstor Config file."""
        logger.info("read old DBstor Config file.")
        try:
            conf = ReadConfigParserNoCast()
            conf.read(self.backup_conf_file, encoding="utf-8")
            for option in conf.options(SECTION):
                value = conf.get(SECTION, option)
                self.dbstor_config[option.strip().upper()] = value.strip()
            if "LOG_VSTOR" not in self.dbstor_config.keys():
                self.dbstor_config["LOG_VSTOR"] = self.dbstore_fs_vstore_id
            if "PAGE_VSTOR" not in self.dbstor_config.keys():
                self.dbstor_config["PAGE_VSTOR"] = self.dbstor_page_fs_vstore_id
            logger.info("Generate DBstor Config File.")
            self.set_dbstor_conf(self.dbstor_config, self.dbstor_conf_file, False)
        except Exception as error:
            logger.error(str(error))

    def check_backup_ini_file(self):
        """
        check backup ini file exists
        """
        if not check_path(self.backup_conf_file):
            log_exit("Error: There is invalid character in specified backup dbstor config file.")
        if not os.path.exists(self.backup_conf_file):
            log_exit("Error: Backup dbstor config file {} not existed " .format(self.backup_conf_file))

    def check_ini_path(self):
        """
        check ini file exists
        """
        if len(self.note_id.strip()) == 0:
            log_exit("Parameter note_id is not input.")
            # check ini file exists
        if not os.path.exists(self.conf_file_path):
            try:
                os.makedirs(self.conf_file_path, MAX_DIRECTORY_MODE)
            except ValueError as error:
                log_exit("Failed to create dbstor config file path. Error: %s", error)


    def install(self):
        self.dbstor_config = self.dbstor_config_tmp
        self.check_log()
        with os.fdopen(os.open(JS_CONF_FILE, os.O_RDONLY | os.O_EXCL, stat.S_IWUSR | stat.S_IRUSR), "r")\
                as file_handle:
            json_data = json.load(file_handle)
            self.backup = json_data.get('install_type', "override").strip()
            self.note_id = json_data.get('node_id', "").strip()
            self.cluster_id = json_data.get('cluster_id', "").strip()
            self.share_logic_ip = json_data.get('share_logic_ip', "").strip()
            self.dbstore_fs_vstore_id = json_data.get('dbstore_fs_vstore_id', "0").strip()
            self.conf_file_path = os.path.join(
                DBSTOR_CONF_FILE + json_data.get('storage_share_fs'), "node" + self.note_id)
            self.backup_conf_file = os.path.join(BACKUP_CONF_FILE, "dbstor_config.ini")
            self.cluster_name = json_data.get("cluster_name", '')

        dbstor_check_share_logic_ip_isvalid(self.share_logic_ip)
        self.check_ini_path()
        self.dbstor_conf_file = os.path.join(self.conf_file_path, "dbstor_config.ini")
        if self.backup == "reserve":
            self.check_backup_ini_file()
            self.read_old_dbstor_config()
        else:
            self.read_dbstor_para()
            self.check_dbstor_para()
            self.generate_db_config()
        self.cp_ini_to_client_test()
    
     
    def cp_ini_to_client_test(self):
        self.dbstor_conf_file
        cmd = "cp -rf %s/dbstor_config.ini /opt/cantian/dbstor/tools/dbstor_config.ini" % self.conf_file_path.strip()
        logger.info(cmd)
        ret_code, stdout, stderr = _exec_popen(cmd)
        if ret_code:
            raise ValueError("Failed to copy dbstor config ini file. Error: %s", stderr)


def main():
    """
    main entry
    """
    global GLOBAL_KMC_EXT
    GLOBAL_KMC_EXT = CApiWrapper()
    logger.info("-----------start init kmc--------------------")
    ret = GLOBAL_KMC_EXT.initialize()
    logger.info("init kmc return(%s)", ret)
    check_runner()
    installer = DBStor()
    installer.install()
    GLOBAL_KMC_EXT.finalize()
    console_and_log("DBStor config install successfully!")
    if DBSTOR_WARN_TYPE != 0:
        raise EOFError("DBSTOR_WARN_TYPE is %s" % DBSTOR_WARN_TYPE)


if __name__ == "__main__":
    try:
        main()
    except ValueError as err:
        exit(1)
    except EOFError as err:
        exit(2)

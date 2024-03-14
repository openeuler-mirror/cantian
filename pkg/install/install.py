#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Perform hot backups of CantianDB100 databases.
# Copyright © Huawei Technologies Co., Ltd. 2010-2018. All rights reserved.


import sys
sys.dont_write_bytecode = True

try:
    import getopt
    import getpass
    import grp
    import os
    import platform
    import pwd
    import random
    import re
    import shutil
    import socket
    import stat
    import subprocess
    import time
    import tarfile
    import copy
    import json
    from funclib import CommonValue, SingleNodeConfig, ClusterNode0Config, ClusterNode1Config, DefaultConfigValue
    import argparse

    PYTHON242 = "2.4.2"
    PYTHON25 = "2.5"
    gPyVersion = platform.python_version()

    if PYTHON242 <= gPyVersion < PYTHON25:
        import sha256
    elif gPyVersion >= PYTHON25:
        import hashlib
    else:
        print("This install script can not support python version: %s"
              % gPyVersion)
        sys.exit(1)

    sys.path.append(os.path.split(os.path.realpath(__file__))[0])
    sys.dont_write_bytecode = True
except ImportError as err:
    sys.exit("Unable to import module: %s." % str(err))


CURRENT_OS = platform.system()

CANTIAND = "cantiand"
CANTIAND_WITH_MYSQL = "cantiand_with_mysql"
CANTIAND_WITH_MYSQL_ST = "cantiand_with_mysql_st" #single process mode with mysql llt
CANTIAND_IN_CLUSTER = "cantiand_in_cluster"
CANTIAND_WITH_MYSQL_IN_CLUSTER = "cantiand_with_mysql_in_cluster"
MYSQLD = "mysqld"

INSTALL_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "installdb.sh")

VALID_RUNNING_MODE = {CANTIAND, CANTIAND_WITH_MYSQL, CANTIAND_WITH_MYSQL_ST, CANTIAND_IN_CLUSTER, CANTIAND_WITH_MYSQL_IN_CLUSTER, MYSQLD}

VALID_SINGLE_MYSQL_RUNNING_MODE = {CANTIAND_WITH_MYSQL_IN_CLUSTER, CANTIAND_WITH_MYSQL_ST, CANTIAND_WITH_MYSQL}

CLUSTER_SIZE = 2 # default to 2, 4 node cluster mode need add parameter to specify this

INSTALL_SCPRIT_DIR = os.path.dirname(os.path.abspath(__file__))
PKG_DIR = os.path.abspath(os.path.join(INSTALL_SCPRIT_DIR, "../.."))

VERSION_DOCKER_META = 0
VERSION_DOCKER_NOMETA = 1
VERSION_ENV_META = 2
VERSION_ENV_NOMETA = 3

if os.path.exists("/.dockerenv"):
    MYSQL_CODE_DIR = os.path.join(PKG_DIR, "cantian-connector-mysql/mysql-source")
    is_mysql_metadata_in_cantian = (DefaultConfigValue.CANTIAND_CONFIG["MYSQL_METADATA_IN_CANTIAN"] == "TRUE")
    MYSQL_VERSION = VERSION_DOCKER_META if is_mysql_metadata_in_cantian else VERSION_DOCKER_NOMETA
    MYSQL_DATA_DIR = "/data/data"
    MYSQL_BIN_DIR = "/usr/local/mysql"
else:
    MYSQL_CODE_DIR = os.path.join(PKG_DIR, "cantian-connector-mysql")
    CONFIG_FILE = "/opt/cantian/config/deploy_param.json"
    with open(CONFIG_FILE, "r") as conf:
        _tmp = conf.read()
        info = json.loads(_tmp)
    is_mysql_metadata_in_cantian = info.get("mysql_metadata_in_cantian")
    MYSQL_VERSION = VERSION_ENV_META if is_mysql_metadata_in_cantian else VERSION_ENV_NOMETA
    MYSQL_DATA_DIR = "/mnt/dbdata/remote/metadata_{metadata}/node{node}"\
        .format(metadata=info["storage_metadata_fs"], node=info["node_id"])
    MYSQL_BIN_DIR = "/opt/cantian/mysql/install/mysql"

MYSQL_LOG_FILE = os.path.join(MYSQL_DATA_DIR, "mysql.log")

class Options(object):
    """
    command line options
    """
    def __init__(self):
        self.log_file = ""
        self.install_user_privilege = ""
        self.opts = []

        # Database username and password are required after disabling
        # confidential login
        self.db_user = "SYS"
        # New passwd of user [SYS]
        self.db_passwd = ""

        # User info
        self.os_user = ""
        self.os_group = ""

        # The object of opened log file.
        self.fp = None

        # program running mode
        self.running_mode = CANTIAND

        # node id, even not in cluster mode, still given value 0
        self.node_id = 0

        # flag indicate user using gss storage
        self.use_gss = False
        
        # flag indicate user using dbstor storage
        self.use_dbstor = False
        
        self.link_type = "TCP"
        self.link_type_from_para = False

        # list contains ip white list
        self.white_list = ""

        # flag of if install inside docker container
        self.in_container = False

        # flag of if need to check package is mattched with current os version
        self.ignore_pkg_check = False

        # path of mysql config file
        self.mysql_config_file_path = "unset"

        # In slave cluster:
        self.slave_cluster = False


g_opts = Options()


def check_kernel_parameter(para):
    """Is kernel parameter invalid?"""
    pattern = re.compile("^[A-Z_][A-Z0-9_]+$")
    if not pattern.match(para.upper().strip()):
        print("The kernel parameter '%s' is invalid." % para)
        sys.exit(1)


def check_invalid_symbol(para):
    """
    If there is invalid symbol in parameter?
    :param para: parameter's value
    :return: NA
    """
    symbols = ["|", "&", "$", ">", "<", "\"", "'", "`"]
    for symbol in symbols:
        if para.find(symbol) > -1:
            print("There is invalid symbol \"%s\" in %s" % (symbol, para))
            sys.exit(1)


def all_zero_addr_after_ping(nodeIp):
    """
    check ip is all 0
    :param nodeIp: ip addr
    :return: bool
    """
    if not nodeIp:
        return False
    allowed_chars = set('0:.')
    if set(nodeIp).issubset(allowed_chars):
        return True
    else:
        return False


def checkPath(path_type_in):
    """
    Check the validity of the path.
    :param path_type_in: path
    :return: weather validity
    """
    path_len = len(path_type_in)
    a_ascii = ord('a')
    z_ascii = ord('z')
    A_ascii = ord('A')
    Z_ascii = ord('Z')
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
        return checkPathLinux(path_len, path_type_in, a_ascii, z_ascii,
                              A_ascii, Z_ascii, num0_ascii, num9_ascii,
                              char_check_list1)
    elif CURRENT_OS == "Windows":
        return checkPathWindows(path_len, path_type_in, a_ascii, z_ascii,
                                A_ascii, Z_ascii, num0_ascii, num9_ascii,
                                char_check_list2)
    else:
        print("Error: Can not support this platform.")
        sys.exit(1)


def checkPathLinux(path_len, path_type_in, a_ascii, z_ascii,
                   A_ascii, Z_ascii, num0_ascii, num9_ascii, char_check_list):
    for i in range(0, path_len):
        char_check = ord(path_type_in[i])
        if (not (a_ascii <= char_check <= z_ascii
                 or A_ascii <= char_check <= Z_ascii
                 or num0_ascii <= char_check <= num9_ascii
                 or char_check in char_check_list)):
            return False
    return True


def checkPathWindows(path_len, path_type_in, a_ascii, z_ascii, A_ascii,
                     Z_ascii, num0_ascii, num9_ascii, char_check_list):
    for i in range(0, path_len):
        char_check = ord(path_type_in[i])
        if (not (a_ascii <= char_check <= z_ascii
                 or A_ascii <= char_check <= Z_ascii
                 or num0_ascii <= char_check <= num9_ascii
                 or char_check in char_check_list)):
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
        stdout, stderr = pobj.communicate()
        stdout = stdout.decode()
        stderr = stderr.decode()
    else:
        pobj.stdin.write(cmd)
        pobj.stdin.write(os.linesep)
        for value in values:
            pobj.stdin.write(value)
            pobj.stdin.write(os.linesep)
        stdout, stderr = pobj.communicate()

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
        print("Can not get platform information.")
        sys.exit(1)
    if CURRENT_OS == "Linux":
        pass
    else:
        print("This install script can not support %s platform." % CURRENT_OS)
        sys.exit(1)


def check_runner():
    """Check whether the user and owner of the script are the same."""
    owner_uid = os.stat(__file__).st_uid
    runner_uid = os.getuid()
    # Owner is root
    if owner_uid == 0:
        if runner_uid != 0:
            runner = pwd.getpwuid(runner_uid).pw_name
            print("Error: The owner of install.py has root privilege,"
                  " can't run it by user [%s]." % runner)
            sys.exit(1)
    else:
        if runner_uid == 0:
            owner = pwd.getpwuid(owner_uid).pw_name
            print("Error: The owner of install.py is [%s],"
                  " can't run it by root." % owner)
            sys.exit(1)
        elif runner_uid != owner_uid:
            runner = pwd.getpwuid(runner_uid).pw_name
            owner = pwd.getpwuid(owner_uid).pw_name
            print("Error: The owner of install.py [%s] is different"
                  " with the executor [%s]." % (owner, runner))
            sys.exit(1)


def get_random_num(lower_num, upper_num):
    # range of values
    differ_num = upper_num - lower_num + 1
    # get the first ten rows of random numbers
    cmd = "cat /dev/random | head -n 10 | cksum | awk -F ' ' '{print $1}'"
    p = subprocess.Popen(["bash", "-c", cmd], shell=False,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    # format result to string
    result_num = p.stdout.read().strip().decode()
    # string to int
    result_num = int(result_num)
    rand_num = result_num % differ_num + lower_num
    return rand_num


def generate_password():
    """
    Generate password of ssl cert.
    :return: password
    """
    case1 = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    case2 = set("abcdefghijklmnopqrstuvwxyz")
    case3 = set("0123456789")
    case4 = set(r"""`~!@#$%^&*()-_=+\|[{}]:,<.>/?""")
    # Use 3 times the number to avoid the low proportion of numbers
    # in the generated password
    cases = "".join(case1 | case2 | case3 | case4) + "".join(case3) * 2

    case_len = len(cases)
    pw_len = get_random_num(16, 20)
    chars = [cases[get_random_num(1, case_len) - 1] for _ in range(pw_len)]
    c_set = set(chars)
    # Various types of characters must exist at the same time.
    if c_set & case1 and c_set & case2 and c_set & case3 and c_set & case4:
        return "".join(chars)
    else:
        chars.append(list(case1)[get_random_num(1, 26) - 1])
        chars.append(list(case2)[get_random_num(1, 26) - 1])
        chars.append(list(case3)[get_random_num(1, 10) - 1])
        chars.append(list(case4)[get_random_num(1, len(case4)) - 1])
        random.shuffle(chars)
        return "".join(chars)


def usage():
    """install.py is a utility to install cantiand server.

Usage:
  python install.py --help
  python install.py -U user:group -R installpath -M cantiand -N 0 -D DATADIR [-O] [-c]
                    [-C PARAMETER=VALUE] [-g withoutroot] [-f SQLFILE] [-d] [-p]
  python install.py -U user:group -R installpath -M cantiand_in_cluster -N 0 -D DATADIR [-O] [-c]
                    [-C 'PARAMETER=VALUE'] [-g withoutroot] [-f SQLFILE] [-d] [-p]
  python install.py -U user:group -R installpath -M cantiand_with_mysql -N 0 -D DATADIR [-O] [-c]
                    [-C 'PARAMETER=VALUE'] [-g withoutroot] [-f SQLFILE] [-d] [-p]
  python install.py -U user:group -R installpath -M cantiand_in_cluster -N 1 -D DATADIR [-O] [-c]
                    [-C \"PARAMETER=VALUE\"] [-g withoutroot] [-f SQLFILE] [-d] [-p]

Common options:
  -U        the database program and cluster owner
  -R        the database program path
  -M        the database running mode, case insensitive, default value [cantiand]
            cantiand: running cantiand in single mode;
            cantiand_with_mysql: running cantiand with mysql connector in single mode;
            cantiand_with_mysql_st: running cantiand(mysql llt) with mysql connector in single mode;
            cantiand_in_cluster: running cantiand in cluster mode;
            cantiand_with_mysql_in_cluster: running cantiand with mysql connector in cluster mode.
  -N        node id, value is [0, 1]
  -O        only install database program, and omit other optional parameters
  -D        location of the database cluster storage area
  -g        run install script without root privilege,
            but you must have permission of installation folder
            note: use \"-g withoutroot\" exactly
  -Z        configure the database cluster config, eg: -Z "LSNR_PORT=1611",
            for more detail information see documentation.
  -C        configure the database cluster cms config, eg: -C "GCC_HOME=/dev/cms-disk1",
            for more detail information see documentation.
  -G        configure the database cluster gss config, eg: -G "STORAGE_MODE=CLUSTER_RAID",
            for more detail information see documentation.
  -W        configure the database ip white list, eg: -W "127.0.0.1".
  -c        not use SSL-based secure connections
  -s        using gss as storage, default using file system
  -l        specify the cantiand install log file path and name,
            if not, use the default
            disable it(not recommended)
  -P        Compatibility parameter, which does not take effect.
  -f        specify a customized create database sql file.
            if not, use default create database sql file.
  -d        install inside docker container
  -p        if ignore pkg version check
  -m        assign the config file of mysql
  --help    show this help, then exit

If all the optional parameters are not specified, -O option will be used.
    """
    print(usage.__doc__)


def check_user(user, group):
    """Verify user legitimacy"""
    try:
        user_ = pwd.getpwnam(user)
    except KeyError:
        print("Parameter input error: -U, the user does not exists.")
        sys.exit(1)

    try:
        group_ = grp.getgrnam(group)
    except KeyError:
        print("Parameter input error: -U, the group does not exists.")
        sys.exit(1)

    if user_.pw_gid != group_.gr_gid:
        print("Parameter input error: -U, the user does not match the group.")
        sys.exit(1)
    elif user == "root" or user_.pw_uid == 0:
        print("Parameter input error: -U, can not install program to"
              " root user.")
        sys.exit(1)
    elif group == "root" or user_.pw_gid == 0:
        print("Parameter input error: -U, can not install program to"
              " user with root privilege.")
        sys.exit(1)

    runner_uid = os.getuid()
    if runner_uid != 0 and runner_uid != user_.pw_uid:
        runner = pwd.getpwuid(runner_uid).pw_name
        print("Parameter input error: -U, has to be the same as the"
              " executor [%s]" % runner)
        sys.exit(1)


def parse_parameter():
    """
    parse parameters
    -U: username and group
    -R: install path
    -M: running mode
    -N: node id
    -D: data path
    -Z: kernel parameter
    -C: cms parameter
    -G: gss parameter
    -W: cthba white list
    -O: don't create database
    -S: In slave cluster
    -P: Compatibility parameter
    -l: log file
    -g: no-root user to install
    -s: using gss storage
    -d: install inside docker container
    -p: ignore checking package and current os version
    """
    try:
        # Parameters are passed into argv. After parsing, they are stored
        # in opts as binary tuples. Unresolved parameters are stored in args.
        opts, args = getopt.getopt(sys.argv[1:],
                                   "U:R:M:N:OD:Z:C:G:W:cg:sdl:Ppf:m:S", ["help", "dbstor", "linktype="])
        if args:
            print("Parameter input error: " + str(args[0]))
            exit(1)

        # If there is "--help" in parameter, we should print the usage and
        # ignore other parameters.
        for _key, _value in opts:
            if _key == "--help":
                usage()
                print("End check parameters")
                exit(0)

        for _key, _value in opts:
            if _key == "-g":
                if os.getuid():
                    g_opts.install_user_privilege = _value
            elif _key == "-l":
                g_opts.log_file = _value.strip()
            elif _key == "-M":
                g_opts.running_mode = _value.strip()
            elif _key == "-N":
                g_opts.node_id = int(_value.strip())
            elif _key == "-W":
                g_opts.white_list = _value.strip()
            elif _key == "-s":
                g_opts.use_gss = True
            elif _key == "--dbstor":
                g_opts.use_dbstor = True
            elif _key == "--linktype":
                g_opts.link_type = _value.strip()
                g_opts.link_type_from_para = True
            elif _key == "-d":
                g_opts.in_container = True
            elif _key == "-p":
                g_opts.ignore_pkg_check = True
            # Get the user name and user group
            elif _key == "-U":
                _value = _value.strip()
                user_info = _value.split(":")
                if len(user_info) != 2 or not user_info[0] or not user_info[1]:
                    print("Parameter input error: -U " + _value)
                    exit(1)
                # The username and user group can't have invalid symbol.
                check_user(user_info[0], user_info[1])
                g_opts.os_user, g_opts.os_group = user_info[0], user_info[1]
            elif _key == "-m":
                g_opts.mysql_config_file_path = _value.strip()

        g_opts.opts = opts
    except getopt.GetoptError as err:
        print("Parameter input error: " + err.msg)
        sys.exit(1)


def is_mlnx():
    """
    is_mlnx
    """
    ret_code, _, stderr = _exec_popen("which ofed_info")
    if ret_code:
        log("no ofed_info cmd found")
        return False

    ret_code, stdout, _ = _exec_popen("ofed_info -s")
    if ret_code:
        log("exec ofed_info cmd failed")
        return False

    if 'MLNX_OFED_LINUX-5.5' in stdout:
        log("Is mlnx 5.5")
        return True

    log("Not mlnx 5.5")
    return False


def is_rdma_startup():
    """
    is_rdma_startup
    """
    if g_opts.link_type == "RDMA" and is_mlnx():
        return True

    return False


def check_dbstor_parameter():
    if g_opts.use_gss and g_opts.use_dbstor:
        print("Can't enable gss and dbstor at the same time")
        sys.exit(1)

    if g_opts.use_dbstor:
        if g_opts.link_type_from_para:
            if g_opts.link_type not in {"RDMA", "TCP"}:
                print("The link type should be RDMA or TCP")
                sys.exit(1)
        else:
            g_opts.link_type = "TCP"

        if g_opts.link_type == "RDMA" and not is_mlnx():
            print("Not support RDMA for drive so not installed.")
            sys.exit(1)


def check_parameter():
    """
    check parameter
    """
    if g_opts.install_user_privilege != "withoutroot":
        if os.getuid():
            print("Error: User has no root privilege, do install,"
                  " need specify parameter '-g withoutroot'.")
            sys.exit(1)
    # Check the log path.
    check_log_path()
    # Use the default log path.
    if not g_opts.log_file:
        use_default_log_path()
    # Check the legitimacy of the path logfile
    if not checkPath(g_opts.log_file):
        print("Error: There is invalid character in specified log file.")
        sys.exit(1)
    if os.path.exists(g_opts.log_file):
        try:
            os.chmod(g_opts.log_file, stat.S_IWUSR + stat.S_IRUSR)
            os.remove(g_opts.log_file)
        except OSError as ex:
            print("Error: Can not remove log file: " + g_opts.log_file)
            print(str(ex))
            sys.exit(1)
    # Check running mode
    if len(g_opts.running_mode) == 0 or g_opts.running_mode.lower() not in VALID_RUNNING_MODE:
        print("Invalid running mode: " + g_opts.running_mode)
        sys.exit(1)
    if g_opts.node_id not in [0 ,1]:
        print("Invalid node id: " + g_opts.node_id)
        sys.exit(1)
    if g_opts.running_mode.lower() in [CANTIAND, CANTIAND_WITH_MYSQL, CANTIAND_WITH_MYSQL_ST] and g_opts.node_id == 1:
        print("Invalid node id: " + g_opts.node_id + ", this node id can only run in cluster mode")
        sys.exit(1)
    # Check docker option
    if g_opts.in_container ^ os.path.exists("/.dockerenv"):
        print("Wrong docker container env option of -d")
        sys.exit(1)

    check_dbstor_parameter()

    try:
        with open(g_opts.log_file, "w"):
            pass
    except IOError as ex:
        print("Error: Can not create or open log file: " + g_opts.log_file)
        print(str(ex))
        sys.exit(1)

    try:
        uid = pwd.getpwnam(g_opts.os_user).pw_uid
        gid = grp.getgrnam(g_opts.os_group).gr_gid
        os.chown(g_opts.log_file, uid, gid)
        os.chmod(g_opts.log_file, stat.S_IWUSR + stat.S_IRUSR)
    except OSError as ex:
        print("Error: Can not change the mode of log file: " + g_opts.log_file)
        print(str(ex))
        sys.exit(1)


def check_log_path():
    if g_opts.log_file:
        g_opts.log_file = os.path.realpath(os.path.normpath(g_opts.log_file))
        base_name = os.path.basename(g_opts.log_file)
        dir_path = os.path.dirname(g_opts.log_file)

        if not os.path.isdir(dir_path):
            g_opts.log_file = ""
            print("Specified log path: \"%s\" does not exist, "
                  "choose the default path instead." % dir_path)
        elif not base_name:
            g_opts.log_file = ""
            print("Log file does not been specified, "
                  "choose the default logfile instead.")


def use_default_log_path():
    # The default log is ~/cantiandinstall.log
    if g_opts.install_user_privilege == "withoutroot":
        cmd = "echo ~"
    else:
        cmd = "su - '%s' -c \"echo ~\"" % g_opts.os_user
    ret_code, stdout, _ = _exec_popen(cmd)
    if ret_code:
        print("Can not get user home, command: %s" % cmd)
        sys.exit(1)
    if not os.path.exists(os.path.realpath(stdout)):
        print("Cant get the home path of current user.")
        sys.exit(1)
    g_opts.log_file = os.path.join(os.path.realpath(os.path.normpath(stdout)),
                                   "cantiandinstall.log")


def log(msg, is_screen=False):
    """
    Print log
    :param msg: log message
    :return: NA
    """
    if is_screen:
        print(msg)

    with open(g_opts.log_file, "a") as fp:
        fp.write(time.strftime("[%Y-%m-%d %H:%M:%S] ") + msg)
        fp.write(os.linesep)


def logExit(msg):
    """
    Print log and exit
    :param msg: log message
    :return: NA
    """
    log("Error: " + msg)
    print("Error: " + msg)
    print("Please refer to install log \"%s\" for more detailed information."
          % g_opts.log_file)
    sys.exit(1)


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
            m = release_re.match(etc_file)
            # regular expression matched
            if m is None:
                continue
            _distname, dummy = m.groups()

            # read the first line
            try:
                etc_file_name = os.path.join(Platform.UNIXCONFDIR, etc_file)
                with open(etc_file_name, 'r') as f:
                    firstline = f.readline()
            except Exception:
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


class SslCertConstructor(object):
    """Generate ssl cert"""

    def __init__(self, keys_path):
        self.keys_path = keys_path
        self.tmp_conf = os.path.join(keys_path, "openssl.cnf")
        self.bin = ""
        self.passwd = generate_password()

        self.__get_bin()

    def __get_bin(self):
        cmd = "which openssl"
        ret_code, stdout, stderr = _exec_popen(cmd)
        if ret_code:
            raise OSError("Failed to get openssl command. Error: %s" % stderr)
        self.bin = os.path.realpath(stdout.strip())

    def _create_ssl_tmp_path(self):
        """
        Create tmp dirs and files for generate ssl cert.
        :return: NA
        """
        if os.path.exists(self.keys_path):
            shutil.rmtree(self.keys_path)

        os.makedirs(self.keys_path, 0o700)

    def _modify_ssl_config(self):
        """
        Generate config file.
        """
        log("Create config file.")
        v3_ca_ = [
            "[ v3_ca ]",
            "subjectKeyIdentifier=hash",
            "authorityKeyIdentifier=keyid:always,issuer:always",
            "basicConstraints = CA:true",
            "keyUsage = keyCertSign,cRLSign",
        ]
        v3_ca = os.linesep.join(v3_ca_)

        # Create config file.
        with open(self.tmp_conf, "w") as fp:
            # Write config item of Signature
            fp.write(v3_ca)
        log("Successfully create config file.")

    def __execute_openssl_command(self, cmd, cert_name):
        values = (self.passwd,)
        try:
            status, stdout, stderr = _exec_popen(cmd, values)
        except Exception as error:
            err_msg = str(error).replace(self.passwd, "*")
            raise OSError("Failed to generate {}."
                          " Error: {}".format(cert_name, err_msg))

        output = stdout + stderr
        output = output.replace(self.passwd, "*")
        if status:
            raise OSError("Failed to generate {}."
                          " Error: {}".format(cert_name, output))
        if not self.check_certificate_files_exist([cert_name]):
            raise OSError("Failed to generate {}. The file does not exist now."
                          " Error: {}".format(cert_name, output))

        # Verify key files.
        if cert_name.endswith(".key") or cert_name == "cakey.pem":
            path = os.path.join(self.keys_path, cert_name)
            try:
                self.verify_ssl_key(path)
            except (OSError, ValueError) as error:
                raise OSError("Failed to verify {}."
                              " Error: {}".format(cert_name, error))

    def __generate_cert_file(self, cmd, cert_name):
        """Generate cert file."""
        # Retry
        loop_times = 3
        for i in range(loop_times):
            try:
                self.__execute_openssl_command(cmd, cert_name)
                break
            except OSError:
                if i == loop_times - 1:
                    raise

    def check_certificate_files_exist(self, cert_names):
        """Check whether the certificate file is generated."""
        log("Check whether the certificate files %s are generated."
            % cert_names)
        for cert_name in cert_names:
            cert_path = os.path.join(self.keys_path, cert_name)
            if not os.path.exists(cert_path):
                return False
        return True

    @staticmethod
    def verify_ssl_key(path):
        """Verify ssl key file"""
        try:
            with open(path) as fp:
                content = fp.read().strip()
        except OSError as error:
            raise OSError("Failed to be opened: %s" % error)

        start_str = "-----BEGIN RSA PRIVATE KEY-----"
        end_str = "-----END RSA PRIVATE KEY-----"
        proc_type = "Proc-Type: 4,ENCRYPTED"
        if not content.startswith(start_str):
            raise ValueError("Content not starts with '%s'" % start_str)
        elif not content.endswith(end_str):
            raise ValueError("Content not ends with '%s'" % end_str)
        elif proc_type not in content:
            raise ValueError("Proc-Type in content is wrong.")

    def _generate_root_cert(self):
        """
        Generate ca cert.
        :return: NA
        """
        log("Generate ca keys.")

        # cakey.pem
        cmd = ('openssl genrsa -aes256 -f4 -passout stdin'
               ' -out {0}/cakey.pem 2048'.format(self.keys_path))
        self.__generate_cert_file(cmd, "cakey.pem")

        # cacert.pem
        cmd = ('openssl req -new -x509 -passin stdin -days 10950'
               ' -key {0}/cakey.pem -out {0}/cacert.pem'
               ' -subj "/C=CN/ST=NULL/L=NULL/O=NULL/OU=NULL/'
               'CN=CA"'.format(self.keys_path))
        self.__generate_cert_file(cmd, "cacert.pem")

    def _generate_cert(self, role):
        """
        Generate cert of role.
        :param role: role
        :return: NA
        """
        log("Generate %s keys." % role)

        # key
        cmd = ("openssl genrsa -aes256 -passout stdin -out {0}/{1}.key"
               " 2048".format(self.keys_path, role))
        cert_name = "{}.key".format(role)
        self.__generate_cert_file(cmd, cert_name)

        # csr
        cmd = ('openssl req -new -key {0}/{1}.key -passin stdin -out '
               '{0}/{1}.csr -subj "/C=CN/ST=NULL/L=NULL/O=NULL/OU=NULL/'
               'CN={1}"'.format(self.keys_path, role))
        cert_name = "{}.csr".format(role)
        self.__generate_cert_file(cmd, cert_name)

        # crt
        cmd = ('openssl x509 -req -days 10950 -in {0}/{1}.csr'
               ' -CA {0}/cacert.pem -CAkey {0}/cakey.pem -passin stdin'
               ' -CAserial {0}/cacert.srl -CAcreateserial -out {0}/{1}.crt'
               ' -extfile {0}/openssl.cnf'.format(self.keys_path, role))
        cert_name = "{}.crt".format(role)
        self.__generate_cert_file(cmd, cert_name)

        srl_file = os.path.join(self.keys_path, "cacert.srl")
        if os.path.exists(srl_file):
            os.unlink(srl_file)

    def _check_all_keys_exists(self):
        """All keys must be exists."""
        keys = ["cacert.pem", "server.crt", "server.key",
                "client.crt", "client.key"]
        keys_ = set(keys)
        files = set([_ for _ in os.listdir(self.keys_path)])
        lack_keys = keys_ - files
        if lack_keys:
            raise Exception("Failed to generate keys: %s"
                            % " ".join(lack_keys))

    def _clean_useless_path(self):
        """
        Clean useless dirs and files, chmod the target files
        :return: NA
        """
        keys = ["cacert.pem", "server.crt", "server.key",
                "client.crt", "client.key"]
        for filename in os.listdir(self.keys_path):
            if filename in [os.curdir, os.pardir]:
                continue
            file_path = os.path.join(self.keys_path, filename)
            if filename not in keys:
                if os.path.isdir(file_path):
                    shutil.rmtree(file_path)
                else:
                    os.remove(file_path)
            else:
                # Permission 400
                os.chmod(file_path, CommonValue.MIN_FILE_PERMISSION)

    def clean_all(self):
        if not os.path.exists(self.keys_path):
            return

        try:
            for filename in os.listdir(self.keys_path):
                file_path = os.path.join(self.keys_path, filename)
                # We can't remove file without permission write
                if os.path.isdir(file_path):
                    os.chmod(file_path, CommonValue.KEY_DIRECTORY_PERMISSION)
                    shutil.rmtree(file_path)
                else:
                    os.chmod(file_path, CommonValue.KEY_FILE_PERMISSION)
                    os.remove(file_path)
            shutil.rmtree(self.keys_path)
        except OSError:
            pass

    def generate(self):
        """
        Generate ssl certificate
        :return: NA
        """
        log("Start to generate ssl certificate.")
        try:
            self._create_ssl_tmp_path()
            self._modify_ssl_config()
            self._generate_root_cert()
            self._generate_cert("server")
            self._generate_cert("client")
            self._check_all_keys_exists()
            self._clean_useless_path()
        except Exception as ssl_err:
            self.clean_all()
            err_msg = str(ssl_err).replace(self.passwd, "*")
            raise Exception("Failed to generate ssl certificate. Error: %s"
                            % err_msg)
        log("Complete to generate ssl certificate.")


def skip_execute_in_node_1():
    if g_opts.running_mode in [CANTIAND_IN_CLUSTER, CANTIAND_WITH_MYSQL_IN_CLUSTER] and g_opts.node_id == 1:
        return True
    return False


def skip_execute_in_slave_cluster():
    if g_opts.slave_cluster:
        return True
    return False

def create_dir_if_needed(condition, dir):
    if condition:
        return
    os.makedirs(dir, CommonValue.KEY_DIRECTORY_PERMISSION)


def check_command(cmd):
    try:
        output = subprocess.check_output(['/usr/bin/which', cmd], stderr=subprocess.STDOUT)
        return True
    except subprocess.CalledProcessError as e:
        return False


class Installer:
    """ This is Cantiand installer. """

    # Defining a constant identifies which step the installer failed to take.
    # For roll back.
    FAILED_INIT = "0"
    DECOMPRESS_BIN_FAILED = "1"
    SET_ENV_FAILED = "2"
    PRE_DATA_DIR_FAILED = "3"
    INIT_DB_FAILED = "4"
    CREATE_DB_FAILED = "5"
    # Define the installation mode constant identifier
    INS_ALL = "all"
    INS_PROGRAM = "program"
    # Record the steps for the current operation to fail
    FAILED_POS = FAILED_INIT
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
    CMS_CONF_FILE = "cms.ini"
    CLUSTER_CONF_FILE = "cluster.ini"
    CANTIAND_HBA_FILE = "cthba.conf"
    DEFAULT_INSTANCE_NAME = "cantian"
    # backup cantiand install log dir
    backup_log_dir = ""

    LOGIN_IP = ""
    IPV_TYPE = "ipv4"

    def __init__(self, user, group):
        """ Constructor for the Installer class. """
        log("Begin init...")
        log("Installer runs on python version : " + gPyVersion)

        os.umask(0o27)

        # User
        self.user = user
        # Sysdba login enabled by default
        self.enableSysdbaLogin = True
        # Group
        self.group = group
        self.user_info = "%s:%s" % (self.user, self.group)
        # Install path
        self.installPath = ""
        # Option for installing program only or all.
        self.option = "program"
        self.flagOption = 0
        # old pgdata path
        self.oldDataPath = ""
        # Data path
        self.data = ""
        # gcc home path
        self.gcc_home = ""
        # DB config parameters
        self.cantiandConfigs = {}
        self.cmsConfigs = {}
        self.gssConfigs = {}
        self.dn_conf_dict = ParameterContainer()
        # run file
        self.runFile = ""
        # run package name
        self.run_pkg_name = ""
        # run MDf file
        self.runSha256File = ""

        self.lsnr_addr = ""
        self.lsnr_port = "1611"
        self.instance_name = self.DEFAULT_INSTANCE_NAME

        self.userHomePath = ""
        # dir path
        self.dirName = ""
        self.pid = 0

        # create database sql that user specify
        self.create_db_file = ""

        self.create_cantian_defs_file = ""

        # user profile
        self.userProfile = ""
        # flag for creating program dir
        self.isMkdirProg = False
        # flag for creating data dir
        self.isMkdirData = False

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

        self.os_type = platform.machine()
        self.have_numactl = check_command('numactl')
        self.numactl_str = ""
        if self.os_type == 'aarch64' and self.have_numactl == True:
            last_cpu_core = os.cpu_count() - 1
            self.numactl_str = "numactl -C  0-1,6-11,16-" + str(last_cpu_core) + " "        

        log("End init")

    def find_file(self, path, name_pattern):

        file_list = os.listdir(path)
        find_files = []
        for file_name in file_list:
            if re.match(name_pattern, file_name):
                find_files.append(file_name)

        if not find_files:
            return ''

        if len(find_files) > 1:
            raise Exception("More than one target found in %s: %s\n"
                            "Please remove the unused files."
                            % (path, ' ;'.join(find_files)))
        # file exists, return absolute file name
        file_name = os.path.realpath(os.path.join(path, find_files[0]))
        if not os.path.isfile(file_name):
            raise Exception("%s is not file, please check your package."
                            % file_name)
        return file_name

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

    def check_pkg_version(self):
        """
        check package version is matched with os version
        """
        # In python3.7 the function platform.dist is not recommended, and
        # it will cause a warning. so we must inhibition it.
        distname, _, _ = Platform.dist()
        bits, _ = platform.architecture()

        # check package version
        if self.run_pkg_name.find(distname.upper().replace("OS", "")) == -1:
            logExit("Run package %s.tar.gz is inconsistent with os system %s."
                    % (self.run_pkg_name, distname))

        # check package bits, 64bits
        if self.runFile.find(bits) == -1:
            logExit("Run package %s.tar.gz is inconsistent with os system %s."
                    % (self.run_pkg_name, bits))

    def getRunPkg(self):
        """
        Get the database package.
        :return: NA
        """
        installFile = os.path.join(os.getcwd(), sys.argv[0])
        installFile = os.path.realpath(os.path.normpath(installFile))

        self.dirName = os.path.dirname(installFile)

        # get run.tar.gz package
        run_pattern = ("^(%s|%s)-[A-Z0-9]+-64bit.tar.gz$"
                       % (self.RUN_VERSION_A, self.RUN_VERSION_B))
        self.runFile = self.find_file(self.dirName, run_pattern)
        if not self.runFile:
            raise Exception("Can not get correct run package in path %s"
                            % self.dirName)
        # get run.sha256 file
        sha256_pattern = ("^(%s|%s)-[A-Z0-9]+-64bit.sha256$"
                          % (self.RUN_VERSION_A, self.RUN_VERSION_B))
        self.runSha256File = self.find_file(self.dirName, sha256_pattern)
        if not self.runSha256File:
            raise Exception("Can not get correct sha256 file in path %s"
                            % self.dirName)
        # get run file name without suffix
        # compress package name is run.tar.gz,
        # decompress is run, remove .tar.gz
        self.run_pkg_name = self.get_decompress_tarname(self.runFile)
        # check os version of package is mattched with current os version
        if not g_opts.ignore_pkg_check:
            self.check_pkg_version()

        log("Using run file as : %s" % self.runFile)

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

    def clean_dir(self, dir_path):
        if not os.path.isdir(dir_path):
            return

        try:
            for filename in os.listdir(dir_path):
                file_path = os.path.join(dir_path, filename)
                # We can't remove file without permission write
                if os.path.isdir(file_path):
                    os.chmod(file_path, CommonValue.MAX_DIRECTORY_PERMISSION)
                    shutil.rmtree(file_path)
                else:
                    os.chmod(file_path, CommonValue.KEY_FILE_PERMISSION)
                    os.remove(file_path)
        except OSError:
            pass

    def checkCreatedbFile(self):
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
        if not checkPath(self.create_db_file):
            raise Exception("Error: %s file path invalid: "
                            % self.create_db_file)
        # if execute user is root, check common user has read permission
        file_path = os.path.dirname(self.create_db_file)

        # check path of create db sql file that user can cd
        permission_ok, _ = self.checkPermission(file_path, True)
        if not permission_ok:
            raise Exception("Error: %s can not access %s"
                            % (self.user, file_path))

        # check create db file is readable for user
        if not self.is_readable(self.create_db_file, self.user):
            raise Exception("Error: %s is not readable for user %s"
                            % (self.create_db_file, self.user))
        # change file to a realpath file
        self.create_db_file = os.path.realpath(self.create_db_file)

    def parseDefaultConfig(self):
        """
        Parse cantiand, cms, gss default config
        :return: cantiand config, cms config, gss config
        """
        if g_opts.running_mode in [CANTIAND, CANTIAND_WITH_MYSQL, CANTIAND_WITH_MYSQL_ST]:
            self.cantiandConfigs, self.cmsConfigs, self.gssConfigs = SingleNodeConfig.get_config(g_opts.in_container)
        if g_opts.running_mode in [CANTIAND_IN_CLUSTER, CANTIAND_WITH_MYSQL_IN_CLUSTER] and g_opts.node_id == 0:
            self.cantiandConfigs, self.cmsConfigs, self.gssConfigs = ClusterNode0Config.get_config(g_opts.in_container)
        if g_opts.running_mode in [CANTIAND_IN_CLUSTER, CANTIAND_WITH_MYSQL_IN_CLUSTER] and g_opts.node_id == 1:
            self.cantiandConfigs, self.cmsConfigs, self.gssConfigs =  ClusterNode1Config.get_config(g_opts.in_container)

    def addConfigForGss(self):
        self.cantiandConfigs["CONTROL_FILES"] = "{0}, {1}, {2}".format(os.path.join(self.data, "data/ctrl1"),
                                                                      os.path.join(self.data, "data/ctrl2"),
                                                                      os.path.join(self.data, "data/ctrl3"))
        self.gssConfigs["INTERCONNECT_ADDR"] = self.cantiandConfigs["INTERCONNECT_ADDR"]
        self.gssConfigs["LOG_HOME"] = self.cantiandConfigs["LOG_HOME"]
        del self.gssConfigs["STORAGE_MODE"]
        self.cmsConfigs["_IP"] = self.cantiandConfigs["LSNR_ADDR"]
        self.cmsConfigs["GCC_HOME"] = os.path.join(self.data, "gcc_home")
        self.cmsConfigs["GCC_TYPE"] = "FILE"
        
        if g_opts.use_gss:
            self.cantiandConfigs["CONTROL_FILES"] = "(+vg1/ctrl1, +vg1/ctrl2, +vg1/ctrl3)"
            self.gssConfigs["STORAGE_MODE"] = "CLUSTER_RAID"
            self.cmsConfigs["GCC_HOME"] = "/dev/gcc-disk"
            self.cmsConfigs["GCC_TYPE"] = "SD"
        elif g_opts.use_dbstor:
            self.cantiandConfigs["CONTROL_FILES"] = "(-ctrl1, -ctrl2, -ctrl3)"
            self.cantiandConfigs["SHARED_PATH"] = "-"
            self.cantiandConfigs["ENABLE_DBSTOR"] = "TRUE"
            self.cantiandConfigs["DBSTOR_NAMESPACE"] = "test1"
            self.cmsConfigs["GCC_HOME"] = "/dev/gcc-disk"
            self.cmsConfigs["GCC_TYPE"] = "SD"

    def checkParameter(self):
        """
        Detect the legality of input parameters,
        and return process if not legal.
        :return: NA
        """
        log("Checking parameters.", True)
        self.parseDefaultConfig()
        self.parseKeyAndValue()
        if len(self.cantiandConfigs["INTERCONNECT_ADDR"]) == 0:
            logExit("Database INTERCONNECT_ADDR must input, need -Z parameter.")
        # Check database user
        if g_opts.db_user and g_opts.db_user.lower() != "sys":
            logExit("Database connector's name must be [sys].")
        if not self.installPath:
            logExit("Parameter input error, need -R parameter.")
        self.installPath = os.path.normpath(self.installPath)
        if not self.data:
            logExit("Parameter input error, need -D parameter.")
        self.data = os.path.normpath(self.data)
        # Check user
        if not self.user:
            logExit("Parameter input error, need -U parameter.")
        os.environ['cantiand_user'] = str(self.user)
        # User must be exist.
        strCmd = "id -u ${cantiand_user}"
        ret_code, _, _ = _exec_popen(strCmd)
        if ret_code:
            logExit("%s : no such user, command: %s" % (self.user, strCmd))
        if self.option == self.INS_ALL:
            # App data and inst data can't be the same one.
            if self.installPath == self.data:
                logExit("Program path should not equal to data path!")
            elif self.installPath.find(self.data + os.sep) == 0:
                logExit("Can not install program under data path!")
            elif self.data.find(self.installPath + os.sep) == 0:
                logExit("Can not install data under program path!")
            else:
                log("Program path is separated with data path!")
        # Check the app path
        realPath = os.path.realpath(self.installPath)
        if not checkPath(realPath):
            logExit("Install program path invalid: " + self.installPath)
        # Check the data path
        realPath = os.path.realpath(self.data)
        if not checkPath(realPath):
            logExit("Install data path invalid: " + self.data)
        if len(self.cantiandConfigs["LOG_HOME"]) == 0:
            self.cantiandConfigs["LOG_HOME"] = os.path.join(self.data, "log")
        if len(self.cantiandConfigs["SHARED_PATH"]) == 0:
            self.cantiandConfigs["SHARED_PATH"] = os.path.join(self.data, "data")

        self.cantiandConfigs["MYSQL_DEPLOY_GROUP_ID"] = grp.getgrnam(g_opts.os_group).gr_gid
        self.addConfigForGss()
        self.gcc_home = self.cmsConfigs["GCC_HOME"]
        self.ssl_path = os.path.join(self.installPath, "sslkeys")
        self.showParseResult()

    def showParseResult(self):
        # Print the result of parse.
        log("Using %s:%s to install database" % (self.user, self.group))
        log("Using install program path : %s" % self.installPath)
        log("Using option : " + self.option)
        log("Using install data path : %s" % self.data)

        conf_parameters = copy.deepcopy(self.cantiandConfigs)
        for key in conf_parameters.keys():
            # Ignore the values of some parameters. For example,
            # _SYS_PASSWORD and SSL_KEY_PASSWORD.
            if key.endswith("PASSWORD") or key.endswith("PASSWD"):
                conf_parameters[key] = "*"
            elif key.endswith("KEY") and key != "SSL_KEY":
                conf_parameters[key] = "*"
        log("Using set cantiand config parameters : " + str(conf_parameters))
        log("Using set cms config parameters : " + str(self.cmsConfigs))
        log("Using set gss config parameters : " + str(self.gssConfigs))
        log("End check parameters.", True)

    def parseKeyAndValue(self):
        for key, value in g_opts.opts:
            # Get the app path.
            if key == "-R":
                self.installPath = value.strip()
            elif key == "-O":
                self.option = self.INS_PROGRAM
                self.flagOption = 1
            # Start the cluster as slave.
            elif key == "-S":
                g_opts.slave_cluster = True
            # Get the datadir
            elif key == "-D":
                self.data = value.strip()
                if self.flagOption == 0:
                    self.option = self.INS_ALL
                if self.flagOption == 1:
                    self.option = self.INS_PROGRAM
            # Get the kernel parameter
            elif key == "-Z":
                _value = value.strip().split('=')
                if len(_value) != 2:
                    log("Warning: kernel parameter will not take effect reason is invalid parameter: " + value, True)
                    continue
                self.cantiandConfigs[_value[0].strip().upper()] = _value[1].strip()
            elif key == "-C":
                _value = value.strip().split('=')
                if len(_value) != 2:
                    log("Warning: cms parameter will not take effect reason is invalid parameter: " + value, True)
                    continue
                self.cmsConfigs[_value[0].strip().upper()] = _value[1].strip()
            elif key == "-G":
                _value = value.strip().split('=')
                if len(_value) != 2:
                    log("Warning: gss parameter will not take effect reason is invalid parameter: " + value, True)
                    continue
                self.gssConfigs[_value[0].strip().upper()] = _value[1].strip()
            elif key == "-P":
                pass  # Compatibility parameter
            elif key in ["-g", "-l", "-U", "-M", "-W", "-s", "-N", "-d", "-p", "--dbstor", "--linktype"]:
                pass
            elif key == "-f":
                self.create_db_file = value.strip()
            elif key == '-c':
                self.close_ssl = True
            else:
                logExit("Parameter input error: %s." % value)

    def checkRunner(self):
        """
        The user currently running the script must be root or in root group,
        if not exit.
        :return: NA
        """

        log("Checking runner.", True)
        gid = os.getgid()
        uid = os.getuid()
        log("Check runner user id and group id is : %s, %s"
            % (str(uid), str(gid)))
        if(gid != 0 and uid != 0):
            logExit("Only user with root privilege can run this script")

        log("End check runner is root")

    def chownLogFile(self):
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
            logExit("Can not change log file's owner. Output:%s" % str(ex))
    
    def chownDataDir(self):
        """
        chown data and gcc dirs
        :return:
        """
        cmd = "chown %s:%s -R \"%s\" \"%s\";" % (self.user, self.group, self.data, self.gcc_home)
        if g_opts.in_container:
            cmd += "chown %s:%s -R \"%s\" \"%s\";" % (self.user, self.group, CommonValue.DOCKER_DATA_DIR, CommonValue.DOCKER_GCC_DIR)
        log("Change owner cmd: %s" % cmd)
        ret_code, _, stderr = _exec_popen(cmd)
        if ret_code:
            raise Exception("chown to %s:%s return: %s%s%s" % (self.user, self.group, str(ret_code), os.linesep, stderr))

    ###########################################################################
    # Is there a database installed by the user? If right, raise error
    # and exit. Because each user is only allowed install one database by
    # this script.
    ###########################################################################
    def checkOldInstall(self):
        """
        Is there a database installed by the user?
        :return: NA
        """

        log("Checking old install.", True)

        # Check $CTDB_HOME.
        if(g_opts.install_user_privilege == "withoutroot"):
            strCmd = "echo ~"
        else:
            strCmd = "su - '%s' -c \"echo ~\"" % self.user
        ret_code, stdout, _ = _exec_popen(strCmd)
        if ret_code:
            logExit("Can not get user home.")
        # Get the profile of user.
        output = os.path.realpath(os.path.normpath(stdout))
        if (not checkPath(output)):
            logExit("The user home directory is invalid.")
        self.userProfile = os.path.join(output, ".bashrc")
        self.userHomePath = output
        log("Using user profile : " + self.userProfile)

        isFind = False
        try:
            with open(self.userProfile, "r") as _file:
                isFind = self.dealwithCTDB(isFind, _file)
        except IOError as ex:
            logExit("Can not read user profile: " + str(ex))
        except IndexError as ex:
            logExit("Failed to read user profile: %s" % str(ex))

        if isFind:
            logExit("Database has been installed already.")

        log("End check old install.", True)

    def dealwithCTDB(self, isFind, _file):
        while True:
            strLine = _file.readline()
            if (not strLine):
                break
            strLine = strLine.strip()
            if (strLine.startswith("#")):
                continue
            user_info = strLine.split()
            self.dealwithCTDB_DATA(user_info, strLine)
            if (len(user_info) >= 2 and user_info[0] == "export"
                    and user_info[1].startswith("CTDB_HOME=") > 0):
                isFind = True
                break
            else:
                continue
        return isFind

    def dealwithCTDB_DATA(self, user_info, strLine):
        # deal with the CTDB_DATA with """
        if (len(user_info) >= 2 and user_info[0] == "export"
                and user_info[1].startswith('CTDB_DATA="') > 0):
            self.oldDataPath = strLine[strLine.find("=") + 2:-1]
            self.oldDataPath = os.path.normpath(self.oldDataPath)
            realPath = os.path.realpath(self.oldDataPath)
            if not checkPath(realPath):
                logExit("The Path specified by CTDB_DATA is invalid.")
            log("Old data path: " + self.oldDataPath)
            if self.option == self.INS_ALL and self.oldDataPath != self.data:
                logExit("User CTDB_DATA is different from -D parameter value")
        # deal with the CTDB_DATA path without """
        elif (len(user_info) >= 2 and user_info[0] == "export"
              and user_info[1].startswith("CTDB_DATA=") > 0):
            self.oldDataPath = strLine[strLine.find("=") + 1:]
            self.oldDataPath = os.path.normpath(self.oldDataPath)
            realPath = os.path.realpath(self.oldDataPath)
            if (not checkPath(realPath)):
                logExit("The Path specified by CTDB_DATA is invalid.")
            log("Old data path: " + self.oldDataPath)
            if self.option == self.INS_ALL and self.oldDataPath != self.data:
                logExit("User CTDB_DATA is different from -D parameter value")

    def prepareGivenPath(self, onePath, checkEmpty=True):
        """
        function:
            make sure the path exist and user has private to access this path
        precondition:
            1.checkEmpty is True or False
            2.path list has been initialized
        input:
            1.path list
            2.checkEmpty
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
        log("Preparing path [%s]." % onePath)
        ownerPath = onePath
        if(os.path.exists(onePath)):
            if(checkEmpty):
                fileList = os.listdir(onePath)
                if(len(fileList) != 0):
                    logExit("Database path %s should be empty." % onePath)
        else:
            while True:
                # find the top path to be created
                (ownerPath, dirName) = os.path.split(ownerPath)
                if os.path.exists(ownerPath) or dirName == "":
                    ownerPath = os.path.join(ownerPath, dirName)
                    break
            # create the given path
            log("Path [%s] does not exist. Please create it." % onePath)
            os.makedirs(onePath, 0o750)
            self.isMkdirProg = True

        # if the path already exist, just change the top path mode,
        # else change mode with -R
        # do not change the file mode in path if exist
        # found error: given path is /a/b/c, script path is /a/b/c/d,
        # then change mode with -R
        # will cause an error
        if ownerPath != onePath:
            cmd = "chown -R %s:%s %s; " % (self.user, self.group, ownerPath)
            cmd += "chmod -R %s %s" % (CommonValue.MAX_DIRECTORY_MODE,
                                       ownerPath)
        else:
            cmd = "chown %s:%s %s; " % (self.user, self.group, ownerPath)
            cmd += "chmod %s %s" % (CommonValue.MAX_DIRECTORY_MODE, ownerPath)

        log("cmd path %s" % cmd)
        ret_code, _, stderr = _exec_popen(cmd)
        if ret_code:
            logExit(" Command: %s. Error:\n%s" % (cmd, stderr))

        # check permission
        log("check [%s] user permission" % onePath)
        permission_ok, stderr = self.checkPermission(onePath)
        if not permission_ok:
            logExit("Failed to check user [%s] path [%s] permission. Error: %s"
                    % (self.user, onePath, stderr))

    def checkPermission(self, originalPath, check_enter_only=False):
        """
        function:
            check if given user has operation permission for given path
        precondition:
            1.user should be exist
            2.originalPath should be an absolute path
            3.caller should has root privilege
        postcondition:
            1.return True or False
        input : originalPath,check_enter_only
        output: True/False
        """
        # check the user has enter the directory permission or not
        if g_opts.install_user_privilege == "withoutroot":
            cmd = "cd %s" % originalPath
        else:
            cmd = "su - '%s' -c 'cd %s'" % (self.user, originalPath)

        status, _, stderr = _exec_popen(cmd)
        if status:
            return False, stderr

        if check_enter_only:
            return True, ""

        # check the user has write permission or not
        testFile = os.path.join(originalPath, "touch.tst")
        if g_opts.install_user_privilege == "withoutroot":
            cmd = ("touch %s && chmod %s %s "
                   % (testFile, CommonValue.KEY_FILE_MODE, testFile))
        else:
            cmd = ("su - '%s' -c 'touch %s && chmod %s %s' " %
                   (self.user, testFile, CommonValue.KEY_FILE_MODE, testFile))

        status, _, stderr = _exec_popen(cmd)
        if status != 0:
            return False, stderr
        if g_opts.install_user_privilege == "withoutroot":
            cmd = "echo aaa > %s " % testFile
        else:
            cmd = "su - '%s' -c 'echo aaa > %s' " % (self.user, testFile)

        # delete tmp file
        status, _, stderr = _exec_popen(cmd)
        if status != 0:
            cmd = "rm -f %s " % testFile
            _exec_popen(cmd)
            return False, stderr

        cmd = "rm -f %s " % testFile
        status, _, stderr = _exec_popen(cmd)
        if status != 0:
            return False, stderr

        return True, ""

    def checkDIR(self):
        """
        Check dir.

        1. Check the length of the directory entered by the user, and exit
           if it is longer than 110 characters.
        2. Check that the directory entered by the user is empty or does not
           exist, otherwise it will exit.
        3. Check if the size of the installation directory entered by the
           user is less than 100M. If it is less than, exit it.
        4. Check whether the database initialization directory entered by
           the user is less than 20G. If it is less than quit, the default
           template for building the library needs 20G to enter.
        5. Check that the installation directory entered by the user and
           the database initialization directory are on the same disk, and
           exit if the total size is less than 20580M.
        :return:
        """

        log("Checking directory.", True)
        # check if data or app path is too long(over 100 chars)
        if(len(self.data) >= 110 or len(self.installPath) >= 110):
            logExit("Install path or Data path is over 110 characters, exit.")
        # check install path is empty or not.
        self.prepareGivenPath(self.installPath)
        # check data dir is empty or not.
        if g_opts.slave_cluster:
            # Allow the data dir not empty in slave_cluster.
            self.prepareGivenPath(self.data, False)
        else:   
            self.prepareGivenPath(self.data)
        # check install path
        vfs = os.statvfs(self.installPath)
        availableSize = vfs.f_bavail * vfs.f_bsize / (1024*1024)
        log("Database program install path available size: %sM"
            % str(availableSize))
        if availableSize < 100:
            logExit("Database program install path available size smaller"
                    " than 100M, current size is: %sM"
                    % str(availableSize))
        # check data dir.
        if self.option == self.INS_ALL:
            # check partition of install path
            strCmd1 = "df -h \"%s\"" % self.installPath
            strCmd2 = "df -h \"%s\" | head -2" % self.installPath
            strCmd3 = "df -h \"%s\" | head -2 |tail -1" % self.installPath
            strCmd4 = ("df -h \"%s\" | head -2 |tail -1 | "
                       "awk -F\" \" '{print $1}'" % self.installPath)
            cmds = [strCmd1, strCmd2, strCmd3, strCmd4]
            stdout = ""
            stdout_list = []
            for cmd in cmds:
                ret_code, stdout, stderr = _exec_popen(strCmd1)
                if ret_code:
                    logExit("Can not get the partition of path: %s "
                            "%scommand: %s. %sError: %s"
                            % (self.installPath, os.linesep,
                               cmd, os.linesep, stderr))
                stdout_list.append(stdout)
            log("The partition of path \"%s\": %s"
                % (self.installPath, stdout))
            self.checkPartitionOfDataDir(strCmd1, stdout_list)
        log("End check dir.")

    def checkPartitionOfDataDir(self, strCmd1, stdout_list):
        strCmd5 = "df -h \"%s\"" % self.data
        strCmd6 = "df -h \"%s\" | head -2" % self.data
        strCmd7 = "df -h \"%s\" | head -2 |tail -1" % self.data
        strCmd8 = ("df -h \"%s\" | head -2 |tail -1 "
                   "| awk -F\" \" '{print $1}'" % self.data)

        cmds = [strCmd5, strCmd6, strCmd7, strCmd8]
        stdout = ""
        for cmd in cmds:
            ret_code, stdout, stderr = _exec_popen(strCmd1)
            if ret_code:
                logExit("Can not get the partition of path: %s "
                        "%scommand: %s. %sError: %s"
                        % (self.data, os.linesep,
                           cmd, os.linesep, stderr))
        log("The partition of path \"%s\": %s"
            % (self.data, stdout))

        vfs = os.statvfs(self.data)
        availableSize = vfs.f_bavail * vfs.f_bsize / (1024 * 1024)
        log("Database data directory available size: %sM" % str(availableSize))

        # check install path and data dir are in the same path or not
        if stdout_list[0] == stdout_list[1]:
            if (availableSize < 20580):
                logExit("The sum of database program and data directories"
                        " available size smaller than 20580M, "
                        "current size is: %sM" % str(availableSize))
        else:
            if (availableSize < 20480):
                logExit("Database data directory available size smaller"
                        " than 20480M, current size is: "
                        "%sM" % str(availableSize))

    ########################################################################
    # Check if the port is used in the installation parameters, and exit
    # if the port is used.
    ########################################################################
    def checkPort(self, value):
        """
        Check if the port is used in the installation parameters, and exit
        if the port is used.
        :param value: port
        :return: NA
        """
        # the value can't be empty and must be a digit.
        # the value must > 1023 and <= 65535
        TIME_OUT, innerPort = self.checkInnerPort(value)

        # Get the sokcet object
        if self.IPV_TYPE == "ipv6":
            sk = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
            sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Test the socket connection.
        sk.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sk.settimeout(TIME_OUT)

        try:
            sk.bind((self.LOGIN_IP, innerPort))
            sk.close()
        except socket.error as err:
            sk.close()
            if gPyVersion >= PYTHON242:
                try:
                    # 98: Address already in use
                    # 95: Operation not supported
                    # 13: Permission denied
                    if (int(err.errno) == 98 or int(err.errno) == 95
                            or int(err.errno) == 13):
                        log("Error: port %s has been used,the detail"
                            " information is as follows:" % value, True)
                        strCmd = "netstat -unltp | grep %s" % value
                        ret_code, stdout, _ = _exec_popen(strCmd)
                        if ret_code:
                            logExit("can not get detail information of the"
                                    " port, command: " + strCmd)
                        logExit(str(stdout))
                except ValueError as ex:
                    logExit("check port failed: " + str(ex))
            else:
                logExit("This install script can not support python version"
                        " : " + gPyVersion)

    def checkInnerPort(self, value):
        TIME_OUT = 2
        if not value:
            logExit("the number of port is null.")
        if not value.isdigit():
            logExit("illegal number of port.")
        try:
            innerPort = int(value)
            if innerPort < 0 or innerPort > 65535:
                logExit("illegal number of port.")
            if innerPort >= 0 and innerPort <= 1023:
                logExit("system reserve port.")
        except ValueError as ex:
            logExit("check port failed: " + str(ex))
        return TIME_OUT, innerPort

    #########################################################################
    # Check if the port is used in the installation parameters, and exit
    # if the port is used.
    #########################################################################
    def checkIPisVaild(self, nodeIp):
        """
        function: Check the ip is valid
        input : ip
        output: NA
        """
        log("check the node IP address.")
        try:
            socket.inet_aton(nodeIp)
            self.IPV_TYPE = "ipv4"
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, nodeIp)
                self.IPV_TYPE = "ipv6"
            except socket.error:
                logExit("The invalid IP address : %s is not ipv4 or ipv6 format." % nodeIp)

        if self.IPV_TYPE == "ipv6":
            ping_cmd = "ping6"
        else:
            ping_cmd = "ping"
        # use ping command to check the the ip, if no package lost,
        # the ip is valid
        cmd = "%s %s -i 1 -c 3 | grep ttl | wc -l" % (ping_cmd, nodeIp)
        ret_code, stdout, _ = _exec_popen(cmd)

        if ret_code or stdout != '3':
            logExit("The invalid IP address is %s. "
                    "ret_code : %s, stdout : %s" % (nodeIp, ret_code, stdout))

        if all_zero_addr_after_ping(nodeIp):
            ip_is_found = 1
        elif len(nodeIp) != 0:
            ip_cmd = "ip addr | grep -w %s | wc -l" % nodeIp
            ret_code, ip_is_found, _ = _exec_popen(ip_cmd)
        else:
            ip_is_found = 0
        
        if ret_code or not int(ip_is_found):
            logExit("The invalid IP address is %s. "
                    "ret_code : %s, ip_is_found : %s" % (nodeIp, ret_code, ip_is_found))


        log("checked the node IP address : %s" % nodeIp)

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
            logExit("can not get numa node parameters, err: %s" % stderr)
        _result = result.strip().split(':')
        
        if len(_result) != 2:
            log("Warning: numa get error, result:%s" % result)
            return

        numa_num = 0
        numa_info = ""
        #判断_result[1].strip()
        if not _result[1].strip().isdigit():
            log("Warning: numa(s) size get error, result:%s" % result)
            return
        while numa_num < int(_result[1].strip()):
            err_code, ans, err_msg = _exec_popen('/usr/bin/lscpu | grep -i "NUMA node%s"' % numa_num)
            _ans = ans.strip().split(':')
            if len(_ans) != 2:
                log("Warning: numa node get error, ans:%s" % ans)
                return
            numa_info += _ans[1].strip() + " "
            numa_num += 1
        if not numa_info.isspace():
            self.cantiandConfigs["SHM_MYSQL_CPU_GROUP_INFO"] = numa_info
            self.cantiandConfigs["SHM_CPU_GROUP_INFO"] = numa_info

    def checkConfigOptions(self):
        """
        Check the operating system kernel parameters and exit if they do
        not meet the requirements of the database。
        :return: NA
        """
        log("Checking kernel parameters.", True)
        # GB MB kB
        GB = 1024*1024*1024
        MB = 1024*1024
        KB = 1024
        # The size of database
        log_buffer_size = 4*MB
        shared_pool_size = 128*MB
        data_buffer_size = 128*MB
        temp_buffer_size = 32*MB
        sga_buff_size = (log_buffer_size + shared_pool_size + data_buffer_size
                         + temp_buffer_size)

        # getNuma
        self.set_numa_config()

        # parse the value of kernel parameters
        for key, value in self.cantiandConfigs.items():
            if not isinstance(value, str):
                value = str(value)
                self.cantiandConfigs[key] = value
            try:
                check_kernel_parameter(key)
                check_invalid_symbol(value)
                # Unit conversion
                sga_buff_size = self.doUnitConversion(GB, MB, KB, key, value,
                                                             sga_buff_size,
                                                             temp_buffer_size,
                                                             data_buffer_size,
                                                             shared_pool_size,
                                                             log_buffer_size)
            except ValueError as ex:
                logExit("check kernel parameter failed: " + str(ex))

        if self.lsnr_addr != "":
            _list = self.lsnr_addr.split(",")
            # Check the ip address
            for item in _list:
                if len(_list) != 1 and all_zero_addr_after_ping(item):
                    logExit("lsnr_addr contains all-zero ip,"
                            " can not specify other ip.")
                self.checkIPisVaild(item)
        else:
            # If this parameter is empty, the IPv4 is used by default.
            # The default IP address is 127.0.0.1
            self.lsnr_addr = "127.0.0.1"
        self.checkSgaBuffSize(sga_buff_size, MB, KB)

    def checkSgaBuffSize(self, sga_buff_size, MB, KB):
        """
        check sga buffer size
        :param sga_buff_size:
        :param MB:
        :param KB:
        :return:
        """
        self.LOGIN_IP = self.lsnr_addr.split(",")[0]
        self.checkPort(self.lsnr_port)
        self.lsnr_port = int(self.lsnr_port)
        # check sga_buff_size
        strCmd = "cat /proc/meminfo"
        ret_code, cur_avi_memory, _ = _exec_popen(strCmd)
        if ret_code:
            logExit("can not get shmmax parameters, command: %s" % strCmd)

        cmd = ("cat /proc/meminfo  |grep -wE 'MemFree:|Buffers:|Cached:"
               "|SwapCached' |awk '{sum += $2};END {print sum}'")
        ret_code, cur_avi_memory, strerr = _exec_popen(cmd)
        if ret_code:
            logExit("can not get shmmax parameters, command: %s, err: %s" % (cmd, stderr))
        if sga_buff_size < 114 * MB:
            logExit("sga_buff_size should bigger than or equal to 114*MB,"
                    " please check it!")
        try:
            if sga_buff_size > int(cur_avi_memory) * KB:
                logExit("sga_buff_size should smaller than shmmax,"
                        " please check it!")
        except ValueError as ex:
            logExit("check kernel parameter failed: " + str(ex))

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

    def init_specify_kernel_para(self, key, value):
        """get the value of some kernel parameters."""
        if key == "LSNR_ADDR":
            self.lsnr_addr = value
        elif key == "INSTANCE_NAME":
            self.instance_name = value
        elif key == "LSNR_PORT":
            self.lsnr_port = value
        elif key == "ENABLE_SYSDBA_LOGIN":
            self.enableSysdbaLogin = Installer.check_pare_bool_value(
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

    def doUnitConversion(self, GB, MB, KB, key, value, sga_buff_size,
                         temp_buffer_size, data_buffer_size, shared_pool_size,
                         log_buffer_size):
        if key in ["TEMP_BUFFER_SIZE", "DATA_BUFFER_SIZE",
                         "SHARED_POOL_SIZE", "LOG_BUFFER_SIZE"]:
            if value[0:-1].isdigit() and value[-1:] in ["G", "M", "K"]:
                unit_map = {
                    "G": GB,
                    "M": MB,
                    "K": KB,
                }
                size_unit = unit_map[value[-1:]]
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

    def checkSHA256(self):
        """
        Verify the integrity of the bin file, exit if it is not complete
        :return: NA
        """

        log("Checking integrality of run file...", True)
        self.execLogExit()
        _file = None
        sha256Obj = None
        oldSHA256 = ""
        strSHA256 = ""
        isSameSHA256 = False
        try:
            with open(self.runFile, "rb") as _file:
                # Use sha256 when python version is lower higher 2.4 and
                # lower than 2.5.
                if(gPyVersion >= PYTHON242 and gPyVersion < PYTHON25):
                    sha256Obj = sha256.new()
                # Use hash when python version is higher than 2.5
                elif(gPyVersion >= PYTHON25):
                    sha256Obj = hashlib.sha256()
                if(sha256Obj is None):
                    logExit("check integrality of bin file failed, can not get"
                            " verification Obj.")
                while True:
                    strRead = _file.read(8096)
                    if(not strRead):
                        break
                    sha256Obj.update(strRead)
                strSHA256 = sha256Obj.hexdigest()
                with open(self.runSha256File, "r") as fileSHA256:
                    strRead = fileSHA256.readline()
                    oldSHA256 = strRead.strip()
                    if(strSHA256 == oldSHA256):
                        isSameSHA256 = True
                    else:
                        isSameSHA256 = False
        except IOError as ex:
            logExit("Check integrality of bin file except: " + str(ex))

        if isSameSHA256:
            log("Check integrality of bin file ok")
        else:
            logExit("Check integrality of bin file failed")
        log("End check integrality of bin file")

    def execLogExit(self):
        if (self.runFile == ""):
            logExit("Can not find run file.")
        if (self.runSha256File == ""):
            logExit("Can not find verification file.")

    def changeAppPermission(self):
        """
        function: after decompression install package, change file permission
        input : NA
        output: NA
        """
        # change install path privilege to 700
        strCmd = "chmod %s %s -R" % (CommonValue.KEY_DIRECTORY_MODE,
                                     self.installPath)
        # chmod add-ons/ file 500
        strCmd += ("&& find '%s'/add-ons -type f | xargs chmod %s "
                   % (self.installPath, CommonValue.MID_FILE_MODE))
        # chmod admin/ file 600
        strCmd += ("&& find '%s'/admin -type f | xargs chmod %s "
                   % (self.installPath, CommonValue.KEY_FILE_MODE))
        # chmod lib/ file 500
        strCmd += ("&& find '%s'/lib -type f | xargs chmod %s"
                   % (self.installPath, CommonValue.MID_FILE_MODE))
        # chmod bin/ file 500
        strCmd += ("&& find '%s'/bin -type f | xargs chmod %s "
                   % (self.installPath, CommonValue.MID_FILE_MODE))
        package_xml = os.path.join(self.installPath, "package.xml")
        if os.path.exists(package_xml):
            strCmd += ("&& chmod %s '%s'/package.xml"
                       % (CommonValue.MIN_FILE_MODE, self.installPath))

        log("Change app permission cmd: %s" % strCmd)
        ret_code, _, stderr = _exec_popen(strCmd)
        if ret_code:
            self.FAILED_POS = self.DECOMPRESS_BIN_FAILED
            self.rollBack()
            logExit("chmod %s return: " % CommonValue.KEY_DIRECTORY_MODE
                    + str(ret_code) + os.linesep + stderr)

        if not self.close_ssl:
            for file_name in os.listdir(self.ssl_path):
                file_path = os.path.join(self.ssl_path, file_name)
                os.chmod(file_path, CommonValue.KEY_FILE_PERMISSION)

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
            print("Please enter %s of %s: " % (pw_prompt, user_prompt))
            new_passwd = getpass.getpass()
            try:
                self.verify_new_passwd(new_passwd, shortest_len)
            except ValueError as error:
                print(str(error))
                continue

            print("Please enter %s of %s again: " % (pw_prompt, user_prompt))
            new_passwd2 = getpass.getpass()

            if new_passwd == new_passwd2:
                break
            print("Passwd not match.")
        else:
            raise ValueError("Failed to get new %s." % pw_prompt)

        if new_passwd:
            return new_passwd
        else:
            raise ValueError("Failed to get new %s." % pw_prompt)

    def checkSysPasswd(self):
        """
        Whether the password of the sys user has been specified. If not, raise
        :return: NA
        """
        # 0. "_SYS_PASSWORD" can't be set when ENABLE_SYSDBA_LOGIN is False
        sys_password = self.cantiandConfigs["_SYS_PASSWORD"]
        if not self.enableSysdbaLogin and len(sys_password) != 0:
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
            except EOFError:
                # Not find passwd from pipe
                raise ValueError("The content got from pipe not find passwd.")
            self.verify_new_passwd(g_opts.db_passwd, 8)

    def copy_dbstore_path(self):
        str_cmd = ""
        if g_opts.use_dbstor:
            os.makedirs("%s/dbstor/conf/dbs" % self.data, CommonValue.KEY_DIRECTORY_PERMISSION)
            os.makedirs("%s/dbstor/conf/infra/config" % self.data, CommonValue.KEY_DIRECTORY_PERMISSION)
            os.makedirs("%s/dbstor/data/logs" % self.data, CommonValue.KEY_DIRECTORY_PERMISSION)
            os.makedirs("%s/dbstor/data/ftds" % self.data, CommonValue.KEY_DIRECTORY_PERMISSION)
            if is_rdma_startup():
                str_cmd += " && cp %s/cfg/node_config_rdma.xml %s/dbstor/conf/infra/config/node_config.xml" % (
                    self.installPath, self.data)
            else:
                str_cmd += " && cp %s/cfg/node_config_tcp.xml %s/dbstor/conf/infra/config/node_config.xml" % (
                    self.installPath, self.data)
            
            str_cmd += " && cp %s/cfg/osd.cfg %s/dbstor/conf/infra/config/osd.cfg" % (self.installPath, self.data)
            str_cmd += " && cp /home/conf/dbstor_config.ini %s/dbstor/conf/dbs/" % (self.data)
                
        return str_cmd
        
    #########################################################################
    # Unzip the installation files to the installation directory.
    #########################################################################
    def decompressBin(self):
        """
        Unzip the installation files to the installation directory.
        :return: NA
        """

        log("Decompressing run file.", True)

        # let bin executable
        str_cmd = "chmod %s \"%s\"" % (CommonValue.KEY_DIRECTORY_MODE,
                                      self.runFile)
        log("decompress bin file executable cmd: %s" % str_cmd)
        ret_code, _, stderr = _exec_popen(str_cmd)
        if ret_code:
            self.FAILED_POS = self.DECOMPRESS_BIN_FAILED
            self.rollBack()
            logExit("decompress bin file executable return: %s%s%s"
                    % (str(ret_code), os.linesep, stderr))
        # decompress bin file.
        cantian_pkg_file = "%s/%s" % (self.installPath, self.run_pkg_name)
        str_cmd = "tar -xvf \"%s\" -C \"%s\"" % (self.runFile, self.installPath)
        str_cmd = ("%s && cp -rf %s/add-ons %s/admin %s/bin %s/cfg %s/lib "
                  "%s/package.xml %s"
                  % (str_cmd, cantian_pkg_file, cantian_pkg_file, cantian_pkg_file,
                     cantian_pkg_file, cantian_pkg_file, cantian_pkg_file,
                     self.installPath))
        
        str_cmd += self.copy_dbstore_path()
        str_cmd += " && rm -rf %s" % cantian_pkg_file
        log("Decompress cmd: " + str_cmd)
        ret_code, _, stderr = _exec_popen(str_cmd)
        if ret_code:
            self.FAILED_POS = self.DECOMPRESS_BIN_FAILED
            self.rollBack()
            logExit("Decompress bin return: " + str(ret_code)
                    + os.linesep + stderr)

        # change app permission
        self.changeAppPermission()

        # change owner to user:group
        str_cmd = "chown %s:%s -R %s " % (self.user, self.group,
                                         self.installPath)
        # Change the owner
        log("Change owner cmd: %s" % str_cmd)
        ret_code, _, stderr = _exec_popen(str_cmd)
        if ret_code:
            self.FAILED_POS = self.DECOMPRESS_BIN_FAILED
            self.rollBack()
            logExit("chown to %s: %s return: %s%s%s"
                    % (self.user, self.group, str(ret_code),
                       os.linesep, stderr))

        log("End decompress bin file.")

    def generateSslCert(self):
        """
        Generate ssl certificate
        :return: NA
        """
        if self.close_ssl:
            log("Skip generate ssl certificate.")
            return

        log("Create ssl certificate path.")
        # Generate ssl cert in tmp path
        os.makedirs(self.ssl_path, 0o700)
        log("Generate create ssl certificate path.")

    def exportUserEnv(self):
        try:
            with open(self.userProfile, "a") as _file:
                _file.write("export CTDB_HOME=\"%s\"" % self.installPath)
                _file.write(os.linesep)
                _file.write("export PATH=\"%s\":\"%s\":$PATH"
                            % (os.path.join(self.installPath, "bin"),
                               os.path.join(MYSQL_BIN_DIR, "bin")))
                _file.write(os.linesep)
                _file.write("export LD_LIBRARY_PATH=\"%s\":\"%s\""
                            ":$LD_LIBRARY_PATH"
                            % (os.path.join(self.installPath, "lib"),
                               os.path.join(self.installPath, "add-ons")))
                _file.write(os.linesep)
                if self.oldDataPath == "":
                    # set CTDB_DATA
                    _file.write("export CTDB_DATA=\"%s\"" % self.data)
                    _file.write(os.linesep)
                    _file.write("export CMS_HOME=\"%s\"" % self.data)
                    _file.write(os.linesep)
                _file.flush()
        except IOError as ex:
            self.FAILED_POS = self.SET_ENV_FAILED
            self.rollBack()
            logExit("Can not set user environment variables: %s" % str(ex))

    def setUserEnv(self):
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
        log("Setting user env.", True)
        # set PATH, LD_LIBRARY_PATH
        self.exportUserEnv()
        # Avoid create database failed by the value of CTSQL_SSL_KEY_PASSWD
        self.clean_ssl_env()

        os.environ['PATH'] = (os.path.join(self.installPath, "bin")
                                + ":" + os.environ['PATH'])
        # in some system LD_LIBRARY_PATH is not set,
        #  so must check it, or excetion will be raise
        if 'LD_LIBRARY_PATH' in os.environ:
            os.environ['LD_LIBRARY_PATH'] = ("%s:%s:%s" % (
                os.path.join(self.installPath, "lib"), os.path.join(
                    self.installPath, "add-ons",),
                os.environ['LD_LIBRARY_PATH']))
        else:
            os.environ['LD_LIBRARY_PATH'] = ("%s:%s" % (
                os.path.join(self.installPath, "lib"),
                os.path.join(self.installPath, "add-ons"),))
        os.environ["CTDB_HOME"] = self.installPath
        os.environ["CTDB_DATA"] = self.data
        os.environ["CMS_HOME"] = self.data

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
        if g_opts.install_user_privilege == "withoutroot":
            cmd = "%s/bin/ctencrypt -e PBKDF2" % self.installPath
        else:
            cmd = (""" su - '%s' -c "%s/bin/ctencrypt -e PBKDF2" """
                   % (self.user, self.installPath))
        g_opts.db_passwd = g_opts.db_passwd if len(plain_passwd.strip()) == 0 else plain_passwd.strip()
        values = [g_opts.db_passwd, g_opts.db_passwd]
        ret_code, stdout, stderr = _exec_popen(cmd, values)
        if ret_code:
            raise OSError("Failed to encrypt password of user [sys]."
                          " Error: %s" % (stderr+os.linesep+stderr))

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
            common_parameters["_SYS_PASSWORD"] = self.generate_nomount_passwd(common_parameters["_SYS_PASSWORD"])
        if "GCC_TYPE" in common_parameters and\
            (common_parameters["GCC_TYPE"] == "FILE" or common_parameters["GCC_TYPE"] == "NFS"):
            common_parameters["GCC_HOME"] = os.path.join(common_parameters["GCC_HOME"], "gcc_file")

        # 1.clean old conf
        self.clean_old_conf(list(common_parameters.keys()), conf_file)
        # 2.set new conf
        self.set_new_conf(common_parameters, conf_file)

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
            raise Exception("Can not write the %s, command: %s,"
                            " output: %s" % (conf_file, cmd, stderr))
        size = CLUSTER_SIZE
        if g_opts.running_mode in [CANTIAND, CANTIAND_WITH_MYSQL, CANTIAND_WITH_MYSQL_ST]:
            size = 1
        node_ip = re.split(r"[;,]", self.cantiandConfigs["INTERCONNECT_ADDR"])
        if len(node_ip) == 1:
            node_ip.append("127.0.0.1")
        
        gcc_home = self.cmsConfigs["GCC_HOME"]
        if self.cmsConfigs["GCC_TYPE"] == "FILE" or self.cmsConfigs["GCC_TYPE"] == "NFS":
            gcc_home = os.path.join(gcc_home, "gcc_file")
        
        # Generate new kernel parameters
        common_parameters = {
            "GCC_HOME": gcc_home,
            "REPORT_FILE": g_opts.log_file,
            "STATUS_LOG": os.path.join(self.data, "log", "cantianstatus.log"),
            "LD_LIBRARY_PATH": os.environ['LD_LIBRARY_PATH'],
            "USER_HOME": self.userHomePath,
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
            "MYSQL_CODE_DIR": MYSQL_CODE_DIR,
            "MYSQL_BIN_DIR": MYSQL_BIN_DIR,
            "MYSQL_DATA_DIR": MYSQL_DATA_DIR,
            "MYSQL_LOG_FILE": MYSQL_LOG_FILE,
        }

        # 1.clean old conf
        self.clean_old_conf(list(common_parameters.keys()), conf_file)
        # 2.set new conf
        self.set_new_conf(common_parameters, conf_file)

    def set_cthba_ssl(self):
        """Replace host to hostssl in cthba.conf"""
        cthba_file = os.path.join(self.data, "cfg", self.CANTIAND_HBA_FILE)
        cmd = "sed -i 's#^host #hostssl #g' %s" % cthba_file
        log("Set white list from host to hostssl.")
        ret_code, _, stderr = _exec_popen(cmd)
        if ret_code:
            err_msg = "Failed to set user white list from host to hostssl."
            log(err_msg + " Error: %s" % stderr)
            logExit(err_msg)

    def add_cthba_item(self):
        """Add INTERCONNECT_ADDR and ip white list to cthba.conf"""
        addr_list = []
        if len(g_opts.white_list) != 0:
            addr_list = [_.strip() for _ in g_opts.white_list.split(",")]
        for item in re.split(r"[;,]", self.cantiandConfigs["INTERCONNECT_ADDR"]):
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
    def update_ssl_conf(self):
        """Update ssl config."""
        if self.close_ssl:
            log("Skip update ssl config.")
            return
        log("Update ssl config.", True)
        # 1. Generate ssl certificate
        ssl_constructor = SslCertConstructor(self.ssl_path)
        ssl_constructor.generate()
        self._change_ssl_cert_owner()

        # 2. Modify cantiand.ini by sql
        # Set _FACTOR_KEY and LOCAL_KEY
        skip_execute_sql = True
        if self.option == self.INS_ALL:
            key_, work_key = self.get_ctencrypt_keys(skip_execute_sql)
        else:
            key_, work_key = self.get_ctencrypt_keys_and_file()
        # Get the value of SSL_KEY_PASSWORD from ini and
        # CTSQL_SSL_KEY_PASSWD from env and set SSL_KEY_PASSWORD into ini
        cipher = self.encrypt_ssl_key_passwd(key_, work_key,
                                             ssl_constructor.passwd, skip_execute_sql)
        # 3. Modify cantiand.ini by write
        # Set the ssl config in cantiand.ini for server
        self.set_ssl_conf(cipher, key_, work_key)
        # 4. Modify environment variables
        # Set the ssl config in cantiand.ini for client
        self.set_ssl_env(cipher)
        log("Update ssl config successfully.", True)

    def InitDbInstance(self):
        """
        Modify the database configuration file cantiand.ini with the given
        parameters, which are specified by the -C parameter.
        :return: NA
        """

        log("Initialize db instance.", True)
        try:
            self.FAILED_POS = self.INIT_DB_FAILED
            # Set cthba.conf to hostssl
            if not self.close_ssl:
                self.set_cthba_ssl()
            self.add_cthba_item()
            self.set_conf(self.cantiandConfigs, self.CANTIAND_CONF_FILE, True)
            self.set_conf(self.cmsConfigs, self.CMS_CONF_FILE)
            self.set_cluster_conf()
            self.update_ssl_conf()
        except Exception as err:
            self.rollBack()
            logExit(str(err))

        log("End init db instance")

    def generateReplAuthKeys(self):
        """Generate REPL_AUTH keys."""
        if not self.repl_auth:
            return

        try:
            log("Get password of REPL_AUTH keys.")
            if sys.stdin.isatty():
                # If not pipe content, get passwd by interactive input
                passwd = self.get_new_passwd(pw_prompt="password",
                                             user_prompt="REPL_AUTH keys",
                                             shortest_len=16)
            else:
                try:
                    # Get passwd from pipe
                    passwd = _get_input("")
                except EOFError:
                    # Not find passwd from pipe
                    err_msg = "The content got from pipe not find passwd."
                    raise ValueError(err_msg)
                self.verify_new_passwd(passwd, 16)
            log("Successfully get password of REPL_AUTH keys.")

            log("Generate REPL_AUTH keys.", True)
            if g_opts.install_user_privilege == "withoutroot":
                cmd = "%s/bin/ctencrypt -r -d '%s'" % (self.installPath,
                                                      self.data)
            else:
                cmd = (""" su - '%s' -c "%s/bin/ctencrypt -r -d '%s'" """
                       % (self.user, self.installPath, self.data))
            ret_code, stdout, stderr = _exec_popen(cmd, [passwd, passwd])
            if ret_code:
                raise OSError("Failed to generate REPL_AUTH keys."
                              " Error: %s" % (stdout + os.linesep + stderr))
            log("Successfully generate REPL_AUTH keys")
        except Exception as err:
            self.rollBack()
            logExit(str(err))

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
        insStr = text
        insList = insStr.split(os.sep)
        regString = ""
        for i in insList:
            if(i == ""):
                continue
            else:
                regString += r"\/" + i
        log("End gen regular string")
        return regString

    def __clean_env_cmd(self, cmds):
        # do clean
        for cmd in cmds:
            cmd = 'sed -i "%s" "%s"' % (cmd, self.userProfile)
            log("Clean environment variables cmd: %s" % cmd)
            ret_code, _, stderr = _exec_popen(cmd)
            if ret_code:
                log("Failed to clean environment variables."
                    " Error: %s" % stderr)
                logExit("Failed to clean environment variables.")

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

    def cleanEnvironment(self):
        """
        Clear environment variables
        :return: NA
        """
        log("Begin clean user environment variables...")

        # Clear environment variable CTDB_DATA
        data_cmd = r"/^\s*export\s*CTDB_DATA=.*$/d"
        # Clear environment variable PATH about database
        path_cmd = (r"/^\s*export\s*PATH=.*%s\/bin.*:\$PATH$/d"
                    % self.genregstring(self.installPath))
        # Clear environment variable LD_LIBRARY_PATH about database
        lib_cmd = (r"/^\s*export\s*LD_LIBRARY_PATH=.*%s\/lib.*"
                   r":.*%s\/add-ons.*:\$LD_LIBRARY_PATH$/d"
                   % (self.genregstring(self.installPath),
                      self.genregstring(self.installPath)))
        # Clear environment variable CTDB_HOME
        home_cmd = r"/^\s*export\s*CTDB_HOME=.*$/d"
        # Clear environment variable CMS_HOME
        cms_cmd = r"/^\s*export\s*CMS_HOME=.*$/d"

        # Clear environment ssl cert
        ca_cmd = r"/^\s*export\s*CTSQL_SSL_CA=.*$/d"
        cert_cmd = r"/^\s*export\s*CTSQL_SSL_CERT=.*$/d"
        key_cmd = r"/^\s*export\s*CTSQL_SSL_KEY=.*$/d"
        mode_cmd = r"/^\s*export\s*CTSQL_SSL_MODE=.*$/d"
        cipher_cmd = r"/^\s*export\s*CTSQL_SSL_KEY_PASSWD=.*$/d"

        cmds = [path_cmd, lib_cmd, home_cmd, cms_cmd,
                ca_cmd, cert_cmd, key_cmd, mode_cmd, cipher_cmd]
        if self.option == self.INS_ALL:
            cmds.insert(0, data_cmd)

        # do clean
        self.__clean_env_cmd(cmds)
        log("End clean user environment variables...")

    def rollBack(self):
        """
        Rollback operation.

        This function mainly used to fail during the installation process,
        clear the files and environment variables that have been installed,
        and let the environment restore the state before installation.
        :return: NA
        """
        log("Begin roll back...")

        if not self.userProfile:
            logExit("Roll back failed, can not find user user profile.")
        log("Roll back type: " + self.FAILED_POS)
        # rollback from decompress
        if self.FAILED_POS == self.DECOMPRESS_BIN_FAILED:
            # Delete program.
            self.rollbackFromDecompress()
        # rollback from set user env
        elif(self.FAILED_POS == self.SET_ENV_FAILED
             or self.FAILED_POS == self.PRE_DATA_DIR_FAILED
             or self.FAILED_POS == self.INIT_DB_FAILED):
            self.rollbackFromSetUserEnv()

        # rollback from create database
        elif self.FAILED_POS == self.CREATE_DB_FAILED:
            self.rollbackFromCreateDatabase()
        # rollback from init, nothing to do
        elif self.FAILED_POS == self.FAILED_INIT:
            # init status, pass
            log("Roll back: init ")
        else:
            # should not be here.
            logExit("Roll back can not recognize this operation: " + str(self.FAILED_POS))
        log("End roll back")

    def rollbackDataDirs(self):
        if os.path.exists(self.data):
            if g_opts.in_container and os.path.exists(CommonValue.DOCKER_DATA_DIR):
                shutil.rmtree(CommonValue.DOCKER_DATA_DIR)
                log("Roll back: " + CommonValue.DOCKER_DATA_DIR)
            shutil.rmtree(self.data)
            log("Roll back: " + self.data)

        if not g_opts.use_gss and not g_opts.use_dbstor:
            if g_opts.in_container and os.path.exists(CommonValue.DOCKER_GCC_DIR):
                shutil.rmtree(CommonValue.DOCKER_GCC_DIR)
                log("Roll back: " + CommonValue.DOCKER_GCC_DIR)

    def rollbackFromDecompress(self):
        if os.path.exists(self.installPath):
            shutil.rmtree(self.installPath)
            log("Roll back: " + self.installPath)
        if self.option == self.INS_ALL:
            # Delete data
            self.rollbackDataDirs()

    def rollbackFromSetUserEnv(self):
        log("Using user profile: " + self.userProfile)
        # Delete program
        if os.path.exists(self.installPath):
            shutil.rmtree(self.installPath)
            log("Roll back: remove " + self.installPath)
        if self.option == self.INS_ALL:
            # Delete data
            self.rollbackDataDirs()
        # Delete env value
        self.cleanEnvironment()

        log("Roll back: profile is updated ")

    def __kill_process(self, process_name):
        # root do install, need su - user kill process
        cmd = ("proc_pid_list=\`ps ux | grep %s | grep -v grep "
               "| awk '{print \$2}'\`" % process_name)
        cmd += (" && (if [ X\\\"\$proc_pid_list\\\" != X\\\"\\\" ]; "
                "then echo \\\"\$proc_pid_list\\\" | xargs kill -9 ; "
                "exit 0; fi)")
        kill_cmd = "su - '%s' -c \"%s\" " % (self.user, cmd)

        if g_opts.install_user_privilege == "withoutroot":
            # user do install, kill process
            kill_cmd = (r"proc_pid_list=`ps ux | grep %s | grep -v grep"
                        r"|awk '{print $2}'` && " % process_name)
            kill_cmd += (r"(if [ X\"$proc_pid_list\" != X\"\" ];then echo "
                         r"$proc_pid_list | xargs kill -9; exit 0; fi)")
        log("kill process cmd: %s" % kill_cmd)
        ret_code, _, _ = _exec_popen(kill_cmd)
        if ret_code:
            logExit("kill process %s faild" % process_name)

    def rollbackFromCreateDatabase(self):
        log("Using user profile: " + self.userProfile)
        # backup cantiand log before rm data

        strCmd = "cp -r %s/log %s" % (self.data, self.backup_log_dir)
        log("Begin to backup log cmd: " + strCmd)
        ret_code, _, stderr = _exec_popen(strCmd)
        if ret_code:
            logExit("Can not backup cantiand log command: %s, output: %s" % (strCmd, stderr))
        log("Error:The detail log for CREATE_DB_FAILED: %s" % self.backup_log_dir)

        # backup cantiand cfg before rm data
        strCmd = "cp -r %s/cfg %s" % (self.data, self.backup_log_dir)
        log("Begin to backup cfg cmd: " + strCmd)
        ret_code, _, stderr = _exec_popen(strCmd)
        if ret_code:
            logExit("Can not backup cantiand cfg command: %s, output: %s" % (strCmd, stderr))
        log("Error:The detail log for CREATE_DB_FAILED: %s" % self.backup_log_dir)

        # kill database process
        self.__kill_process("cms")
        if g_opts.use_gss:
            self.__kill_process("gssd")
        # TODO add back when install completely success
        log("Roll back: process killed.")

        # Delete program
        if os.path.exists(self.installPath):
            # Clean ssl keys.
            SslCertConstructor(self.ssl_path).clean_all()
            # Clean all files.
            shutil.rmtree(self.installPath)
            log("Roll back: remove " + self.installPath)
        # Delete data
        self.rollbackDataDirs()

        self.cleanEnvironment()

        log("Roll back: profile is updated ")

    #######################################################################
    # check datadir and prepare cfg/cantiand.ini,
    # mkdir datadir/data, datadir/log
    # The function fails to execute, the log is printed, and then exits
    #######################################################################
    def prepareDataDir(self):
        """
        function: check datadir and prepare cfg/cantiand.ini,
                  mkdir datadir/data, datadir/log, datadir/trc
        input : NA
        output: NA
        """
        print("Checking data dir and config file")
        try:
            self.FAILED_POS = self.PRE_DATA_DIR_FAILED
            strCmd = "chmod %s %s/ -R " % (CommonValue.KEY_DIRECTORY_MODE, self.data)
            log("Change privilege cmd: %s" % strCmd)
            ret_code, _, stderr = _exec_popen(strCmd)
            if ret_code:
                raise Exception("chmod %s return: " % CommonValue.KEY_DIRECTORY_MODE + str(ret_code) + os.linesep + stderr)

            # create data, cfg, log dir, trc
            data_dir = "%s/data" % self.data
            if g_opts.in_container:
                # Do not create the data dir in slave cluster.
                if not g_opts.slave_cluster:
                    create_dir_if_needed(skip_execute_in_node_1(), CommonValue.DOCKER_DATA_DIR)
                cmd = "ln -s %s %s;" % (CommonValue.DOCKER_DATA_DIR, data_dir)
                ret_code, _, stderr = _exec_popen(cmd)
                if ret_code:
                    raise Exception("Can not link data dir, command: %s, output: %s" % (cmd, stderr))
            else:
                os.makedirs(data_dir, CommonValue.KEY_DIRECTORY_PERMISSION)
            os.makedirs("%s/log" % self.data, CommonValue.KEY_DIRECTORY_PERMISSION)
            os.makedirs("%s/archive_log" % self.data, CommonValue.KEY_DIRECTORY_PERMISSION)
            os.makedirs("%s/trc" % self.data, CommonValue.KEY_DIRECTORY_PERMISSION)
            os.makedirs("%s/tmp" % self.data, CommonValue.KEY_DIRECTORY_PERMISSION)
            if not g_opts.use_gss and not g_opts.use_dbstor:
                if g_opts.in_container:
                    create_dir_if_needed(skip_execute_in_node_1(), CommonValue.DOCKER_GCC_DIR)
                    cmd = "ln -s %s %s" % (CommonValue.DOCKER_GCC_DIR, self.gcc_home)
                    ret_code, _, stderr = _exec_popen(cmd)
                    if ret_code:
                        raise Exception("Can not link gcc home dir, command: %s, output: %s" % (cmd, stderr))
                else:
                    os.makedirs(self.gcc_home, CommonValue.KEY_DIRECTORY_PERMISSION)

            if not self.close_ssl and self.option != self.INS_ALL:
                os.makedirs("%s/dbs" % self.data, CommonValue.KEY_DIRECTORY_PERMISSION)

            # move the config files about database.
            cmd = "mv -i %s/cfg %s" % (self.installPath, self.data)
            ret_code, _, stderr = _exec_popen(cmd)
            if ret_code:
                raise Exception("Can not create prepare data dir, command: %s, output: %s" % (cmd, stderr))

            # Change the mode of config files to 600
            cmd = "chmod {0} {1}/cfg/{2} {1}/cfg/{3} {1}/cfg/{4}".format(
                CommonValue.KEY_FILE_MODE, self.data, self.CANTIAND_CONF_FILE,
                self.CMS_CONF_FILE, self.CANTIAND_HBA_FILE)
            ret_code, _, stderr = _exec_popen(cmd)
            if ret_code:
                raise Exception("chmod %s return: " % CommonValue.KEY_FILE_MODE + str(ret_code) + os.linesep + stderr)

            # Change the owner of config files
            self.chownDataDir()
        except Exception as ex:
            self.rollBack()
            logExit(str(ex))

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
        log("setcap sucessed", True)
    
    def prepareMysqlForSingle(self):
        if g_opts.running_mode.lower() not in VALID_SINGLE_MYSQL_RUNNING_MODE:
            return
        log("prepareMysqlForSingle", True)
        self.check_parameter_mysql()
        self.prepare_mysql_data_dir()
        self.prepare_mysql_bin_dir()
        self.set_mysql_env()
    pass
    def start_gss(self):
        if not g_opts.use_gss:
            return
        log("Starting gss...", True)
        cmd = "sh %s -P gss >> %s 2>&1" % (INSTALL_SCRIPT, g_opts.log_file)
        if os.getuid() == 0:
            cmd = "su - %s -c '" % self.user + cmd + "'"
        ret_code, stdout, stderr = _exec_popen(cmd)
        if ret_code:
            output = stdout + stderr
            raise Exception("Can not start gss.\nStart cmd: %s.\nOutput: %s" % (cmd, output))
        log("gss has started", True)

    def start_cms(self):
        log("Starting cms...", True)
        cmd = "sh %s -P cms >> %s 2>&1" % (INSTALL_SCRIPT, g_opts.log_file)
        if os.getuid() == 0:
            cmd = "su - %s -c '" % self.user + cmd + "'"
        ret_code, stdout, stderr = _exec_popen(cmd)
        if ret_code:
            output = stdout + stderr
            raise Exception("Can not start cms.\nStart cmd: %s.\nOutput: %s" % (cmd, output))
        log("cms has started", True)
    
    ##################################################################
    # start cantian instance
    ##################################################################
    def start_cantiand(self):
        """
        function:start cantian instacne
        input : start mode, start type
        output: NA
        """
        log("Starting cantiand...", True)
        # start cantian dn
        self.chownDataDir()
        status_success = False
        start_mode = self.NOMOUNT_MODE
        # Start the slave_cluster in OPEN_MODE.
        if g_opts.slave_cluster == True:
            start_mode = self.OPEN_MODE
        if g_opts.node_id == 1:
            start_mode = self.OPEN_MODE
        
        # Start instance, according to running mode can point to cantiand or cantiand with mysql
        cmd = "sh %s -P cantiand -M %s -T %s -C %s >> %s 2>&1" % (
            INSTALL_SCRIPT, start_mode, g_opts.running_mode.lower(), g_opts.mysql_config_file_path, g_opts.log_file)
        if os.getuid() == 0:
            cmd = "su - %s -c '" % self.user + cmd + "'"
        log("start cantiand with cmd:%s"%cmd)
        status, stdout, stderr = _exec_popen(cmd)
        if status != 0:
            output = stdout + stderr
            raise Exception("Can not start instance %s.\nStart cmd: %s.\nOutput: %s" % (self.data, cmd, output))

        # In some condition cantian will take some time to start, so wait
        # it by checking the process cyclically after the start command
        # returned. If the cantiand process can't be found within the
        # expected time, it is considered that the startup failed.
        tem_log_info, status_success = self.initSomeCondition(status_success, self.status_log)

        # the log file's permission is 600, change it
        if os.path.exists(self.status_log):
            uid = pwd.getpwnam(self.user).pw_uid
            gid = grp.getgrnam(self.group).gr_gid
            os.chown(self.status_log, uid, gid)
            os.chmod(self.status_log, CommonValue.KEY_FILE_PERMISSION)

        if not status_success:
            raise Exception("Can not get instance '%s' process pid,"
                            "The detailed information: '%s' " % (self.data, tem_log_info))
        log("cantiand has started", True)

    def get_invalid_parameter(self):
        log_home = self.cantiandConfigs["LOG_HOME"]
        run_log = os.path.join(log_home, "run", "cantiand.rlog")
        cmd = "cat %s | grep 'ERROR' " % run_log
        ret_code, stdout, stderr = _exec_popen(cmd)
        output = stdout + stderr
        if ret_code:
            log("Failed to get the error message from '%s'. Output: %s" % (run_log, output))
            return ""
        else:
            return output

    def initSomeCondition(self, status_success, status_log):
        start_time = 1200
        tem_log_info = ""
        for i in range(0, start_time):
            time.sleep(3)
            if g_opts.install_user_privilege == "withoutroot":
                cmd = ("ps ux | grep -v grep | grep %s | grep $ "
                       "|awk '{print $2}'" % (self.data))
            else:
                cmd = ("su - '%s' -c \"ps ux | grep -v grep | grep cantiand | "
                       "grep %s$ |awk '{print \$2}'\" "
                       % (self.user, self.data))
            if g_opts.running_mode.lower() in [CANTIAND_WITH_MYSQL, CANTIAND_WITH_MYSQL_ST, CANTIAND_WITH_MYSQL_IN_CLUSTER]:
                cmd = ("su - '%s' -c \"ps -ef | grep -v grep | grep mysqld\""%(self.user))
                status_log = MYSQL_LOG_FILE
            pass
            ret_code, stdout, stderr = _exec_popen(cmd)
            if ret_code:
                status_success = False
                tem_log_info = ("Failed to execute cmd: %s.output:%s"
                                % (str(cmd), str(stderr)))
                break
            else:
                all_the_text = open(status_log).read()
                log("Instance start log output:%s.cmd:%s" %(str(all_the_text),str(cmd)))
                if all_the_text.find("instance started") > 0:
                    if stdout:
                        status_success = True
                        self.pid = stdout.strip()
                        log("start instance successfully, pid = %s" % stdout)
                        break
                elif all_the_text.find("instance startup failed") > 0:
                    status_success = False
                    tem_log_info = all_the_text.strip()
                    # Get the error message from run log. After rollback,
                    # all files and logs will be cleaned, so we must get
                    # the error message before rollback.
                    run_log_info = self.get_invalid_parameter()
                    if run_log_info:
                        tem_log_info += os.linesep
                        tem_log_info += ("The run log error: %s%s" % (os.linesep, run_log_info))
                    break
            if (i + 1) == start_time:
                status_success = False
                tem_log_info = "Instance startup timeout, more than 3600s"
            elif (i % 30) != 0:
                log("Instance startup in progress, please wait.", True)
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
        # Do not execute the create db sql in slave cluster.
        if skip_execute_in_node_1() or skip_execute_in_slave_cluster():
            return
        if g_opts.install_user_privilege == "withoutroot":
            if self.enableSysdbaLogin:
                cmd = "%s/bin/ctsql / as sysdba -q -D %s -f \"%s\" " % (
                    self.installPath,
                    self.data,
                    sql_file)
                return_code, stdout_data, stderr_data = _exec_popen(cmd)
            else:
                cmd = "%s/bin/ctsql %s@%s:%s -q -f \"%s\" " % (
                    self.installPath,
                    g_opts.db_user,
                    self.LOGIN_IP,
                    self.lsnr_port,
                    sql_file)
                return_code, stdout_data, stderr_data = _exec_popen(
                    cmd, [g_opts.db_passwd])
        else:
            if self.enableSysdbaLogin:
                cmd = ("su - '%s' -c \"%s/bin/ctsql / as sysdba "
                    "-q -D %s -f \"%s\" \""
                    % (self.user, self.installPath, self.data, sql_file))
                return_code, stdout_data, stderr_data = _exec_popen(cmd)
            else:
                cmd = ("su - '%s' -c \"%s/bin/ctsql %s@%s:%s -q -f \"%s\"\"" % (
                    self.user,
                    self.installPath,
                    g_opts.db_user,
                    self.LOGIN_IP,
                    self.lsnr_port,
                    sql_file))
                return_code, stdout_data, stderr_data = _exec_popen(
                    cmd, [g_opts.db_passwd])

        output = "%s%s" % (str(stdout_data), str(stderr_data))
        log("Execute sql file %s output: %s" % (sql_file, output))
        if return_code:
            raise Exception("Failed to execute sql file %s, output:%s" % (sql_file, output))

        # return code is 0, but output has error info, CT-xxx, ZS-xxx
        result = output.replace("\n", "")
        if re.match(".*CT-\d{5}.*", result) or re.match(".*ZS-\d{5}.*", result):
            raise Exception("Failed to execute sql file %s, output:%s" % (sql_file, output))

    def execute_mysql_update(self, sql_file):
        is_need_update = False
        if is_need_update:
            print("update cantian sys table and views...")
            action_parse = argparse.ArgumentParser()
            action_parse.add_argument("--mysql_cmd", dest="mysql_cmd", required=True) # /usr/local/mysql/bin/mysql
            action_parse.add_argument("--mysql_user", dest="mysql_user", required=True)
            args = action_parse.parse_args()
            mysql_cmd = args.mysql_cmd
            mysql_user = args.mysql_user
            if mysql_user == "root":
                cmd = "%s -u%s < %s" % (mysql_cmd, mysql_user, sql_file)
            else:
                mysql_pwd = getpass.getpass()
                cmd = "%s -u%s -p%s < %s" % (mysql_cmd, mysql_user, mysql_pwd, sql_file)


            return_code, stdout_data, stderr_data = _exec_popen(cmd)
            if return_code and MYSQL_VERSION != VERSION_DOCKER_META:
                output = "%s%s" % (str(stdout_data), str(stderr_data))
                raise Exception("Failed to execute mysql file %s, output:%s, return_code:%s"
                                % (sql_file, output, return_code))

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
        if g_opts.install_user_privilege == "withoutroot":
            if self.enableSysdbaLogin:
                cmd = "%s/bin/ctsql / as sysdba -q -D %s -c \"%s\" " % (
                    self.installPath,
                    self.data,
                    sql)
                return_code, stdout_data, stderr_data = _exec_popen(cmd)
            else:
                cmd = "%s/bin/ctsql %s@%s:%s -q -c \"%s\" " % (
                    self.installPath,
                    g_opts.db_user,
                    self.LOGIN_IP,
                    self.lsnr_port,
                    sql)
                return_code, stdout_data, stderr_data = _exec_popen(
                    cmd, [g_opts.db_passwd])
        else:
            if self.enableSysdbaLogin:
                cmd = ("su - '%s' -c \"%s/bin/ctsql / as sysdba "
                       "-q -D %s -c \\\"%s\\\" \""
                       % (self.user, self.installPath, self.data, sql))
                return_code, stdout_data, stderr_data = _exec_popen(cmd)
            else:
                cmd = ("su - '%s' -c \"%s/bin/ctsql %s@%s:%s -q"
                       " -c \\\"%s\\\"\"" % (self.user,
                                             self.installPath,
                                             g_opts.db_user,
                                             self.LOGIN_IP,
                                             self.lsnr_port,
                                             sql))
                return_code, stdout_data, stderr_data = _exec_popen(
                    cmd, [g_opts.db_passwd])

        output = "%s%s" % (str(stdout_data), str(stderr_data))
        if return_code:
            raise Exception("Failed to %s by sql, output:%s"
                            % (message, output))

        # return code is 0, but output has error info, CT-xxx, ZS-xxx
        result = output.replace("\n", "")
        if re.match(".*CT-\d{5}.*", result) or re.match(".*ZS-\d{5}.*", result):
            raise Exception("Failed to execute sql %s, output:%s" % (sql, output))

    def createDb(self):
        """
        function:config cantian dn
                1. start dn
                2. create database guass
                3. create user
        input : NA
        output: NA
        """
        log("Creating database.", True)
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
            # 1.start dn process in nomount mode
            self.FAILED_POS = self.CREATE_DB_FAILED
            if os.getuid() == 0:
                self.setcap()
            self.start_cms()
            self.start_gss()
            self.start_cantiand()
            log("Creating cantian database...", True)
            self.update_factor_key()
            self.execute_sql_file(self.get_database_file())
        except Exception as err:
            self.rollBack()
            logExit(str(err))
        log("Creating database succeed.", True)

    def get_database_file(self):
        if self.create_db_file:
            # execute customized sql file, check -f parameter
            self.checkCreatedbFile()
            return self.create_db_file

        # execute default sql file
        # modify the sql file for create database
        sql_file_path = "%s/admin/scripts" % self.installPath
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
        else:
            dbDataPath = os.path.join(self.data, "data").replace('/', '\/')
            self._sed_file("dbfiles1", dbDataPath, create_database_sql)
            self._sed_file("dbfiles2", dbDataPath, create_database_sql)
            self._sed_file("dbfiles3", dbDataPath, create_database_sql)
        return create_database_sql

    def _sed_file(self, prefix, replace, file_name):
        fixSqlFileCmd = ("sed -i 's/%s/%s/g' %s" % (prefix, replace, file_name))
        ret_code, _, _ = _exec_popen(fixSqlFileCmd)
        if ret_code:
            raise Exception("sed %s failed, replace %s" % (file_name, replace))

    def _change_ssl_cert_owner(self):
        if g_opts.install_user_privilege == "withoutroot":
            return

        cmd = "chown -R %s:%s %s; " % (self.user, self.group, self.ssl_path)
        ret_code, _, stderr = _exec_popen(cmd)
        if ret_code:
            raise Exception("chown to %s:%s return: %s%s%s"
                            % (self.user, self.group, str(ret_code), os.linesep, stderr))

    def get_ctencrypt_keys(self, skip_execute_sql = False):
        """Set the config about _FACTOR_KEY and LOCAL_KEY."""
        # Generate Key and WorkKey
        log("Generate encrypted keys.")
        if g_opts.install_user_privilege == "withoutroot":
            cmd = "%s/bin/ctencrypt -g" % self.installPath
        else:
            cmd = "su - '%s' -c \"%s/bin/ctencrypt -g \"" % (self.user, self.installPath)
        ret_code, stdout, stderr = _exec_popen(cmd)
        if ret_code:
            raise OSError("Failed to generate encrypted keys. Error: %s"
                          % (stderr+os.linesep+stderr))

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
        f_factor1 = os.path.join(self.data, "dbs", "cantian_key1")
        f_factor2 = os.path.join(self.data, "dbs", "cantian_key2")

        # Generate Key and WorkKey
        #   This command will encrypt _FACTOR_KEY and write it into f_factor1.
        if g_opts.install_user_privilege == "withoutroot":
            cmd = "%s/bin/ctencrypt -g -o '%s' " % (self.installPath, f_factor1)
        else:
            cmd = ("su - '%s' -c \"%s/bin/ctencrypt -g -o '%s' \""
                   % (self.user, self.installPath, f_factor1))
        ret_code, stdout, stderr = _exec_popen(cmd)
        if ret_code:
            raise OSError("Failed to generate encrypted keys. Error: %s"
                          % (stderr+os.linesep+stderr))

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

    def encrypt_ssl_key_passwd(self, key_, work_key, ssl_passwd, skip_execute_sql = False):
        """Encrypt ssl key password with _FACTOR_KEY and LOCAL_KEY."""
        log("Encrypt ssl key password.")
        if g_opts.install_user_privilege == "withoutroot":
            cmd = ("""%s/bin/ctencrypt -e AES256 -f %s -k %s """
                   % (self.installPath, key_, work_key))
        else:
            cmd = ("su - '%s' -c \"%s/bin/ctencrypt -e AES256"
                   " -f '%s' -k '%s' \""
                   % (self.user, self.installPath, key_, work_key))
        values = [ssl_passwd, ssl_passwd]
        ret_code, stdout, stderr = _exec_popen(cmd, values)
        if ret_code:
            raise OSError("Failed to encrypt ssl key password. Error: %s"
                          % (stderr+os.linesep+stderr))

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
            with open(self.userProfile, "a") as _file:
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
                          % str(ex))

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

        if g_opts.install_user_privilege == "withoutroot":
            if not g_opts.db_passwd:
                # connect database by sysdba
                cmd = ("%s/bin/shutdowndb.sh -h %s -p %s -w -m %s -D %s -T %d"
                       % (self.installPath, host_ip, self.lsnr_port,
                          "immediate", self.data, timeout))
                ret_code, _, stderr = _exec_popen(cmd)
            else:
                # connect database by username and password
                cmd = ("%s/bin/shutdowndb.sh -h"
                       " %s -p %s -U %s -m %s -W -D %s -T %d" %
                       (self.installPath, host_ip,
                        self.lsnr_port, g_opts.db_user, "immediate",
                        self.data, timeout))
                ret_code, _, stderr = _exec_popen(cmd, [g_opts.db_passwd])
        else:
            if not g_opts.db_passwd:
                # connect database by sysdba
                cmd = ("su - '%s' -c  \"%s/bin/shutdowndb.sh -h %s"
                       " -p %s -w -m %s -D %s -T %d \" "
                       % (self.user, self.installPath, host_ip, self.lsnr_port,
                          "immediate", self.data, timeout))
                ret_code, _, stderr = _exec_popen(cmd)
            else:
                # connect database by username and password
                cmd = ("su - '%s' -c  \" %s/bin/shutdowndb.sh -h"
                       " %s -p %s -U %s -m %s -W -D %s -T %d \" " %
                       (self.user, self.installPath,
                        host_ip, self.lsnr_port, g_opts.db_user, "immediate",
                        self.data, timeout))
                ret_code, _, stderr = _exec_popen(cmd, [g_opts.db_passwd])

        if ret_code:
            raise Exception("Failed to stop database. Error: %s"
                            % (stderr+os.linesep+stderr))
        log("stop cantian instance successfully.")

    def setSslCert(self):
        """Set ssl cert."""
        if self.close_ssl:
            log("Skip set ssl certificate.")
            return

        try:
            log("Open ssl connection.", True)
            # 1. Generate ssl certificate
            ssl_constructor = SslCertConstructor(self.ssl_path)
            ssl_constructor.generate()
            self._change_ssl_cert_owner()

            # 2. Modify cantiand.ini by sql
            # Set _FACTOR_KEY and LOCAL_KEY
            if self.option == self.INS_ALL:
                key_, work_key = self.get_ctencrypt_keys()
            else:
                key_, work_key = self.get_ctencrypt_keys_and_file()
            # Get the value of SSL_KEY_PASSWORD from ini and
            # CTSQL_SSL_KEY_PASSWD from env and set SSL_KEY_PASSWORD into ini
            cipher = self.encrypt_ssl_key_passwd(key_, work_key,
                                                 ssl_constructor.passwd)

            # 3. Modify cantiand.ini by write
            # Set the ssl config in cantiand.ini for server
            if self.option == self.INS_ALL:
                self.set_ssl_conf()
            else:
                self.set_ssl_conf(cipher, work_key)

            # 4. Stop database to restart.
            # Why stop the database before setting environment variables?
            #   The value of CTSQL_SSL_MODE is "required". If we set the env
            # before stop database, the shutdown.sh will failed to connect
            # database with this error:
            #   CT-00343, SSL is required but the server doesn't support it
            # and it will wait for timeout.
            if self.option == self.INS_ALL:
                self.stop_database()

            # 5. Modify environment variables
            # Set the ssl config in cantiand.ini for client
            self.set_ssl_env(cipher)

            # 6. Restart the database to make the configuration take effect
            if self.option == self.INS_ALL:
                log("Start database with open mode.")
                self.start_cantiand()
            log("Open ssl connection successfully.", True)
        except Exception as err:
            self.rollBack()
            logExit(str(err))

    def chmodInstallSqlfile(self):
        """
        function: when install finished, modify sql file permission to 400
        input : NA
        output: NA
        """
        try:
            strCmd = ("find '%s'/admin -type f | xargs chmod %s "
                      % (self.installPath, CommonValue.MIN_FILE_MODE))
            ret_code, _, _ = _exec_popen(strCmd)
            if ret_code:
                print("Change file permission to %s failed."
                      " Please chmod %s filein directory %s/admin manually."
                      % (CommonValue.MIN_FILE_MODE,
                         CommonValue.MIN_FILE_MODE, self.installPath))
        except Exception as err:
            logExit(str(err))

    def securityAudit(self):
        """
        function:  securityAudit, add oper if you needed
                1. chmod sql file permission
                2. ...
                3.
        input : NA
        output: NA
        """

        log("Changing file permission due to security audit.", True)
        # 1. chmod sql file permission
        self.chmodInstallSqlfile()
    
    def set_core_dump_filter(self):
        """
        function: set_core_dump_filter, modify num to support core dump shared memory
                1. the value in the file is a bit mask of memory mapping types
                2. if a bit is set in the mask, then memory mappings of the corresponding type are dumped
                3. the bits in this file have the following meanings:
                    bit 0   dump anonymous private mappings
                    bit 1   dump anonymous shared mappings
                    bit 2   dump file-backed private mappings
                    bit 3   dump file-backed shared mappings
                    bit 4   dump ELF headers
                    bit 5   dump private huge pages
                    bit 6   dump shared huge pages
        input:  NA
        output: NA
        """
        log("set cantiand coredump_filter value to 0x6f(1101111)", True)
        sep_mark = os.path.sep
        cmd = "pidof cantiand"
        ret_code, cantiand_pids, stderr = _exec_popen(cmd)
        if ret_code:
            logExit("can not get pid of cantiand, command: %s, err: %s" % (cmd, stderr))
        for cantiand_pid in cantiand_pids.split():
            cantiand_pid = cantiand_pid.strip()
            if cantiand_pid is not None and len(cantiand_pid) > 0:
                cmd = "echo 0x6f > " + sep_mark + "proc" + sep_mark + str(cantiand_pid) + \
                    sep_mark + "coredump_filter"
                ret_code, _, stderr = _exec_popen(cmd)
                if ret_code:
                    logExit("can not set coredump_filter, command: %s, err: %s" % (cmd, stderr))
    
    def set_core_dump_filter_mysql(self):
        """
        function: set_core_dump_filter_mysql, modify num to support core dump shared memory
                1. the value in the file is a bit mask of memory mapping types
                2. if a bit is set in the mask, then memory mappings of the corresponding type are dumped
                3. the bits in this file have the following meanings:
                    bit 0   dump anonymous private mappings
                    bit 1   dump anonymous shared mappings
                    bit 2   dump file-backed private mappings
                    bit 3   dump file-backed shared mappings
                    bit 4   dump ELF headers
                    bit 5   dump private huge pages
                    bit 6   dump shared huge pages
        input:  NA
        output: NA
        """
        log("set mysqld coredump_filter value to 0x6f(1101111)", True)
        sep_mark = os.path.sep
        cmd = "pidof mysqld"
        ret_code, mysqld_pids, stderr = _exec_popen(cmd)
        if ret_code:
            logExit("can not get pid of mysqld, command: %s, err: %s" % (cmd, stderr))
        for mysqld_pid in mysqld_pids.split():
            mysqld_pid = mysqld_pid.strip()
            if mysqld_pid is not None and len(mysqld_pid) > 0:
                cmd = "echo 0x6f > " + sep_mark + "proc" + sep_mark + str(mysqld_pid) + \
                    sep_mark + "coredump_filter"
                ret_code, _, stderr = _exec_popen(cmd)
                if ret_code:
                    logExit("can not set coredump_filter, command: %s, err: %s" % (cmd, stderr))

    ######################################################################
    # The main process of installation.
    # It is not necessary to check the return value of each function,
    # because there are check behavior them. If failed to execute code,
    # they will print the log and exit.
    #######################################################################
    def install(self):
        """
        install cantian app and create database
        the step of install for rollback:
        1. init
        2. create database
        3. set user env
        4. decompress bin file
        the install process will save the install step in
        temp file, and when some step failed, the rollback
        process read the install step and clean the files
        and directory created when install
        """
        self.getRunPkg()
        if g_opts.install_user_privilege == "withoutroot":
            pass
        else:
            self.checkRunner()
        self.checkParameter() # add cantiand, cms, gss config parameter check logic in this method
        # user and group is right, change owner of the log file to user
        self.chownLogFile()
        self.checkOldInstall()
        self.checkConfigOptions()
        self.checkSysPasswd()
        self.checkDIR()
        self.checkSHA256()
        self.generateSslCert()
        self.decompressBin()    #TODO shiyi check CMS, GSS bin when compile success
        self.setUserEnv()
        self.prepareDataDir()
        self.prepareMysqlForSingle()
        self.InitDbInstance() # init db config, including cantiand, cms, gss, ssl
        self.generateReplAuthKeys()
        log("Successfully Initialize %s instance." % self.instance_name)
        if self.option == self.INS_ALL:
            self.createDb()
        self.securityAudit()
        # Don't set the core_dump_filter with -O option.
        if self.option == self.INS_ALL:
            self.set_core_dump_filter()
        log("Successfully install %s instance." % self.instance_name)

    def check_parameter_mysql(self):
        if g_opts.mysql_config_file_path == "unset":
            g_opts.mysql_config_file_path = os.path.join(MYSQL_CODE_DIR, "scripts/my.cnf")
            log("no mysql config file assigned, set to %s" % g_opts.mysql_config_file_path, True)
        real_path = os.path.realpath(g_opts.mysql_config_file_path)
        if not os.path.isfile(real_path):
            logExit("mysql config file {} not existed or it is not a file".format(real_path))
        if not self.is_readable(real_path, self.user):
            logExit("mysql config file {} is not readable by {}".format(real_path, self.user))
        g_opts.mysql_config_file_path = real_path
        cmd = "chown {}:{} {};".format(self.user, self.group, real_path)
        cmd += "chmod {} {}".format(CommonValue.MAX_FILE_MODE, real_path)
        ret_code, _, stderr = _exec_popen(cmd)
        if ret_code:
            logExit("Can not set mysql config mode, command: %s, output: %s" % (cmd, stderr))

    def prepare_mysql_data_dir(self):
        log("Preparing mysql data dir...", True)
        self.clean_dir(MYSQL_DATA_DIR)
        self.prepareGivenPath(MYSQL_DATA_DIR, True)

    def prepare_mysql_bin_dir(self):
        log("Preparing mysql bin dir...", True)
        self.clean_dir(MYSQL_BIN_DIR)
        self.prepareGivenPath(MYSQL_BIN_DIR, True)
        cmd = "cp -arf {} {};".format(os.path.join(MYSQL_CODE_DIR, "mysql_bin/mysql/*"), MYSQL_BIN_DIR)

        cmd += "cp %s/cfg/osd.cfg %s/bin/osd.cfg;" % (self.data, MYSQL_BIN_DIR)
        cmd += "chown -R {}:{} {};".format(self.user, self.group, MYSQL_BIN_DIR)
        cmd += "chmod 550 {};".format(os.path.join(MYSQL_BIN_DIR, "bin/mysql"))
        ret_code, _, stderr = _exec_popen(cmd)
        if ret_code:
            logExit("Can not copy mysql bin, command: %s, output: %s" % (cmd, stderr))

    def set_mysql_env(self):
        log("Preparing mysql running env...", True)
        if 'LD_LIBRARY_PATH' in os.environ:
            os.environ['LD_LIBRARY_PATH'] = ("%s:%s:%s:%s" % (
                os.path.join(MYSQL_BIN_DIR, "lib"),
                os.path.join(MYSQL_CODE_DIR, "daac_lib"),
                os.path.join(MYSQL_BIN_DIR, "lib/private"),
                os.environ['LD_LIBRARY_PATH']))
        else:
            os.environ['LD_LIBRARY_PATH'] = ("%s:%s:%s" % (
                os.path.join(MYSQL_BIN_DIR, "lib"), os.path.join(MYSQL_BIN_DIR, "lib/private"), os.path.join(
                    MYSQL_CODE_DIR, "daac_lib")))
        cmd = "ldconfig -N %s %s" % (os.path.join(MYSQL_CODE_DIR, "daac_lib"), os.path.join(MYSQL_BIN_DIR, "lib"))
        ret_code, _, stderr = _exec_popen(cmd)
        if ret_code:
            logExit("Can not link mysql lib, command: %s, output: %s" % (cmd, stderr))

    def start_mysql(self, is_slave_cluster):
        log("Starting mysqld...", True)
        if os.path.exists(MYSQL_LOG_FILE) and os.path.isfile(MYSQL_LOG_FILE):
            log("Warning: the mysql log file %s should empty for mysqld start" % MYSQL_LOG_FILE, True)
        # mysql init
        # Do not init mysql in slave cluster.
        if not is_slave_cluster:
            mysql_view_file = self.get_cantian_defs_file()
            cmd = "%s --defaults-file=%s --initialize-insecure --datadir=%s --init-file=%s \
                --early-plugin-load=\"ctc_ddl_rewriter=ha_ctc.so;ctc=ha_ctc.so;\" \
                --core-file --log-error=%s" % (
                os.path.join(MYSQL_BIN_DIR, "bin/mysqld"),
                g_opts.mysql_config_file_path,
                MYSQL_DATA_DIR,
                mysql_view_file,
                MYSQL_LOG_FILE)
            if os.getuid() == 0:
                cmd = "su %s -c '" % self.user + cmd + "'"
            status, stdout, stderr = _exec_popen(cmd)
            if status != 0:
                output = stdout + stderr
                raise Exception("Can not init mysqld %s.\nStart cmd: %s.\nOutput: %s" % (self.data, cmd, output))

        # start mysqld
        cmd = """%s %s --defaults-file=%s --datadir=%s --plugin-dir=%s \
        --plugin_load=\"ctc_ddl_rewriter=ha_ctc.so;ctc=ha_ctc.so;\" \
        --check_proxy_users=ON --mysql_native_password_proxy_users=ON \
        --default-storage-engine=CTC \
        --core-file > %s 2>&1 &
        """ % (self.numactl_str, os.path.join(MYSQL_BIN_DIR, "bin/mysqld"), g_opts.mysql_config_file_path,
               MYSQL_DATA_DIR, os.path.join(MYSQL_BIN_DIR, "lib/plugin"), MYSQL_LOG_FILE)
        if os.getuid() == 0:
            cmd = "su %s -c '" % self.user + cmd + "'"
        status, stdout, stderr = _exec_popen(cmd)
        if status != 0:
            output = stdout + stderr
            raise Exception("Can not start mysqld %s.\nStart cmd: %s.\nOutput: %s" % (self.data, cmd, output))
        if self.check_has_start_mysqld() == False:
            raise Exception("failed or exceed time to start mysqld\nPlease see the log of %s" % MYSQL_LOG_FILE)
 
    def start_mysql_with_metadata_in_cantian(self):
        log("Starting mysqld...", True)
        if os.path.exists(MYSQL_LOG_FILE) and os.path.isfile(MYSQL_LOG_FILE):
            log("Warning: the mysql log file %s should empty for mysqld start" % MYSQL_LOG_FILE, True)
        mysql_view_file = self.get_cantian_defs_file()
        cmd_init_metadata_in_cantian = "%s --defaults-file=%s --initialize-insecure --datadir=%s --init-file=%s \
                                       --early-plugin-load=\"ha_ctc.so\" --core-file --log-error=%s" % (
                                       os.path.join(MYSQL_BIN_DIR, "bin/mysqld"),
                                       g_opts.mysql_config_file_path,
                                       MYSQL_DATA_DIR,
                                       mysql_view_file,
                                       MYSQL_LOG_FILE)
        if os.path.exists("/.dockerenv"):
            cmd_start_mysqld = """ %s --defaults-file=%s --datadir=%s --user=root --skip-innodb \
            --early-plugin-load="ha_ctc.so" --core-file >> %s 2>&1 &
            """ % (os.path.join(MYSQL_BIN_DIR, "bin/mysqld"), g_opts.mysql_config_file_path, MYSQL_DATA_DIR,
                MYSQL_LOG_FILE)
        else:
            cmd_start_mysqld = """%s %s --defaults-file=%s --datadir=%s --plugin-dir=%s \
            --early-plugin-load="ha_ctc.so" \
            --core-file >> %s 2>&1 &
            """ % (self.numactl_str, os.path.join(MYSQL_BIN_DIR, "bin/mysqld"), g_opts.mysql_config_file_path,
                MYSQL_DATA_DIR, os.path.join(MYSQL_BIN_DIR, "lib/plugin"), MYSQL_LOG_FILE)
            if os.getuid() == 0:
                cmd_init_metadata_in_cantian = "su %s -c '" % self.user + cmd_init_metadata_in_cantian + "'"
                cmd_start_mysqld = "su %s -c '" % self.user + cmd_start_mysqld + "'"
        # we donot check initialize metadata dir failure since metadata init failed can also succeed to start mysqld.
        # metadata maybe initialized by other node
        retry_time = 2
        while retry_time > 0:
            self.clean_dir(MYSQL_DATA_DIR)
            status, stdout, stderr = _exec_popen(cmd_init_metadata_in_cantian)
            status, stdout, stderr = _exec_popen(cmd_start_mysqld)
            if self.check_has_start_mysqld():
                break
            retry_time = retry_time - 1
            time.sleep(2)
            log("retry initilize and start mysqld again...", True)
        if retry_time == 0:
            raise Exception("failed or exceed time to start mysqld\nPlease see the log of %s" % MYSQL_LOG_FILE)

    def check_has_start_mysqld(self):
        log_data = ""
        retry_time = 20
        while retry_time > 0:
            try:
                with open(MYSQL_LOG_FILE) as file_hanlde:
                    log_data = "".join(file_hanlde.readlines())
                if log_data.find("ready for connections") != -1 and log_data.find("tse reg instance success") != -1:
                    log("succeed to start mysqld", True)
                    return True
            except Exception as exerr:
                log("open log file failed: %s." % str(exerr), False)
            retry_time = retry_time - 1
            time.sleep(2)
        if retry_time == 0:
            return False


    def install_mysql(self):
        self.check_parameter_mysql()
        # If it is not normalized, do not prepare_mysql_data_dir in slave cluster.
        self.prepare_mysql_data_dir()
        self.prepare_mysql_bin_dir()
        self.set_mysql_env()

        if MYSQL_VERSION == VERSION_DOCKER_META:
            print("mysql_meta: going to start docker mysql in meta.")
            self.start_mysql_with_metadata_in_cantian()
            #self.execute_mysql_update(self.get_cantian_defs_file())
        elif MYSQL_VERSION == VERSION_DOCKER_NOMETA:
            print("mysql_nometa: developer docker deploy.")
            self.start_mysql(g_opts.slave_cluster)
            #self.execute_mysql_update(self.get_cantian_defs_file())
        elif MYSQL_VERSION == VERSION_ENV_META:
            mysql_plugin_path = os.path.join(MYSQL_BIN_DIR, "lib/plugin")
            print("mysql_meta: going to start mysql in meta. bin_dir:%s" % mysql_plugin_path)
            self.start_mysql_with_metadata_in_cantian()
            #if g_opts.node_id == 0:
            #self.execute_mysql_update(self.get_cantian_defs_file())
        elif MYSQL_VERSION == VERSION_ENV_NOMETA:
            mysql_plugin_path = os.path.join(MYSQL_BIN_DIR, "lib/plugin")
            ctc_path = os.path.join(MYSQL_BIN_DIR, "lib/plugin/nometa/ha_ctc.so")
            shutil.copy(ctc_path, mysql_plugin_path)
            print("mysql_nometa: copy ha_ctc.so from %s to %s" % (ctc_path, mysql_plugin_path))
            self.start_mysql(g_opts.slave_cluster)
            # self.execute_mysql_update(self.get_cantian_defs_file())

        # Don't set the core_dump_filter with -O option.
        # if self.option == INS_ALL:
        #     self.set_core_dump_filter_mysql()

    def checkCreatecantiandefsFile(self):
        '''
        check it is a file; user has read permission,
        :return:
        '''
        # check it is a file
        if not os.path.isfile(self.create_cantian_defs_file):
            raise Exception("Error: %s does not exists or is not a file"
                            " or permission is not right."
                            % self.create_cantian_defs_file)
        if not checkPath(self.create_cantian_defs_file):
            raise Exception("Error: %s file path invalid: "
                            % self.create_cantian_defs_file)
        # if execute user is root, check common user has read permission
        file_path = os.path.dirname(self.create_cantian_defs_file)

        # check path of cantian defs sql file that user can cd
        permission_ok, _ = self.checkPermission(file_path, True)
        if not permission_ok:
            raise Exception("Error: %s can not access %s"
                            % (self.user, file_path))

        # check cantian defs file is readable for user
        if not self.is_readable(self.create_cantian_defs_file, self.user):
            raise Exception("Error: %s is not readable for user %s"
                            % (self.create_cantian_defs_file, self.user))
        # change file to a realpath file
        self.create_cantian_defs_file = os.path.realpath(self.create_cantian_defs_file)

    def get_cantian_defs_file(self):
        if self.create_cantian_defs_file:
            # execute customized sql file, check -f parameter
            self.checkCreatecantiandefsFile()
            return self.create_cantian_defs_file
        if os.path.exists("/.dockerenv"):
            sql_file_path = "/home/regress/CantianKernel/pkg/admin/scripts"
        else:
            sql_file_path = "/opt/cantian/mysql/scripts/"
        file_name = "cantian_defs.sql"
        create_cantian_defs_file = os.path.join(sql_file_path, file_name)
        return create_cantian_defs_file

def main():
    """
    main entry
    """
    check_platform()
    check_runner()
    parse_parameter()
    check_parameter()

    try:
        installer = Installer(g_opts.os_user, g_opts.os_group)
        if g_opts.running_mode == MYSQLD:
            installer.install_mysql()
        else:
            installer.install()
        log("Install successfully, for more detail information see %s." % g_opts.log_file, True)
    except Exception as err:
        logExit("Install failed: " + str(err))


if __name__ == "__main__":
    main()

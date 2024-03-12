#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Perform hot backups of CantianDB100 databases.
# Copyright © Huawei Technologies Co., Ltd. 2010-2018. All rights reserved.


import sys

# If run by root, the import behavior will create folder '__pycache__'
# whose owner will be root. The database owner has'nt permission to
# remove the folder. So we can't create it.
sys.dont_write_bytecode = True
try:
    import getopt
    import getpass
    import os
    import platform
    import pwd
    import shutil
    import stat
    import subprocess
    import time
    import sys
    import json
    import socket
    from get_config_info import get_value
    from log import LOGGER
    from Common import DefaultValue, CommonPrint
    from exception import NormalException
except ImportError as err:
    raise ValueError("Unable to import module: %s." % str(err)) from err

# Get the operating system type
CURRENT_OS = platform.system()

MYSQL_BIN_DIR = "/opt/cantian/mysql/install/mysql"
MYSQL_DATA_DIR = ""
MYSQL_LOG_FILE = ""

INSTALL_SCPRIT_DIR = os.path.dirname(os.path.abspath(__file__))
PKG_DIR = os.path.abspath(os.path.join(INSTALL_SCPRIT_DIR, "../.."))

JS_CONF_FILE = os.path.join(PKG_DIR, "action", "cantian", "install_config.json")
UNINSTALL_PATH = os.path.join(PKG_DIR, "action", "cantian")
CANTIAN_UNINSTALL_CONF_FILE = os.path.join(PKG_DIR, "action", "cantian", "cantian_uninstall_config.json")
CANTIAN_START_STATUS_FILE = os.path.join("/opt/cantian/cantian", "cfg", "start_status.json")
CANTIAN_UNINSTALL_LOG_FILE = "/opt/cantian/cantian/log/cantian_deploy.log"
CONFIG_PARAMS_FILE = os.path.join(PKG_DIR, "config", "deploy_param.json")
FORCE_UNINSTALL = None
CHECK_MAX_TIMES = 60


def _exec_popen(_cmd, values=None):
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
        pobj.stdin.write(_cmd.encode())
        pobj.stdin.write(os.linesep.encode())
        for value in values:
            pobj.stdin.write(value.encode())
            pobj.stdin.write(os.linesep.encode())
        try:
            stdout_1, stderr_1 = pobj.communicate(timeout=1800)
        except subprocess.TimeoutExpired as err_cmd:
            pobj.kill()
            return -1, "Time Out.", str(err_cmd)
        stdout_1 = stdout_1.decode()
        stderr_1 = stderr_1.decode()
    else:
        pobj.stdin.write(_cmd)
        pobj.stdin.write(os.linesep)
        for value in values:
            pobj.stdin.write(value)
            pobj.stdin.write(os.linesep)
        try:
            stdout_1, stderr_1 = pobj.communicate(timeout=1800)
        except subprocess.TimeoutExpired as err_cmd:
            pobj.kill()
            return -1, "Time Out.", str(err_cmd)

    if stdout_1[-1:] == os.linesep:
        stdout_1 = stdout_1[:-1]
    if stderr_1[-1:] == os.linesep:
        stderr_1 = stderr_1[:-1]

    return pobj.returncode, stdout_1, stderr_1


def cantian_check_share_logic_ip_isvalid(node_ip):
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

    log("check nfs logic ip address or domain name.")
    if not ping_execute("ping") and not ping_execute("ping6"):
        log_exit("checked the node IP address or domain name failed: %s" % node_ip)

    log("checked the node IP address or domain name success: %s" % node_ip)


class Options(object):
    """
    class for command line options
    """

    def __init__(self):
        # user information
        self.user_info = pwd.getpwuid(os.getuid())
        # Whether to mark the cleanup of the specified data directory,
        # the value range is 0 or 1. The default value is 1, the data
        # directory is not cleared, and when the value is 0, the data
        # directory is cleared.
        self.clean_data_dir_on = 1
        # data dir
        self.clean_data_dir = ""

        # The user and password of database
        self.db_user = ""
        self.db_passwd = ""
        self.install_user_privilege = "withoutroot"
        self.log_file = ""
        self.install_path_l = ""
        self.user_env_path = ""
        self.gs_data_path = ""

        # The object of opened log file.
        self.tmp_fp = None

        self.use_gss = False
        self.namespace = ""
        self.node_id = 0


g_opts = Options()
gPyVersion = platform.python_version()


def usage():
    """uninstall.py is a utility to uninstall cantiand server.
    Usage:
    python uninstall.py --help
    python uninstall.py [-U user] [-F] [-D DATADIR]  [-g withoutroot] [-d] [-s]

    Common options:
    -U        user who install the db
    -F        clean the database storage area
    -D        location of the database cluster storage area,
                it will be available after -F
    -g        run uninstall script without root privilege,
                but you must have permission of uninstallation folder
    -d        uninstall inside docker container
    -P        if sysdba login is disabled by configuration,
                specify this option the end
    -s        uninstall with gss
    --help    show this help, then exit
    """
    print_str = CommonPrint()
    print_str.common_log(usage.__doc__)


def parse_parameter():
    """
    parse command line parameters
    input: NA
    output: NA
    """
    log("Checking uninstall parameters...")
    try:
        # Parameters are passed into argv. After parsing, they are stored
        # in opts as binary tuples. Unresolved parameters are stored in args.

        flags = os.O_RDONLY
        modes = stat.S_IWUSR | stat.S_IRUSR
        with os.fdopen(os.open(JS_CONF_FILE, flags, modes), 'r') as fp:
            json_data = json.load(fp)
            g_opts.clean_data_dir_on = 0  # -F
            g_opts.clean_data_dir = json_data['UNINSTALL_D_LOCATION_DATABASE_AREA'].strip()  # -D
            if os.getuid() != 0:  # -g
                g_opts.install_user_privilege = json_data['UNINSTALL_g_RUN_UNINSTALL_SCRIPT'].strip()
            g_opts.use_gss = True  # -s

        flags = os.O_RDONLY
        modes = stat.S_IWUSR | stat.S_IRUSR
        with os.fdopen(os.open(CONFIG_PARAMS_FILE, flags, modes), 'r') as config_fp:
            json_data = json.load(config_fp)
            g_opts.namespace = json_data.get('cluster_name', 'test1').strip()
            g_opts.node_id = int(json_data.get('node_id'))
            metadata_str = "metadata_" + json_data.get('storage_metadata_fs', '').strip()
            node_str = "node" + str(g_opts.node_id)
            global MYSQL_DATA_DIR
            MYSQL_DATA_DIR = os.path.join("/mnt/dbdata/remote", metadata_str, node_str)
            global MYSQL_LOG_FILE
            MYSQL_LOG_FILE = os.path.join(MYSQL_DATA_DIR, "mysql.log")

    except getopt.GetoptError as error:
        # Error output reminder
        print_str = CommonPrint()
        print_str.common_log("Parameter input error: " + error.msg)
        raise ValueError("Parameter input error: %s." % error.msg) from error


def check_parameter():
    """
    check command line parameter
    input: NA
    output: NA
    """
    if CURRENT_OS == "Linux":
        deploy_user = get_value("deploy_user")
        user_id = os.getuid()

        cmd = "id -u %s" % deploy_user
        ret_code, stdout, stderr = _exec_popen(cmd)

        if ret_code:
            log_exit("cannot get uid. error: %s" % stderr)

        if user_id != int(stdout):
            print_str = CommonPrint()
            print_str.common_log("Error:Only user with installer can run this script")
            raise ValueError("Error:Only user with installer can run this script")

        if g_opts.install_user_privilege != "withoutroot":
            print_str = CommonPrint()
            print_str.common_log("Error: User has no root privilege, "
                                 "do uninstall, need specify parameter '-g withoutroot'.")
            raise ValueError("Error: User has no root privilege, "
                             "do uninstall, need specify parameter '-g withoutroot'.")
    else:
        print_str = CommonPrint()
        print_str.common_log("Error:Check os failed:current os is not linux")
        raise ValueError("Error:Check os failed:current os is not linux")

    if g_opts.clean_data_dir_on == 1:
        if g_opts.clean_data_dir:
            print_str = CommonPrint()
            print_str.common_log("Error: Parameter input error: "
                                 "you can not use -D without using -F")
            raise ValueError("Error: Parameter input error: "
                             "you can not use -D without using -F")
    if g_opts.clean_data_dir:
        g_opts.clean_data_dir = os.path.realpath(
            os.path.normpath(g_opts.clean_data_dir))
        DefaultValue.check_invalid_path(g_opts.clean_data_dir)


def check_log_path():
    flags = os.O_RDONLY
    modes = stat.S_IWUSR | stat.S_IRUSR
    with os.fdopen(os.open(CANTIAN_UNINSTALL_CONF_FILE, flags, modes), 'r') as fp:
        json_data = json.load(fp)
        if json_data.get('LOG_FILE', '').strip() == "":
            g_opts.log_file = CANTIAN_UNINSTALL_LOG_FILE
        else:
            g_opts.log_file = json_data.get('LOG_FILE', '').strip()

    if not g_opts.log_file:
        g_opts.log_file = CANTIAN_UNINSTALL_LOG_FILE


def log(msg, is_print=False):
    """
    Print log
    :param msg: log message
    :return: NA
    """
    if is_print:
        print_str = CommonPrint()
        print_str.common_log(msg)

    LOGGER.info(msg)


def log_exit(msg):
    """
    Print log and exit
    :param msg: log message
    :return: NA
    """
    LOGGER.error(msg)
    if FORCE_UNINSTALL != "force":
        raise ValueError("Execute cantian_unstall.py failed")


def get_install_path():
    """
    Obtain the path of the uninstall script, that is, the bin directory
    under the installation path
    :return: NA
    """
    log("Getting install path...")

    flags = os.O_RDONLY
    modes = stat.S_IWUSR | stat.S_IRUSR
    with os.fdopen(os.open(JS_CONF_FILE, flags, modes), 'r') as fp:
        json_data = json.load(fp)
        g_opts.install_path_l = json_data['R_INSTALL_PATH'].strip()
        # Must be exist
    if not os.path.exists(g_opts.install_path_l):
        log_exit("Failed to get install path.")
    log("End get install path")


def get_deploy_user():
    flags = os.O_RDONLY
    modes = stat.S_IWUSR | stat.S_IRUSR

    with os.fdopen(os.open(CONFIG_PARAMS_FILE, flags, modes), 'r') as fp1:
        json_data_deploy = json.load(fp1)

    deploy_user = get_value("deploy_user")

    return deploy_user, json_data_deploy


def get_user_environment_file():
    """
    Get the path to the user environment variable.
    :return: NA
    """
    log("Getting user environment variables file path...")
    home_path = g_opts.user_info.pw_dir
    g_opts.user_env_path = os.path.realpath(
        os.path.normpath(os.path.join(home_path, ".bashrc")))
    if not os.path.isfile(os.path.realpath(g_opts.user_env_path)):
        log_exit("Can't get the environment variables file.")
    log("End get user environment variables file path")


#####################################################################
# Determine if there is a string in front of it
#####################################################################
def find_before_slice(slice_, str_):
    """
    find '#' in the head of line
    """
    place = str_.find(slice_)
    return str_.find('#', 0, place)


####################################################################
# Check if there is an installation path in the environment variable
####################################################################


def check_environment_install_path():
    """
    check environment install path
    input: NA
    output: NA
    """
    log("Checking whether install path in the user environment variables...")

    tmp_f = None
    try:
        tmp_f = open(g_opts.user_env_path)
    except IOError:
        log_exit("Check environment variables failed:can not open "
                 "environment variables file,please check the user that "
                 "you offered is right")

    line = tmp_f.readline()
    while line:
        # Obtain 'export CTDB_HOME'
        if line.find('export CTDB_HOME') != -1:
            # Determine whether there is "#" before CTDB_HOME, the
            # function returns a value of -1, indicating that it is
            # not found, CTDB_HOME is valid.
            if find_before_slice(line, 'CTDB_HOME') == -1:
                install_env_dic_l = line.split('=')
                install_env_temp_l = install_env_dic_l[1].rstrip()
                install_env_l = os.path.normpath(install_env_temp_l)
                install_env_l = os.path.realpath(install_env_l[1:-1])
                if install_env_l == g_opts.install_path_l:
                    log("Found install path in user environment variables.")
                    tmp_f.close()
                    return 0
        line = tmp_f.readline()
    tmp_f.close()
    log_exit("Check install path in user environment variables failed:"
             "can not find install path in user: %s environment variables"
             % g_opts.user_info.pw_name)

    log("End check install path in user environment variables")


######################################################################
# Get the CTDB_HOME path in the environment variable
######################################################################
def get_gsdata_path_env():
    """
    get CTDB_HOME environment variable
    input: NA
    output: NA
    """
    log("Getting data directory...")
    log("Begin get data directory in user environment variables")

    try:
        f = open(g_opts.user_env_path)
    except IOError:
        log_exit("Failed to open the environment file.")

    line = f.readline()
    # the environment varible write by install.py whil start with '"'
    # such as: export CTDB_DATA="data_path", and user set the environment
    # varible will not start with '"', like export CTDB_DATA=data_path
    while line:
        # deal with the CTDB_DATA with """
        # Obtain 'export CTDB_DATA'
        if line.find('export CTDB_DATA="') != -1:
            # Determine whether there is "#" before CTDB_DATA, the
            # function returns a value of -1, indicating that it is
            # not found, CTDB_DATA is valid.
            if find_before_slice('export CTDB_DATA', line) == -1:
                gsdata_path_dic_temp = line.split('=')
                gsdata_path_temp = gsdata_path_dic_temp[1].rstrip()
                gsdata_path = os.path.normpath(gsdata_path_temp)
                g_opts.gs_data_path = os.path.realpath(gsdata_path[1:-1])
                DefaultValue.check_invalid_path(g_opts.gs_data_path)
                if not os.path.exists(g_opts.gs_data_path):
                    f.close()
                    log_exit("Get data directory in user environment variables"
                             " failed:data directory have been destroyed,"
                             "can not uninstall")
                log("End find data directory in user environment variables")
                f.close()
                return 0
        # deal with the CTDB_HOME with """
        # Obtain 'export CTDB_DATA'
        elif line.find('export CTDB_DATA') != -1:
            # Determine whether there is "#" before CTDB_DATA, the
            # function returns a value of -1, indicating that it is
            # not found, CTDB_DATA is valid.
            if find_before_slice('export CTDB_DATA', line) == -1:
                gsdata_path_dic_temp = line.split('=')
                gsdata_path_temp = gsdata_path_dic_temp[1].rstrip()
                g_opts.gs_data_path = os.path.realpath(
                    os.path.normpath(gsdata_path_temp))
                if not os.path.exists(g_opts.gs_data_path):
                    f.close()
                    log_exit("Get data directory in user environment variables "
                             "failed:data directory have been destroyed,"
                             "can not uninstall")
                log("End find data directory in user environment variables")
                f.close()
                return 0
        # Loop through each line
        line = f.readline()
    f.close()
    log("Not find data directory in user environment variables")
    log("End find data directory int user environment variables")
    return 1


########################################################################
# Check if the specified -D detection matches CTDB_DATA
########################################################################
def check_data_dir():
    """
    check the value specify by -D is same as CTDB_DATA
    input: NA
    output: NA
    """
    log("Begin check data dir...")
    if g_opts.clean_data_dir:
        if os.path.exists(g_opts.clean_data_dir) \
                and os.path.isdir(g_opts.clean_data_dir) \
                and g_opts.clean_data_dir == g_opts.gs_data_path:
            log("path: \"%s\" is correct" % g_opts.clean_data_dir)
        else:
            log_exit("path: \"%s\" is incorrect" % g_opts.clean_data_dir)
    log("end check,match")


#########################################################################
# Check the uninstall script location
#########################################################################


def check_uninstall_pos():
    """
    check uninstall.py position
    input: NA
    output: NA
    """
    log("Checking uninstall.py position...")
    bin_path = g_opts.install_path_l + os.sep + 'bin'
    addons_path = g_opts.install_path_l + os.sep + 'add-ons'
    admin_path = g_opts.install_path_l + os.sep + 'admin'
    lib_path = g_opts.install_path_l + os.sep + 'lib'
    pkg_file = g_opts.install_path_l + os.sep + 'package.xml'

    # Check if the install path exists
    if not os.path.exists(g_opts.install_path_l):
        log_exit("Check uninstall.py position failed:You have"
                 " changed uninstall.py position,install path not exist")
    # Check if the bin path exists
    if not os.path.exists(bin_path):
        log_exit("Check uninstall.py position failed:You have"
                 " changed uninstall.py position,can not find path bin")
    # Check if the addons path exists
    if not os.path.exists(addons_path):
        log_exit("Check uninstall.py position failed:You have"
                 " changed uninstall.py position,can not find path add-ons")
    # Check if the admin path exists
    if not os.path.exists(admin_path):
        log_exit("Check uninstall.py position failed:You have"
                 " changed uninstall.py position,can not find path admin")
    # Check if the lib path exists
    if not os.path.exists(lib_path):
        log_exit("Check uninstall.py position failed:You have"
                 " changed uninstall.py position,can not find file lib")
    # Check if the package path exists
    if not os.path.isfile(pkg_file):
        log_exit("Check uninstall.py position failed:You have"
                 " changed uninstall.py position,can not find file package.xml")
    log("End check uninstall.py position")


#########################################################################
# Clear the installation path
#########################################################################


def clean_install_path():
    """
    clean install path
    input: NA
    output: NA
    """
    log("Cleaning install path...")
    try:
        # Remove the install path and cfg
        if os.path.exists(os.path.join(g_opts.install_path_l, "../cfg")):
            shutil.rmtree(os.path.join(g_opts.install_path_l, "../cfg"))
        if os.path.exists(g_opts.install_path_l):
            shutil.rmtree(g_opts.install_path_l)
    except OSError as error:
        log_exit("Clean install path failed:can not delete install path "
                 "%s\nPlease manually delete it." % str(error))
    log("Clean install path success")
    log("End clean Install path")


###########################################################################
# Clear environment variables
###########################################################################

# Resolution path
def gen_reg_string(text):
    """
    process text string
    param: text string
    output: new text string
    """
    if not text:
        return ""
    in_s_str = text
    in_s_list = in_s_str.split(os.sep)
    reg_string = ""
    for i in in_s_list:
        if (i == ""):
            continue
        else:
            reg_string += r"\/" + i
    return reg_string


# Clear environment variables


def clean_environment():
    """
    clean environment variable
    input: NA
    output: NA
    """
    log("Cleaning user environment variables...")
    # Clear environment variable CTDB_DATA
    data_cmd = r"/^\s*export\s*CTDB_DATA=\".*\"$/d"
    # Clear environment variable PATH about database
    path_cmd = (r"/^\s*export\s*PATH=\"%s\/bin\":\$PATH$/d"
                % gen_reg_string(g_opts.install_path_l))
    # Clear environment variable LD_LIBRARY_PATH about database
    lib_cmd = (r"/^\s*export\s*LD_LIBRARY_PATH=\"%s\/lib\":\"%s\/add-ons\".*$/d"
               % (gen_reg_string(g_opts.install_path_l),
                  gen_reg_string(g_opts.install_path_l)))
    # Clear environment variable CTDB_HOME
    home_cmd = r"/^\s*export\s*CTDB_HOME=\".*\"$/d"

    # Clear environment ssl cert
    ca_cmd = r"/^\s*export\s*CTSQL_SSL_CA=.*$/d"
    cert_cmd = r"/^\s*export\s*CTSQL_SSL_CERT=.*$/d"
    key_cmd = r"/^\s*export\s*CTSQL_SSL_KEY=.*$/d"
    mode_cmd = r"/^\s*export\s*CTSQL_SSL_MODE=.*$/d"
    cipher_cmd = r"/^\s*export\s*CTSQL_SSL_KEY_PASSWD=.*$/d"

    cmds = [path_cmd, lib_cmd, home_cmd,
            ca_cmd, cert_cmd, key_cmd, mode_cmd, cipher_cmd]
    if g_opts.clean_data_dir_on == 0:
        cmds.insert(0, data_cmd)

    # do clean
    for _cmd in cmds:
        _cmd = 'sed -i "%s" "%s"' % (_cmd, g_opts.user_env_path)
        ret_code_1, _, stderr_1 = _exec_popen(_cmd)
        if ret_code_1:
            log("Failed to clean environment variables. Error: %s" % stderr_1)
            log_exit("Failed to clean environment variables.")
    log("End clean user environment variables...")


def read_ifile(ifile, keyword):
    if not os.path.isfile(ifile):
        log_exit("The value of IFILE '{}' is not exists.".format(ifile))
    flags = os.O_RDONLY
    modes = stat.S_IWUSR | stat.S_IRUSR
    with os.fdopen(os.open(ifile, flags, modes), 'r') as fp:
        for line in fp:
            items = line.split("=", 1)
            if len(items) == 2 and items[0].strip() == keyword:
                return items[1].strip()
    return ""


def read_cantiand_cfg(keyword):
    """
    function: read cantiand config
    input:string
    output:string
    """
    log("Begin read cantiand cfg file")
    # Get the cantiand config file.
    cantiand_cfg_file = os.path.join(g_opts.gs_data_path, "cfg", "cantiand.ini")
    if not os.path.exists(cantiand_cfg_file):
        log_exit("File %s is not exists." % cantiand_cfg_file)

    cantiand_cfg_file = os.path.realpath(os.path.normpath(cantiand_cfg_file))
    # keyword is value in cantiand.ini
    # get value from cantiand.ini
    values = []

    flags = os.O_RDONLY
    modes = stat.S_IWUSR | stat.S_IRUSR
    with os.fdopen(os.open(cantiand_cfg_file, flags, modes), 'r') as fp:
        for line in fp:
            items = line.split("=", 1)
            if len(items) != 2:
                continue
            key_ = items[0].strip()
            if key_ == keyword:
                values.append(items[1].strip())
            elif key_ == "IFILE":
                values.append(read_ifile(items[1].strip(), keyword))
    values = list(filter(bool, values))
    return values and values[-1] or ""


def get_instance_id():
    """
    get cantian instance process id
    input: NA
    output: NA
    """
    _cmd = ("ps ux | grep -v grep | grep cantiand "
            "| grep -w '\-D %s' |awk '{print $2}'") % g_opts.gs_data_path
    status, output, _ = _exec_popen(_cmd)
    if status:
        log_exit("Failed to execute cmd: %s. Error:%s." % (str(_cmd),
                                                           str(output)))
    # process exists
    return output


def get_error_id(error_name):
    """
    get installdb.sh cantian_start.py process id
    input: NA
    output: NA
    """
    if error_name == "installdb.sh":
        _cmd = ("ps ux | grep -v grep | grep installdb.sh | grep P | grep cantiand "
                "| awk '{print $2}'")
    elif error_name == "cantian_start.py":
        _cmd = ("ps ux | grep -v grep | grep python | grep cantian_start.py "
                "| awk '{print $2}'")
    status, output, error = _exec_popen(_cmd)
    if status:
        log_exit("Failed to execute cmd: %s. Output:%s. Error:%s" % (str(_cmd),
                                                                     str(output), str(error)))
    # process exists
    return output


def kill_instance(instance_pid):
    """
    kill cantiand instance
    :return: NA
    """
    # user do install, kill process
    kill_cmd_tmp = "kill -9 %s" % instance_pid
    log("kill process cmd: %s" % kill_cmd_tmp)
    ret_code_1, stdout, stderr = _exec_popen(kill_cmd_tmp)
    if ret_code_1 and "No such process" not in stderr:
        log_exit("kill process %s failed."
                 "ret_code : %s, stdout : %s, stderr : %s" % (instance_pid, ret_code_1, stdout, stderr))

    check_process_status("cantiand")
    log("Kill cantiand instance succeed")


def kill_extra_process():
    """
    kill cantian_start.py installdb.sh
    :return: NA
    """
    # user do install, kill extra process
    extra_processes = ["installdb.sh", "cantian_start.py"]
    for extra_process in extra_processes:
        installdb_pid = get_error_id(extra_process)
        if installdb_pid:
            kill_cmd_tmp = "kill -9 %s" % installdb_pid
            log("kill process cmd: %s" % kill_cmd_tmp)
            ret_code, output, error = _exec_popen(kill_cmd_tmp)
            if ret_code and "No such process" not in error:
                log_exit("kill extra process failed. Output:%s. Error:%s." % (str(output), str(error)))

            check_process_status(extra_process)
            log("Kill %s succeed" % extra_process)


def check_process_status(process_name):
    """
    check process status
    :return: NA
    """
    pid = None
    for i in range(CHECK_MAX_TIMES):
        if process_name == "cantiand":
            pid = get_instance_id()
        else:
            pid = get_error_id(process_name)

        if pid:
            log("checked %s times, %s pid is %s" % (i + 1, process_name, pid))
            if i != CHECK_MAX_TIMES - 1:
                time.sleep(5)
        else:
            return
    log_exit("Failed to kill %s. It is still alive after 5 minutes." % process_name)


def kill_process(process_name):
    kill_cmd_1 = (r"proc_pid_list=`ps ux | grep %s | grep -v grep"
                  r"|awk '{print $2}'` && " % process_name)
    kill_cmd_1 += (r"(if [ X\"$proc_pid_list\" != X\"\" ];then echo "
                   r"$proc_pid_list | xargs kill -9; exit 0; fi)")
    log("kill process cmd: %s" % kill_cmd_1)
    ret_code_2, stdout, stderr = _exec_popen(kill_cmd_1)
    if ret_code_2:
        log_exit("kill process %s faild."
                 "ret_code : %s, stdout : %s, stderr : %s" % (process_name, ret_code_2, stdout, stderr))


def stop_instance():
    """
    function:stop cantian instance
    input : NA
    output: NA
    """
    log("Stopping cantian instance...")

    # Get the listen port
    lsnr_port = read_cantiand_cfg("LSNR_PORT")
    if not lsnr_port:
        log_exit("Failed to get the listen port of database.")

    # Get the listen address
    lsnr_addr = read_cantiand_cfg("LSNR_ADDR")
    if not lsnr_addr:
        log_exit("Failed to get the listen address of database.")
    host_ip = lsnr_addr.split(',')[0]

    # if the cantian process not exists, and disable sysdba user
    # tell user the user name and password input interactive are
    # not used.
    instance_pid = get_instance_id()
    # specify -P parameter, db password is supported
    if not instance_pid and g_opts.db_passwd:
        log("Notice: Instance '%s' has been stopped." %
            g_opts.gs_data_path)
        log(("Notice: The Database username and password"
             " that are interactive entered "
             "will not be verified correct and used."))
    kill_process("mysqld")
    if g_opts.use_gss:
        kill_process("gssd")
    kill_extra_process()

    if g_opts.clean_data_dir_on == 0 and instance_pid:
        # uninstall, clean data dir, stop failed, kill process
        kill_instance(instance_pid)
        g_opts.db_passwd = ""
        log("Successfully killed cantian instance.")
        return

    # becasue lsof will can't work for find cantian process,
    # and in this condition, we try to use ps to find the
    # process, so we pass data directory to indicating the
    # running cantian process
    # not specify -P, db password is empty, login database by sysdba
    if not g_opts.db_passwd:
        install_path_l = g_opts.install_path_l
        gs_data_path = g_opts.gs_data_path
        tmp_cmd = "%s/bin/shutdowndb.sh -h %s -p %s -w -m immediate -D %s" % (
            install_path_l, host_ip, lsnr_port, gs_data_path)
    else:
        tmp_cmd = ("echo '%s' | %s/bin/shutdowndb.sh"
                   " -h %s -p %s -U %s -m immediate -W -D %s") % (
                      g_opts.db_passwd,
                      g_opts.install_path_l,
                      host_ip,
                      lsnr_port,
                      g_opts.db_user,
                      g_opts.gs_data_path)
    return_code_3, stdout_2, stderr_2 = _exec_popen(tmp_cmd)
    if return_code_3:
        g_opts.db_passwd = ""
        stdout_2 = get_error_msg(stdout_2, stderr_2)
        if (not g_opts.db_passwd) and stdout_2.find(
                "login as sysdba is prohibited") >= 0:
            stdout_2 += ("\nsysdba login is disabled, please specify -P "
                         "parameter to input password, refer to --help.")

        log_exit("stop cantian instance failed. Error: %s" % stdout_2)

    g_opts.db_passwd = ""
    log("Successfully stopped cantian instance.")


def get_error_msg(outmsg, errmsg):
    """
    function: check stdout and stderr, return no-empty string
    input: stdout message, stderr message
    """
    output = ""
    if outmsg and (not errmsg):
        output = outmsg
    elif (not outmsg) and errmsg:
        output = errmsg
    elif outmsg and errmsg:
        output = outmsg + "\n" + errmsg
    return output


def clean_archive_dir(json_data_deploy):
    db_type = json_data_deploy.get('db_type', '')
    uninstall_type = sys.argv[1]
    if db_type == '' or db_type == '0' or uninstall_type == "reserve":
        return
    node_id = json_data_deploy.get('node_id', '').strip()
    if node_id == "":
        log_exit("node_id is not found.")
    archive_logic_ip = json_data_deploy.get('archive_logic_ip', '').strip()
    storage_archive_fs = json_data_deploy.get('storage_archive_fs', '').strip()
    archive_dir = os.path.join("/mnt/dbdata/remote", "archive_" + storage_archive_fs)
    cantian_check_share_logic_ip_isvalid(archive_logic_ip)
    cmd = "timeout 10 ls %s" % archive_dir
    ret_code, _, stderr = _exec_popen(cmd)
    if node_id == "0" and (ret_code == 0 or FORCE_UNINSTALL != "force"):
        cmd_str = "rm -rf %s/arch*.arc %s/*arch_file.tmp" % (archive_dir, archive_dir)
        ret_code, _, stderr = _exec_popen(cmd_str)
        if ret_code:
            log_exit("can not clean the archive dir %s, command: %s, output: %s" % (archive_dir, cmd_str, stderr))
    log("cleaned archive files.")


class CanTian(object):
    def cantian_stop(self):
        """
        main entry
        the step for uninstall:
        1. parse input parameters
        2. check the parameter invalid
        3. check the environment
        4. stop cantian process
        5. if -F specify, clean data directory
        6. clean environment
        7. clean install directory
        8. change mode for log file
        """
        try:
            check_log_path()
            parse_parameter()
            check_parameter()
            get_install_path()
            check_uninstall_pos()
            get_user_environment_file()
            check_environment_install_path()
            get_gsdata_path_env()
            if not g_opts.clean_data_dir_on:
                check_data_dir()

            cantian_uninstall_config_data = {
                "INSTALL_PATH_L": g_opts.install_path_l,
                "CLEAN_DATA_DIR_ON": g_opts.clean_data_dir_on,
                "USER_ENV_PATH": g_opts.user_env_path,
                "LOG_FILE": g_opts.log_file,
                "S_IRUSR": stat.S_IRUSR,
            }

            log("Begin uninstall cantiand ")
            stop_instance()

            flags = os.O_WRONLY | os.O_TRUNC
            modes = stat.S_IWUSR | stat.S_IRUSR | stat.S_IXOTH | stat.S_IWOTH
            with os.fdopen(os.open(CANTIAN_UNINSTALL_CONF_FILE, flags, modes), 'w') as fp:
                json.dump(cantian_uninstall_config_data, fp)
            log("Uninstall cantiand finish ")

            flags = os.O_RDWR | os.O_CREAT
            modes = stat.S_IWUSR | stat.S_IRUSR
            with os.fdopen(os.open(CANTIAN_START_STATUS_FILE, flags, modes), 'w+') as load_fp:
                start_parameters = json.load(load_fp)
                start_status_item = {'start_status': "default"}
                start_parameters.update(start_status_item)
                load_fp.seek(0)
                load_fp.truncate()
                json.dump(start_parameters, load_fp)
        except Exception as error:
            log("Stop failed: " + str(error))
            log("Please refer to uninstall log \"%s\" for more detailed information." % g_opts.log_file)
            raise ValueError(str(error)) from error

    def cantian_uninstall(self):
        check_log_path()
        log("uninstall step 0")
        user, json_data_deploy = get_deploy_user()

        flags = os.O_RDONLY
        modes = stat.S_IWUSR | stat.S_IRUSR

        with os.fdopen(os.open(CANTIAN_UNINSTALL_CONF_FILE, flags, modes), 'r') as fp:
            json_data = json.load(fp)

            g_opts.clean_data_dir_on = json_data.get('CLEAN_DATA_DIR_ON', '')
            if json_data.get('USER_ENV_PATH', '').strip() == "":
                g_opts.user_env_path = os.path.join("/home", user, ".bashrc")
            else:
                g_opts.user_env_path = json_data.get('USER_ENV_PATH', '').strip()
            g_opts.install_path_l = json_data.get('INSTALL_PATH_L', '').strip()
            stat.S_IRUSR = json_data.get('S_IRUSR', '')

        g_opts.gs_data_path = "/mnt/dbdata/local/cantian/tmp/data"

        log("uninstall step 1")
        parse_parameter()
        log("uninstall step 2")
        clean_environment()
        log("uninstall step 3")
        clean_archive_dir(json_data_deploy)
        log("uninstall step 4")

        start_parameters = {'start_status': 'default', 'db_create_status': 'default'}
        flags = os.O_WRONLY | os.O_TRUNC | os.O_CREAT
        with os.fdopen(os.open(CANTIAN_START_STATUS_FILE, flags, modes), 'w') as load_fp:
            json.dump(start_parameters, load_fp)
        log("uninstall step 5")
        clean_install_path()
        log("uninstall step 6")
        log("Cantiand was successfully removed from your computer, "
            "for more message please see %s." % g_opts.log_file)

        os.chmod(g_opts.log_file, stat.S_IWUSR + stat.S_IRUSR + stat.S_IRGRP)

        if g_opts.tmp_fp:
            g_opts.tmp_fp.flush()
            g_opts.tmp_fp.close()

        ret_code, cantiand_pid, stderr = _exec_popen('exit')
        if ret_code:
            log_exit("can not logout, command: exit"
                     " ret_code : %s, stdout : %s, stderr : %s" % (ret_code, cantiand_pid, stderr))

    def cantian_check_status(self):
        g_opts.gs_data_path = "/mnt/dbdata/local/cantian/tmp/data"
        instance_pid = get_instance_id()
        extra_processes = ["installdb.sh", "cantian_start.py"]
        has_extra_process = False
        for extra_process in extra_processes:
            if get_error_id(extra_process):
                has_extra_process = True

        if not instance_pid and not has_extra_process:
            raise ValueError("Instance_pid is None.")
        else:
            return


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "override":
        FORCE_UNINSTALL = sys.argv[2]
    Func = CanTian()
    try:
        Func.cantian_uninstall()
    except ValueError as err:
        exit(str(err))
    except Exception as err:
        exit(str(err))
    exit(0)

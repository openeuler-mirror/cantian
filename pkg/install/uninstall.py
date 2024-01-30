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
    from Common import DefaultValue
except ImportError as err:
    sys.exit("Unable to import module: %s." % str(err))


# Get the operating system type
CURRENT_OS = platform.system()

MYSQL_DATA_DIR = "/data/data"
MYSQL_LOG_FILE = os.path.join(MYSQL_DATA_DIR, "mysql.log")

if os.path.exists("/.dockerenv"):
    MYSQL_BIN_DIR = "/usr/local/mysql"
else:
    MYSQL_BIN_DIR = "/opt/cantian/mysql/install/mysql"

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
        self.fp = None
        
        self.use_gss = False
        self.in_container = False


g_opts = Options()
gPyVersion = platform.python_version()


def _exec_popen(cmd):
    """
    subprocess.Popen in python2 and 3.
    :param cmd: commands need to execute
    :return: status code, standard output, error output
    """
    bash_cmd = ["bash"]
    p = subprocess.Popen(bash_cmd, shell=False, stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if gPyVersion[0] == "3":
        stdout, stderr = p.communicate(cmd.encode())
        stdout = stdout.decode()
        stderr = stderr.decode()
    else:
        stdout, stderr = p.communicate(cmd)

    if stdout[-1:] == os.linesep:
        stdout = stdout[:-1]
    if stderr[-1:] == os.linesep:
        stderr = stderr[:-1]

    return p.returncode, stdout, stderr


def _get_input(msg):
    """
    Packaged function about user input which compatible with Python 2
    and Python 3.
    :param msg: input function's prompt message
    :return: the input value of user
    """
    if gPyVersion[0] == "3":
        return input(msg)
    else:
        return raw_input(msg)


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
    print(usage.__doc__)


def parse_parameter():
    """
    parse command line parameters
    input: NA
    output: NA
    """
    print("Checking uninstall parameters...")
    try:
        # Parameters are passed into argv. After parsing, they are stored
        # in opts as binary tuples. Unresolved parameters are stored in args.
        opts, args = getopt.getopt(sys.argv[1:], "FU:dD:g:sP", ["help"])
        if args:
            print("Parameter input error: " + str(args[0]))
            sys.exit(1)

        # If there is "--help" in parameter, we should print the usage and
        # ignore other parameters.
        for key, value in opts:
            if key == "--help":
                usage()
                sys.exit(0)
            elif key == "-g":
                if os.getuid() != 0:
                    g_opts.install_user_privilege = value
            elif key == "-s":
                g_opts.use_gss = True
            # Get the user name
            elif key == "-U":
                pass
            # Determine whether to delete the data directory
            elif key == '-F':
                g_opts.clean_data_dir_on = 0
            # Get the specified data directory
            elif key == '-D':
                # If the file is checked directly here, the attacker can
                # query it through the error message here. A valid file
                # that is not found by it, so the correctness of the
                # parameter value will be checked in the following function.
                g_opts.clean_data_dir = value.strip()
            elif key == '-P':
                print("Need database connector's name and password:")
                g_opts.db_user = _get_input("Username:")
                check_invalid_symbol(g_opts.db_user)
                g_opts.db_passwd = getpass.getpass().replace("'", "'\"'\"'")
                # username or password is empty, exit 1
                if (not g_opts.db_user) or (not g_opts.db_passwd):
                    print("Username and password can not be empty.")
                    sys.exit(1)
            elif key == '-d':
                g_opts.in_container = True

    except getopt.GetoptError as err:
        # Error output reminder
        print("Parameter input error: " + err.msg)
        sys.exit(1)


def check_parameter():
    """
    check command line parameter
    input: NA
    output: NA
    """
    if CURRENT_OS == "Linux":
        user = os.getgid()
        if user == 0:
            print("Error:Only user with installer can run this script")
            sys.exit(1)

        if g_opts.install_user_privilege != "withoutroot":
            print("Error: User has no root privilege, "
                  "do uninstall, need specify parameter '-g withoutroot'.")
            sys.exit(1)
    else:
        print("Error:Check os failed:current os is not linux")
        sys.exit(1)

    if g_opts.clean_data_dir_on == 1:
        if g_opts.clean_data_dir:
            print("Error: Parameter input error: "
                  "you can not use -D without using -F")
            sys.exit(1)
    if g_opts.clean_data_dir:
        g_opts.clean_data_dir = os.path.realpath(
            os.path.normpath(g_opts.clean_data_dir))
        DefaultValue.checkInvalidPath(g_opts.clean_data_dir)


def check_log():
    """
    check log
    and the log for normal user is: ~/cantianduninstall.log
    """
    # Get the log path
    home_path = g_opts.user_info.pw_dir
    g_opts.log_file = os.path.join(os.path.realpath(
        os.path.normpath(home_path)), "cantianduninstall.log")

    # Clean the old log file.
    if os.path.exists(g_opts.log_file):
        try:
            os.chmod(g_opts.log_file, stat.S_IWUSR + stat.S_IRUSR)
            os.remove(g_opts.log_file)
        except OSError as err:
            print("Error: Can not remove log file: " + g_opts.log_file)
            print(str(err))
            sys.exit(1)

    try:
        g_opts.fp = open(g_opts.log_file, "w")
    except IOError as err:
        print("Error: Can not create or open log file: " + g_opts.log_file)
        print(str(err))
        sys.exit(1)

    try:
        os.chmod(g_opts.log_file, stat.S_IWUSR + stat.S_IRUSR)
    except OSError as err:
        print("Error: Can not change the mode of log file: " + g_opts.log_file)
        print(str(err))
        sys.exit(1)


def log(msg, is_print=False):
    """
    Print log
    :param msg: log message
    :return: NA
    """
    if is_print:
        print(msg)

    if g_opts.fp:
        g_opts.fp.write(time.strftime("[%Y-%m-%d %H:%M:%S] ") + msg)
        g_opts.fp.write(os.linesep)
        g_opts.fp.flush()


def logExit(msg):
    """
    Print log and exit
    :param msg: log message
    :return: NA
    """
    log("Error: %s" % msg, True)

    if g_opts.fp:
        g_opts.fp.flush()
        g_opts.fp.close()
        os.chmod(g_opts.log_file, stat.S_IRUSR)
        g_opts.fp = None

    print("Please refer to uninstall log \"%s\" for more detailed information."
          % g_opts.log_file)
    sys.exit(1)


def get_install_path():
    """
    Obtain the path of the uninstall script, that is, the bin directory
    under the installation path
    :return: NA
    """
    log("Getting install path...", True)
    # get uninstall.py path info
    current_path = os.path.dirname(os.path.realpath(__file__))
    # get $CTDB_HOME or app path info
    g_opts.install_path_l = os.path.dirname(current_path)
    # Must be exist
    if not os.path.exists(g_opts.install_path_l):
        logExit("Failed to get install path.")
    log("End get install path")


def get_user_environment_file():
    """
    Get the path to the user environment variable.
    :return: NA
    """
    log("Getting user environment variables file path...", True)
    home_path = g_opts.user_info.pw_dir
    g_opts.user_env_path = os.path.realpath(
        os.path.normpath(os.path.join(home_path, ".bashrc")))
    if not os.path.isfile(os.path.realpath(g_opts.user_env_path)):
        logExit("Can't get the environment variables file.")
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
    log("Checking whether install path in the user environment variables...",
        True)

    f = None
    try:
        f = open(g_opts.user_env_path)
    except IOError:
        logExit("Check environment variables failed:can not open "
                "environment variables file,please check the user that "
                "you offered is right")

    LINE = f.readline()
    while LINE:
        # Obtain 'export CTDB_HOME'
        if LINE.find('export CTDB_HOME') != -1:
            # Determine whether there is "#" before CTDB_HOME, the
            # function returns a value of -1, indicating that it is
            # not found, CTDB_HOME is valid.
            if find_before_slice(LINE, 'CTDB_HOME') == -1:
                INSTALL_ENV_DIC_L = LINE.split('=')
                INSTALL_ENV_TEMP_L = INSTALL_ENV_DIC_L[1].rstrip()
                INSTALL_ENV_L = os.path.normpath(INSTALL_ENV_TEMP_L)
                INSTALL_ENV_L = os.path.realpath(INSTALL_ENV_L[1:-1])
                if INSTALL_ENV_L == g_opts.install_path_l:
                    log("Found install path in user environment variables.")
                    f.close()
                    return 0
        LINE = f.readline()
    f.close()
    logExit("Check install path in user environment variables failed:"
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
    log("Getting data directory...", True)
    log("Begin get data directory in user environment variables")

    try:
        f = open(g_opts.user_env_path)
    except IOError:
        logExit("Failed to open the environment file.")

    LINE = f.readline()
    # the environment varible write by install.py whil start with '"'
    # such as: export CTDB_DATA="data_path", and user set the environment
    # varible will not start with '"', like export CTDB_DATA=data_path
    while LINE:
        # deal with the CTDB_DATA with """
        # Obtain 'export CTDB_DATA'
        if LINE.find('export CTDB_DATA="') != -1:
            # Determine whether there is "#" before CTDB_DATA, the
            # function returns a value of -1, indicating that it is
            # not found, CTDB_DATA is valid.
            if find_before_slice('export CTDB_DATA', LINE) == -1:
                GSDATA_PATH_DIC_TEMP = LINE.split('=')
                GSDATA_PATH_TEMP = GSDATA_PATH_DIC_TEMP[1].rstrip()
                GSDATA_PATH = os.path.normpath(GSDATA_PATH_TEMP)
                g_opts.gs_data_path = os.path.realpath(GSDATA_PATH[1:-1])
                DefaultValue.checkInvalidPath(g_opts.gs_data_path)
                if not os.path.exists(g_opts.gs_data_path):
                    f.close()
                    logExit("Get data directory in user environment variables"
                            " failed:data directory have been destroyed,"
                            "can not uninstall")
                log("End find data directory in user environment variables")
                f.close()
                return 0
        # deal with the CTDB_HOME with """
        # Obtain 'export CTDB_DATA'
        elif LINE.find('export CTDB_DATA') != -1:
            # Determine whether there is "#" before CTDB_DATA, the
            # function returns a value of -1, indicating that it is
            # not found, CTDB_DATA is valid.
            if find_before_slice('export CTDB_DATA', LINE) == -1:
                GSDATA_PATH_DIC_TEMP = LINE.split('=')
                GSDATA_PATH_TEMP = GSDATA_PATH_DIC_TEMP[1].rstrip()
                g_opts.gs_data_path = os.path.realpath(
                    os.path.normpath(GSDATA_PATH_TEMP))
                if not os.path.exists(g_opts.gs_data_path):
                    f.close()
                    logExit("Get data directory in user environment variables "
                            "failed:data directory have been destroyed,"
                            "can not uninstall")
                log("End find data directory in user environment variables")
                f.close()
                return 0
        # Loop through each line
        LINE = f.readline()
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
    log("Begin check data dir...", True)
    if g_opts.clean_data_dir:
        if os.path.exists(g_opts.clean_data_dir) \
           and os.path.isdir(g_opts.clean_data_dir) \
           and g_opts.clean_data_dir == g_opts.gs_data_path:
            log("path: \"%s\" is correct" % g_opts.clean_data_dir)
        else:
            logExit("path: \"%s\" is incorrect" % g_opts.clean_data_dir)
    log("end check,match")


#######################################################################
# Delete data directory
#######################################################################
def clean_data_dir():
    """
    clean data directory
    input: NA
    output: NA
    """
    log("Cleaning data path...", True)
    if not g_opts.clean_data_dir_on:
        if os.path.exists(g_opts.gs_data_path):
            if g_opts.in_container and os.path.exists(DefaultValue.DOCKER_DATA_DIR):
                try:
                    shutil.rmtree(DefaultValue.DOCKER_DATA_DIR)
                except OSError as err:
                    logExit("Clean share data path failed:can not delete share data path "
                            "%s\nPlease manually delete it." % str(err))
            try:
                shutil.rmtree(g_opts.gs_data_path)
            except OSError as err:
                logExit("Clean data path failed:can not delete data path "
                        "%s\nPlease manually delete it." % str(err))
        else:
            logExit("Clean data failed:can not find data directory path"
                    " in user environment variables,"
                    "it might be destroyed or not exist")
        if not g_opts.use_gss:
            if g_opts.in_container and os.path.exists(DefaultValue.DOCKER_GCC_DIR):
                try:
                    shutil.rmtree(DefaultValue.DOCKER_GCC_DIR)
                except OSError as err:
                    logExit("Clean gcc path failed:can not delete gcc path "
                            "%s\nPlease manually delete it." % str(err))
    else:
        log("Not clean data path")
    log("End clean data path")

#########################################################################
# Check the uninstall script location
#########################################################################


def check_uninstall_pos():
    """
    check uninstall.py position
    input: NA
    output: NA
    """
    log("Checking uninstall.py position...", True)
    bin_path = g_opts.install_path_l + os.sep + 'bin'
    addons_path = g_opts.install_path_l + os.sep + 'add-ons'
    admin_path = g_opts.install_path_l + os.sep + 'admin'
    lib_path = g_opts.install_path_l + os.sep + 'lib'
    pkg_file = g_opts.install_path_l + os.sep + 'package.xml'

    # Check if the install path exists
    if not os.path.exists(g_opts.install_path_l):
        logExit("Check uninstall.py position failed:You have"
                " changed uninstall.py position,install path not exist")
    # Check if the bin path exists
    if not os.path.exists(bin_path):
        logExit("Check uninstall.py position failed:You have"
                " changed uninstall.py position,can not find path bin")
    # Check if the addons path exists
    if not os.path.exists(addons_path):
        logExit("Check uninstall.py position failed:You have"
                " changed uninstall.py position,can not find path add-ons")
    # Check if the admin path exists
    if not os.path.exists(admin_path):
        logExit("Check uninstall.py position failed:You have"
                " changed uninstall.py position,can not find path admin")
    # Check if the lib path exists
    if not os.path.exists(lib_path):
        logExit("Check uninstall.py position failed:You have"
                " changed uninstall.py position,can not find file lib")
    # Check if the package path exists
    if not os.path.isfile(pkg_file):
        logExit("Check uninstall.py position failed:You have"
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
    log("Cleaning msyqld path...", True)
    cmd = "rm -rf {}/* {}/*".format(MYSQL_DATA_DIR, MYSQL_BIN_DIR)
    ret_code, _, stderr = _exec_popen(cmd)
    if ret_code:
        logExit("Can not remove mysql data, command: %s, output: %s" % (cmd, stderr))
    log("Cleaning install path...", True)
    try:
        # Remove the install path
        shutil.rmtree(g_opts.install_path_l)
    except OSError as err:
        logExit("Clean install path failed:can not delete install path "
                "%s\nPlease manually delete it." % str(err))
    log("Clean install path success")
    log("End clean Install path")


###########################################################################
# Clear environment variables
###########################################################################

# Resolution path
def Genregstring(text):
    """
    process text string
    param: text string
    output: new text string
    """
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
    return regString

# Clear environment variables


def clean_environment():
    """
    clean environment variable
    input: NA
    output: NA
    """
    log("Cleaning user environment variables...", True)
    # Clear environment variable CTDB_DATA
    data_cmd = r"/^\s*export\s*CTDB_DATA=\".*\"$/d"
    # Clear environment variable PATH about database
    path_cmd = (r"/^\s*export\s*PATH=\"%s\/bin\":\$PATH$/d"
                % Genregstring(g_opts.install_path_l))
    # Clear environment variable LD_LIBRARY_PATH about database
    lib_cmd = (r"/^\s*export\s*LD_LIBRARY_PATH=\"%s\/lib\":\"%s\/add-ons\":"
               r"\$LD_LIBRARY_PATH$/d"
               % (Genregstring(g_opts.install_path_l),
                  Genregstring(g_opts.install_path_l)))
    # Clear environment variable CTDB_HOME
    home_cmd = r"/^\s*export\s*CTDB_HOME=\".*\"$/d"
    # Clear environment variable CMS_HOME
    cms_cmd = r"/^\s*export\s*CMS_HOME=\".*\"$/d"

    # Clear environment ssl cert
    ca_cmd = r"/^\s*export\s*CTSQL_SSL_CA=.*$/d"
    cert_cmd = r"/^\s*export\s*CTSQL_SSL_CERT=.*$/d"
    key_cmd = r"/^\s*export\s*CTSQL_SSL_KEY=.*$/d"
    mode_cmd = r"/^\s*export\s*CTSQL_SSL_MODE=.*$/d"
    cipher_cmd = r"/^\s*export\s*CTSQL_SSL_KEY_PASSWD=.*$/d"

    cmds = [path_cmd, lib_cmd, home_cmd, cms_cmd,
            ca_cmd, cert_cmd, key_cmd, mode_cmd, cipher_cmd]
    if g_opts.clean_data_dir_on == 0:
        cmds.insert(0, data_cmd)

    # do clean
    for cmd in cmds:
        cmd = 'sed -i "%s" "%s"' % (cmd, g_opts.user_env_path)
        ret_code, _, stderr = _exec_popen(cmd)
        if ret_code:
            log("Failed to clean environment variables. Error: %s" % stderr)
            logExit("Failed to clean environment variables.")
    log("End clean user environment variables...")


def read_ifile(ifile, keyword):
    if not os.path.isfile(ifile):
        logExit("The value of IFILE '{}' is not exists.".format(ifile))
    with open(ifile) as fp:
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
        logExit("File %s is not exists." % cantiand_cfg_file)

    cantiand_cfg_file = os.path.realpath(os.path.normpath(cantiand_cfg_file))
    # keyword is value in cantiand.ini
    # get value from cantiand.ini
    values = []
    with open(cantiand_cfg_file) as fp:
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
    cmd = ("ps ux | grep -v grep | grep cantiand "
           "| grep -w '\-D %s' |awk '{print $2}'") % g_opts.gs_data_path
    status, output, _ = _exec_popen(cmd)
    if status:
        logExit("Failed to execute cmd: %s. Error:%s." % (str(cmd),
                                                          str(output)))
    # process exists
    return output


def kill_instance(instance_pid):
    """
    kill cantiand instance
    :return: NA
    """
    # user do install, kill process
    kill_cmd = "kill -9 %s; exit 0" % instance_pid
    log("kill process cmd: %s" % kill_cmd)
    ret_code, _, _ = _exec_popen(kill_cmd)
    if ret_code:
        logExit("kill process %s failed" % instance_pid)
    log("Kill cantiand instance succeed")

def kill_process(process_name):
    # kill process
    kill_cmd = (r"proc_pid_list=`ps ux | grep %s | grep -v grep"
                r"|awk '{print $2}'` && " % process_name)
    kill_cmd += (r"(if [ X\"$proc_pid_list\" != X\"\" ];then echo "
                 r"$proc_pid_list | xargs kill -9; exit 0; fi)")
    log("kill process cmd: %s" % kill_cmd)
    ret_code, _, _ = _exec_popen(kill_cmd)
    if ret_code:
        logExit("kill process %s faild" % process_name)


def stop_instance():
    """
    function:stop cantian instance
    input : NA
    output: NA
    """
    log("Stopping cantian instance...", True)

    # Get the listen port
    lsnr_port = read_cantiand_cfg("LSNR_PORT")
    if not lsnr_port:
        logExit("Failed to get the listen port of database.")

    # Get the listen address
    lsnr_addr = read_cantiand_cfg("LSNR_ADDR")
    if not lsnr_addr:
        logExit("Failed to get the listen address of database.")
    host_ip = lsnr_addr.split(',')[0]

    # if the cantian process not exists, and disable sysdba user
    # tell user the user name and password input interactive are
    # not used.
    instance_pid = get_instance_id()
    # specify -P parameter, db password is supported
    if not instance_pid and g_opts.db_passwd:
        log("Notice: Instance '%s' has been stopped." %
            g_opts.gs_data_path, True)
        log(("Notice: The Database username and password"
             " that are interactive entered "
             "will not be verified correct and used.", True))
    kill_process("mysqld")
    kill_process("cms")
    if g_opts.use_gss:
        kill_process("gssd")

    if g_opts.clean_data_dir_on == 0 and instance_pid:
        # uninstall, clean data dir, stop failed, kill process
        kill_instance(instance_pid)
        g_opts.db_passwd = ""
        log("Successfully Stopped cantian instance.", True)
        return

    # becasue lsof will can't work for find cantian process,
    # and in this condition, we try to use ps to find the
    # process, so we pass data directory to indicating the
    # running cantian process
    # not specify -P, db password is empty, login database by sysdba
    if not g_opts.db_passwd:
        cmd = "%s/bin/shutdowndb.sh -h %s -p %s -w -m immediate -D %s" % (
            g_opts.install_path_l, host_ip, lsnr_port, g_opts.gs_data_path)
    else:
        cmd = ("echo '%s' | %s/bin/shutdowndb.sh"
               " -h %s -p %s -U %s -m immediate -W -D %s") % (
            g_opts.db_passwd,
            g_opts.install_path_l,
            host_ip,
            lsnr_port,
            g_opts.db_user,
            g_opts.gs_data_path)
    return_code, stdout, stderr = _exec_popen(cmd)
    if return_code:
        g_opts.db_passwd = ""
        stdout = get_error_msg(stdout, stderr)
        if (not g_opts.db_passwd) and stdout.find(
                "login as sysdba is prohibited") >= 0:
            stdout += ("\nsysdba login is disabled, please specify -P "
                       "parameter to input password, refer to --help.")

        logExit("stop cantian instance failed. Error: %s" % stdout)

    g_opts.db_passwd = ""
    log("Successfully stopped cantian instance.", True)


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


def check_invalid_symbol(para):
    """
    If there is invalid symbol in parameter?
    :param para: parameter
    :return: NA
    """
    symbols = (
        "|", ";", "&", "$", "<", ">", "`", "\\", "'", "\"", "{", "}",
        "(", ")", "[", "]", "~", "*", "?", "!", "\n",
    )
    for symbol in symbols:
        if para.find(symbol) > -1:
            logExit("There is invalid symbol \"%s\" in %s" % (symbol, para))


def main():
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
    parse_parameter()
    check_parameter()
    check_log()
    get_install_path()
    check_uninstall_pos()
    get_user_environment_file()
    check_environment_install_path()
    get_gsdata_path_env()
    if not g_opts.clean_data_dir_on:
        check_data_dir()

    log("Begin uninstall cantiand ")
    stop_instance()
    # if -F parameter used, clean CTDB_DATA
    if not g_opts.clean_data_dir_on:
        clean_data_dir()
    clean_environment()
    clean_install_path()

    log("Cantiand was successfully removed from your computer, "
        "for more message please see %s." % g_opts.log_file, True)
    log("Cantiand was successfully removed from your computer")

    os.chmod(g_opts.log_file, stat.S_IRUSR)

    if g_opts.fp:
        g_opts.fp.flush()
        g_opts.fp.close()


if __name__ == "__main__":
    main()

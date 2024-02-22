import sys
sys.dont_write_bytecode = True

try:
    import getopt
    import os
    import time
    import platform
    import json
    import configparser
    import tty
    import termios
    import subprocess
    import stat
    import logging
    import copy
    from configparser import ConfigParser
    from dbstor_install import dbstor_check_share_logic_ip_isvalid
    from kmc_adapter import CApiWrapper
    PYTHON242 = "2.4.2"
    PYTHON25 = "2.5"
    gPyVersion = platform.python_version()

    if PYTHON242 <= gPyVersion < PYTHON25:
        import sha256
    elif gPyVersion >= PYTHON25:
        pass
    else:
        raise ImportError("This install script can not support python version: %s"
              % gPyVersion)
except ImportError as import_err:
    raise ValueError("Unable to import module: %s." % str(import_err)) from import_err

GLOBAL_KMC_EXT = None

TIMEOUT_COUNT = 1800
KEY_FILE_PERMISSION = 600
MAX_DIRECTORY_MODE = 750


class ReadConfigParserNoCast(ConfigParser):
    "Inherit from built-in class: ConfigParser"
    def optionxform(self, optionstr):
        "Rewrite without lower()"
        return optionstr


class Options(object):
    """
    command line options
    """
    def __init__(self):
        self.section = 'CLIENT'
        self.dbstor_config = {}
        self.inipath = "/mnt/dbdata/remote/share_"
        self.log_path = "/opt/cantian/dbstor/log"
        self.log_file = "/opt/cantian/dbstor/log/update.log"
        self.js_conf_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../config/deploy_param.json")
        self.note_id = ""
        self.local_ini_path = "/mnt/dbdata/local/cantian/tmp/data/dbstor/conf/dbs/dbstor_config.ini"
        self.cstool_ini_path = "/opt/cantian/dbstor/conf/dbs/dbstor_config.ini"
        self.tools_ini_path = "/opt/cantian/dbstor/tools/dbstor_config.ini"
        self.cms_ini_path = "/opt/cantian/cms/dbstor/conf/dbs/dbstor_config.ini"
        self.share_logic_ip = ""
        self.cluster_name = ""

db_opts = Options()
if not os.path.exists(db_opts.log_path):
    os.makedirs(db_opts.log_path, MAX_DIRECTORY_MODE)
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
logger_handle = logging.FileHandler(db_opts.log_file, 'a', "utf-8")

logger_handle.setLevel(logging.DEBUG)
logger_formatter = logging.Formatter('[%(asctime)s]-[%(filename)s]-[line:%(lineno)d]-[%(levelname)s]-'
                                     '%(message)s-[%(process)s]')
logger_handle.setFormatter(logger_formatter)
logger.addHandler(logger_handle)
logger.info("init logging success")


def console_and_log(msg):
    """
    Print log
    :param msg: log message
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
          % db_opts.log_file)
    raise ValueError(str(msg))


def check_log():
    """
    check log
    and the log for normal user is: ~/install.log
    """
    # check the log path
    flags = os.O_CREAT | os.O_EXCL
    modes = stat.S_IWUSR | stat.S_IRUSR | stat.S_IRGRP
    if not os.path.exists(db_opts.log_file):
        try:
            with os.fdopen(os.open(db_opts.log_file, flags, modes), "w", encoding="utf-8"):
                pass
        except IOError as ex:
            log_exit("Error: Can not create or open log file: %s", db_opts.log_file)

    try:
        os.chmod(db_opts.log_file, modes)
    except OSError as ex:
        log_exit("Error: Can not chmod log file: %s", db_opts.log_file)


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
        stdout, stderr = pobj.communicate(timeout=TIMEOUT_COUNT)
        stdout = stdout.decode()
        stderr = stderr.decode()
    else:
        pobj.stdin.write(cmd)
        pobj.stdin.write(os.linesep)
        for value in values:
            pobj.stdin.write(value)
            pobj.stdin.write(os.linesep)
        stdout, stderr = pobj.communicate(timeout=TIMEOUT_COUNT)

    if stdout[-1:] == os.linesep:
        stdout = stdout[:-1]
    if stderr[-1:] == os.linesep:
        stderr = stderr[:-1]
    return pobj.returncode, stdout, stderr


def usage():
    """update_dbstor_config.py is a utility to updates dbstor_config.ini file.

     Usage:
      python3 update_dbstor_config.py --help
      python3 update_dbstor_config.py --NAMESPACE_FSNAME 0 --REMOTE_IP x.xx.xx.xxx/x.xx.xx.xxy

    Common options:
      --NAMESPACE_FSNAME:   namespace file system name
      --NAMESPACE_PAGE_FSNAME namespace file system for page name
      --DPU_UUID            dpu uuid
      --LOCAL_IP            local ip address
      --REMOTE_IP           remote ip address
      --USER_NAME           user name
      --PASSWORD:           password
      --help                show this help, then exit

    If all the optional parameters are not specified, -O option will be used.
    """
    console_and_log(usage.__doc__)


def read_default_parameter():
    dbstor_check_share_logic_ip_isvalid(db_opts.share_logic_ip)
    #Read default parameters
    conf = ReadConfigParserNoCast()
    conf.read(db_opts.inipath, encoding="utf-8")
    for option in conf.options(db_opts.section):
        value = conf.get(db_opts.section, option)
        db_opts.dbstor_config[option.strip().upper()] = value.strip()


def parse_parameter():
    """
    parse parameters
    --NAMESPACE_FSNAME: namespace file system name
    --NAMESPACE_PAGE_FSNAME namespace file system for page name
    --DPU_UUID:         dpu uuid
    --LINK_TYPE:        link type
    --LOCAL_IP:         local ip address
    --REMOTE_IP:        remote ip
    --USER_NAME:        user name
    --PASSWORD:         password
    """
    try:
        # Parameters are passed into argv. After parsing, they are stored
        # in opts as binary tuples. Unresolved parameters are stored in args.
        opts, args = getopt.getopt(sys.argv[1:], "",
         ["help", "NAMESPACE_FSNAME=", "NAMESPACE_PAGE_FSNAME=", "DPU_UUID=", "LINK_TYPE=", "LOCAL_IP=", "REMOTE_IP="])
        if args:
            log_exit("Parameter input error: " + str(args[0]))

        # If there is "--help" in parameter, we should print the usage and
        # ignore other parameters.
        for _key, _value in opts:
            if _key == "--help":
                usage()
                log_exit("End check parameters")

        for _key, _value in opts:
            if _value.strip() == "":
                continue
            if _key == "--NAMESPACE_FSNAME":
                db_opts.dbstor_config["NAMESPACE_FSNAME"] = _value.strip().replace('/', ';')
            if _key == "--NAMESPACE_PAGE_FSNAME":
                db_opts.dbstor_config["NAMESPACE_PAGE_FSNAME"] = _value.strip().replace('/', ';')
            elif _key == "--DPU_UUID":
                db_opts.dbstor_config["DPU_UUID"] = _value.strip()
            elif _key == "--LINK_TYPE":
                db_opts.dbstor_config["LINK_TYPE"] = _value.strip()
            elif _key == "--LOCAL_IP":
                db_opts.dbstor_config["LOCAL_IP"] = _value.strip().replace('/', ';')
            elif _key == "--REMOTE_IP":
                db_opts.dbstor_config["REMOTE_IP"] = _value.strip().replace('/', ';')
    except getopt.GetoptError as error:
        log_exit("Parameter input error: " + error.msg)


def check_parameter():
    console_and_log("Checking parameters.")
    if len(db_opts.dbstor_config.get("NAMESPACE_FSNAME", "").strip()) == 0:
        log_exit("The storage_dbstore_fs parameter is not entered")
    if len(db_opts.dbstor_config.get("NAMESPACE_PAGE_FSNAME", "").strip()) == 0:
        log_exit("The storage_dbstore_page_fs parameter is not entered")
    if len(db_opts.dbstor_config.get("DPU_UUID", "").strip()) == 0:
        log_exit("The uuid parameter is not exist")
    if len(db_opts.dbstor_config.get("LOCAL_IP", "").strip()) == 0:
        log_exit("The cantian_vlan_ip parameter is not entered")
    if len(db_opts.dbstor_config.get("REMOTE_IP", "").strip()) == 0:
        log_exit("The storage_vlan_ip parameter is not entered")
    else:
        remote_ip_list = db_opts.dbstor_config.get("REMOTE_IP", "").strip().split(';')
        for remote_ip in remote_ip_list:
            cmd = "ping -c 1 %s" % remote_ip.strip()
            logger.info("exec cmd: %s", cmd)
            ret_code, stdout, stderr = _exec_popen(cmd)
            if ret_code:
                log_exit("Failed to ping remote ip. Error: %s" % remote_ip.strip())


def clean_ini(file_path):
    # clean the ini file
    if os.path.exists(file_path):
        try:
            os.remove(file_path)
        except IOError as ex:
            log_exit("Error: Can not remove dbstor config file: " + file_path)


def update_file_parameter(file_path, ini_file, encrypt_passwd=False):
    #Update parameters
    clean_ini(file_path)
    conf = ReadConfigParserNoCast()
    conf.add_section(db_opts.section)

    if encrypt_passwd:
        ini_file['PASSWORD'] = GLOBAL_KMC_EXT.encrypt(ini_file.get('PASSWORD', ""))
    # rewrite parameters
    for key in ini_file:
        conf.set(db_opts.section, key, ini_file[key])
    flags = os.O_CREAT | os.O_RDWR
    modes = stat.S_IWUSR | stat.S_IRUSR
    try:
        with os.fdopen(os.open(file_path, flags, modes), "w") as file_obj:
            conf.write(file_obj)
    except Exception as error:
        log_exit(str(error))


def update_parameter():
    #Update parameters
    dbstor_check_share_logic_ip_isvalid(db_opts.share_logic_ip)
    console_and_log("Start to update parameters")
    cantian_dbstor_config = copy.deepcopy(db_opts.dbstor_config)
    cantian_dbstor_config["DBSTOR_OWNER_NAME"] = "cantian"
    cms_dbstor_config = copy.deepcopy(db_opts.dbstor_config)
    cms_dbstor_config["DBSTOR_OWNER_NAME"] = "cms"
    #update share ini file
    update_file_parameter(db_opts.inipath, db_opts.dbstor_config)
    #update local ini file
    update_file_parameter(db_opts.local_ini_path, cantian_dbstor_config)
    # update cstool ini file
    update_file_parameter(db_opts.cstool_ini_path, db_opts.dbstor_config)
    # update ini in dbstor/tools
    update_file_parameter(db_opts.tools_ini_path, db_opts.dbstor_config)
    # update ini for cms
    update_file_parameter(db_opts.cms_ini_path, cms_dbstor_config)
    console_and_log("Successfully to updata dbstor config parameter.")


def verify_dbstor_usernm(in_type, passwd, shortest_len, longest_len):
    """
    Verify new password.
    :return: NA
    """

    if len(passwd) < shortest_len or len(passwd) > longest_len:
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


def verify_dbstor_passwd(in_type, passwd, shortest_len, longest_len):
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
    user_name = db_opts.dbstor_config.get('USER_NAME')
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


def input_username_password():
    """Generate DBstor Config parameter."""
    try:
        console_and_log("Input Username and Password")
        db_opts.dbstor_config['USER_NAME'] = get_dbstor_usernm_passwd(input_prompt="UserName",
                                    file_prompt="dbstor config",
                                    shortest_len=6, longest_len=32)
        if db_opts.dbstor_config.get('USER_NAME', 0) == 0:
            raise ValueError("input param is invalid")
        db_opts.dbstor_config['PASSWORD'] = get_dbstor_usernm_passwd(input_prompt="PassWord",
                                    file_prompt="dbstor config",
                                    shortest_len=8, longest_len=16)
        if db_opts.dbstor_config.get('PASSWORD', 0) == 0:
            raise ValueError("input param is invalid")
        db_opts.dbstor_config['PASSWORD'] = GLOBAL_KMC_EXT.encrypt(db_opts.dbstor_config.get('PASSWORD', ""))
        console_and_log("\nSuccessfully to input user name and password")
    except ValueError as error:
        log_exit(str(error))
    except EOFError as error:
        log_exit(str(error))


def getch():
    file_handle = sys.stdin.fileno()
    old_settings = termios.tcgetattr(file_handle)
    try:
        tty.setraw(sys.stdin.fileno())
        char = sys.stdin.read(1)
    finally:
        termios.tcsetattr(file_handle, termios.TCSADRAIN, old_settings)
    return char


def getpass(input_prompt, maskchar="*"):
    password = ""
    console_and_log(input_prompt + ":")
    while True:
        char = getch()
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


def verify_double_password(pwd, new_pwd):
    if pwd != new_pwd:
        console_and_log("\nThe two passwords are inconsistent.")
        raise EOFError("The two passwords are inconsistent.")


def get_dbstor_usernm_passwd(input_prompt, file_prompt, shortest_len, longest_len):
    """Get new passwd"""
    flag = 0
    new_param = ""
    for _ in range(3):
        console_and_log("Please enter %s of %s: " % (input_prompt, file_prompt))
        try:
            if input_prompt == "UserName":
                new_param = input(input_prompt + ":\n")
                verify_dbstor_usernm(input_prompt, new_param, shortest_len, longest_len)
            else:
                new_param = getpass(input_prompt)
                new_param_new = getpass("\nPlease Enter " + input_prompt + " Again")
                verify_double_password(new_param, new_param_new)
                verify_dbstor_passwd(input_prompt, new_param, shortest_len, longest_len)
            break
        except ValueError as error:
            console_and_log(str(error))
            flag += 1
            continue
    if flag == 3:
        return 0
    return new_param


def read_file_path():
    with os.fdopen(os.open(db_opts.js_conf_file, os.O_RDONLY | os.O_EXCL, stat.S_IWUSR | stat.S_IRUSR), "r")\
            as file_obj:
        json_data = json.load(file_obj)
        db_opts.note_id = json_data.get('node_id', "").strip()
        db_opts.inipath = "/opt/cantian/dbstor/tools/dbstor_config.ini"
        db_opts.share_logic_ip = json_data.get('share_logic_ip', "").strip()
        db_opts.cluster_name = json_data.get('cluster_name', "").strip()


def check_ini():
    """
    check ini
    """
    dbstor_check_share_logic_ip_isvalid(db_opts.share_logic_ip)
    console_and_log("Check whether dbstor_config.ini exists")
    if not os.path.exists(db_opts.inipath):
        log_exit("Failed to get dbstor_config.ini. DBStor config is not installed")
    if not os.path.exists(db_opts.local_ini_path):
        log_exit("Failed to get local dbstor_config.ini. cantian is not installed")
    console_and_log("dbstor_config.ini and local dbstor_config.ini exists")


def main():
    """
    main entry
    """
    global GLOBAL_KMC_EXT
    GLOBAL_KMC_EXT = CApiWrapper()
    logger.info("-----------start init kmc--------------------")
    ret = GLOBAL_KMC_EXT.initialize()
    logger.info(f"init kmc return({ret})")
    check_log()
    read_file_path()
    check_ini()
    read_default_parameter()
    parse_parameter()
    check_parameter()
    input_username_password()
    update_parameter()
    GLOBAL_KMC_EXT.finalize()


if __name__ == "__main__":
    try:
        main()
    except ValueError as err:
        exit(1)

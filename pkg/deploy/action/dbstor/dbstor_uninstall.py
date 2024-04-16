#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Perform hot backups of CantianDB100 databases.
# Copyright © Huawei Technologies Co., Ltd. 2010-2018. All rights reserved.


import sys

sys.dont_write_bytecode = True
try:
    import getopt
    import getpass
    import os
    import platform
    import pwd
    import json
    import shutil
    import stat
    import subprocess
    import time
    import logging
    import sys
    from configparser import ConfigParser
except ImportError as error:
    raise ValueError("Unable to import module: %s." % str(error)) from error

# Get the operating system type
CURRENT_OS = platform.system()
TIMEOUT_COUNT = 1800


class ReadConfigParserNoCast(ConfigParser):
    "Inherit from built-in class: ConfigParser"
    def optionxform(self, optionstr):
        "Rewrite without lower()"
        return optionstr


class Options(object):
    """
    class for command line options
    """
    def __init__(self):
        self.install_user_privilege = "withoutroot"
        self.dbstor_log_path = "/opt/cantian/dbstor"
        self.log_path = "/opt/cantian/dbstor/log"
        self.log_file = "/opt/cantian/dbstor/log/uninstall.log"
        self.ini_file = "/opt/cantian/dbstor/tools/dbstor_config.ini"
        self.docker_ini_file = "/home/regress/cantian_data"
        self.js_conf_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../config/deploy_param.json")
        self.note_id = ""
        self.ini_exist = False
        self.share_logic_ip = ""
        self.cluster_name = ""
        self.force_uninstall = ""


g_opts = Options()
gPyVersion = platform.python_version()
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
logger_handle = logging.FileHandler(g_opts.log_file, 'a', "utf-8")

logger_handle.setLevel(logging.DEBUG)
logger_formatter = logging.Formatter('[%(asctime)s]-[%(filename)s]-[line:%(lineno)d]-[%(levelname)s]-'
                            '%(message)s-[%(process)s]')
logger_handle.setFormatter(logger_formatter)
logger.addHandler(logger_handle)
logger.info("init logging success")


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
          % g_opts.log_file)
    if g_opts.force_uninstall != "force":
        raise ValueError(str(msg))


def check_log():
    """
    check log
    and the log for normal user is: ~/uninstall.log
    """
    # check the log path
    flags = os.O_CREAT | os.O_EXCL
    modes = stat.S_IWUSR | stat.S_IRUSR
    if not os.path.exists(g_opts.log_file):
        try:
            with os.fdopen(os.open(g_opts.log_file, flags, modes), "w"):
                pass
        except IOError as ex:
            log_exit("Error: Can not create or open log file: %s", g_opts.log_file)

    try:
        os.chmod(g_opts.log_file, modes)
    except OSError as ex:
        log_exit("Error: Can not chmod log file: %s", g_opts.log_file)


def check_ini():
    """
    check ini
    """
    console_and_log("Check whether dbstor_config.ini exists")
    cmd = "timeout 10 ls %s" % g_opts.ini_file
    ret_code, stdout, _ = _exec_popen(cmd)
    if ret_code:
        console_and_log("dbstor_config.ini not exists ret(%s)" % ret_code)
    else:
        g_opts.ini_exist = True
        console_and_log("dbstor_config.ini exists")


def clean_ini():
    """
    clean ini
    """
    console_and_log("Begin uninstall dbstor config ")
    try:
        os.remove(g_opts.ini_file)
    except OSError as error_msg:
        log_exit("Clean dbstor config: can not delete dbstor_config.ini "
                "%s\nPlease manually delete it." % str(error_msg))


def read_file_path():
    with os.fdopen(os.open(g_opts.js_conf_file, os.O_RDONLY | os.O_EXCL, stat.S_IWUSR | stat.S_IRUSR), "r")\
            as file_handle:
        json_data = json.load(file_handle)
        g_opts.note_id = json_data.get('node_id', "").strip()
        g_opts.share_logic_ip = json_data.get('share_logic_ip', "").strip()
        g_opts.cluster_name = json_data.get('cluster_name', "").strip()
        g_opts.ini_file = "/opt/cantian/dbstor/tools/dbstor_config.ini"


def main():
    """
    main entry
    the step for uninstall:
    1. read ini file path
    2. check uninstall log exist
    3. check ini exist, and dele dbstor_config.ini
    """
    if len(sys.argv) > 2 and sys.argv[1] == "override":
        g_opts.force_uninstall = sys.argv[2]
    read_file_path()
    check_log()
    check_ini()
    if g_opts.ini_exist:
        clean_ini()
    console_and_log("dbstor config was successfully removed from your computer, "
        "for more message please see %s." % g_opts.log_file)


if __name__ == "__main__":
    try:
        main()
    except ValueError as err:
        exit(1)

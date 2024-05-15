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
    from configparser import ConfigParser
except ImportError as error:
    raise ValueError("Unable to import module: %s." % str(error)) from error

# Get the operating system type
CURRENT_OS = platform.system()
TIMEOUT_COUNT = 1800
MAX_DIRECTORY_MODE = 755


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
        self.conf_file_path = "/opt/cantian/backup/files"
        self.backup_ini_file = ""
        self.backup_select = True
        self.log_file = "/opt/cantian/dbstor/log/backup.log"
        self.ini_file = "/opt/cantian/dbstor/tools/dbstor_config.ini"
        self.docker_ini_file = "/home/regress/cantian_data"
        self.js_conf_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../config/deploy_param.json")
        self.dbstor_config = {}
        self.section = 'CLIENT'
        self.note_id = ""
        self.cluster_name = ""


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
    raise ValueError(str(msg))


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


def check_log():
    """
    check log
    and the log for normal user is: ~/backup.log
    """
    flags = os.O_CREAT | os.O_EXCL
    modes = stat.S_IWUSR | stat.S_IRUSR | stat.S_IRGRP
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
    if len(g_opts.note_id.strip()) == 0:
        log_exit("Parameter note_id is not input.")
    logger.info("Check whether dbstor_config.ini exists")
    if not os.path.exists(g_opts.ini_file):
        log_exit("Failed to get dbstor_config.ini. DBStor config is not installed")
    logger.info("dbstor_config.ini exists")


def clean_backup_ini():
    """
    clean backup ini
    """
    # Clean the old log file.
    if os.path.exists(g_opts.backup_ini_file):
        try:
            os.remove(g_opts.backup_ini_file)
        except IOError as io_err:
            log_exit("Error: Can not remove backup dbstor config file: " + g_opts.backup_ini_file)


def read_ini_parameter():
    console_and_log("read DBstor Config file.")
    conf = ReadConfigParserNoCast()
    conf.read(g_opts.ini_file, encoding="utf-8")
    for option in conf.options(g_opts.section):
        value = conf.get(g_opts.section, option)
        g_opts.dbstor_config[option.strip().upper()] = value.strip()
    console_and_log("Generate DBstor Config File.")


def backup_ini():
    """
    function: set dbstor conf
    input : config data
    input : should generate encrypt passwd
    output: NA
    """
    clean_backup_ini()
    # Generate new kernel parameters
    conf = ReadConfigParserNoCast()
    # rewrite parameters
    conf.add_section(g_opts.section)
    for key in g_opts.dbstor_config:
        conf.set(g_opts.section, key, g_opts.dbstor_config[key])
    flags = os.O_CREAT | os.O_RDWR
    modes = stat.S_IWUSR | stat.S_IRUSR
    with os.fdopen(os.open(g_opts.backup_ini_file, flags, modes), "w") as file_handle:
        conf.write(file_handle)
    console_and_log("Successful backup dbstor config file")


def check_backup_ini_path():
    # check backup ini file exists
    if not os.path.exists(g_opts.conf_file_path):
        log_exit("backup ini file not exist ")


def read_file_path():
    with os.fdopen(os.open(g_opts.js_conf_file, os.O_RDONLY | os.O_EXCL, stat.S_IWUSR | stat.S_IRUSR), "r",)\
            as file_handle:
        json_data = json.load(file_handle)
        g_opts.note_id = json_data.get('node_id', "").strip()
        g_opts.cluster_name = json_data.get('cluster_name', "").strip()
        g_opts.ini_file = "/opt/cantian/dbstor/tools/dbstor_config.ini"
        g_opts.backup_ini_file = os.path.join(g_opts.conf_file_path, "dbstor_config.ini")


def main():

    read_file_path()
    check_log()
    check_ini()
    check_backup_ini_path()
    read_ini_parameter()
    backup_ini()


if __name__ == "__main__":
    try:
        main()
    except ValueError as err:
        exit(1)

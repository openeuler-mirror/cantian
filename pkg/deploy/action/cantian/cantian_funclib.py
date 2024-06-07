#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Perform hot backups of CantianDB100 databases.
# Copyright © Huawei Technologies Co., Ltd. 2010-2018. All rights reserved.

import sys
import grp
sys.dont_write_bytecode = True
try:
    import os
    import platform
    import subprocess
    import time
    import select
    import re
    import struct
    import resource
    import pty
    import termios
    import fcntl
    import errno
    import signal
    import shlex

    from multiprocessing.dummy import Pool
    from exception import NormalException
    from get_config_info import get_value
except ImportError as import_err:
    raise ValueError("Unable to import module: %s." % str(import_err)) from import_err

py_verion = platform.python_version()

SYS_PATH = os.environ["PATH"].split(':')


class CommonValue(object):
    """
    common value for some variables
    """
    def __init__(self):
        pass
    # file mode
    MAX_FILE_MODE = 640
    MIN_FILE_MODE = 400
    KEY_FILE_MODE = 600
    MID_FILE_MODE = 500
    MID_FILE_MODE_GROUP = 550
    MIN_FILE_MODE_GROUP = 440

    MIN_DIRECTORY_MODE_GROUP = 550
    KEY_DIRECTORY_MODE = 700
    MID_DIRECTORY_MODE_GROUP = 740
    MAX_DIRECTORY_MODE = 750

    KEY_DIRECTORY_MODE_STR = '0700'

    MIN_FILE_PERMISSION = 0o400
    MID_FILE_PERMISSION = 0o500
    KEY_FILE_PERMISSION = 0o600
    KEY_DIRECTORY_PERMISSION = 0o700


class DefaultConfigValue(object):
    """
    default value for cantiand, cms, gss config
    """
    def __init__(self):
        pass

    deploy_mode = get_value("deploy_mode")
    PRIMARY_KEYSTORE = "/opt/cantian/common/config/primary_keystore_bak.ks"
    STANDBY_KEYSTORE = "/opt/cantian/common/config/standby_keystore_bak.ks"
    mes_type = get_value("mes_type")
    mes_ssl_switch = get_value("mes_ssl_switch")
    node_id = get_value("node_id")
    mysql_group = get_value("mysql_group")
    mysql_group_id = grp.getgrnam(mysql_group).gr_gid
    storage_share_fs = get_value("storage_share_fs")

    CANTIAND_CONFIG = {
        "CHECKPOINT_IO_CAPACITY": 4096,
        "DTC_CKPT_NOTIFY_TASK_RATIO": 0.032,
        "DTC_CLEAN_EDP_TASK_RATIO": 0.032,
        "DTC_TXN_INFO_TASK_RATIO": 0.125,
        "BUFFER_PAGE_CLEAN_PERIOD": 1,
        "BUFFER_LRU_SEARCH_THRE": 40,
        "BUFFER_PAGE_CLEAN_RATIO": 0.1,
        "_DEADLOCK_DETECT_INTERVAL": 1000,
        "INTERCONNECT_CHANNEL_NUM": 3 if (mes_type == "UC" or mes_type == "UC_RDMA") and deploy_mode != "nas" else 32,
        "_UNDO_AUTO_SHRINK": "FALSE",
        "_CHECKPOINT_TIMED_TASK_DELAY": 100,
        "DBWR_PROCESSES": 8,
        "SESSIONS": 18432,
        "CLUSTER_DATABASE": "TRUE",
        "_DOUBLEWRITE": "FALSE" if deploy_mode != "nas" else "TRUE",
        "TEMP_BUFFER_SIZE": "25G",
        "DATA_BUFFER_SIZE": "200G",
        "SHARED_POOL_SIZE": "25G",
        "LOG_BUFFER_COUNT": 16,
        "LOG_BUFFER_SIZE": "110M",
        "MES_POOL_SIZE": 16384,
        "TIMED_STATS": "TRUE",
        "SQL_STAT": "TRUE",
        "MES_ELAPSED_SWITCH": "TRUE",
        "_LOG_LEVEL": 7,
        "DAAC_TASK_NUM": 256,
        "REACTOR_THREAD_NUM": 6,
        "_INDEX_BUFFER_SIZE": "1G",
        "_DISABLE_SOFT_PARSE": "FALSE",
        "_ENABLE_QOS": "FALSE",
        "USE_NATIVE_DATATYPE": "TRUE",
        "_PREFETCH_ROWS": 100,
        "CHECKPOINT_PERIOD": 1,
        "CHECKPOINT_PAGES": 200000,
        "REACTOR_THREADS": 1,
        "OPTIMIZED_WORKER_THREADS": 2000,
        "MAX_WORKER_THREADS": 2000,
        "STATS_LEVEL": "TYPICAL",
        "BUF_POOL_NUM": 32,
        "PAGE_CHECKSUM": "TYPICAL",
        "CR_MODE": "PAGE",
        "_AUTO_INDEX_RECYCLE": "ON",
        "DEFAULT_EXTENTS": 128,
        "TEMP_POOL_NUM": 8,
        "UNDO_RETENTION_TIME": 600,
        "CR_POOL_SIZE": "1G",
        "CR_POOL_COUNT": 32,
        "VARIANT_MEMORY_AREA_SIZE": "2G",
        "_VMP_CACHES_EACH_SESSION": 50,
        "_PRIVATE_KEY_LOCKS": 128,
        "_PRIVATE_ROW_LOCKS": 128,
        "_UNDO_SEGMENTS": 1024,
        "_UNDO_ACTIVE_SEGMENTS": 64,
        "USE_LARGE_PAGES": "FALSE",
        "CTSTORE_MAX_OPEN_FILES": 40960,
        "REPLAY_PRELOAD_PROCESSES": 0,
        "LOG_REPLAY_PROCESSES": 64,
        "_LOG_MAX_FILE_SIZE": "160M",
        "_LOG_BACKUP_FILE_COUNT": 128,
        "RECYCLEBIN": "FALSE",
        "LARGE_POOL_SIZE": "1G",
        "JOB_QUEUE_PROCESSES": 100,
        "MAX_COLUMN_COUNT": 4096,
        "UPPER_CASE_TABLE_NAMES": "FALSE",
        "INSTANCE_ID": 0,
        "INTERCONNECT_PORT": "1601",
        "LSNR_PORT": 1611,
        "INTERCONNECT_TYPE": mes_type if (mes_type == "UC" or mes_type == "UC_RDMA") and deploy_mode != "nas" else "TCP",
        "INTERCONNECT_BY_PROFILE": "FALSE",
        "INSTANCE_NAME": "cantian",
        "ENABLE_SYSDBA_LOGIN": "FALSE",
        "REPL_AUTH": "FALSE",
        "REPL_SCRAM_AUTH": "TRUE",
        "ENABLE_ACCESS_DC": "FALSE",
        "REPLACE_PASSWORD_VERIFY": "TRUE",
        "LOG_HOME": "",  # generate by installer
        "_SYS_PASSWORD": "",  # input by user in command line parameter or from shell command interactively
        "INTERCONNECT_ADDR": "",  # input by user in command line parameter
        "LSNR_ADDR": "127.0.0.1",
        "SHARED_PATH": "+vg1",
        "ARCHIVE_DEST_1": "",
        "MAX_ARCH_FILES_SIZE" : "300G",
        "PAGE_CLEAN_MODE" : "ALL",
        "ENABLE_IDX_KEY_LEN_CHECK": "FALSE",
        "EMPTY_STRING_AS_NULL": "FALSE",
        "_CHECKPOINT_MERGE_IO": "FALSE",
        "ENABLE_DBSTOR_BATCH_FLUSH": "TRUE",
        "CLUSTER_ID": "",
        "_BUFFER_PAGE_CLEAN_WAIT_TIMEOUT": "1",
        "SHM_MQ_MSG_RECV_THD_NUM": 40,
        "MYSQL_METADATA_IN_CANTIAN": "TRUE",
        "MYSQL_DEPLOY_GROUP_ID": mysql_group_id
    }
    
    CANTIAND_DBG_CONFIG = {
        "DBWR_PROCESSES": 8,
        "SESSIONS": 8192,
        "CLUSTER_DATABASE": "TRUE",
        "_DOUBLEWRITE": "FALSE" if deploy_mode != "nas" else "TRUE",
        "TEMP_BUFFER_SIZE": "1G",
        "DATA_BUFFER_SIZE": "8G",
        "SHARED_POOL_SIZE": "1G",
        "LOG_BUFFER_COUNT": 16,
        "LOG_BUFFER_SIZE": "64M",
        "MES_POOL_SIZE": 16384,
        "_LOG_LEVEL": 7,
        "DAAC_TASK_NUM": 64,
        "REACTOR_THREAD_NUM": 2,
        "_INDEX_BUFFER_SIZE": "256M",
        "_DISABLE_SOFT_PARSE": "FALSE",
        "_ENABLE_QOS": "FALSE",
        "USE_NATIVE_DATATYPE": "TRUE",
        "CHECKPOINT_PERIOD": 1,
        "CHECKPOINT_PAGES": 200000,
        "REACTOR_THREADS": 10,
        "OPTIMIZED_WORKER_THREADS": 2000,
        "MAX_WORKER_THREADS": 2000,
        "STATS_LEVEL": "TYPICAL",
        "BUF_POOL_NUM": 16,
        "PAGE_CHECKSUM": "OFF",
        "CR_MODE": "PAGE",
        "_AUTO_INDEX_RECYCLE": "ON",
        "UNDO_RETENTION_TIME": 600,
        "CR_POOL_SIZE": "2G",
        "CR_POOL_COUNT": 4,
        "VARIANT_MEMORY_AREA_SIZE": "1G",
        "REPLAY_PRELOAD_PROCESSES":0,
        "LOG_REPLAY_PROCESSES": 64,
        "_LOG_MAX_FILE_SIZE": "1G",
        "RECYCLEBIN": "FALSE",
        "_LOG_BACKUP_FILE_COUNT": 128,
        "LARGE_POOL_SIZE": "2G",
        "JOB_QUEUE_PROCESSES": 100,
        "MAX_COLUMN_COUNT": 4096,
        "UPPER_CASE_TABLE_NAMES": "FALSE",
        "INSTANCE_ID": 0,
        "INTERCONNECT_PORT": "1601",
        "LSNR_PORT": 1611,
        "INTERCONNECT_TYPE": mes_type if (mes_type == "UC" or mes_type == "UC_RDMA") and deploy_mode != "nas" else "TCP",
        "INTERCONNECT_BY_PROFILE": "FALSE",
        "INSTANCE_NAME": "cantian",
        "ENABLE_SYSDBA_LOGIN": "FALSE",
        "REPL_AUTH": "FALSE",
        "REPL_SCRAM_AUTH": "TRUE",
        "ENABLE_ACCESS_DC": "FALSE",
        "REPLACE_PASSWORD_VERIFY": "TRUE",
        "INTERCONNECT_ADDR": "127.0.0.1",
        "LSNR_ADDR": "127.0.0.1",
        "SHARED_PATH": "",  # generate by installer
        "LOG_HOME": "",  # generate by installer
        "_SYS_PASSWORD": "",  # input by user in command line parameter or from shell command interactively
        "ENABLE_IDX_KEY_LEN_CHECK": "FALSE",
        "EMPTY_STRING_AS_NULL": "FALSE",
        "_CHECKPOINT_MERGE_IO": "FALSE",
        "MYSQL_METADATA_IN_CANTIAN": "TRUE",
        "MES_SSL_SWITCH": "TRUE",
        "MES_SSL_KEY_PWD": None,
        "MES_SSL_CRT_KEY_PATH": "/opt/cantian/certificate",
        "KMC_KEY_FILES": None,
        "MYSQL_DEPLOY_GROUP_ID": mysql_group_id
    }
    MES_CONFIG = {
        "MES_SSL_SWITCH": mes_ssl_switch,
        "MES_SSL_KEY_PWD": None,
        "MES_SSL_CRT_KEY_PATH": "/opt/cantian/common/config/certificates",
        "KMC_KEY_FILES": f"({PRIMARY_KEYSTORE}, {STANDBY_KEYSTORE})"
    }
    
    CANTIAND_CONFIG.update(MES_CONFIG)
    CANTIAND_DBG_CONFIG.update(MES_CONFIG)


class SingleNodeConfig(object):

    @staticmethod
    def get_config(cantian_in_container=False):
        if not cantian_in_container:
            cantiand_cfg = DefaultConfigValue.CANTIAND_CONFIG
        else:
            cantiand_cfg = DefaultConfigValue.CANTIAND_DBG_CONFIG
        return cantiand_cfg


class ClusterNode0Config(object):

    @staticmethod
    def get_config(cantian_in_container=False):
        if not cantian_in_container:
            cantiand_cfg = DefaultConfigValue.CANTIAND_CONFIG
        else:
            cantiand_cfg = DefaultConfigValue.CANTIAND_DBG_CONFIG
        if cantian_in_container:
            cantiand_cfg["LSNR_ADDR"] = "127.0.0.1"
            cantiand_cfg["INTERCONNECT_ADDR"] = "192.168.86.1,192.168.86.2"
        cantiand_cfg["INTERCONNECT_PORT"] = "1601,1602"
        return cantiand_cfg


class ClusterNode1Config(object):

    @staticmethod
    def get_config(cantian_in_container=False):
        if not cantian_in_container:
            cantiand_cfg = DefaultConfigValue.CANTIAND_CONFIG
        else:
            cantiand_cfg = DefaultConfigValue.CANTIAND_DBG_CONFIG
        if cantian_in_container:
            cantiand_cfg["LSNR_ADDR"] = "127.0.0.1"
            cantiand_cfg["INTERCONNECT_ADDR"] = "192.168.86.1,192.168.86.2"
        cantiand_cfg["INSTANCE_ID"] = 1
        cantiand_cfg["INTERCONNECT_PORT"] = "1601,1602"
        return cantiand_cfg


class SshToolException(Exception):
    """
    Exception for SshTool
    """


def exec_popen(cmd):
    """
    subprocess.Popen in python2 and 3.
    :param cmd: commands need to execute
    :return: status code, standard output, error output
    """
    bash_cmd = ["bash"]
    pobj = subprocess.Popen(bash_cmd, shell=False, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if py_verion[0] == "3":
        stdout, stderr = pobj.communicate(cmd.encode(), timeout=1800)
        stdout = stdout.decode()
        stderr = stderr.decode()
    else:
        stdout, stderr = pobj.communicate(cmd, timeout=1800)

    if stdout[-1:] == os.linesep:
        stdout = stdout[:-1]
    if stderr[-1:] == os.linesep:
        stderr = stderr[:-1]

    return pobj.returncode, stdout, stderr


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


def get_abs_path(_file):
    for _path in SYS_PATH:
        if not check_path(_path):
            return ""
        abs_file = os.path.normpath(os.path.join(_path, _file))
        if os.path.exists(abs_file):
            return abs_file
    return ""


def check_path(path_type_in):
    path_len = len(path_type_in)
    current_os = platform.system()
    if current_os == "Linux":
        system_check_linux(path_len, path_type_in)
    elif current_os == "Windows":
        system_check_windows(path_len, path_type_in)
    else:
        raise ValueError("Can not support this platform.")
    return True


def system_check_linux(path_len, path_type_in):
    i = 0
    a_ascii, a_uppercase_ascii, blank_ascii, num0_ascii, num9_ascii, sep1_ascii, sep2_ascii,\
        sep3_ascii, sep4_ascii, sep5_ascii, z_ascii, z_uppercase_ascii = check_ascii()
    ascii_list = [blank_ascii, sep1_ascii, sep2_ascii, sep4_ascii, sep5_ascii]
    for i in range(0, path_len):
        char_check = ord(path_type_in[i])
        if not (a_ascii <= char_check <= z_ascii
                or a_uppercase_ascii <= char_check <= z_uppercase_ascii
                or num0_ascii <= char_check <= num9_ascii
                or char_check in ascii_list):
            return False
    return True


def system_check_windows(path_len, path_type_in):
    i = 0
    a_ascii, a_uppercase_ascii, blank_ascii, num0_ascii, num9_ascii, sep1_ascii, sep2_ascii,\
        sep3_ascii, sep4_ascii, sep5_ascii, z_ascii, z_uppercase_ascii = check_ascii()
    ascii_list = [blank_ascii, sep1_ascii, sep2_ascii, sep3_ascii, sep4_ascii]
    for i in range(0, path_len):
        char_check = ord(path_type_in[i])
        if not (a_ascii <= char_check <= z_ascii
                or a_uppercase_ascii <= char_check <= z_uppercase_ascii
                or num0_ascii <= char_check <= num9_ascii
                or char_check in ascii_list):
            return False
    return True


def check_ascii():
    a_ascii = ord('a')
    z_ascii = ord('z')
    a_uppercase_ascii = ord('A')
    z_uppercase_ascii = ord('Z')
    num0_ascii = ord('0')
    num9_ascii = ord('9')
    blank_ascii = ord(' ')
    sep1_ascii = ord(os.sep)
    sep2_ascii = ord('_')
    sep3_ascii = ord(':')
    sep4_ascii = ord('-')
    sep5_ascii = ord('.')
    ascii_list = [
        a_ascii, a_uppercase_ascii, blank_ascii, num0_ascii, num9_ascii, sep1_ascii, sep2_ascii,
        sep3_ascii, sep4_ascii, sep5_ascii, z_ascii, z_uppercase_ascii
    ]
    return ascii_list


def check_ssh_connection(ips):
    '''
    check ssh connection without password, if success to
    connect the node user trust to the node has be created
    '''
    failed_ip = []
    success_ip = []
    ssh = get_abs_path("ssh")
    if not ssh:
        raise Exception("Can not find ssh in PATH.")
    for ip in ips:
        cmd = "%s %s " % (ssh, ip)
        cmd += "-o PasswordAuthentication=no -o ConnectTimeout=10 "
        cmd += "-o ServerAliveInterval=100 -o ServerAliveCountMax=36 "
        cmd += "-n 'echo Last login'"
        process = Execution(cmd)
        idx =\
            process.expect(['Permission denied',
                            'Last login',
                            'Are you sure you want to continue connecting',
                            'Password', 'ssh:', TimeoutException,
                            EOFException], 60)
        if idx == 0:
            failed_ip.append(ip)
        elif idx == 1:
            success_ip.append(ip)
            process.send_line("exit")
        elif idx == 2:
            process.send_line('yes')
            idx = process.expect(['Permission denied', 'Last login',
                                  'Password', 'ssh:'], 60)
            if idx == 0:
                failed_ip.append(ip)
            elif idx == 1:
                success_ip.append(ip)
                process.send_line("exit")
            elif idx == 2:
                raise Exception("Check ssh connection"
                                       " failed,check your ssh"
                                       " configure file please.")
            elif idx == 3:
                raise Exception(str(process.context_buffer))

            elif idx in [5, 6]:
                failed_ip.append(ip)

        elif idx == 3:
            # when ChallengeResponseAuthentication is
            # yes in sshd configure file,
            # the check method will change to use
            #  password authentication method,
            # so we must expect Password key word
            # to avoid to wait to timeout
            raise Exception("Check ssh"
                                   " connection failed,"
                                   " check your ssh"
                                   " configure file please.")
        elif idx == 4:
            raise Exception(str(process.context_buffer))

        elif idx in [5, 6]:
            failed_ip.append(ip)

    return failed_ip, success_ip


class CommandTool(object):
    """
    class for CommandTool
    """
    def __init__(self, log):

        self.log = log
        self.ssh = get_abs_path("ssh")
        self.bash = get_abs_path("bash")

        if not self.ssh:
            raise SshToolException("Can't find ssh command.")
        if not self.bash:
            raise SshToolException("Can't find bash command.")

    def __execute(self, arg):
        '''
        execute shell command by ssh to login remote host
        arg - list for argument, ip address and shell command
        '''
        ip = arg[0]
        cmd = arg[1]
        ssh_options = " -o ServerAliveInterval=100 "
        ssh_options += " -o ServerAliveCountMax=36 "
        cmd = "export TMOUT=0; %s" % cmd
        ssh_cmd = "ssh %s %s \"%s\"" % (ssh_options, ip, cmd)
        return [ip, exec_popen(ssh_cmd)]

    def __scp(self, arg):
        ip = arg[0]
        ip = "[%s]" % ip
        src = arg[1]
        dest = arg[2]
        _dir = arg[3]
        if _dir is True:
            scp_cmd = "scp -r %s %s:%s" % (src, ip, dest)
        else:
            scp_cmd = "scp -2 %s %s:%s" % (src, ip, dest)

        return [ip, exec_popen(scp_cmd)]

    def __interactive_input(self, process, ip, pw1, pw2):

        pw_str = 'Please enter password'
        self.log("Expect(%s) on: [%s]" % (ip, pw_str))
        process.expect(['Please enter password'])
        self.log("Send(%s) password." % ip)
        process.send_line(pw1)
        if pw2:
            self.log("Expect(%s) on: [%s]" % (ip, pw_str))
            process.expect(['Please enter password'])
            self.log("Send(%s) password." % ip)
            process.send_line(pw2)

    def __expect_execute(self, arg):
        """
        execute shell command with expect,
        input: arg - list of command information, like [ip, command, user_info]
               ip  - the ip address of execute the command, if it is not None,
                     use ssh, or use bash
               command - shell command
               user_info - user password
        """
        ip = arg[0]
        cmd = arg[1]
        user = arg[2]
        instlist = arg[3]
        self.log("Expect(%s) execute start." % ip)
        pdict = {}
        ssh_options = " -o ServerAliveInterval=100 "
        ssh_options += " -o ServerAliveCountMax=36 "
        process = None
        try:
            if ip:
                process = Execution("%s %s %s" % (self.ssh, ssh_options, ip))
                pdict = user[1]
                self.log("ssh session info:\n%s %s %s" % (self.ssh,
                                                          ssh_options,
                                                          ip))
            else:
                process = Execution("%s" % (self.bash))
                self.log("bash session")
                if isinstance(user, list):
                    if isinstance(user[1], dict):
                        for key, valuse in user[1].items():
                            pdict["None" + "_" + key.split("_", 1)[1]] = valuse

            self.log("Send(%s): export TMOUT=0" % ip)
            process.send_line("export TMOUT=0")
            self.log("Send(%s): %s" % (cmd, ip))
            process.send_line(cmd)
            if user:
                if instlist:
                    for inst in instlist:
                        p0 = pdict.get(str(ip) + "_" + inst)[0]
                        p1 = pdict.get(str(ip) + "_" + inst)[1]
                        self.__interactive_input(process, ip, p0, p1)
                else:
                    self.__interactive_input(process, ip, user[1], user[2])

            self.log("Expect(%s) on: [Done, Upgrade Failed]" % ip)
            idx = process.expect(['Done', 'Upgrade Failed'], timeout=51200)
            if idx == 0:
                self.log("Expect(%s) received Done." % ip)
                process.send_line('exit')
                return [ip, ('0', str(process.context_before))]
            self.log("Expect(%s) received Upgrade Failed." % ip)
            process.send_line('exit')
            return [ip, ('1', str(process.context_buffer))]
        except (TimeoutException, EOFException) as err:
            self.log("Expect(%s) timeout." % ip)
            if process:
                process.send_line('exit')
            return [ip, ('1', str(err) + '\n' + str(process.context_buffer))]

    def execute_local(self, cmd):
        ret_code, output, errput = exec_popen(cmd)
        output = get_error_msg(output, errput)
        return ret_code, output

    def expect_execute(self, ip_cmd_map):
        '''
        execute shell command with expect
        '''
        try:
            pool = Pool(len(ip_cmd_map))
            result = pool.map(self.__expect_execute, ip_cmd_map)
            return self.__parse(result)
        except KeyboardInterrupt as e:
            #captured and processed by the caller
            raise

    def execute_in_node(self, ip_cmd_map):
        '''
        '''
        pool = Pool(len(ip_cmd_map))
        result = pool.map(self.__execute, ip_cmd_map)
        return self.__parse(result)

    def scp_in_node(self, ip_dest_map):
        '''
        '''
        pool = Pool(len(ip_dest_map))
        result = pool.map(self.__scp, ip_dest_map)
        return self.__parse(result)

    def __parse(self, result):
        """
        parse execute result, if return code in any host is not 0, the return
        code for the execution is failed, and put all failed information in
        failed_node
        """
        ret_code = 0
        success_node = []
        failed_node = []
        for tmp_rs in result:
            if str(rs[1][0]) != '0':
                ret_code = 1
                failed_node.append(tmp_rs)
            success_node.append(tmp_rs)
        return ret_code, success_node, failed_node

    def expect_ctsql(self, ip_cmd_map):
        '''
        expect execute ctsql and sql command
        '''
        pool = Pool(len(ip_cmd_map))
        result = pool.map(self.__expect_ctsql, ip_cmd_map)
        return self.__parse(result)

    def __expect_ctsql(self, arg):
        '''
        '''
        ip = arg[0]
        ctsql = arg[1]
        sql = arg[2]
        passwd = arg[3]
        ssh_options = " -o ServerAliveInterval=100 "
        ssh_options += " -o ServerAliveCountMax=36 "
        process = None
        try:
            if ip:
                process = Execution("%s %s %s" % (self.ssh, ssh_options, ip))
            else:
                process = Execution("%s" % self.bash)

            process.send_line(ctsql)
            if passwd:
                process.expect(['Please enter password'])
                process.send_line(passwd)
            process.expect(['SQL>'])
            process.send_line(sql)
            idx = process.expect(['rows fetched', 'Succeed', 'CT-', 'SQL>'],
                                 timeout=600)
            if idx == 0 or idx == 1:
                process.send_line('exit')
                return [ip, ('0', str(process.context_before))]
            process.send_line('exit')
            return [ip, '1', str(process.context_buffer)]
        except (TimeoutException, EOFException):
            if process:
                process.send_line('exit')
            return [ip, ('1', str(process.context_buffer))]


class ExpectException(Exception):
    def __init__(self, errorInfo):
        super(ExpectException, self).__init__(errorInfo)
        self.errorinfo = errorInfo

    def __str__(self):
        return str(self.errorinfo)


class EOFException(ExpectException):
    pass


class TimeoutException(ExpectException):
    pass


class Execution(object):
    STRING_TYPE = bytes
    if py_verion[0] == "3":
        ALLOWED_STRING_TYPES = (str,)
    else:
        ALLOWED_STRING_TYPES = (type(b''), type(''), type(u''),)

    LINE_SEPERATOR = os.linesep
    CTRLF = '\r\n'

    def __init__(self, command, timeout=1800, max_read_size=4096,
                 delimiter=None):

        self.matcher = None
        self.context_before = None
        self.context_after = None
        self.match = None
        self.matchIndex = None
        # flag for process terminate
        self.is_terminated = True
        self.eof_flag = False
        self.child_pid = None
        self.child_fd = -1
        self.timeout = timeout
        self.delimiter = delimiter if delimiter else EOFException
        self.max_read_size = max_read_size
        self.context_buffer = self.STRING_TYPE()
        self.send_delay = 0.05
        self.close_delay = 0.1
        self.terminate_delay = 0.1
        self.is_closed = True
        self.context_match = None
        try:
            from termios import CEOF
            from termios import CINTR
            (self._INTR, self._EOF) = (CINTR, CEOF)
        except ImportError:
            try:
                from termios import VEOF
                from termios import VINTR
                tmp_fp = sys.__stdin__.fileno()
                self._INTR = ord(termios.tcgetattr(tmp_fp)[6][VINTR])
                self._EOF = ord(termios.tcgetattr(tmp_fp)[6][VEOF])
            except (ImportError, OSError, IOError, termios.error):
                (self._INTR, self._EOF) = (3, 4)
        self._excute(command)

    @staticmethod
    def _ascii(content):
        if not isinstance(content, bytes):
            return content.encode('ascii')
        return content

    @staticmethod
    def _utf8(content):
        if not isinstance(content, bytes):
            return content.encode('utf-8')
        return content

    def __del__(self):
        if not self.is_closed:
            try:
                self.close()
            except Exception as e:
                raise Exception(e) from e

    def __str__(self):
        tmp_s = list()
        tmp_s.append('%r' % self)
        tmp_s.append('after: %r' % self.context_after)
        tmp_s.append('pid: %s' % str(self.child_pid))
        tmp_s.append('child_fd: %s' % str(self.child_fd))
        tmp_s.append('closed: %s' % str(self.is_closed))
        tmp_s.append('timeout: %s' % str(self.timeout))
        tmp_s.append('delimiter: %s' % str(self.delimiter))
        tmp_s.append('maxReadSize: %s' % str(self.max_read_size))
        return '\n'.join(tmp_s)

    def _excute(self, command):
        self.args = shlex.split(command)

        if self.child_pid is not None:
            raise ExpectException('The pid member must be None.')

        if self.command is None:
            raise ExpectException('The command member must not be None.')

        try:
            self.child_pid, self.child_fd = pty.fork()
        except OSError as err:  # pragma: no cover
            raise ExpectException('pty.fork() failed: ' + str(err)) from err

        if self.child_pid == pty.CHILD:
            # child
            self.child_fd = pty.STDIN_FILENO
            try:
                self.set_win_size(24, 80)
            except IOError as e:
                if e.args[0] not in (errno.EINVAL, errno.ENOTTY):
                    raise

            self.set_echo(False)
            # close the handle
            max_fd_number = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
            os.closerange(3, max_fd_number)

            signal.signal(signal.SIGHUP, signal.SIG_IGN)
            # execute command in child process
            exec_popen(self.command)

        # parent
        try:
            self.set_win_size(24, 80)
        except IOError as e:
            if e.args[0] not in (errno.EINVAL, errno.ENOTTY):
                raise

        self.is_terminated = False
        self.is_closed = False

    def fileno(self):
        return self.child_fd

    def close(self):
        if self.is_closed:
            return
        os.close(self.child_fd)
        # give kernel time to update process status.
        time.sleep(self.close_delay)
        if self.is_alive() and not self.terminate():
            raise ExpectException('Could not terminate the child.')
        self.child_fd = -1
        self.is_closed = True

    def set_echo(self, state):
        err_msg = ('method set_echo() may not be available on'
                   ' this operating system.')

        try:
            child_attr = termios.tcgetattr(self.child_fd)
        except termios.error as e:
            if e.args[0] == errno.EINVAL:
                raise IOError(e.args[0], '%s: %s.' % (e.args[1], err_msg)) from e
            raise

        if state:
            child_attr[3] = child_attr[3] | termios.ECHO
        else:
            child_attr[3] = child_attr[3] & ~termios.ECHO

        try:
            termios.tcsetattr(self.child_fd, termios.TCSANOW, child_attr)
        except IOError as e:
            if e.args[0] == errno.EINVAL:
                raise IOError(e.args[0], '%s: %s.' % (e.args[1], err_msg)) from e
            raise

    def read_non_block(self, size=1, timeout=-1):
        if self.is_closed:
            raise ValueError('I/O operation on closed file.')

        if timeout == -1:
            timeout = self.timeout

        if not self.is_alive():
            # if timeout is 0, means "poll"
            rfds, _, _ = self.select([self.child_fd], [], [], 0)
            if not rfds:
                self.eof_flag = True
                raise EOFException('End Of File (EOF). Braindead platform.')

        rfds, _, _ = self.select([self.child_fd], [], [], timeout)

        if not rfds:
            if not self.is_alive():
                self.eof_flag = True
                raise EOFException('Reach end of File (EOF).')
            else:
                raise TimeoutException('Timeout exceeded.')

        if self.child_fd in rfds:
            try:
                child_data = os.read(self.child_fd, size)
            except OSError as e:
                if e.args[0] == errno.EIO:
                    self.eof_flag = True
                    raise EOFException('Reach End Of File (EOF). '
                                       'Exception style platform.') from e
                raise
            if child_data == b'':
                self.eof_flag = True
                raise EOFException('Reach end Of File (EOF).'
                                   ' Empty string style platform.')

            return child_data

        raise ExpectException('Reached an unexpected state.')
        # pragma: no cover

    def read(self, size=-1, timeout=-1):
        if size == 0:
            return self.STRING_TYPE()
        self.expect(self.delimiter, timeout)
        return self.context_before

    def send(self, content):
        time.sleep(self.send_delay)
        content = self._utf8(content)
        return self._send(content)

    def _send(self, content):
        return os.write(self.child_fd, content)

    def send_line(self, content=''):
        send_count = self.send(content)
        send_count = send_count + self.send(self.LINE_SEPERATOR)
        return send_count

    def terminate(self):
        if not self.is_alive():
            return True
        try:
            self.kill(signal.SIGHUP)
            time.sleep(self.terminate_delay)
            if not self.is_alive():
                return True
            self.kill(signal.SIGCONT)
            time.sleep(self.terminate_delay)
            if not self.is_alive():
                return True
            self.kill(signal.SIGINT)
            time.sleep(self.terminate_delay)
            if not self.is_alive():
                return True
            self.kill(signal.SIGKILL)
            time.sleep(self.terminate_delay)
            if not self.is_alive():
                return True
            else:
                return False
        except OSError:
            time.sleep(self.terminate_delay)

            return False if self.is_alive() else True

    def is_alive(self):
        if self.is_terminated:
            return False

        wait_pid_options = 0 if self.eof_flag else os.WNOHANG
        child_pid, child_status = self.wait_child_process(wait_pid_options)

        if child_pid == 0:
            child_pid, child_status = self.wait_child_process(wait_pid_options)
            if child_pid == 0:
                return True

        self.check_child_process(child_status)

        return False

    def check_child_process(self, child_status):
        if os.WIFEXITED(child_status) or os.WIFSIGNALED(child_status):
            self.is_terminated = True
        elif os.WIFSTOPPED(child_status):
            raise ExpectException('process already been stopped.')

    def wait_child_process(self, wait_pid_options):
        try:
            child_pid, child_status = os.waitpid(self.child_pid, wait_pid_options)
        except OSError as error:
            # No child processes
            if error.errno == errno.ECHILD:
                raise ExpectException('process already not exist.') from error
            else:
                raise error
        return child_pid, child_status

    def kill(self, sig):
        if self.is_alive():
            try:
                os.kill(self.child_pid, sig)
            except OSError as e:
                # No such process
                if e.errno == 3:
                    pass
                else:
                    raise

    def raise_pattern_type_error(self, pattern):
        raise TypeError(
            'got %s as pattern, must be one'
            ' of: %s, pexpect.EOFException, pexpect.TIMEOUTException'
            % (type(pattern), ', '.join([str(ast) for ast in self.ALLOWED_STRING_TYPES])))

    def compile_pattern_list(self, pattern_list):
        if not pattern_list:
            return []
        if not isinstance(pattern_list, list):
            pattern_list = [pattern_list]

        pattern_list_temp = []
        for _, pattern in enumerate(pattern_list):
            if isinstance(pattern, self.ALLOWED_STRING_TYPES):
                pattern = self._ascii(pattern)
                pattern_list_temp.append(re.compile(pattern, re.DOTALL))
            elif pattern is EOFException:
                pattern_list_temp.append(EOFException)
            elif pattern is TimeoutException:
                pattern_list_temp.append(TimeoutException)
            elif isinstance(pattern, type(re.compile(''))):
                pattern_list_temp.append(pattern)
            else:
                self.raise_pattern_type_error(pattern)
        return pattern_list_temp

    def expect(self, pattern, timeout=-1):
        pattern_list = self.compile_pattern_list(pattern)
        return self.expect_list(pattern_list, timeout)

    def expect_list(self, pattern_list, timeout=-1):
        return self.loop_expect(RESearcher(pattern_list), timeout)

    def loop_expect(self, re_searcher, timeout=-1):
        self.matcher = re_searcher
        if timeout == -1:
            timeout = self.timeout
        if timeout is not None:
            end_time = time.time() + timeout

        try:
            context_buffer = self.context_buffer
            while True:
                match_index = re_searcher.search(context_buffer)
                if match_index > -1:
                    self.context_buffer = context_buffer[re_searcher.end:]
                    self.context_before = context_buffer[: re_searcher.start]
                    self.context_after = context_buffer[re_searcher.start: re_searcher.end]
                    self.context_match = re_searcher.context_match
                    self.matchIndex = match_index
                    return self.matchIndex
                # no match at this point
                if (timeout is not None) and (timeout < 0):
                    raise TimeoutException('Timeout exceeded in loop_expect().')
                # not timed out, continue read
                more_context = self.read_non_block(self.max_read_size, timeout)
                time.sleep(0.0001)
                context_buffer += more_context
                if timeout is not None:
                    timeout = end_time - time.time()
        except EOFException as err:
            self.context_buffer = self.STRING_TYPE()
            self.context_before = context_buffer
            self.context_after = EOFException
            match_index = re_searcher.eof_index
            if match_index > -1:
                self.context_match, self.matchIndex = EOFException, match_index
                return self.matchIndex
            else:
                self.context_match, self.matchIndex = None, None
                raise EOFException("%s\n%s" % (str(err), str(self))) from err
        except TimeoutException as err:
            self.context_buffer = context_buffer
            self.context_before = context_buffer
            self.context_after = TimeoutException
            match_index = re_searcher.timeout_index
            if match_index > -1:
                self.context_match, self.matchIndex = TimeoutException, match_index
                return self.matchIndex
            else:
                self.context_match, self.matchIndex = None, None
                raise TimeoutException("%s\n%s" % (str(err), str(self))) from err
        except Exception:
            self.context_before = context_buffer
            self.context_after, self.context_match, self.matchIndex = None, None, None
            raise

    def set_win_size(self, rows, cols):
        win_size = getattr(termios, 'TIOCSWINSZ', -2146929561)
        s_size = struct.pack('HHHH', rows, cols, 0, 0)
        fcntl.ioctl(self.fileno(), win_size, s_size)

    def select(self, inputs, outputs, errputs, timeout=None):
        if timeout:
            end_time = time.time() + timeout
        while True:
            try:
                return select.select(inputs, outputs, errputs, timeout)
            except select.error as error:
                if self.error_msg(error, error, timeout, end_time):
                    return [], [], []

    def error_msg(self, error, timeout, end_time):
        if error.args[0] == errno.EINTR:
            if timeout is not None:
                timeout = end_time - time.time()
                if timeout < 0:
                    return True
            return False
        else:
            raise Exception("Time out error.")


class RESearcher(object):
    def __init__(self, pattern_list):
        self.eof_index = -1
        self.timeout_index = -1
        self._searches = []
        self.start = None
        self.context_match = None
        self.end = None
        for index, pattern_item in zip(list(range(len(pattern_list))),
                                       pattern_list):
            if pattern_item is EOFException:
                self.eof_index = index
                continue
            if pattern_item is TimeoutException:
                self.timeout_index = index
                continue
            self._searches.append((index, pattern_item))

    def __str__(self):
        result_list = list()
        for index, pattern_item in self._searches:
            try:
                result_list.append((index, '    %d: re.compile("%s")' %
                                    (index, pattern_item.pattern)))
            except UnicodeEncodeError:
                result_list.append((index, '    %d: re.compile(%r)' %
                                    (index, pattern_item.pattern)))
        result_list.append((-1, 'RESearcher:'))
        if self.eof_index >= 0:
            result_list.append((self.eof_index, '    %d: EOF' %
                                self.eof_index))
        if self.timeout_index >= 0:
            result_list.append((self.timeout_index, '    %d: TIMEOUT' %
                                self.timeout_index))
        result_list.sort()
        s_result_list = list(zip(*result_list))[1]
        return '\n'.join(s_result_list)

    def search(self, content):
        first_match_index = None
        start_index = 0
        for index, pattern_item in self._searches:
            match_context = pattern_item.search(content, start_index)
            if match_context is None:
                continue
            match_index = match_context.start()
            if first_match_index is None or match_index < first_match_index:
                first_match_index = match_index
                the_match_context = match_context
                best_index = index
        if first_match_index is None:
            return -1
        self.start = first_match_index
        self.context_match = the_match_context
        self.end = self.context_match.end()
        return best_index

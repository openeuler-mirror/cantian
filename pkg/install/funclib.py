#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Perform hot backups of CantianDB100 databases.
# Copyright © Huawei Technologies Co., Ltd. 2010-2018. All rights reserved.

import sys
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

except ImportError as import_err:
    sys.exit("Unable to import module: %s." % str(import_err))

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

    KEY_DIRECTORY_MODE = 700
    MAX_DIRECTORY_MODE = 750

    KEY_DIRECTORY_MODE_STR = '0700'

    MIN_FILE_PERMISSION = 0o400
    MID_FILE_PERMISSION = 0o500
    KEY_FILE_PERMISSION = 0o600
    KEY_DIRECTORY_PERMISSION = 0o700
    MAX_DIRECTORY_PERMISSION = 0o770

    DOCKER_SHARE_DIR = "/home/regress/cantian_data"
    DOCKER_DATA_DIR = "{}/data".format(DOCKER_SHARE_DIR)
    DOCKER_GCC_DIR = "{}/gcc_home".format(DOCKER_SHARE_DIR)


class DefaultConfigValue(object):
    """
    default value for cantiand, cms, gss config
    """
    def __init__(self):
        pass

    CANTIAND_CONFIG = {
        "CHECKPOINT_IO_CAPACITY": 4096,
        "DTC_CKPT_NOTIFY_TASK_RATIO": 0.032,
        "DTC_CLEAN_EDP_TASK_RATIO": 0.032,
        "DTC_TXN_INFO_TASK_RATIO": 0.125,
        "BUFFER_PAGE_CLEAN_PERIOD": 1,
        "BUFFER_LRU_SEARCH_THRE": 100,
        "BUFFER_PAGE_CLEAN_RATIO": 0.3,
        "_DEADLOCK_DETECT_INTERVAL": 1000,
        "INTERCONNECT_CHANNEL_NUM": 3,
        "_UNDO_AUTO_SHRINK": "FALSE",
        "_CHECKPOINT_TIMED_TASK_DELAY": 100,
        "DBWR_PROCESSES": 32,
        "SESSIONS": 18432,
        "CLUSTER_DATABASE": "TRUE",
        "_DOUBLEWRITE": "FALSE",
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
        "AUDIT_LEVEL": 0,
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
	    "REPLAY_PRELOAD_PROCESSES":0,
        "LOG_REPLAY_PROCESSES": 64,
        "_LOG_MAX_FILE_SIZE": "4G",
        "_LOG_BACKUP_FILE_COUNT": 128,
        "RECYCLEBIN": "FALSE",
        "LARGE_POOL_SIZE": "1G",
        "JOB_QUEUE_PROCESSES": 100,
        "MAX_COLUMN_COUNT": 4096,
        "UPPER_CASE_TABLE_NAMES": "FALSE",
        "INSTANCE_ID": 0,
        "INTERCONNECT_PORT": "1601",
        "LSNR_PORT": 1611,
        "INTERCONNECT_TYPE": "TCP",
        "INTERCONNECT_BY_PROFILE": "FALSE",
        "INSTANCE_NAME": "cantian",
        "ENABLE_SYSDBA_LOGIN": "TRUE",
        "REPL_AUTH": "FALSE",
        "REPL_SCRAM_AUTH": "TRUE",
        "ENABLE_ACCESS_DC": "FALSE",
        "REPLACE_PASSWORD_VERIFY": "TRUE",
        "LOG_HOME": "", #generate by installer
        "_SYS_PASSWORD": "", #input by user in command line parameter or from shell command interactively
        "INTERCONNECT_ADDR": "", #input by user in command line parameter
        "LSNR_ADDR": "", #input by user in command line parameter
        "SHARED_PATH": "+vg1",
        "ENABLE_IDX_KEY_LEN_CHECK": "FALSE",
        "EMPTY_STRING_AS_NULL": "FALSE",
        "MYSQL_METADATA_IN_CANTIAN": "TRUE",
        "MYSQL_DEPLOY_GROUP_ID": "5000"
    }
    
    GSS_CONFIG = {
        "INTERCONNECT_PORT": "1621",
        "MAX_SESSION_NUMS": 4096,
        "LSNR_PATH": "/tmp",
        "_LOG_LEVEL": 4294967295,
        "STORAGE_MODE": "CLUSTER_RAID",
        "INST_ID": 0,
        "LOG_HOME": "",  #generate by installer
        "INTERCONNECT_ADDR": "", #input by user in command line parameter, same as CANTIAND_CONFIG#INTERCONNECT_ADDR
    }
    
    CMS_CONFIG = {
        "NODE_ID": 0,
        "GCC_HOME": "", #generate by installer
        "GCC_TYPE": "", #generate by installer
        "_PORT": 14587,
        "_IP": "", #input by user in command line parameter, same as CANTIAND_CONFIG#LSNR_ADDR
        "_LOG_LEVEL": 7,
        "_SPLIT_BRAIN": "TRUE",
        "_LOG_MAX_FILE_SIZE": "1G",
        "_DETECT_DISK_TIMEOUT": 6000,
        "_DISK_DETECT_FILE": "gcc_file,",
        "_STOP_RERUN_CMS_SCRIPT" : "/opt/cantian/common/script/cms_reg.sh",
        "_EXIT_NUM_COUNT_FILE": "/home/cantiandba/data/exit_num.txt",
        "_CMS_MES_THREAD_NUM" : "5",
        "_CMS_MES_MAX_SESSION_NUM" : "40",
        "_CMS_MES_MESSAGE_POOL_COUNT" : "1",
        "_CMS_MES_MESSAGE_QUEUE_COUNT" : "1",
        "_CMS_MES_MESSAGE_BUFF_COUNT" : "4096",
        "_CMS_MES_MESSAGE_CHANNEL_NUM" : "1",
        "_CMS_NODE_FAULT_THRESHOLD" : "5",
        "_USE_DBSTOR" : "FALSE",
        "_DBSTOR_NAMESPACE" : "",
        "_CMS_MES_PIPE_TYPE" : "TCP",
        "_CMS_MES_CRC_CHECK_SWITCH" : "TRUE",
        "SHARED_PATH": "/home/cantiandba/data/data",
    }
    
    CANTIAND_DBG_CONFIG = {
        "DBWR_PROCESSES": 8,
        "SESSIONS": 8192,
        "CLUSTER_DATABASE": "TRUE",
        "_DOUBLEWRITE": "FALSE",
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
        "AUDIT_LEVEL": 0,
        "PAGE_CHECKSUM": "TYPICAL",
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
        "INTERCONNECT_TYPE": "TCP",
        "INTERCONNECT_BY_PROFILE": "FALSE",
        "INSTANCE_NAME": "cantian",
        "ENABLE_SYSDBA_LOGIN": "TRUE",
        "REPL_AUTH": "FALSE",
        "REPL_SCRAM_AUTH": "TRUE",
        "ENABLE_ACCESS_DC": "FALSE",
        "REPLACE_PASSWORD_VERIFY": "TRUE",
        "INTERCONNECT_ADDR": "127.0.0.1",
        "LSNR_ADDR": "127.0.0.1",
        "SHARED_PATH": "", #generate by installer
        "LOG_HOME": "", #generate by installer
        "_SYS_PASSWORD": "", #input by user in command line parameter or from shell command interactively
        "ENABLE_IDX_KEY_LEN_CHECK": "FALSE",
        "EMPTY_STRING_AS_NULL": "FALSE",
        "MYSQL_METADATA_IN_CANTIAN": "TRUE",
        "MYSQL_DEPLOY_GROUP_ID": "5000"
    }


class SingleNodeConfig(object):

    @staticmethod
    def get_config(in_container = False):
        cantiand_cfg = DefaultConfigValue.CANTIAND_CONFIG if not in_container else DefaultConfigValue.CANTIAND_DBG_CONFIG
        return cantiand_cfg, DefaultConfigValue.CMS_CONFIG, DefaultConfigValue.GSS_CONFIG


class ClusterNode0Config(object):

    @staticmethod
    def get_config(in_container = False):
        cantiand_cfg = DefaultConfigValue.CANTIAND_CONFIG if not in_container else DefaultConfigValue.CANTIAND_DBG_CONFIG
        if in_container:
            cantiand_cfg["LSNR_ADDR"] = "192.168.86.1"
            cantiand_cfg["INTERCONNECT_ADDR"] = "192.168.86.1;192.168.86.2"
        cantiand_cfg["INTERCONNECT_PORT"] = "1601,1602"
        DefaultConfigValue.GSS_CONFIG["INTERCONNECT_PORT"] = "1621,1621"
        return cantiand_cfg, DefaultConfigValue.CMS_CONFIG, DefaultConfigValue.GSS_CONFIG


class ClusterNode1Config(object):

    @staticmethod
    def get_config(in_container = False):
        cantiand_cfg = DefaultConfigValue.CANTIAND_CONFIG if not in_container else DefaultConfigValue.CANTIAND_DBG_CONFIG
        if in_container:
            cantiand_cfg["LSNR_ADDR"] = "192.168.86.2"
            cantiand_cfg["INTERCONNECT_ADDR"] = "192.168.86.1;192.168.86.2"
        cantiand_cfg["INSTANCE_ID"] = 1
        cantiand_cfg["INTERCONNECT_PORT"] = "1601,1602"
        DefaultConfigValue.GSS_CONFIG["INST_ID"] = 1
        DefaultConfigValue.GSS_CONFIG["INTERCONNECT_PORT"] = "1621,1621"
        DefaultConfigValue.CMS_CONFIG["NODE_ID"] = 1
        return cantiand_cfg, DefaultConfigValue.CMS_CONFIG, DefaultConfigValue.GSS_CONFIG


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
        stdout, stderr = pobj.communicate(cmd.encode())
        stdout = stdout.decode()
        stderr = stderr.decode()
    else:
        stdout, stderr = pobj.communicate(cmd)

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
    i = 0
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

    CURRENT_OS = platform.system()
    if CURRENT_OS == "Linux":
        for i in range(0, path_len):
            char_check = ord(path_type_in[i])
            if(not (a_ascii <= char_check <= z_ascii
                    or A_ascii <= char_check <= Z_ascii
                    or num0_ascii <= char_check <= num9_ascii
                    or char_check == blank_ascii
                    or char_check == sep1_ascii
                    or char_check == sep2_ascii
                    or char_check == sep4_ascii
                    or char_check == sep5_ascii)):
                return False
    elif CURRENT_OS == "Windows":
        for i in range(0, path_len):
            char_check = ord(path_type_in[i])
            if(not (a_ascii <= char_check <= z_ascii
                    or A_ascii <= char_check <= Z_ascii
                    or num0_ascii <= char_check <= num9_ascii
                    or char_check == blank_ascii
                    or char_check == sep1_ascii
                    or char_check == sep2_ascii
                    or char_check == sep3_ascii
                    or char_check == sep4_ascii)):
                return False
    else:
        print("Error: Can not support this platform.")
        sys.exit(1)
    return True


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
            process.sendLine("exit")
        elif idx == 2:
            process.sendLine('yes')
            idx = process.expect(['Permission denied', 'Last login',
                                  'Password', 'ssh:'], 60)
            if idx == 0:
                failed_ip.append(ip)
            elif idx == 1:
                success_ip.append(ip)
                process.sendLine("exit")
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
        process.sendLine(pw1)
        if pw2:
            self.log("Expect(%s) on: [%s]" % (ip, pw_str))
            process.expect(['Please enter password'])
            self.log("Send(%s) password." % ip)
            process.sendLine(pw2)

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
            process.sendLine("export TMOUT=0")
            self.log("Send(%s): %s" % (cmd, ip))
            process.sendLine(cmd)
            if user:
                if instlist:
                    for inst in instlist:
                        p0 = pdict[str(ip)+"_"+inst][0]
                        p1 = pdict[str(ip)+"_"+inst][1]
                        self.__interactive_input(process, ip, p0, p1)
                else:
                    self.__interactive_input(process, ip, user[1], user[2])

            self.log("Expect(%s) on: [Done, Upgrade Failed]" % ip)
            idx = process.expect(['Done', 'Upgrade Failed'], timeout=51200)
            if idx == 0:
                self.log("Expect(%s) received Done." % ip)
                process.sendLine('exit')
                return [ip, ('0', str(process.context_before))]
            self.log("Expect(%s) received Upgrade Failed." % ip)
            process.sendLine('exit')
            return [ip, ('1', str(process.context_buffer))]
        except (TimeoutException, EOFException) as err:
            self.log("Expect(%s) timeout." % ip)
            if process:
                process.sendLine('exit')
            return [ip, ('1', str(err)+'\n'+str(process.context_buffer))]

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
        except KeyboardInterrupt:
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
        for rs in result:
            if str(rs[1][0]) != '0':
                ret_code = 1
                failed_node.append(rs)
            success_node.append(rs)
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

            process.sendLine(ctsql)
            if passwd:
                process.expect(['Please enter password'])
                process.sendLine(passwd)
            process.expect(['SQL>'])
            process.sendLine(sql)
            idx = process.expect(['rows fetched', 'Succeed', 'CT-', 'SQL>'],
                                 timeout=600)
            if idx == 0 or idx == 1:
                process.sendLine('exit')
                return [ip, ('0', str(process.context_before))]
            process.sendLine('exit')
            return [ip, '1', str(process.context_buffer)]
        except (TimeoutException, EOFException):
            if process:
                process.sendLine('exit')
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

    def __init__(self, command, timeout=1800, maxReadSize=4096,
                 delimiter=None):

        self.matcher = None
        self.context_before = None
        self.context_after = None
        self.match = None
        self.matchIndex = None
        # flag for process terminate
        self.is_terminated = True
        self.eofFlag = False
        self.childPid = None
        self.childFd = -1
        self.timeout = timeout
        self.delimiter = delimiter if delimiter else EOFException
        self.maxReadSize = maxReadSize
        self.context_buffer = self.STRING_TYPE()
        self.sendDelay = 0.05
        self.closeDelay = 0.1
        self.terminateDelay = 0.1
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
                fp = sys.__stdin__.fileno()
                self._INTR = ord(termios.tcgetattr(fp)[6][VINTR])
                self._EOF = ord(termios.tcgetattr(fp)[6][VEOF])
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
            except Exception:
                pass

    def __str__(self):
        s = list()
        s.append('%r' % self)
        s.append('after: %r' % self.context_after)
        s.append('pid: %s' % str(self.childPid))
        s.append('child_fd: %s' % str(self.childFd))
        s.append('closed: %s' % str(self.is_closed))
        s.append('timeout: %s' % str(self.timeout))
        s.append('delimiter: %s' % str(self.delimiter))
        s.append('maxReadSize: %s' % str(self.maxReadSize))
        return '\n'.join(s)

    def _excute(self, command):
        self.args = shlex.split(command)

        if self.childPid is not None:
            raise ExpectException('The pid member must be None.')

        if self.command is None:
            raise ExpectException('The command member must not be None.')

        try:
            self.childPid, self.childFd = pty.fork()
        except OSError as err:  # pragma: no cover
            raise ExpectException('pty.fork() failed: ' + str(err))

        if self.childPid == pty.CHILD:
            # child
            self.childFd = pty.STDIN_FILENO
            try:
                self.setWinSize(24, 80)
            except IOError as e:
                if e.args[0] not in (errno.EINVAL, errno.ENOTTY):
                    raise

            self.setEcho(False)
            # close the handle
            maxFdNumber = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
            os.closerange(3, maxFdNumber)

            signal.signal(signal.SIGHUP, signal.SIG_IGN)
            # execute command in child process
            exec_popen(self.command)

        # parent
        try:
            self.setWinSize(24, 80)
        except IOError as e:
            if e.args[0] not in (errno.EINVAL, errno.ENOTTY):
                raise

        self.is_terminated = False
        self.is_closed = False

    def fileno(self):
        return self.childFd

    def close(self):
        if self.is_closed:
            return
        os.close(self.childFd)
        # give kernel time to update process status.
        time.sleep(self.closeDelay)
        if self.isAlive() and not self.terminate():
            raise ExpectException('Could not terminate the child.')
        self.childFd = -1
        self.is_closed = True

    def setEcho(self, state):
        err_msg = ('method setEcho() may not be available on'
                   ' this operating system.')

        try:
            child_attr = termios.tcgetattr(self.childFd)
        except termios.error as e:
            if e.args[0] == errno.EINVAL:
                raise IOError(e.args[0], '%s: %s.' % (e.args[1], err_msg))
            raise

        if state:
            child_attr[3] = child_attr[3] | termios.ECHO
        else:
            child_attr[3] = child_attr[3] & ~termios.ECHO

        try:
            termios.tcsetattr(self.childFd, termios.TCSANOW, child_attr)
        except IOError as e:
            if e.args[0] == errno.EINVAL:
                raise IOError(e.args[0], '%s: %s.' % (e.args[1], err_msg))
            raise

    def readNonBlock(self, size=1, timeout=-1):
        if self.is_closed:
            raise ValueError('I/O operation on closed file.')

        if timeout == -1:
            timeout = self.timeout

        if not self.isAlive():
            # if timeout is 0, means "poll"
            rfds, _, _ = self.__select([self.childFd], [], [], 0)
            if not rfds:
                self.eofFlag = True
                raise EOFException('End Of File (EOF). Braindead platform.')

        rfds, _, _ = self.__select([self.childFd], [], [], timeout)

        if not rfds:
            if not self.isAlive():
                self.eofFlag = True
                raise EOFException('Reach end of File (EOF).')
            else:
                raise TimeoutException('Timeout exceeded.')

        if self.childFd in rfds:
            try:
                child_data = os.read(self.childFd, size)
            except OSError as e:
                if e.args[0] == errno.EIO:
                    self.eofFlag = True
                    raise EOFException('Reach End Of File (EOF). '
                                       'Exception style platform.')
                raise
            if child_data == b'':
                self.eofFlag = True
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
        time.sleep(self.sendDelay)
        content = self._utf8(content)
        return self._send(content)

    def _send(self, content):
        return os.write(self.childFd, content)

    def sendLine(self, content=''):
        sendCount = self.send(content)
        sendCount = sendCount + self.send(self.LINE_SEPERATOR)
        return sendCount

    def terminate(self):
        if not self.isAlive():
            return True
        try:
            self.kill(signal.SIGHUP)
            time.sleep(self.terminateDelay)
            if not self.isAlive():
                return True
            self.kill(signal.SIGCONT)
            time.sleep(self.terminateDelay)
            if not self.isAlive():
                return True
            self.kill(signal.SIGINT)
            time.sleep(self.terminateDelay)
            if not self.isAlive():
                return True
            self.kill(signal.SIGKILL)
            time.sleep(self.terminateDelay)
            if not self.isAlive():
                return True
            else:
                return False
        except OSError:
            time.sleep(self.terminateDelay)

            return False if self.isAlive() else True

    def isAlive(self):
        if self.is_terminated:
            return False

        waitpidOptions = 0 if self.eofFlag else os.WNOHANG
        try:
            childPid, childStatus = os.waitpid(self.childPid, waitpidOptions)
        except OSError as e:
            # No child processes
            if e.errno == errno.ECHILD:
                raise ExpectException('process already not exist.')
            else:
                raise e

        if childPid == 0:
            try:
                childPid, childStatus = os.waitpid(self.childPid,
                                                   waitpidOptions)
            except OSError as err:
                # pragma: no cover
                if err.errno == errno.ECHILD:
                    raise ExpectException('process already not exist.')
                else:
                    raise

            if childPid == 0:
                return True

        if childPid == 0:
            return True

        if os.WIFEXITED(childStatus) or os.WIFSIGNALED(childStatus):
            self.is_terminated = True
        elif os.WIFSTOPPED(childStatus):
            raise ExpectException('process already been stopped.')

        return False

    def kill(self, sig):
        if self.isAlive():
            try:
                os.kill(self.childPid, sig)
            except OSError as e:
                # No such process
                if e.errno == 3:
                    pass
                else:
                    raise

    def raisePatternTypeError(self, pattern):
        raise TypeError(
            'got %s as pattern, must be one'
            ' of: %s, pexpect.EOFException, pexpect.TIMEOUTException'
            % (type(pattern), ', '.join([str(ast) for ast in
                                         self.ALLOWED_STRING_TYPES])))

    def compilePatternList(self, pattern_list):
        if not pattern_list:
            return []
        if not isinstance(pattern_list, list):
            pattern_list = [pattern_list]

        patternList = []
        for _, pattern in enumerate(pattern_list):
            if isinstance(pattern, self.ALLOWED_STRING_TYPES):
                pattern = self._ascii(pattern)
                patternList.append(re.compile(pattern, re.DOTALL))
            elif pattern is EOFException:
                patternList.append(EOFException)
            elif pattern is TimeoutException:
                patternList.append(TimeoutException)
            elif isinstance(pattern, type(re.compile(''))):
                patternList.append(pattern)
            else:
                self.raisePatternTypeError(pattern)
        return patternList

    def expect(self, pattern, timeout=-1):
        patternList = self.compilePatternList(pattern)
        return self.expectList(patternList, timeout)

    def expectList(self, patternList, timeout=-1):
        return self.loopExpect(RESearcher(patternList), timeout)

    def loopExpect(self, re_searcher, timeout=-1):
        self.matcher = re_searcher
        if timeout == -1:
            timeout = self.timeout
        if timeout is not None:
            endTime = time.time() + timeout

        try:
            context_buffer = self.context_buffer
            while True:
                matchIndex = re_searcher.search(context_buffer)
                if matchIndex > -1:
                    self.context_buffer = context_buffer[re_searcher.end:]
                    self.context_before = context_buffer[: re_searcher.start]
                    self.context_after = context_buffer[re_searcher.start:
                                                        re_searcher.end]
                    self.context_match = re_searcher.context_match
                    self.matchIndex = matchIndex
                    return self.matchIndex
                # no match at this point
                if (timeout is not None) and (timeout < 0):
                    raise TimeoutException('Timeout exceeded in loopExpect().')
                # not timed out, continue read
                more_context = self.readNonBlock(self.maxReadSize, timeout)
                time.sleep(0.0001)
                context_buffer += more_context
                if timeout is not None:
                    timeout = endTime - time.time()
        except EOFException as err:
            self.context_buffer = self.STRING_TYPE()
            self.context_before = context_buffer
            self.context_after = EOFException
            matchIndex = re_searcher.eof_index
            if matchIndex > -1:
                self.context_match = EOFException
                self.matchIndex = matchIndex
                return self.matchIndex
            else:
                self.context_match = None
                self.matchIndex = None
                raise EOFException("%s\n%s" % (str(err), str(self)))
        except TimeoutException as err:
            self.context_buffer = context_buffer
            self.context_before = context_buffer
            self.context_after = TimeoutException
            matchIndex = re_searcher.timeout_index
            if matchIndex > -1:
                self.context_match = TimeoutException
                self.matchIndex = matchIndex
                return self.matchIndex
            else:
                self.context_match = None
                self.matchIndex = None
                raise TimeoutException("%s\n%s" % (str(err), str(self)))
        except Exception:
            self.context_before = context_buffer
            self.context_after = None
            self.context_match = None
            self.matchIndex = None
            raise

    def setWinSize(self, rows, cols):
        win_size = getattr(termios, 'TIOCSWINSZ', -2146929561)
        s_size = struct.pack('HHHH', rows, cols, 0, 0)
        fcntl.ioctl(self.fileno(), win_size, s_size)

    def __select(self, inputs, outputs, errputs, timeout=None):
        if timeout:
            endTime = time.time() + timeout
        while True:
            try:
                return select.select(inputs, outputs, errputs, timeout)
            except select.error as e:
                if e.args[0] == errno.EINTR:
                    if timeout is not None:
                        timeout = endTime - time.time()
                        if timeout < 0:
                            return([], [], [])
                else:
                    raise


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

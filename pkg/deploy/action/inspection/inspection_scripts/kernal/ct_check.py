# !/usr/bin/env python
# -*- coding:utf-8 -*-
# coding: UTF-8

import sys
import subprocess
import os
import platform
import time
import socket
import pwd
import json
import traceback
import re
from abc import abstractmethod

sys.path.append("/opt/cantian/action/cantian")
from cantian_funclib import Execution
from cantian_funclib import get_abs_path

sys.dont_write_bytecode = True

DEFAULT_TIMEOUT = 300

CANTIAND_CONF_NAME = "cantiand.ini"

CURRENT_OS = platform.system()

gPyVersion = platform.python_version()

# Python3 does not support imp module but importlib
# Python2.6.9 and below does not support importlib module but imp
if gPyVersion[0] == "3":
    import importlib

if CURRENT_OS != 'Linux':
    raise ValueError("Error:Check os failed:current os is not linux")


class CheckContext:
    """
    check execution context
    """

    def __init__(self):
        """
        Constructor
        """
        # Initialize the self.clusterInfo variable
        curr_path = os.path.realpath(__file__)
        self.base_path = os.path.join(os.path.split(curr_path)[0], 'inspection')
        self.user = None
        self.support_items = {}
        self.support_scenes = {}
        self.items = []
        self.root_items = []
        self.cluster = None

        self.copyright = True
        self.single_type = True
        self.trust_ok = False
        self.db_user = ""
        self.db_passwd = ""
        self.port = ""
        self.db_addr = ""

        self.nodes = None
        self.remote_nodes = None
        self.local_nodes = None
        self.mpprc = None
        self.check_id = None
        self.app_path = "/opt/cantian/cantian/server/"
        self.data_path = "/mnt/dbdata/local/cantian/tmp/data/"
        self.out_path = None
        self.log_file = None
        self.tmp_path = "/tmp"
        self.passwd_map = {}
        self.cluster_ver = ""


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Exception class
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
class CheckException(Exception):
    '''
    base class of exception
    '''

    def __init__(self, content):
        super(CheckException, self).__init__(self)
        self.code = "CANTIAN-53000"
        self.content = content

    def __str__(self):
        return "[%s]: ERROR: " % self.code + self.content


class CheckNAException(CheckException):
    '''
    NA checkItem exception
    '''

    def __init__(self, item):
        super(CheckNAException, self).__init__(self.__class__.__name__)
        self.code = "CANTIAN-53033"
        self.content = "Check item %s are not needed" % item
        self.content += " at the current node"


class TimeoutException(CheckException):
    '''
    timeout exception
    '''

    def __init__(self, second):
        super(TimeoutException, self).__init__(self.__class__.__name__)
        self.code = "CANTIAN-53028"
        self.content = "Execute timeout. The timeout has been"
        self.content += " set to %d second." % second


def get_current_user():
    '''
    get current user
    '''
    # Get the current user
    return pwd.getpwuid(os.getuid())[0]


def check_legality(parameter_string):
    '''
    Check for illegal characters
    '''
    # the list of invalid characters
    value_check_list = [
        "|", ";", "&", "$", "<", ">", "`", "\\", "'", "\"", "{", "}", "(", ")", "[", "]", "~", "*", "?", "!", "\n", " "
    ]
    # judge illegal characters
    for ch in value_check_list:
        if parameter_string.find(ch) >= 0:
            msg = "the parameter value contains invalid characters: '%s'" % ch
            raise Exception(msg)


class SharedFuncs:
    '''
    defined tools for executing cmd and sql
    '''

    def __init__(self):
        pass

    @staticmethod
    def login_ssh_ex(ip, user, passwd, ssh_sql, db_passwd):
        """
        function : login remote node
        input : String,String,String,int
        output : String
        """
        process = None
        ssh = get_abs_path("ssh")
        try:
            ssh_base = "%s -o NumberOfPasswordPrompts=1 %s@%s" % (ssh, user, ip)
            process = Execution(ssh_base)

            idx = process.expect(['(P|p)assword:'])
            if idx == 0:
                process.sendLine(passwd)
            done_flag = 'ct_check done'
            process.sendLine("%s; echo 'ct_check done'" % ssh_sql)
            escape = 'unicode-escape'
            while True:
                idx = process.expect([done_flag, "Please enter password"],
                                     timeout=50)
                if idx == 0:
                    process.sendLine('exit')
                    status = 0
                    output = str(process.context_before.decode(escape).split(done_flag)[0])
                    break
                elif idx == 1:
                    process.sendLine(db_passwd)
                else:
                    process.sendLine('exit')
                    status = 1
                    output = str(process.context_buffer.decode(escape).split(done_flag)[0])
                    break
        except Exception as err:
            if process:
                process.sendLine('exit')
            status = 1
            output = f"{err}\n{process.context_buffer.decode('unicode-escape').split(done_flag)[0]}"
        return status, output

    @staticmethod
    def get_abs_path(self, _file):
        for _path in os.environ["PATH"].split(':'):
            abs_file = os.path.normpath(os.path.join(_path, _file))
            if os.path.exists(abs_file):
                return 0, abs_file
        return -1, "File not found."

    @staticmethod
    def exec_open(cmd, values=None):
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

        py_version = platform.python_version()
        if py_version[0] == "3":
            pobj.stdin.write(cmd.encode())
            pobj.stdin.write(os.linesep.encode())
            for value in values:
                pobj.stdin.write(value.encode())
                pobj.stdin.write(os.linesep.encode())
            stdout, stderr = pobj.communicate(timeout=100)
            stdout = stdout.decode()
            stderr = stderr.decode()
        else:
            pobj.stdin.write(cmd)
            pobj.stdin.write(os.linesep)
            for value in values:
                pobj.stdin.write(value)
                pobj.stdin.write(os.linesep)
            stdout, stderr = pobj.communicate(timeout=100)

        if stdout[-1:] == os.linesep:
            stdout = stdout[:-1]
        if stderr[-1:] == os.linesep:
            stderr = stderr[:-1]

        return pobj.returncode, stdout, stderr

    @staticmethod
    def process_command_output(array, stderrdata, stdoutdata):
        for state in array:
            state_str = stdoutdata.strip("").strip("\n")
            state_str = state_str.split("\n")[-1].strip().split()[state]
            state_int = int(state_str)

            if state_int:
                state_out = stdoutdata.strip().strip("\n")
                state_out = "".join(state_out.split("\n")[:-1])
                return state_int, state_out + stderrdata
        # no exception return
        result = stdoutdata.strip("").strip("\n").split("\n")[:-1]
        return 0, "\n".join(result)

    def run_shell_cmd(self, cmd, user=None, mpprc_file="", array=(0,)):
        '''
        defined tools for cmd
        '''
        if not isinstance(array, tuple):
            return -1, "parameter [array] is illegal"

        for state in array:
            if not isinstance(state, int):
                return -1, "parameter [array] is illegal"

        # prevent parameter anomalies
        if max(array) > len(cmd.split("|")) - 1:
            return -1, "parameter [array] is illegal"

        if (mpprc_file):
            cmd = "source '%s'; %s" % (mpprc_file, cmd)

        cmd = cmd + "; echo ${PIPESTATUS[*]}"
        # change user but can not be root user
        if (user and user != get_current_user()):
            cmd = "su -s /bin/bash - %s -c 'source ~/.bashrc; %s'" % (user, cmd)

        returncode, stdout, stderr = self.exec_open(cmd)
        output = stdout + stderr
        status = returncode

        if not status:
            # all states executed are displayed in normal output
            status, output = SharedFuncs.process_command_output(array, stderr, stdout)
            return status, output

        else:
            # overall state abnormality
            return status, output

    def run_sql_cmd(self, *args):
        """
        function : Execute sql command
        input : String,String,String,int
        output : String
        """
        sql, db_user, db_passwd, db_addr, port, app_path = args
        if not db_passwd:
            return 1, "CantianDB 100 V300R001"

        ctsql_path = os.path.join(app_path, "bin")
        sql_cmd = "source ~/.bashrc && echo -e %s| %s/ctsql %s@%s:%s -q -c \"%s\"" % (db_passwd, ctsql_path,
                                                                                      db_user,
                                                                                      db_addr,
                                                                                      port,
                                                                                      sql)
        returncode, stdout, stderr = self.exec_open(sql_cmd)
        output = stdout + stderr
        return returncode, output

    def get_sql_result(self, *args):
        '''
        get records of sql output
        success:state, {'records':[[list1], [list2]], "title":[list_title]}
        failed: state, string_errormsg
        '''
        sql, db_user, db_passwd, db_addr, port, app_path = args
        params = [sql, db_user, db_passwd, db_addr, port, app_path]
        status, output = self.run_sql_cmd(*params)
        if not status:
            if "CT-" in output:
                status = -1
                return status, output.split("\n")[2]
            result_records = {"title": [], "records": []}
            result_list = [line for line in output.split("\n") if line]
            num_records = int(re.findall(r"(\d+) rows fetched.", output)[0])
            end_index = result_list.index(f"{num_records} rows fetched.")
            result_records["title"] = result_list[end_index - 2 - num_records].split()
            for result_line in result_list[end_index - num_records: end_index]:
                result_records["records"].append(result_line.split())
            return status, result_records
        else:
            return status, "\n".join([line for line in output.split("\n") if line])

    def verify_conn(self, *args_):
        '''
        function : get ip type
        input :string, string, string, string, string, string
        output : iptype
        '''
        sql, dbuser, dbpwd, db_addr, port, app_path = args_
        params = [sql, dbuser, dbpwd, db_addr, port, app_path]
        if not (dbuser and dbpwd):
            raise Exception("[ERROR]: Username and password cannot be empty")
        check_legality(dbuser)
        # execute the command to verify the database connection
        status, output = self.run_sql_cmd(params)
        if status:
            raise Exception("[ERROR]: %s" % output)


def get_validity(path, path_desc):
    """
    function: get the validity path
    input : path, description about path
    output: status, message
    """
    real_path = os.path.realpath(path)
    if not os.path.exists(real_path):
        raise Exception("The %s %s is not exists." % (path_desc, real_path))
    if not os.path.isdir(real_path):
        raise Exception("The %s %s is not directory type." % (path_desc, real_path))
    return real_path


class ResultStatus(object):
    '''
    define result status
    '''
    OK = "OK"
    NA = "NA"
    WARNING = "WARNING"
    NG = "FAILED"
    ERROR = "ERROR"


class LocalItemResult(object):
    '''
    the check result running on one host
    '''

    def __init__(self, name, host):
        self.name = name
        self.host = host
        self.raw = ""
        self.sug = ""
        self.epv = ""
        self.des = ""
        self.rst = ResultStatus.NA
        self.val = ""
        self.check_id = None
        self.user = None

    def output(self, out_path):
        """
        format output
        """
        output_doc = (
            "[HOST       ]   {host}\n"
            "[NAME       ]   {name}\n"
            "[RESULT     ]   {rst}\n"
            "[VALUE      ]\n"
            "             {val}\n"
            "[EXPECT     ]\n"
            "             {epv}\n"
            "[DESCRIPT_EN]\n"
            "             {des}\n"
            "[SUGGEST    ]\n"
            "             {sug}\n"
            "[REFER      ]\n"
            "             {raw}\n"

        )
        val = self.val if self.val else ""
        raw = self.raw if self.raw else ""
        try:
            content = output_doc.format(name=self.name,
                                        rst=self.rst,
                                        host=self.host,
                                        val=val,
                                        epv=self.epv,
                                        des=self.des,
                                        sug=self.sug,
                                        raw=raw)
        except Exception:
            output_utf8 = output_doc.encode('utf-8')
            content = output_utf8.format(name=self.name,
                                         rst=self.rst,
                                         host=self.host,
                                         val=val,
                                         epv=self.epv,
                                         des=self.des,
                                         sug=self.sug,
                                         raw=raw.decode('utf-8'))
        return content

    def to_json(self):
        detail_result = {
            "data": {
                "RESULT": self.rst,
                "HOST": self.host,
                "VALUE": json.loads(self.val),
                "EXPECT": self.epv,
                "SUGGEST": self.sug,
                "DESCRIPT_EN": self.des,
                "REFER": [raw.strip() for raw in self.raw.split("\n") if raw]
            },
            "error": {
                "code": 0,
                "description": ""
            }
        }
        if (self.rst == ResultStatus.NA):
            rst = "\033[0;37m%s\033[0m" % "NONE"
        elif (self.rst == ResultStatus.WARNING or
              self.rst == ResultStatus.ERROR or
              self.rst == ResultStatus.NG):
            rst = "\033[0;31m%s\033[0m" % self.rst
        else:
            rst = "\033[0;32m%s\033[0m" % ResultStatus.OK

        val = json.loads(self.val)

        if (self.rst == ResultStatus.NG):
            detail_result["error"]["code"] = 1
            detail_result["error"]["description"] = \
                "{} is failed, expect val: {} current val: {}".format(self.des, self.epv, val)
        elif (self.rst == ResultStatus.ERROR):
            detail_result["error"]["code"] = -1
            detail_result["error"]["description"] = "{} is failed, error msg: \"{}\"".format(self.des, val["except"])

        json_dump = json.dumps(detail_result, ensure_ascii=False, indent=2)
        print(json_dump)


class BaseItem(object):
    '''
    base class of check item
    '''

    def __init__(self, name):
        '''
        Constructor
        '''
        self.name = name
        self.title = None
        self.suggestion = None
        self.epv = ""
        self.time = int(time.time())
        self.standard = None
        self.threshold = {}
        self.category = 'other'
        self.permission = 'user'
        self.analysis = 'default'
        self.scope = 'all'
        self.cluster = None
        self.user = None
        self.nodes = None
        self.remote_nodes = None
        self.local_nodes = None
        self.mpprc_file = None
        self.context = None
        self.tmp_path = None
        self.out_path = None
        self.app_path = None
        self.data_path = None
        self.single_type = True
        self.trust_ok = False
        self.passwd_map = {}
        self.copyright = True
        self.host = socket.gethostname()
        self.result = LocalItemResult(name, self.host)
        curr_path = os.path.realpath(__file__)

    @abstractmethod
    def do_check(self):
        '''
        check script for each item
        '''
        pass

    def init_form(self, context):
        '''
        initialize the check item from context
        '''
        self.context = context
        self.user = context.user
        self.nodes = context.nodes
        self.remote_nodes = context.remote_nodes
        self.local_nodes = context.local_nodes
        self.single_type = context.single_type
        self.trust_ok = context.trust_ok
        self.passwd_map = context.passwd_map
        self.copyright = context.copyright
        self.result.check_id = context.check_id
        self.result.user = context.user
        self.app_path = context.app_path
        self.data_path = context.data_path
        self.tmp_path = context.tmp_path
        self.out_path = context.out_path

        self.result.sug = self.suggestion
        self.result.epv = self.epv
        self.result.des = self.title
        # new host without cluster installed
        if (not self.user):
            self.host = socket.gethostname()
            self.result.host = socket.gethostname()

    def get_cmd_result(self, cmd, user=None):
        '''
        get cmd result
        '''
        if not user:
            user = self.user
        status, output = SharedFuncs().run_shell_cmd(cmd, user)
        return status, output

    def get_sql_result(self, sql):
        '''
        get sql result
        '''
        if self.context.port:
            status, output = SharedFuncs().get_sql_result(sql,
                                                          self.context.db_user,
                                                          self.context.db_passwd,
                                                          self.context.db_addr,
                                                          self.context.port,
                                                          self.context.app_path)
            return status, output
        else:
            return "-1", "miss parameter [-P]"

    def run_check(self, context, logger):
        '''
        main process for checking
        '''
        content = ""
        except_val = {}
        self.init_form(context)
        try:
            # Perform the inspection
            logger.info(f"Start to run {self.name}")
            self.do_check()
            logger.info(f"finish to run {self.name}")
        except CheckNAException:
            self.result.rst = ResultStatus.NA
        # An internal error occurred while executing code
        except Exception as e:
            except_val["except"] = str(e)
            self.result.rst = ResultStatus.ERROR
            self.result.val = json.dumps(except_val)
            logger.error("Exception occur when running %s:\n%s:traceback%s", self.name, str(e),
                         traceback.format_exc())
        finally:
            # output result
            content = self.result.output(context.out_path)
            self.result.to_json()
        return content


class ItemResult(object):
    '''
    inspection inspection framework
    '''

    def __init__(self, name):
        self.name = name
        self._items = []
        self.rst = ResultStatus.NA
        self.standard = ""
        self.suggestion = ""
        self.epv = ""
        self.des = ""
        self.category = 'other'
        self.analysis = ""

    def __iter__(self):
        '''
        make iterable
        '''
        return iter(self._items)

    def __getitem__(self, idx):
        '''
        get item
        '''
        return self._items[idx]

    @staticmethod
    def parse(output):
        '''
        parse output
        '''
        item_result = None
        local_item_result = None
        lines = output.splitlines()
        host = None

        for idx, line in enumerate(lines):
            if idx == len(lines) and local_item_result is not None:
                item_result.append(local_item_result)
            line = line.strip()
            if not line:
                continue

            if line.startswith('[HOST       ]'):
                host = line.split()[-1]
            if line.startswith('[NAME       ]'):
                name = line.split()[-1]
                if item_result is None:
                    item_result = ItemResult(name)
                else:
                    item_result.append(local_item_result)
                local_item_result = LocalItemResult(name, host)
            if line.startswith('[RESULT     ]'):
                local_item_result.rst = line.split()[-1]

            value = ItemResult.__parse_multi_line(lines, idx)
            if line.startswith('[VALUE      ]'):
                local_item_result.val = value
            if line.startswith('[EXPECT     ]'):
                local_item_result.epv = value
            if line.startswith('[DESCRIPT_EN]'):
                local_item_result.des = value
            if line.startswith('[SUGGEST    ]'):
                local_item_result.sug = value
            if line.startswith('[REFER      ]'):
                local_item_result.raw = value

        return item_result

    @staticmethod
    def __parse_multi_line(lines, start_idx):
        '''
        parse line by line
        '''
        vals = []
        starter = (
            '[HOST       ]', '[NAME       ]', '[RESULT     ]', '[VALUE      ]', '[REFER      ]', '[EXPECT     ]',
            '[DESCRIPT_EN]', '[SUGGEST    ]'
        )
        for line in lines[start_idx + 1:]:
            if line.strip().startswith(starter):
                break
            else:
                vals.append(line.strip())
        return "\n".join(vals)

    def append(self, val):
        '''
        append item
        '''
        self._items.append(val)

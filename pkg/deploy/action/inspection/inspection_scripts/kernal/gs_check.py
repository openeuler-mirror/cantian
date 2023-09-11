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
    print("Error:Check os failed:current os is not linux")
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
        self.code = "GAUSS-53000"
        self.content = content

    def __str__(self):
        return "[%s]: ERROR: " % self.code + self.content


class CheckNAException(CheckException):
    '''
    NA checkItem exception
    '''
    def __init__(self, item):
        super(CheckNAException, self).__init__(self.__class__.__name__)
        self.code = "GAUSS-53033"
        self.content = "Check item %s are not needed" % item
        self.content += " at the current node"


class TimeoutException(CheckException):
    '''
    timeout exception
    '''
    def __init__(self, second):
        super(TimeoutException, self).__init__(self.__class__.__name__)
        self.code = "GAUSS-53028"
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
    value_check_list = ["|", ";", "&", "$", "<", ">", "`", "\\", "'", "\"",
                        "{", "}", "(", ")", "[", "]", "~", "*",
                        "?", "!", "\n", " "]
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
    def run_shell_cmd(cmd, user=None, mpprc_file="", array=(0,)):
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
            cmd = "su - %s -c 'source ~/.bashrc; %s'" % (user, cmd)

        # execute cmd
        p = subprocess.Popen(['bash', '-c', cmd],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)

        # get normal and abnormal output
        (stdoutdata, stderrdata) = p.communicate()
        # get the overall execution status
        status = p.returncode

        if gPyVersion[0] == "3":
            '''
            python3's Popen returned Byte
            python2's Popen returned str
            convert to str if python3
            '''
            stdoutdata = stdoutdata.decode()
            stderrdata = stderrdata.decode()

        if not status:
            # all states executed are displayed in normal output
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

        else:
            # overall state abnormality
            return status, stdoutdata + stderrdata

    def get_abs_path(self, _file):
        for _path in os.environ["PATH"].split(':'):
            abs_file = os.path.normpath(os.path.join(_path, _file))
            if os.path.exists(abs_file):
                return abs_file
        return ""

    def run_sql_cmd(self, sql, db_user, db_passwd, db_addr, port, app_path):
        """
        function : Execute sql command
        input : String,String,String,int
        output : String
        """
        if not db_passwd:
            return 1, "CANTIAN V300R001"

        zsql_path = os.path.join(app_path, "bin")
        sql_cmd = "%s/ctclient %s@%s:%s -q -c \"%s\"" % (zsql_path,
                                                    db_user,
                                                    db_addr,
                                                    port,
                                                    sql)

        if gPyVersion[0] == "3":
            sql_cmd = sql_cmd.encode()

        p = subprocess.Popen(['bash', '-c', sql_cmd],
                             shell=False,
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)

        db_passwd += "\n"

        if gPyVersion[0] == "3":
            db_passwd = db_passwd.encode()

        p.stdin.write(db_passwd)

        (stdoutdata, stderrdata) = p.communicate()
        output_data = stdoutdata + stderrdata
        output = ""
        if gPyVersion[0] == "3":
            output = output_data.decode()

        return p.returncode, output

    def login_ssh_ex(self, ip, user, passwd, ssh_sql, db_passwd, timeout=0):
        """
        function : login remote node
        input : String,String,String,int
        output : String
        """
        process = None
        ssh = get_abs_path("ssh")
        try:
            ssh_base = "%s -o NumberOfPasswordPrompts=1 %s@%s" % (ssh,
                                                                  user,
                                                                  ip)
            process = Execution(ssh_base)

            idx = process.expect(['(P|p)assword:'])
            if idx == 0:
                process.sendLine(passwd)
            done_flag = 'gs_check done'
            process.sendLine("%s; echo 'gs_check done'" % ssh_sql)
            escape = 'unicode-escape'
            while True:
                idx = process.expect([done_flag, "Please enter password"],
                                     timeout=50)
                if idx == 0:
                    process.sendLine('exit')
                    status = 0
                    output = str(process.context_before.decode(escape))
                    output = output.split(done_flag)[0]
                    break
                elif idx == 1:
                    process.sendLine(db_passwd)
                else:
                    process.sendLine('exit')
                    status = 1
                    context_buffer = process.context_buffer.decode(escape)
                    output = str(context_buffer).split(done_flag)[0]
                    break
        except Exception as err:
            if process:
                process.sendLine('exit')
            status = 1
            output = str(err)
            output += os.linesep
            context_buffer = process.context_buffer.decode('unicode-escape')
            output += context_buffer.split(done_flag)[0]
        return status, output

    def get_sql_result(self, sql, db_user, db_passwd, db_addr, port, app_path):
        '''
        get records of sql output
        success:state, {'records':[[list1], [list2]], "title":[list_title]}
        failed: state, string_errormsg
        '''
        status, output = self.run_sql_cmd(sql,
                                        db_user,
                                        db_passwd,
                                        db_addr,
                                        port,
                                        app_path)
        if not status:
            if (output.find("CT-") != -1) :
                status = -1
                return status, output.split("\n")[2]
            result_records = {"title": [], "records": []}
            result_list = [_f for _f in output.split("\n") if _f]
            end_num = -1
            begin_num = end_num - int(result_list[end_num].split()[0])
            result_records["title"] = result_list[begin_num - 2].split()
            for reslut_line in result_list[begin_num:end_num]:
                result_records["records"].append(reslut_line.split())
            return status, result_records
        else:
            return status, "\n".join([_f for _f in output.split("\n") if _f])

    def verify_conn(self, sql, dbuser, dbpwd, db_addr, port, app_path):
        '''
        function : get ip type
        input :string, string, string, string, string, string
        output : iptype
        '''
        if not (dbuser and dbpwd):
            raise Exception("[ERROR]: Username and password cannot be empty")
        check_legality(dbuser)
        # execute the command to verify the database connection
        status, output = self.run_sql_cmd(sql,
                                        dbuser,
                                        dbpwd,
                                        db_addr,
                                        port,
                                        app_path)
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
        raise Exception("The %s %s is not directory type." % (path_desc,
                                                              real_path))
    return real_path


def __print_on_screen(msg):
    """
    function: print message on screen
    """
    print(msg)


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
        output_doc = """
[HOST       ]   {host}
[NAME       ]   {name}
[RESULT     ]   {rst}
[VALUE      ]
             {val}
[EXPECT     ]
             {epv}
[DESCRIPT_EN]
             {des}
[SUGGEST    ]
             {sug}
[REFER      ]
             {raw}
        """
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
        detail_result = {}
        detail_result["data"] = {}
        detail_result["error"] = {}
        detail_result["error"]["code"] = 0
        detail_result["error"]["description"] = ""
        if (self.rst == ResultStatus.NA):
            rst = "\033[0;37m%s\033[0m" % "NONE"
        elif (self.rst == ResultStatus.WARNING or
                self.rst == ResultStatus.ERROR or
                self.rst == ResultStatus.NG):
            rst = "\033[0;31m%s\033[0m" % self.rst
        else:
            rst = "\033[0;32m%s\033[0m" % ResultStatus.OK

        detail_result["data"]["RESULT"] = self.rst
        # because of the python version of the problem, you need to
        # deal with the character format separately
        detail_result["data"]["HOST"] = self.host
        val = json.loads(self.val)

        # modify the encoding format to utf-8
        detail_result["data"]["VALUE"] = val
        detail_result["data"]["EXPECT"] = self.epv
        detail_result["data"]["SUGGEST"] = self.sug
        detail_result["data"]["DESCRIPT_EN"] = self.des
        detail_result["data"]["REFER"] = []
        for raw in self.raw.split("\n"):
            self.add_refer(raw, detail_result["data"]["REFER"])
        if (self.rst == ResultStatus.NG) :
            detail_result["error"]["code"] = 1
            detail_result["error"]["description"] = \
                "{} is failed, expect val: {} current val: {}".format(self.des, self.epv, val)
        elif (self.rst == ResultStatus.ERROR) :
            detail_result["error"]["code"] = -1
            detail_result["error"]["description"] = "{} is failed, error msg: \"{}\"".format(self.des, val["except"])

        json_dump = json.dumps(detail_result, ensure_ascii=False, indent=2)
        print(json_dump)

    def add_refer(self, raw, refer_l):
        """
        append raw to refer
        """
        if raw:
            refer_l.append(raw.strip())


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
            return "-1", "miss prameter [-P]"

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
        except Exception:
            except_val["except"] = str(Exception)
            self.result.rst = ResultStatus.ERROR
            self.result.val = json.dumps(except_val)
            logger.error("Exception occur when running {}:\n{}".format(self.name, str(Exception)))
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

    def append(self, val):
        '''
        append item
        '''
        self._items.append(val)

    @staticmethod
    def parse(output):
        '''
        parse output
        '''
        item_result = None
        local_item_result = None
        host = None
        idx = 0
        for line in output.splitlines():
            idx += 1
            if (idx == len(output.splitlines()) and
                    local_item_result is not None):
                item_result.append(local_item_result)
            current = line.strip()
            if (not current):
                continue
            if (current.startswith('[HOST       ]')):
                host = current.split()[-1].strip()
            if (current.startswith('[NAME       ]')):
                name = current.split()[-1].strip()
                if (item_result is None):
                    item_result = ItemResult(name)
                if (local_item_result is not None):
                    item_result.append(local_item_result)
                local_item_result = LocalItemResult(current.split()[-1].strip(),
                                                  host)
            if (current.startswith('[RESULT     ]')):
                local_item_result.rst = current.split()[-1].strip()
            if (current.startswith('[VALUE      ]')):
                value = ItemResult.__parse_multi_line(output.splitlines()[idx:])
                local_item_result.val = value
            if (current.startswith('[EXPECT     ]')):
                exp = ItemResult.__parse_multi_line(output.splitlines()[idx:])
                local_item_result.epv = exp
            if (current.startswith('[DESCRIPT_EN]')):
                des_en = ItemResult.__parse_multi_line(output.splitlines()[idx:])
                local_item_result.des = des_en
            if (current.startswith('[SUGGEST    ]')):
                sug = ItemResult.__parse_multi_line(output.splitlines()[idx:])
                local_item_result.sug = sug
            if (current.startswith('[REFER      ]')):
                refer = ItemResult.__parse_multi_line(output.splitlines()[idx:])
                local_item_result.raw = refer
        return item_result

    @staticmethod
    def __parse_multi_line(lines):
        '''
        parse line by line
        '''
        vals = []
        starter = ('[HOST       ]', '[NAME       ]', '[RESULT     ]',
                   '[VALUE      ]', '[REFER      ]', '[EXPECT     ]',
                   '[DESCRIPT_EN]', '[SUGGEST    ]')
        for line in lines:
            current = line.strip()
            if (current.startswith(starter)):
                break
            else:
                vals.append(current)
        return "\n".join(vals)
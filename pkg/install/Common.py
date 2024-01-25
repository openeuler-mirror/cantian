#!/usr/bin/env python
# -*- coding:utf-8 -*-
#############################################################################
# eg "Copyright (c): 2012-2017, Huawei Tech. Co., Ltd."
# eg "FileName     : Common.py"
# eg "Version      :"
# eg "Date         :"
# eg "Description  : Common is a utility with a lot of common functions"
#############################################################################


import sys
sys.dont_write_bytecode = True

try:
    import os
    import platform
    import re
    import subprocess
except ImportError as err:
    sys.exit("Unable to import module: %s." % str(err))


class DefaultValue(object):
    """
    Default value of some variables
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
    CANTIAND_CONF_NAME = "cantiand.ini"
    DOCKER_SHARE_DIR = "/home/regress/cantian_data"
    DOCKER_DATA_DIR = "{}/data".format(DOCKER_SHARE_DIR)
    DOCKER_GCC_DIR = "{}/gcc_home".format(DOCKER_SHARE_DIR)
    
    # get os version and python version
    CURRENT_OS = platform.system()
    PY_VERSION = platform.python_version()

    @staticmethod
    def getTopPathNotExist(topDirPath):
        """
        function : Get the top path if exist
        input : String
        output : String
        """
        tmpDir = os.path.realpath(topDirPath)
        DefaultValue.checkInvalidPath(tmpDir)
        if not tmpDir:
            print("The path is null.")
            sys.exit(1)
        while True:
            # find the top path to be created
            (tmpDir, topDirName) = os.path.split(tmpDir)
            if (os.path.exists(tmpDir) or topDirName == ""):
                tmpDir = os.path.join(tmpDir, topDirName)
                break
        return tmpDir

    @staticmethod
    def cleanTmpFile(path, fp=None):
        """
        function : close and remove temporary file
        input : String,file
        output : NA
        """
        if path:
            path = os.path.realpath(path)
            DefaultValue.checkInvalidPath(path)
        # close the file if file handle is not None
        if fp:
            fp.close()
        if path and os.path.exists(path):
            os.remove(path)

    @staticmethod
    def checkInvalidPath(path):
        """
        function:check the path is invalid
        input:path
        output:NA
        """
        if not path.strip():
            print("The path is null.")
            sys.exit(1)
        # -w:match [A-Z] [a-z] [0-9] '_'
        pattern = r"^[\w\./:\- ]*$"
        if not re.match(pattern, path):
            print("The path is invalid: " + path)
            sys.exit(1)

    @staticmethod
    def exec_popen(cmd, stdin_list=None):
        """
        subprocess.Popen in python2 and 3.
        input: command will be execute
        return: return code, stdout, stderr
        """
        bash_cmd = ["bash"]
        if not stdin_list:
            stdin_list = []
        pobj = subprocess.Popen(bash_cmd, shell=False, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # in python 3, the stand output and stand error is
        # unicode, we must decode it before return
        if DefaultValue.PY_VERSION[0] == "3":
            pobj.stdin.write(cmd.encode())
            pobj.stdin.write(os.linesep.encode())
            for value in stdin_list:
                pobj.stdin.write(value.encode())
                pobj.stdin.write(os.linesep.encode())
            stdout, stderr = pobj.communicate()
            stdout = stdout.decode()
            stderr = stderr.decode()
        else:
            pobj.stdin.write(cmd)
            pobj.stdin.write(os.linesep)
            for value in stdin_list:
                pobj.stdin.write(value)
                pobj.stdin.write(os.linesep)
            stdout, stderr = pobj.communicate()

        if stdout[-1:] == os.linesep:
            stdout = stdout[:-1]
        if stderr[-1:] == os.linesep:
            stderr = stderr[:-1]

        return pobj.returncode, stdout, stderr

    @staticmethod
    def get_input(msg):
        """
        get user input from stdin
        input: prompt message
        return: user input string
        """
        # raw_input is removed in python 3, it provide
        # input function as a safe method to get user
        # input message
        if DefaultValue.PY_VERSION[0] == "3":
            return input(msg)
        return raw_input(msg)

    @staticmethod
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

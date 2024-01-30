#!/usr/bin/env python
# coding: UTF-8
import json
import os
import subprocess
import sys
sys.path.append('/mf_connector/inspection')
from log_tool import setup
from common_func import _exec_popen


class DiskSpaceCheck():

    def __init__(self):
        self.result_json = {
            'data': {},
            'error': {
                'code': 0,
                'description': ''
            }
        }

    @staticmethod
    def get_cmd_res(cmd):
        status, output, _ = _exec_popen(cmd)
        return status, output

    def pwd_check(self, logger):
        cmd_pwd = '/docker-entrypoint-initdb.d/encrypt -d $MYSQL_AGENT_PASSWORD'
        pwd_code, pwd = self.get_cmd_res(cmd_pwd)
        if pwd_code == 0:
            return pwd
        else:
            logger.error("can not get password")
            self.result_json["error"]["code"] = -1
            self.result_json['error']['description'] = pwd
            return self.result_json

    def dir_check(self, logger):
        temp = self.pwd_check(logger)
        if isinstance(temp, dict):
            return temp
        password = temp.strip()
        cmd_dir = "mysql -uRDS_agent -p" + password + ''' -e"show global variables like 'datadir';"'''
        datadir_code, res = self.get_cmd_res(cmd_dir)
        if datadir_code == 0:
            return res
        else:
            logger.error("can not get data directory")
            self.result_json["error"]["code"] = -1
            self.result_json['error']['description'] = res
            return self.result_json

    def diskspace_check(self, logger):
        logger.info("disk spaces check start!")
        dirc = self.dir_check(logger)
        if isinstance(dirc, dict):
            return dirc
        datadir = dirc.split()[-1].strip()
        cmd = "df -h " + datadir
        code, value = self.get_cmd_res(cmd)
        if code == 0:
            use_space = value.split()[-2].replace("%", "")
            if int(use_space) < 90:
                self.result_json["error"]["code"] = 0
                self.result_json["error"]["description"] = ""
                self.result_json["data"]["RESULT"] = ' the used disk space are less than 90%, succ!'
                logger.info("the remaining disk spaces check succ!")
                return self.result_json
            else:
                logger.error("the remaining spaces are less than 10%")
                self.result_json["error"]["code"] = -1
                self.result_json['error']['description'] = "the remaining spaces are less than 10% "
                return self.result_json
        else:
            logger.error("can not get the disk spaces info")
            self.result_json["error"]["code"] = -1
            self.result_json['error']['description'] = value
            return self.result_json


if __name__ == '__main__':
    mysql_log = setup("mysql")
    ds = DiskSpaceCheck()
    result_json = ds.diskspace_check(mysql_log)
    print(json.dumps(result_json, indent=1))

#!/usr/bin/env python
# coding: UTF-8
import json
import os
import subprocess
import sys
sys.path.append('/mf_connector/inspection')
from log_tool import setup
from inspection_scripts.mysql.mysql_diskspace_check import DiskSpaceCheck


class ConnectionCheck():

    def __init__(self):
        self.result_json = {
            'data': {},
            'error': {
                'code': 0,
                'description': ''
            }
        }

    def connection_check(self, logger):
        logger.info("connection check start!")
        password = DiskSpaceCheck().pwd_check(logger)
        if isinstance(password, dict):
            return password
        cmd = "mysql -uRDS_agent -p" + password + ''' -e"show engines;"'''
        status, output = DiskSpaceCheck().get_cmd_res(cmd)
        if status:
            logger.error("can not get engines information")
            self.result_json["error"]["code"] = -1
            self.result_json['error']['description'] = output
        else:
            res = output.split("\n")
            res = res[1:]
            lines = [line.split("\t") for line in res]
            for line in lines:
                if line[0] == "CTC" and line[1] == "DEFAULT":
                    self.result_json["data"]["RESULT"] = 'check connection succ!'
                    logger.info("check connection succ!")
                    break
            else:
                logger.error("the connection check failed")
                self.result_json["error"]["code"] = -1
                self.result_json['error']['description'] = "the connection check failed, CTC is not default"
            return self.result_json
        return self.result_json


if __name__ == '__main__':
    mysql_log = setup("mysql")
    cn = ConnectionCheck()
    result_json = cn.connection_check(mysql_log)
    print(json.dumps(result_json, indent=1))


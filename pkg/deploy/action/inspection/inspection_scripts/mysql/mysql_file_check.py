#!/usr/bin/env python
# coding: UTF-8
import json
import os
import subprocess
import sys
sys.path.append('/mf_connector/inspection')
from log_tool import setup


class SharedFileCheck():

    def __init__(self):
        self.path = "/dev/shm/"
        self.shm_list = [
            "cantian.0", "cantian.1", "cantian.2", "cantian.3", "cantian.4", "cantian.5", "cantian.6",
            "cantian.7", "cantian.8", "cantian.shm_unix_sock", "cantian_shm_config_0.txt",
            "cantian_shm_config_1.txt"
        ]
        self.result_json = {
            'data': {},
            'error': {
                'code': 0,
                'description': ''
            }
        }

    def file_check(self, logger):
        myfile = []
        for i in self.shm_list:
            if os.path.exists(self.path + i) is True:
                myfile.append(i)
            else:
                logger.error("there are some files missed")
                self.result_json["error"]["code"] = -1
                self.result_json['error']['description'] = "not all shm files exist"
                break
        return myfile

    def uid_check(self, logger):
        uid = []
        myfile = self.file_check(logger)
        if myfile != self.shm_list:
            return self.result_json
        for i in myfile:
            # 合法uid是6000， gid是5000
            if os.stat(self.path + i)[4] == 6000 and \
                    os.stat(self.path + i)[5] == 5000:
                uid.append(i)
            else:
                logger.error("not all uid of shm files are 5000")
                self.result_json["error"]["code"] = -1
                self.result_json['error']['description'] = "not all uid of shm files are 5000 "
                break
        return uid

    def rights_check(self, logger):
        logger.info("check shm files start")
        rights = []
        uid = self.uid_check(logger)
        if uid != self.shm_list:
            return self.result_json
        for i in uid:
            if (os.access(self.path + i, os.R_OK) is True) and (os.access(self.path + i, os.W_OK) is True):
                rights.append(i)
            else:
                logger.error("user does not have right to read or write")
                self.result_json["error"]["code"] = -1
                self.result_json['error']['description'] = "not all files can be read and written"
                break
        if rights == self.shm_list:
            self.result_json["data"]["RESULT"] = 'check shm files succ!'
        return self.result_json

if __name__ == '__main__':
    mysql_log = setup("mysql")
    sf = SharedFileCheck()
    result_json = sf.rights_check(mysql_log)
    print(json.dumps(result_json, indent=1))
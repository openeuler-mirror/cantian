#!/usr/bin/env python
# coding: UTF-8
import json
import os
import sys
sys.path.append('/mf_connector/inspection')
from log_tool import setup
from inspection_scripts.mysql.mysql_diskspace_check import DiskSpaceCheck


class TransactionIsolationCheck():

    def __init__(self):
        self.result_json = {
            'data': {},
            'error': {
                'code': 0,
                'description': ''
            }
        }

    def transaction_isolation_check(self, logger):
        logger.info("transaction isolation level check start!")
        password = DiskSpaceCheck().pwd_check(logger)
        if isinstance(password, dict):
            self.result_json['error']['description'] = "Password is a dictionary."
            return self.result_json
        cmd = "mysql -uRDS_agent -p" + password + ''' -e"show variables like 'transaction_isolation';"'''
        status, output = DiskSpaceCheck().get_cmd_res(cmd)
        if status:
            logger.error("can not get transaction isolation information")
            self.result_json["error"]["code"] = -1
            self.result_json['error']['description'] = output
        else:
            res = output.split("\n")
            res = res[1:]
            lines = [line.split("\t") for line in res]
            for line in lines:
                if line[0] == "transaction_isolation" and line[1] == "READ-COMMITTED":
                    self.result_json["data"]["RESULT"] = 'check transaction isolation succ!'
                    logger.info("check transaction isolation succeed!")
                    break
            else:
                logger.error("the transaction isolation check failed")
                self.result_json["error"]["code"] = -1
                self.result_json['error']['description'] = \
                    "the transaction isolation check failed, isolation level is not READ-COMMITTED"
        return self.result_json


if __name__ == '__main__':
    mysql_log = setup("mysql")
    cn = TransactionIsolationCheck()
    result_json = cn.transaction_isolation_check(mysql_log)
    print(json.dumps(result_json, indent=1))
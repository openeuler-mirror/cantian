#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import json
import sys
from pathlib import Path
sys.path.append('/opt/cantian/action/inspection')
from log_tool import setup
from common_func import _exec_popen


def parse_cmd_result(cmd_res):
    keys = ['RESOURCE_NAME', 'RESOURCE_TYPE', 'RESOURCE_GROUP_NAME', 'START_TIMEOUT(ms)', 'STOP_TIMEOUT(ms)',
    'CHECK_TIMEOUT(ms)', 'CHECK_INTERVAL(ms)', 'HB_TIMEOUT(ms)']
    values = cmd_res.split()
    stat_json = {}
    for (idx, key) in enumerate(keys):
        stat_json[key] = values[idx]
    res = True
    if stat_json.get('HB_TIMEOUT(ms)') != '10000':
        res = False 
    return (res)


def fetch_cms_hbtime(logger):
    logger.info("cms res check start!")
    cmd = 'source ~/.bashrc && cms res -list | tail -n +2'
    ret_code, output, stderr = _exec_popen(cmd)
    output = output.split('\n')
    if ret_code:
        logger.error("get cms res failed, std_err: %s", stderr)
    result_json = {}
    result_json['data'] = {}
    result_json["error"] = {}
    result_json["error"]["code"] = 0
    result_json["error"]["description"] = ""
    if len(output) < 1:
        result_json["error"]["code"] = -1
        result_json["error"]["description"] = "cms res check error!"
        logger.error("cms res check error!")
        return (result_json)
    for cmd_res in output:
        (res) = parse_cmd_result(cmd_res)
    if res:
        result_json['data']["RESULT"] = 'HB_TIMEOUT is 10 seconds'
    else:
        result_json["error"]["code"] = -1
        result_json['error']["description"] = '[WAR]: HB_TIMEOUT  greater than 10 seconds'
        result_json['data']["RESULT"] = output
    logger.info("cms res check succ!")
    return (result_json)


def fetch_cls_stat():
    # check if user is root
    cantian_log = setup('cantian') 
    if(os.getuid() == 0):
        cantian_log.error("Cannot use root user for this operation!")
        sys.exit(1)
    (result_json) = fetch_cms_hbtime(cantian_log)
    return json.dumps(result_json, indent=1)


if __name__ == '__main__':
    print(fetch_cls_stat())

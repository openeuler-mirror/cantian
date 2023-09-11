#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import json
import sys
from pathlib import Path
sys.path.append('/opt/cantian/action/inspection')
from log_tool import setup
from common_func import _exec_popen


def fetch_cms_version(logger):
    logger.info("cms version check start!")
    cmd = "cms -help"
    ret_code, output, stderr = _exec_popen(cmd)
    if ret_code:
        logger.error("get cms help information failed, std_err: %s", stderr)
    result_json = {}
    result_json['data'] = {}
    result_json["error"] = {}
    result_json["error"]["code"] = 0
    result_json["error"]["description"] = ""
    result_json["data"]["RESULT"] = output
    logger.info("cms version check succ!")
    return (result_json)


def fetch_cls_stat():
    # check if user is root
    cantian_log = setup('cantian') 
    if(os.getuid() == 0):
        cantian_log.error("Cannot use root user for this operation!")
        sys.exit(1)
    (result_json) = fetch_cms_version(cantian_log)
    return json.dumps(result_json, indent=1)


if __name__ == '__main__':
    print(fetch_cls_stat())

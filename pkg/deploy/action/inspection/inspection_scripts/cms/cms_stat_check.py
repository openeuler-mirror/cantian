#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import json
import sys
from pathlib import Path

sys.path.append('/opt/cantian/action/inspection')
from log_tool import setup
from common_func import _exec_popen


def parse_node_stat(node_stat):
    keys = ['NODE_ID', 'NAME', 'STAT', 'PRE_STAT', 'TARGET_STAT', 'WORK_STAT', 'SESSION_ID', 'INSTANCE_ID', 'ROLE']
    values = node_stat.split()
    stat_json = {}
    node_info = {'NODE STAT': 'OFFLINE', 'NODE ROLE': 'NULL'}
    for (idx, key) in enumerate(keys):
        stat_json[key] = values[idx]
    online = False
    reformer = False
    if stat_json.get('STAT') == 'ONLINE':
        online = True
        node_info['NODE STAT'] = 'ONLINE'
    if stat_json.get('ROLE') == 'REFORMER':
        reformer = True
        node_info['NODE ROLE'] = 'REFORMER'
    return online, reformer, node_info


def fetch_cms_stat(logger):
    logger.info("cms stat check start!")
    cmd = 'cms stat | tail -n +2'
    ret_code, output, stderr = _exec_popen(cmd)
    output = output.split('\n')
    if ret_code:
        logger.error("get cms res information failed, std_err: %s", stderr)
    cluster_stat = {}
    result_json = {}
    result_json['data'] = {}
    result_json["error"] = {}
    result_json["error"]["code"] = 0
    result_json["error"]["description"] = ""
    if len(output) <= 1:
        result_json["error"]["code"] = -1
        logger.error("cms stat check error!")
        return result_json
    online_cnt = 0
    refomer_stat = False
    detail_json = []
    for node_stat in output:
        (online, reformer, node_info) = parse_node_stat(node_stat)
        detail_json.append(node_info)
        if online:
            online_cnt += 1
        if reformer:
            refomer_stat = True
    if online_cnt == len(output) and refomer_stat is True:
        result_json['data']['RESULT'] = 'CLUSTER STAT NORMAL'
    else:
        result_json['data']['RESULT'] = '[WAR] CLUSTER STAT ABNORMAL'
    detail_json.append(cluster_stat)
    result_json['data']['DETAIL'] = detail_json
    logger.info("cms stat check succ!")
    return result_json


def fetch_cls_stat():
    # check if user is root
    cantian_log = setup('cantian')
    if os.getuid() == 0:
        cantian_log.error("Cannot use root user for this operation!")
        sys.exit(1)
    (result_json) = fetch_cms_stat(cantian_log)
    return json.dumps(result_json, indent=1)


if __name__ == '__main__':
    print(fetch_cls_stat())

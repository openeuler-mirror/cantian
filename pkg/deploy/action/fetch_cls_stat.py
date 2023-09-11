#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import json
import subprocess
import platform
from pathlib import Path

CONFIG_PATH = "/opt/cantian/config/deploy_param.json"


def _exec_popen(cmd, values=None):
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


def get_user():
    config_path = Path(CONFIG_PATH)
    config_list = json.loads(config_path.read_text())
    return config_list["deploy_user"].split(':')[0]


def parse_node_stat(node_stat):
    keys = ['NODE_ID', 'NAME', 'STAT', 'PRE_STAT']
    values = node_stat.split()
    stat_json = {}
    for (idx, key) in enumerate(keys):
        stat_json[key] = values[idx]
    online = False
    if stat_json.get('STAT') == 'ONLINE':
        online = True
    return online, stat_json


def fetch_cms_stat():
    user = get_user()
    cmd = 'su - %s -c "cms stat" | tail -n +2' % user
    _, output, _ = _exec_popen(cmd)
    output = output.split('\n')
    cms_stat_json = {}
    if len(output) <= 1:
        return (False, cms_stat_json)
    online_cnt = 0
    detail_json = []
    for node_stat in output:
        (online, stat_json) = parse_node_stat(node_stat)
        detail_json.append(stat_json)
        if online:
            online_cnt += 1
    cms_stat_json['DETAIL'] = detail_json
    if online_cnt == 0:
        cms_stat_json['STATUS'] = 'OFFLINE'
    elif online_cnt == len(output):
        cms_stat_json['STATUS'] = 'ONLINE'
    else:
        cms_stat_json['STATUS'] = 'PARTIALLY_ONLINE'
    return (True, cms_stat_json)


def gen_fault_result():
    result_json = {}
    result_json['RESULT'] = -1
    return json.dumps(result_json)


def fetch_cls_stat():
    (success, cms_stat_json) = fetch_cms_stat()
    if not success:
        return gen_fault_result()
    status_json = {}
    status_json['CMS_STAT'] = cms_stat_json
    status_json['RESULT'] = 0
    return json.dumps(status_json)


if __name__ == '__main__':
    print(fetch_cls_stat())

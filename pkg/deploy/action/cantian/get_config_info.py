# -*- coding: UTF-8 -*-
import sys
import os
import json
from pathlib import Path

INSTALL_SCPRIT_DIR = os.path.dirname(os.path.abspath(__file__))
PKG_DIR = os.path.abspath(os.path.join(INSTALL_SCPRIT_DIR, "../.."))

CONFIG_PARAMS_FILE = os.path.join(PKG_DIR, "config", "deploy_param.json")
CANTIAN_CONFIG_PARAMS_FILE = os.path.join(PKG_DIR, "action", "cantian", "cantian_config.json")
CANTIAN_CONFIG_PARAMS_FILE_BACKUP = "/opt/cantian/backup/files/cantian/cantian_config.json"
CANTIAN_START_STATUS_FILE = os.path.join("/opt/cantian/cantian", "cfg", "start_status.json")
info = {}

with open(CONFIG_PARAMS_FILE, encoding="utf-8") as f:
    _tmp = f.read()
    info = json.loads(_tmp)

if os.path.exists(CANTIAN_CONFIG_PARAMS_FILE_BACKUP):
    with open(CANTIAN_CONFIG_PARAMS_FILE_BACKUP, encoding="utf-8") as f:
        _tmp_cantian = f.read()
        info_cantian = json.loads(_tmp_cantian)

if os.path.exists(CANTIAN_START_STATUS_FILE):
    with open(CANTIAN_START_STATUS_FILE, encoding="utf-8") as f:
        _tmp_cantian = f.read()
        info_cantian_start = json.loads(_tmp_cantian)


def get_value():
    param = sys.argv[1]
    
    if param == 'in_container':
        return info.get('in_container', 0)
    if param == 'SYS_PASSWORD':
        return info_cantian.get('SYS_PASSWORD', "")
    if param == "deploy_user":
        user_and_group = info.get('deploy_user', "")
        user = user_and_group.split(':')[0]
        return user
    if param == "deploy_group":
        user_and_group = info.get('deploy_user', "")
        group = user_and_group.split(':')[1]
        return group
    if param == 'CANTIAN_START_STATUS':
        return info_cantian_start.get('start_status', "")
    if param == 'CANTIAN_DB_CREATE_STATUS':
        return info_cantian_start.get('db_create_status', "")

    return info.get(param)


if __name__ == "__main__":
    res = get_value()
    print(res)


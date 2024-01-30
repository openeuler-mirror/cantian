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
ENV_FILE = os.path.join(PKG_DIR, "action", "env.sh")
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

with open(ENV_FILE, "r", encoding="utf-8") as f:
    env_config = f.readlines()


def get_value(param):
    if param == "mysql_user":
        return info.get('deploy_user').split(':')[0]
    if param == "mysql_group":
        return info.get('deploy_user').split(':')[1]
    if param == 'cantian_in_container':
        return info.get('cantian_in_container', '0')
    if param == 'SYS_PASSWORD':
        return info_cantian.get('SYS_PASSWORD', "")
    if param == "deploy_user":
        for line in env_config:
            if line.startswith("cantian_user"):
                return line.split("=")[1].strip("\n").strip('"')
    if param == "deploy_group":
        for line in env_config:
            if line.startswith("cantian_group"):
                return line.split("=")[1].strip("\n").strip('"')
    if param == 'CANTIAN_START_STATUS':
        return info_cantian_start.get('start_status', "")
    if param == 'CANTIAN_DB_CREATE_STATUS':
        return info_cantian_start.get('db_create_status', "")
    if param == 'CANTIAN_EVER_START':
        return info_cantian_start.get('ever_started', "")

    return info.get(param)


if __name__ == "__main__":
    _param = sys.argv[1]
    res = get_value(_param)
    print(res)


# -*- coding: UTF-8 -*-
import sys
import os
import json

INSTALL_SCPRIT_DIR = os.path.dirname(os.path.abspath(__file__))
PKG_DIR = os.path.abspath(os.path.join(INSTALL_SCPRIT_DIR, "../.."))
INSTALL_CONFIG_FILE = os.path.join(INSTALL_SCPRIT_DIR, "../cantian/install_config.json")
CONFIG_PARAMS_FILE = os.path.join(PKG_DIR, "config", "deploy_param.json")
ENV_FILE = os.path.join(PKG_DIR, "action", "env.sh")
info = {}

with open(CONFIG_PARAMS_FILE, encoding="utf-8") as f:
    _tmp = f.read()
    info = json.loads(_tmp)


with open(ENV_FILE, "r", encoding="utf-8") as f:
    env_config = f.readlines()


with open(INSTALL_CONFIG_FILE, "r", encoding="utf-8") as f:
    install_config = json.loads(f.read())


def get_value(param):
    if param == "deploy_user":
        for line in env_config:
            if line.startswith("cantian_user"):
                return line.split("=")[1].strip("\n").strip('"')
    if param == "deploy_group":
        for line in env_config:
            if line.startswith("cantian_group"):
                return line.split("=")[1].strip("\n").strip('"')
    if param == "M_RUNING_MODE":
        return install_config.get("M_RUNING_MODE")

    return info.get(param, "")


if __name__ == "__main__":
    _param = sys.argv[1]
    res = get_value(_param)
    print(res)

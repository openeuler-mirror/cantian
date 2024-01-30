# -*- coding: UTF-8 -*-
import re
import sys
import os
import json
from pathlib import Path

CUR_PATH = os.path.dirname(os.path.realpath(__file__))
INSTALL_FILE = str(Path(os.path.join(CUR_PATH, "../config/deploy_param.json")))
ENV_FILE = str(Path(os.path.join(CUR_PATH, "env.sh")))

info = {}

with open(INSTALL_FILE, encoding="utf-8") as f:
    _tmp = f.read()
    info = json.loads(_tmp)

with open(ENV_FILE, encoding="utf-8") as f:
    env_info = f.read()


def get_value(param):

    # deploy_user 格式为：用户:用户组
    if param == 'deploy_user':
        return info.get('deploy_user').split(':')[0]

    if param == 'deploy_group':
        return info.get('deploy_user').split(':')[1]

    if param == "cluster_scale":
        return len(info.get("cms_ip").split(";"))

    return info.get(param)


def get_env_info(key):
    pattern = rf'{key}="(.+?)"'
    match = re.search(pattern, env_info)
    return match.group(1)


if __name__ == "__main__":
    _param = sys.argv[1]
    if _param == "share_random_seed":
        SHARE_PATH = get_value("storage_share_fs")
        SHARE_FILE = f"/mnt/dbdata/remote/share_{SHARE_PATH}/deploy_param.json"
        share_info = {}
        if os.path.exists(SHARE_FILE):
            with open(SHARE_FILE, encoding="utf-8") as f:
                _tmp = f.read()
                share_info = json.loads(_tmp)
        print(share_info.get("random_seed"))
    else:
        res = get_value(_param)
        print(res)

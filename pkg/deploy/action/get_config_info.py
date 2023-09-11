# -*- coding: UTF-8 -*-
import sys
import os
import json
from pathlib import Path

CUR_PATH = os.path.dirname(os.path.realpath(__file__))
INSTALL_FILE = str(Path(os.path.join(CUR_PATH, "../config/deploy_param.json")))

info = {}

with open(INSTALL_FILE, encoding="utf-8") as f:
    _tmp = f.read()
    info = json.loads(_tmp)


def get_value():
    param = sys.argv[1]

    # deploy_user 格式为：用户:用户组
    if param == 'deploy_user':
        return info.get('deploy_user').split(':')[0]

    if param == 'deploy_group':
        return info.get('deploy_user').split(':')[1]

    return info.get(param)


if __name__ == "__main__":
    res = get_value()
    print(res)

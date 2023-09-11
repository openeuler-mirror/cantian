import json
import os
import sys
import stat
from pathlib import Path

CUR_PATH = os.path.dirname(os.path.realpath(__file__))
INSTALL_FILE = str(Path(os.path.join(CUR_PATH, "../config/deploy_param.json")))


def read_install_file():
    with open(INSTALL_FILE, 'r', encoding='utf8') as file_path:
        _tmp = file_path.read()
        info = json.loads(_tmp)
        return info


def write_install_file(write_data):
    modes = stat.S_IRWXU | stat.S_IROTH | stat.S_IRGRP
    flag = os.O_RDWR | os.O_CREAT | os.O_TRUNC
    with os.fdopen(os.open(INSTALL_FILE, flag, modes), 'w') as file_path:
        config_params = json.dumps(write_data, indent=4)
        file_path.write(config_params)


if __name__ == '__main__':
    config_key = sys.argv[1]
    config_value = sys.argv[2]
    install_file_data = read_install_file()
    install_file_data[config_key] = config_value
    write_install_file(install_file_data)

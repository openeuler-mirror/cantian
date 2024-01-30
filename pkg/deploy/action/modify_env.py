import json
import sys
import os
import pathlib
import re
import stat
 
 
CUR_PATH = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CUR_PATH, "../"))
 
ENV_FILE = str(pathlib.Path(os.path.join(CUR_PATH, "env.sh")))
CANTIAN_CONFIG = str(pathlib.Path(os.path.join(CUR_PATH, "cantian/install_config.json")))
 
 
def read_file(file_path):
    with open(file_path, 'r', encoding='utf8') as file_path:
        return file_path.read()
 
 
def write_file(write_data, file_path):
    modes = stat.S_IRWXU | stat.S_IROTH | stat.S_IRGRP
    flag = os.O_RDWR | os.O_CREAT | os.O_TRUNC
    with os.fdopen(os.open(file_path, flag, modes), 'w') as file_path:
        file_path.write(write_data)
 
 
def modify_env():
    data = read_file(ENV_FILE)
    new_data = ""
    for line in data.split("\n"):
        new_line = line
        pattern_dbstor = r'"dbstor"'
        pattern_logicrep = r'"logicrep"'
        if "dbstor" in new_line:
            new_line = re.sub(pattern_dbstor, "", line)
        if "logicrep" in new_line:
            new_line = re.sub(pattern_logicrep, "", new_line)
        new_data += new_line + "\n"
    write_file(new_data, ENV_FILE)
 
 
def modify_cantian_config():
    data = json.loads(read_file(CANTIAN_CONFIG))
    if "USE_DBSTORE" in data.keys():
        del data["USE_DBSTORE"]
    data = json.dumps(data, indent=4)
    write_file(data, CANTIAN_CONFIG)
 
 
if __name__ == "__main__":
    modify_env()
    modify_cantian_config()
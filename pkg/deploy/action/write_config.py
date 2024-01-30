import json
import os
import sys
import stat
from pathlib import Path

CUR_PATH = os.path.dirname(os.path.realpath(__file__))
INSTALL_FILE = str(Path(os.path.join(CUR_PATH, "../config/deploy_param.json")))
CHIFFRE_P2 = """10iipPlcwfO+bbn65asichtNGrR8QP6VtNXPe4vpBzSWYLmU8OWNjUcBpY0N/AyE
qEh0EDraErMsEE1VwBQACI4AAUwCBEQD3bISGqSCG0AM0KQyc999un0muibVUzJk
PMsl2JHFEYBBO0RVDYQHwYQACMABE8QHVNgBLAz/BEwAwUABT0RVDYADwQrAJz13
37eSb6KuVRNnQ+wwWancUAoFwgBBj0RVDYwHwsFMdNaAAEwACU4EhKrwSxNxVdvY
11u4PpQB35TWlKBzbu6yFPTBd3EiaWfgXL+eXhzmPZN8A/f6JgFzemfazt7fZl6n
ZCrwpMpZbx2Hh8Hjsc5PGnJnYY1HS18mCOvywPn+sWVFYpcxCnKx76XdttkmHOg3
0LFX+grYBbMkLy8IoLbu7pcXsa1y8rhRsXYn7Sfpz99FgYTyC5J4xHxozSMe+Ji/
coK0LP6xJEoeF0H1lKxUWeHIxpl0x3QZ3D4Htxg4eDi6zyknXoFczbhUGOWIuKBc
FT1ZdzdWycB5pknuP6nP5DwH9nQoRIyC0TyzsHj3jlym1886lifGgL/Gz3xutGea
JVViGOl8yXdK5nFdBq+Oj4KDE5FMensDnZm0HZIyDxm9e2foOmHBYAKZN5novclj"""


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

import glob
import os
import re
import stat
import json
import grp
import configparser
import subprocess
import argparse
from pathlib import Path
import sys
import traceback
import getpass


DEPLOY_CONFIG = "/opt/cantian/config/deploy_param.json"
CUR_PATH = os.path.dirname(os.path.realpath(__file__))
ENV_FILE = str(Path(os.path.join(CUR_PATH, "env.sh")))


def _exec_popen(cmd, values=None):
    """
    subprocess.Popen in python2 and 3.
    :param cmd: commands need to execute
    :return: status code, standard output, error output
    """
    if not values:
        values = []
    bash_cmd = ["bash"]
    pobj = subprocess.Popen(bash_cmd, shell=False, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    pobj.stdin.write(cmd.encode())
    pobj.stdin.write(os.linesep.encode())
    for value in values:
        pobj.stdin.write(value.encode())
        pobj.stdin.write(os.linesep.encode())
    try:
        stdout, stderr = pobj.communicate(timeout=1800)
    except subprocess.TimeoutExpired as err_cmd:
        pobj.kill()
        return -1, "Time Out.", str(err_cmd)
    stdout = stdout.decode()
    stderr = stderr.decode()
    if stdout[-1:] == os.linesep:
        stdout = stdout[:-1]
    if stderr[-1:] == os.linesep:
        stderr = stderr[:-1]

    return pobj.returncode, stdout, stderr


def get_ctencrypt_passwd(passwd):
    file_path = "/opt/cantian/action/cantian/install_config.json"
    flags = os.O_RDONLY
    modes = stat.S_IWUSR | stat.S_IRUSR
    with os.fdopen(os.open(file_path, flags, modes), 'r') as fp:
        json_data = json.load(fp)
        install_path = json_data['R_INSTALL_PATH'].strip()
    cmd = "source ~/.bashrc && %s/bin/ctencrypt -e PBKDF2" % install_path
    values = [passwd, passwd]
    ret_code, stdout, stderr = _exec_popen(cmd, values)
    if ret_code:
        raise OSError("Failed to encrypt password of user [sys]."
                      " Error: %s" % (stderr + os.linesep + stderr))
    # Example of output:
    # Please enter password to encrypt:
    # *********
    # Please input password again:
    # *********
    # eg 'Cipher:         XXXXXXXXXXXXXXXXXXXXXXX'
    lines = stdout.split(os.linesep)
    cipher = lines[4].split(":")[1].strip()
    return cipher


def get_env_info(key):
    with open(ENV_FILE, encoding="utf-8") as _file:
        env_info = _file.read()
    pattern = rf'{key}="(.+?)"'
    match = re.search(pattern, env_info)
    return match.group(1)


def modify_ini_file(file_path, section, option, action, value=None):
    config = configparser.ConfigParser()
    config.optionxform = str
    config.read(file_path)
    if action == "add":
        if section in config:
            config[section][option] = value
        else:
            config[section] = {option: value}
    else:
        if section in config:
            if option in config[section]:
                config.remove_option(section, option)
    flags = os.O_CREAT | os.O_RDWR
    modes = stat.S_IWUSR | stat.S_IRUSR
    try:
        with os.fdopen(os.open(file_path, flags, modes), "w") as file_obj:
            config.write(file_obj)
    except Exception as error:
        raise error


def read_deploy_conf(file_path=DEPLOY_CONFIG):
    with open(file_path, "r") as f:
        return json.loads(f.read())


def write_config_file(file_path, content):
    flags = os.O_RDWR | os.O_CREAT | os.O_TRUNC
    modes = stat.S_IRWXU | stat.S_IROTH | stat.S_IRGRP
    with os.fdopen(os.open(file_path, flags, modes), "w") as file_obj:
        file_obj.write(json.dumps(content))


def update_dbstore_conf(action, key, value=None):
    file_list = [
        "/mnt/dbdata/local/cantian/tmp/data/dbstor/conf/dbs/dbstor_config.ini",
        "/opt/cantian/dbstor/conf/dbs/dbstor_config.ini",
        "/opt/cantian/dbstor/tools/dbstor_config.ini",
        "/opt/cantian/cms/dbstor/conf/dbs/dbstor_config.ini"
    ]
    opt_dbstore_config = "/opt/cantian/dbstor/tools/dbstor_config.ini"
    file_list.append(opt_dbstore_config)
    for file_path in file_list:
        if not os.path.exists(file_path):
            continue
        section = "CLIENT"
        modify_ini_file(file_path, section, key, action, value=value)


def update_cantian_conf(action, key, value):
    file_path = "/opt/cantian/cantian/cfg/cantian_config.json"
    config = read_deploy_conf(file_path=file_path)
    config["USER"] = "cantian"
    config["GROUP"] = "cantian"
    config["USER_HOME"] = "/home/cantian"
    write_config_file(file_path, config)


def update_cms_conf(action, key, value):
    deploy_config = read_deploy_conf()
    file_path = "/opt/cantian/cms/cfg/cms.json"
    if key == "cms_reserve":
        file_path = "/opt/cantian/backup/files/cms.json"
    config = read_deploy_conf(file_path=file_path)
    config["user"] = get_env_info("cantian_user")
    config["group"] = get_env_info("cantian_group")
    config["user_profile"] = "/home/cantian/.bashrc"
    config["user_home"] = "/home/cantian"
    config["share_logic_ip"] = deploy_config.get("share_logic_ip")
    write_config_file(file_path, config)


def update_ini_conf(file_path, action, key, value):
    with open(file_path, "r", encoding="utf-8") as fp:
        config = fp.readlines()
    for i, item in enumerate(config):
        if key in item:
            if action == "update":
                config[i] = f"{key} = {value}\n"
            break
    if action == "add" and key not in str(config):
        config.append(f"{key} = {value}\n")
    flags = os.O_CREAT | os.O_RDWR | os.O_TRUNC
    modes = stat.S_IWUSR | stat.S_IRUSR
    with os.fdopen(os.open(file_path, flags, modes), "w") as file_obj:
        file_obj.writelines(config)


def update_cantian_ini_conf(action, key, value):
    file_path = "/mnt/dbdata/local/cantian/tmp/data/cfg/cantiand.ini"
    update_ini_conf(file_path, action, key, value)


def update_cms_ini_conf(action, key, value):
    file_path = "/opt/cantian/cms/cfg/cms.ini"
    update_ini_conf(file_path, action, key, value)


def update_ctsql_config(action, key, value):
    ctsql_passwd = input()
    encrypt_passwd = get_ctencrypt_passwd(ctsql_passwd)
    update_cmd = f'source ~/.bashrc && echo -e {ctsql_passwd} | ctsql sys@127.0.0.1:1611 -q -c ' \
                 f'"alter system set _sys_password=\'{encrypt_passwd}\'"'
    ret_code, stdout, stderr = _exec_popen(update_cmd)
    stderr = str(stderr)
    stderr.replace(ctsql_passwd, "****")
    if ret_code:
        raise OSError("Failed to encrypt password of user [sys]."
                      " Error: %s" % (stderr + os.linesep + stderr))
    if "Succeed" not in stdout:
        raise Exception("Update ctsql _sys_passwd failed")


def update_ctsql_passwd(action, key, value):
    def _check_passwd():
        check_cmd = f'source ~/.bashrc && echo -e {ctsql_passwd} | ctsql sys@127.0.0.1:1611 -q -c ' \
                    '"select version();"'
        ret_code, stdout, stderr = _exec_popen(check_cmd)
        stderr = str(stderr)
        stderr.replace(ctsql_passwd, "*****")
        if ret_code:
            raise Exception("Check passwd failed, please ensure that the password is entered correctly.")
    file_path = "/opt/cantian/action/cantian/install_config.json"
    with open(file_path, 'r') as fp:
        json_data = json.load(fp)
        data_path = json_data['D_DATA_PATH'].strip()
    sys.path.append(os.path.join(CUR_PATH, "dbstor"))
    from kmc_adapter import CApiWrapper
    primary_keystore = "/opt/cantian/common/config/primary_keystore_bak.ks"
    standby_keystore = "/opt/cantian/common/config/standby_keystore_bak.ks"
    kmc_adapter = CApiWrapper(primary_keystore, standby_keystore)
    kmc_adapter.initialize()
    ctsql_passwd = getpass.getpass("please input new passwd:").strip()
    ctencrypt_passwd = kmc_adapter.encrypt(ctsql_passwd.strip())
    split_env = os.environ['LD_LIBRARY_PATH'].split(":")
    filtered_env = [single_env for single_env in split_env if "/opt/cantian/dbstor/lib" not in single_env]
    os.environ['LD_LIBRARY_PATH'] = ":".join(filtered_env)
    _check_passwd()
    _conf_files = os.path.join(data_path, "cfg", "*sql.ini")
    conf_file = glob.glob(_conf_files)[0]
    with open(conf_file, "r", encoding="utf-8") as fp:
        config = fp.readlines()
    for i, conf in enumerate(config):
        if "SYS_PASSWORD" in conf:
            config[i] = f"SYS_PASSWORD = {ctencrypt_passwd}\n"
    flags = os.O_RDWR | os.O_CREAT | os.O_TRUNC
    modes = stat.S_IRWXU | stat.S_IROTH | stat.S_IRGRP
    with os.fdopen(os.open(conf_file, flags, modes), "w") as file_obj:
        file_obj.writelines(config)


def main():
    update_parse = argparse.ArgumentParser()
    update_parse.add_argument("-c", "--component", dest="component",
                              choices=["dbstore", "cms", "cantian", "cantian_ini", "cms_ini", "ctsql", "ctsql_pwd"],
                              required=True)
    update_parse.add_argument("-a", "--action", dest="action", choices=["del", "add", "update"],
                              required=True)
    update_parse.add_argument("-k", "--key", dest="key", required=True)
    update_parse.add_argument("-v", "--value", dest="value", required=False)
    args = update_parse.parse_args()
    component = args.component
    action = args.action
    key = args.key
    value = args.value
    func_dict = {
        "dbstore": update_dbstore_conf,
        "cantian": update_cantian_conf,
        "cantian_ini": update_cantian_ini_conf,
        "cms": update_cms_conf,
        "cms_ini": update_cms_ini_conf,
        "ctsql": update_ctsql_config,
        "ctsql_pwd": update_ctsql_passwd,
    }
    func_dict.get(component)(action, key, value)


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        exit(str(traceback.format_exc(limit=-1)))

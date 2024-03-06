import stat
import sys
import os
import json

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "dbstor"))
from kmc_adapter import CApiWrapper


def set_mes_passwd(passwd):
    file_path = "/opt/cantian/common/config/certificates/mes.pass"
    flags = os.O_RDWR | os.O_CREAT | os.O_TRUNC
    modes = stat.S_IRWXU | stat.S_IROTH | stat.S_IRGRP
    with os.fdopen(os.open(file_path, flags, modes), "w") as file_obj:
        file_obj.writelines(passwd)


def update_config(file_path, pwd):
    with open(file_path, "r", encoding="utf-8") as fp:
        config = fp.readlines()
    for i, conf in enumerate(config):
        if conf.startswith("_CMS_MES_SSL_KEY_PWD"):
            config[i] = f"_CMS_MES_SSL_KEY_PWD = {pwd}\n"
        if conf.startswith("MES_SSL_KEY_PWD"):
            config[i] = f"MES_SSL_KEY_PWD = {pwd}\n"
    flags = os.O_RDWR | os.O_CREAT | os.O_TRUNC
    modes = stat.S_IRWXU | stat.S_IROTH | stat.S_IRGRP
    with os.fdopen(os.open(file_path, flags, modes), "w") as file_obj:
        file_obj.writelines(config)


def update_mes_key_pwd(plain_text):
    primary_keystore = "/opt/cantian/common/config/primary_keystore_bak.ks"
    standby_keystore = "/opt/cantian/common/config/standby_keystore_bak.ks"
    kmc_adapter = CApiWrapper(primary_keystore, standby_keystore)
    kmc_adapter.initialize()
    try:
        ret_pwd = kmc_adapter.encrypt(plain_text)
    except Exception as error:
        raise Exception("Failed to encrypt password of user [sys]. Error: %s" % str(error)) from error

    cantian_config = "/mnt/dbdata/local/cantian/tmp/data/cfg/cantiand.ini"
    cms_config = "/opt/cantian/cms/cfg/cms.ini"
    update_config(cantian_config, ret_pwd)
    update_config(cms_config, ret_pwd)
    set_mes_passwd(ret_pwd)


if __name__ == "__main__":
    passwd = input()
    action = sys.argv[1]
    options = {
        "update_mes_key_pwd": update_mes_key_pwd
    }
    options.get(action)(passwd.strip())

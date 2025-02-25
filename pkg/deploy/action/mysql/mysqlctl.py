import json
import os
import pathlib
import re
import sys

CUR_PATH = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))

sys.path.append(str(CUR_PATH.parent))
from get_config_info import get_value


INSTALL_PATH = CUR_PATH.parent.parent
INFO_SRC = "/opt/cantian/mysql/install/mysql/docs/INFO_SRC"
CANTIAN_INSTALL_CONFIG = os.path.join(CUR_PATH.parent, "cantian", "install_config.json")
TARGET_VERSION = "1.0.2"


class MysqlCtl(object):
    @staticmethod
    def get_patch_version():
        version = ""
        if os.path.exists(INFO_SRC):
            with open(INFO_SRC, "r") as f:
                content = f.read()
            version = re.findall(r"Cantian patch source ([0-9]+.[0-9]+.[0-9]+)", content)
            if len(version) > 0:
                return version[0]
        return version

    def pre_upgrade(self):
        """
        元数据归一、单进程、canitan多组场景不检查
        """
        with open(CANTIAN_INSTALL_CONFIG, "r") as f:
            install_config = json.load(f)
        single_process = install_config.get("M_RUNING_MODE")
        cantian_in_container = get_value("cantian_in_container")
        mysql_metadata_in_cantian = get_value("mysql_metadata_in_cantian")
        if (cantian_in_container != "0"
                or not mysql_metadata_in_cantian
                or single_process == "cantiand_in_cluster"):
            return
        patch_version = self.get_patch_version()
        if patch_version != TARGET_VERSION:
            err_msg = "Mysql server and Cantian is incompatible, please upgrade mysql server first."
            raise Exception(err_msg)


def main():
    mysql_ctl = MysqlCtl()
    action = sys.argv[1]
    getattr(mysql_ctl, action)()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        exit("[ERROR] " + str(e))

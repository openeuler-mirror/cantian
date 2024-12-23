import os
import pathlib
import re
import sys

CUR_PATH = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))
INSTALL_PATH = CUR_PATH.parent.parent
INFO_SRC = "/opt/cantian/mysql/install/mysql/docs/INFO_SRC"
TARGET_VERSION = "1.0.0"


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

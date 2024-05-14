import sys
import os
import re
from pathlib import Path
from get_config_info import get_value
sys.path.append("..")
from om_log import UPGRADE_VERSION_CHECK_LOGS as LOG

CUR_PATH = os.path.dirname(os.path.realpath(__file__))
METADATA_FS = get_value("storage_metadata_fs")
VERSION_PREFIX = 'Version:'
SUB_VERSION_PREFIX = ('B', 'SP')


class UpgradeVersionCheck:

    def __init__(self):
        self.white_list_file = str(Path(os.path.join(CUR_PATH, "white_list.txt")))
        self.source_version_file = str(Path(os.path.join("/mnt/dbdata/remote/metadata_" + METADATA_FS, "versions.yml")))
        self.white_list_dict = {}
        self.source_version = ''
        self.err = {'read_failed': 'white list or source version read failed',
                    'match_failed': 'source version not in white list',
                    'updata_system_version_failed': 'update system version failed'}

    @staticmethod
    def update_system_version():
        """预留接口，用于更新系统版本号"""
        return True

    @staticmethod
    def execption_handler(err_msg):
        LOG.error(err_msg)
        return 'False {}'.format(err_msg)
    
    def process_white_list(self):
        with open(self.white_list_file, 'r', encoding='utf-8') as file:
            white_list_info = file.readline()

        for white_list_detail in white_list_info[1:]:
            if not white_list_detail.strip():
                continue
            details = white_list_detail.split()
            self.white_list_dict[details[0]] = [details[1], details[2]]

    def read_source_version_info(self):
        version = ''
        with open(self.source_version_file, 'r', encoding='utf-8') as file:
            source_version_info = file.readlines()

        for line in source_version_info:
            if VERSION_PREFIX in line:
                version = line.split()[-1]

        self.source_version = version

    def source_version_check(self):
        for white_list_version, white_list_detail in self.white_list_dict.items():
            *white_main_version, white_sub_version = white_list_version.split('.')
            *source_main_version, source_sub_version = self.source_version.split('.')
            if source_main_version != white_main_version:
                continue

            if white_sub_version == '*' or white_sub_version == source_sub_version:
                if not self.update_system_version():
                    err_msg = 'change system list failed'
                    return self.execption_handler(err_msg)
                return 'True success'

        err_msg = "source version '{}' not in white list.".formate(self.source_version)
        return self.execption_handler(err_msg)

if __name__ == '__main__':
    version_check = UpgradeVersionCheck()
    print(version_check.source_version_check())
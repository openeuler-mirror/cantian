import os
import sys
from pathlib import Path
from string import digits

CUR_PATH = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CUR_PATH, "../"))
from om_log import LOGGER as LOG

VERSION_PREFIX = 'Version:'
SUB_VERSION_PREFIX = ('B', 'SP')


class UpgradeVersionCheck:

    def __init__(self, white_list=None, upgrade_mode=None):
        self.white_list_file = white_list
        self.upgrade_mode = upgrade_mode
        self.source_version_file = str(Path('/opt/cantian/versions.yml'))
        self.white_list_dict = {}  # 格式：{SOURCE-VERSION: [UPGRADE-MODE, CHANGE-SYSTEM]}
        self.source_version = ''

    def process_white_list(self):
        with open(self.white_list_file, 'r', encoding='utf-8') as file:
            white_list_info = file.readlines()

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
        result = ""
        for white_list_version, white_list_detail in self.white_list_dict.items():
            if self.upgrade_mode not in white_list_detail[0]:
                continue
            *white_main_version, white_sub_version = white_list_version.split('.')
            *source_main_version, source_sub_version = self.source_version.split('.')
            if source_main_version != white_main_version:
                continue

            if white_sub_version == '*' or white_sub_version == source_sub_version:
                result = "{} {} {}".format(self.source_version, white_list_detail[0], white_list_detail[1])
                break

            if '-' in white_sub_version:
                min_version, max_version = white_sub_version.split('-')
                trans_map = str.maketrans('', '', digits)
                source_pre_fix = source_sub_version.translate(trans_map)

                if source_pre_fix not in SUB_VERSION_PREFIX:  # 源版本号开头不是B或者SPH返回结果为空
                    break

                sub_version_min_num = min_version.replace(source_pre_fix, '')
                sub_version_max_num = max_version.replace(source_pre_fix, '')
                sub_source_version_num = source_sub_version.replace(source_pre_fix, '')
                if sub_version_min_num.isdigit() \
                        and sub_version_max_num.isdigit() \
                        and int(sub_version_max_num) >= int(sub_source_version_num) >= int(sub_version_min_num):
                    result = "{} {} {}".format(self.source_version, white_list_detail[0], white_list_detail[1])
                    break

        return result


if __name__ == '__main__':
    white_list_input = sys.argv[1]
    upgrade_mode_input = sys.argv[2]
    version_check = UpgradeVersionCheck(white_list_input, upgrade_mode_input)
    try:
        version_check.process_white_list()
    except Exception as err:
        LOG.error('obtain source version white list failed with error: %s', str(err))
        exit('')

    try:
        version_check.read_source_version_info()
    except Exception as err:
        LOG.error('obtain source version failed with error: %s', str(err))
        exit('')
    try:
        print(version_check.source_version_check())
    except Exception as err:
        LOG.error('source version check failed with error: %s', str(err))
        exit('')

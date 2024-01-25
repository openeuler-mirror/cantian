import sys
import os
CUR_PATH = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CUR_PATH, "../"))
from implement.upgrade_version_check import UpgradeVersionCheck
from om_log import LOGGER as LOG


if __name__ == '__main__':
    version_check = UpgradeVersionCheck()
    try:
        version_check.read_source_version_info()
    except Exception as err:
        LOG.error('obtain source version failed with error: %s', str(err))
        exit('')

    print(version_check.source_version)

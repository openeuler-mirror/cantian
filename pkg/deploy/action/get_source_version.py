from upgrade_version_check import UpgradeVersionCheck
from om_log import LOGGER as LOG


if __name__ == '__main__':
    version_check = UpgradeVersionCheck()
    try:
        version_check.read_source_version_info()
    except Exception as err:
        LOG.error(f'obtain source version failed with error: {str(err)}')
        exit('')

    print(version_check.source_version)

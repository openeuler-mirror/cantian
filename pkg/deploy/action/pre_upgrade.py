import sys
import os
import json
from pathlib import Path

from pre_install import CheckInstallConfig
from om_log import LOGGER as LOG

CUR_PATH = os.path.dirname(os.path.realpath(__file__))
NEW_CONFIG_PATH = str(Path(f'{CUR_PATH}/config_params.json'))
SOURCE_CONFIG_PATH = str(Path('/opt/cantian/action/config_params.json'))
NEW_FILE_CONFIG_PATH = str(Path(f'{CUR_PATH}/config_params_file.json'))
SOURCE_FILE_CONFIG_PATH = str(Path('/opt/cantian/action/config_params_file.json'))
DEPLOY_CONFIG = str(Path("/opt/cantian/config/deploy_param.json"))


def read_install_config(config_path):
    try:
        with open(config_path, 'r', encoding='utf8') as file_path:
            json_data = json.load(file_path)
            return json_data
    except Exception as error:
        LOG.error('load %s error, error: %s', config_path, str(error))

    return {}


if __name__ == '__main__':
    # 如果没有指定文件，检查升级包的配置文件中key与源配置文件key是否一致
    if len(sys.argv[:]) == 1:
        deploy_config = read_install_config(DEPLOY_CONFIG)
        deploy_mode = deploy_config.get("deploy_mode", "dbstore")
        if deploy_mode == "nas":
            NEW_CONFIG_PATH = NEW_FILE_CONFIG_PATH
            if os.path.exists(SOURCE_FILE_CONFIG_PATH):
                SOURCE_CONFIG_PATH = SOURCE_FILE_CONFIG_PATH
        new_config_keys = read_install_config(NEW_CONFIG_PATH).keys() - {"install_type", "cantian_in_container",
                                                                         "auto_create_fs"}
        source_config_keys = read_install_config(SOURCE_CONFIG_PATH).keys() - {"install_type", "cantian_in_container",
                                                                               "auto_create_fs"}
        keys_diff = new_config_keys ^ source_config_keys
        if keys_diff:
            LOG.error(f"config keys are different with difference: {keys_diff}")
            sys.exit(1)
        else:
            sys.exit(0)

    CONFIG_PATH = sys.argv[1]
    res = CheckInstallConfig(CONFIG_PATH).get_result()
    if res:
        sys.exit(0)
    else:
        sys.exit(1)

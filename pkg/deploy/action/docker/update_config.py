import os
import json
import re
import sys
CUR_PATH = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CUR_PATH, "../"))
from cantian.get_config_info import get_value
from docker_common.file_utils import read_file, write_file, mkdir
from om_log import LOGGER as LOG

CONFIG_PATH = os.path.join(CUR_PATH, "../../config")
INIT_CONFIG_PATH = os.path.join(CONFIG_PATH, "container_conf/init_conf")
MY_CNF_FILE = "/opt/cantian/image/cantian_connector/cantian-connector-mysql/scripts/my.cnf"
MYSQL_CONFIG_FILE = os.path.join(INIT_CONFIG_PATH, "mysql_config.json")

MYSQL_PARAMS = ["max_connections", "table_open_cache", "table_open_cache_instances"]


def update_my_cnf_with_mem_spec():
    """
    Update predefined MySQL parameters in my.cnf based on mem_spec.
    """
    my_cnf_content = read_file(MY_CNF_FILE)

    my_cnf_content = [line for line in my_cnf_content if line.strip()]

    for param_name in MYSQL_PARAMS:
        param_value = get_value(param_name)
        if param_value:
            updated = False
            for i, line in enumerate(my_cnf_content):
                if re.match(f"^{param_name}=", line):
                    my_cnf_content[i] = f"{param_name}={param_value}\n"
                    updated = True
                    break
            if not updated:
                my_cnf_content.append(f"{param_name}={param_value}\n")
    LOG.info(f"Updated values for mem_spec successfully.")

    write_file(MY_CNF_FILE, my_cnf_content)


def update_my_cnf_with_config():
    """
    Update my.cnf based on the settings in mysql_config.json.
    """
    my_cnf_content = read_file(MY_CNF_FILE)

    # Remove empty lines
    my_cnf_content = [line for line in my_cnf_content if line.strip()]

    if os.path.isfile(MYSQL_CONFIG_FILE):
        LOG.info("mysql_config.json found, updating my.cnf...")
        with open(MYSQL_CONFIG_FILE, "r") as f:
            mysql_config = json.load(f)

        for key, value in mysql_config.items():
            key = key.strip()
            value = value.strip()

            # Check if value is a path or file path
            if os.path.isabs(value):
                try:
                    mkdir(value, permissions=0o750)
                except Exception as e:
                    LOG.error(f"Failed to ensure directory for '{value}': {e}")
                    continue

            if value in ["+add"]:
                if not any(line.strip().startswith(key) for line in my_cnf_content):
                    my_cnf_content.append(f"{key}\n")
                    LOG.info(f"Added '{key}' to my.cnf.")
            elif value in ["-del", "-delete", "-remove"]:
                my_cnf_content = [
                    line for line in my_cnf_content if not line.strip().startswith(key)
                ]
                LOG.info(f"Removed '{key}' from my.cnf.")
            else:
                updated = False
                for i, line in enumerate(my_cnf_content):
                    if re.match(f"^{key}=", line):
                        my_cnf_content[i] = f"{key}={value}\n"
                        updated = True
                        break
                if not updated:
                    my_cnf_content.append(f"{key}={value}\n")
                    LOG.info(f"Added '{key}' with value '{value}' to my.cnf.")

    write_file(MY_CNF_FILE, my_cnf_content)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        LOG.error("Usage: script.py <action>")
        sys.exit(1)

    action = sys.argv[1]

    func_dict = {
        "mem_spec": update_my_cnf_with_mem_spec,
        "mysql_config": update_my_cnf_with_config,
    }

    func = func_dict.get(action)
    if func:
        try:
            func()
        except Exception as e:
            LOG.error(f"An error occurred while executing '{action}': {e}")
            sys.exit(1)
    else:
        LOG.error(f"Invalid action '{action}'. Available options: {', '.join(func_dict.keys())}")
        sys.exit(1)
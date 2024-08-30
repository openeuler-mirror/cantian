import os
import json
import stat
import sys
CUR_PATH = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CUR_PATH, ".."))
from om_log import LOGGER as LOG
dir_name, _ = os.path.split(os.path.abspath(__file__))


def parse_policy_config_file():
    policy_path = os.path.join(dir_name, "../deploy_policy_config.json")
    try:
        with open(policy_path, 'r', encoding='utf8') as file_path:
            json_data = json.load(file_path)
            return json_data
    except Exception as error:
        LOG.error('load %s error, error: %s', policy_path, str(error))
        return False


def parse_cantian_config_file():
    cantian_config_dir = os.path.join(dir_name, "../../config/container_conf/init_conf")
    cantian_config_path = os.path.join(cantian_config_dir, "deploy_param.json")
    try:
        with open(cantian_config_path, 'r', encoding='utf8') as file_path:
            json_data = json.load(file_path)
            return json_data
    except Exception as error:
        LOG.error('load %s error, error: %s', cantian_config_path, str(error))
        return False


def write_back_to_json(cantian_config_json):
    cantian_config_dir = os.path.join(dir_name, "../../config")
    cantian_config_path = os.path.join(cantian_config_dir, "deploy_param.json")
    modes = stat.S_IRWXU | stat.S_IROTH | stat.S_IRGRP
    flag = os.O_RDWR | os.O_CREAT | os.O_TRUNC
    with os.fdopen(os.open(cantian_config_path, flag, modes), 'w') as file_path:
        config_params = json.dumps(cantian_config_json, indent=4)
        file_path.write(config_params)


def main():
    source_deploy_policy_json = parse_policy_config_file()
    source_config_json = parse_cantian_config_file()
    if source_config_json is False:
        LOG.error("parse cantian/install_config.json failed")
        raise Exception("parse cantian/install_config.json failed")
    # 根据配置文件获取配置方案
    deploy_policy_key = source_config_json.get("deploy_policy", "")

    # 如果配置方案为空或者默认走原安装流程，直接返回
    if deploy_policy_key == "" or deploy_policy_key == "default":
        LOG.info("deploy policy is default")
        # 如果未配置套餐参数，初始化套餐参数
        source_config_json["deploy_policy"] = "default"
        write_back_to_json(source_config_json)
        return
    LOG.info("deploy policy is %s" % deploy_policy_key)     

    # 如果配置方案未配置则返回失败，安装结束
    deploy_policy_value = source_deploy_policy_json.get(deploy_policy_key, {})
    if deploy_policy_value == {}:
        LOG.error("can not find the deploy policy(%s)" % deploy_policy_key)
        raise Exception("can not find the deploy policy(%s)" % deploy_policy_key)

    tmp_config = deploy_policy_value.get("config", {})
    for item in tmp_config.keys():
        source_config_json[item] = tmp_config.get(item, "")

    write_back_to_json(source_config_json)


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        exit(str(e))
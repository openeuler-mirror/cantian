import os
import stat
import json
import argparse
import traceback

def opt_ini_conf(file_path, action, key, value):
    with open(file_path, "r", encoding="utf-8")as fp:
        config = fp.readlines()
    for i, item in enumerate(config):
        if "=" not in item:
            continue
        _key, _value = item.split('=', maxsplit=1)
        if key == _key.strip(" "):
            if action == "modify":
                config[i] = f"{key} = {value}\n"
                break
            if action == "query":
                print(item, end="")
                return
    else:
        print("key is incorrect.")
        return
    flags = os.O_CREAT | os.O_RDWR
    modes = stat.S_IWUSR | stat.S_IRUSR
    with os.fdopen(os.open(file_path, flags, modes), "w") as file_obj:
        file_obj.writelines(config)
    print("modify config success.")


def cantian_opt_ini_conf(action, key, value):
    file_path = "/mnt/dbdata/local/cantian/tmp/data/cfg/cantiand.ini"
    opt_ini_conf(file_path, action, key, value)


def cms_opt_ini_conf(action, key, value):
    file_path = "/opt/cantian/cms/cfg/cms.ini"
    opt_ini_conf(file_path, action, key, value)


def main():
    update_parse = argparse.ArgumentParser()
    update_parse.add_argument("-c", "--component", dest="component",
                              choices=["cms", "cantian"],
                              required=True)
    update_parse.add_argument("-a", "--action", dest="action", choices=["query", "modify"],
                              required=True)
    update_parse.add_argument("-k", "--key", dest="key", required=True)
    update_parse.add_argument("-v", "--value", dest="value", required=False)
    args = update_parse.parse_args()
    component = args.component
    action = args.action
    key = args.key
    value = args.value
    func_dict = {
        "cantian": cantian_opt_ini_conf,
        "cms": cms_opt_ini_conf,
    }
    func_dict.get(component)(action, key, value)


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        exit(str(traceback.format_exc(limit=1)))
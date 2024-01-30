import json
import os


CUR_PATH = os.path.dirname(os.path.realpath(__file__))
DEPLOY_PARAM_FILE = os.path.join(CUR_PATH, '../../config/deploy_param.json')
CHECK_LIST = [
    "cluster_id",
    "cluster_name",
    "storage_dbstore_fs",
    "storage_dbstore_page_fs",
    "storage_share_fs",
    "storage_archive_fs",
    "storage_metadata_fs",
    "mes_type",
    "link_type",
    "db_type",
    "mysql_metadata_in_cantian",
    "random_seed"
]


def read_file(file_path):
    with open(file_path, "r") as f:
        info = f.read()
    return json.loads(info)


def check_deploy_param():
    local_deploy_params = read_file(DEPLOY_PARAM_FILE)
    storage_share_fs = local_deploy_params.get("storage_share_fs")
    remote_deploy_file = f"/mnt/dbdata/remote/share_{storage_share_fs}/deploy_param.json"
    if not os.path.exists(remote_deploy_file):
        err_msg = "%s is not exists, please check:\n" \
                  "\t1、node 0 has been successfully installed.\n" \
                  "\t2、storage_share_fs field in the configuration file same as node 0." % remote_deploy_file
        raise Exception(err_msg)
    remote_deploy_params = read_file(remote_deploy_file)
    check_failed_list = []
    for check_key in CHECK_LIST:
        if local_deploy_params.get(check_key) != remote_deploy_params.get(check_key):
            check_failed_list.append(check_key)
    if check_failed_list:
        err_msg = "The configuration items of the current node are different from " \
                  "those of node 0, details:%s" % check_failed_list
        raise Exception(err_msg)


if __name__ == "__main__":
    try:
        check_deploy_param()
    except Exception as err:
        exit(str(err))

import sys
import os
import pathlib

CUR_PATH, _ = os.path.split(os.path.abspath(__file__))
sys.path.append(str(pathlib.Path(CUR_PATH).parent))

from om_log import LOGGER
from utils.client.ssh_client import SshClient
from utils.client.rest_client import read_helper


DEPLOY_PARAMS = os.path.join(str(pathlib.Path(CUR_PATH).parent.parent), "config/deploy_param.json")


class CheckLockSwitch(object):
    def __init__(self, ip, user_name, user_passwd):
        self.user_name = user_name
        self.ip = ip
        self.user_pwd = user_passwd
        self.deploy_config = read_helper(DEPLOY_PARAMS)

    def execute(self):
        LOGGER.info("Begin to check NFSV4 Mandatory Lock Switch")
        ssh_client = SshClient(self.ip, self.user_name, self.user_pwd)
        ssh_client.create_client()
        vstore_id = self.deploy_config.get("vstore_id")
        cmd = f"change vstore view id={vstore_id}"
        res = ssh_client.execute_cmd(cmd, expect=":/>", timeout=10)
        if "Command executed successfully." in res:
            LOGGER.info("Execute cmd[%s] success", cmd)
        else:
            err_msg = "Execute cmd[%s], details:%s" % (cmd, res)
            LOGGER.error(err_msg)
            raise Exception(err_msg)
        cmd = f"show service nfs_config"
        res = ssh_client.execute_cmd(cmd, expect=":/>", timeout=10)
        "NFSV4 Mandatory Lock Switch: Enabled"
        res_lines = res.split("\n")
        for line in res_lines:
            key, value = line.split(":").strip()
            if "NFSV4 Mandatory Lock Switch" in key and "Enabled" in value:
                break
        else:
            err_msg = "Current NFSV4 Mandatory Lock Switch is disabled, details:%s" % res
            LOGGER.error(err_msg)
            raise Exception(err_msg)
        LOGGER.info("Success to check NFSV4 Mandatory Lock Switch")

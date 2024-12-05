#!/usr/bin/python3
# coding=utf-8
import datetime
import json
import os
import stat
import argparse

from storage_operate.dr_deploy_operate.dr_deploy_common import DRDeployCommon
from logic.common_func import read_json_config
from logic.common_func import exec_popen
from logic.storage_operate import StorageInf
from utils.config.rest_constant import HealthStatus, VstorePairConfigStatus, VstorePairRunningStatus, \
    MetroDomainRunningStatus, ReplicationRunningStatus

CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
LOCAL_PROCESS_RECORD_FILE = os.path.join(CURRENT_PATH, "../../../config/dr_process_record.json")
FULL_SYNC_PROGRESS = os.path.join(CURRENT_PATH, "../../../config/full_sync_progress.json")
DR_DEPLOY_CONFIG = os.path.join(CURRENT_PATH, "../../../config/dr_deploy_param.json")
DR_STATUS = os.path.join(CURRENT_PATH, "../../../config/dr_status.json")


class DrDeployQuery(object):
    def __init__(self):
        self.record_file = LOCAL_PROCESS_RECORD_FILE

    @staticmethod
    def table_format(process_data: dict) -> str:
        data = process_data.get("data")
        table = ""
        table += "-" * 68 + "\n"
        table += "|" + "task".center(50, " ") + "|" + "status".center(15, " ") + "|" + "\n"
        table += "-" * 68 + "\n"
        for key, value in data.items():
            table += "|" + key.center(50, " ") + "|" + value.center(15, " ") + "|" + "\n"
        error = process_data.get("error")
        code = error.get("code")
        if code != 0:
            table += "|" + "-" * 66 + "|" + "\n"
            table += "|" + "Error Details:".ljust(66, " ") + "|" + "\n"
            err_msg = error.get("description")
            err_msg_list = err_msg.split("\n")
            err_list = []
            for _err in err_msg_list:
                for i in range(0, len(_err), 62):
                    err_list.append(_err[i:i + 62])
            for _err in err_list:
                table += "|  " + _err.ljust(62, " ") + "  |" + "\n"
        table += "-" * 68 + "\n"
        return table

    @staticmethod
    def check_process() -> bool:
        process_name = "/storage_operate/dr_operate_interface.py deploy"
        cmd = "ps -ef | grep -v grep | grep '%s'" % process_name
        return_code, output, stderr = exec_popen(cmd)
        if return_code or not output:
            return False
        return True

    def execute(self, display) -> str:
        process_status = self.check_process()
        is_json_display = False if display == "table" else True
        if os.path.exists(self.record_file):
            process_data = read_json_config(self.record_file)
            data = process_data.get("data")
            error = process_data.get("error")
            description = process_data.get("description")
            if data.get("dr_deploy") != "success" and not process_status:
                data["dr_deploy"] = "failed"
                error["code"] = -1
                if description == "":
                    error["description"] = "The process exits abnormally," \
                                           "see /opt/cantian/log/deploy/om_deploy/dr_deploy.log for more details."
            table_data = self.table_format(process_data)
            json_data = json.dumps(process_data, indent=4)
            return json_data if is_json_display else table_data
        else:
            return "Dr deploy has not started yet."


class DrStatusCheck(object):
    def __init__(self):
        self.dr_deploy_opt = None
        self.dm_passwd = None
        self.dr_deploy_info = read_json_config(DR_DEPLOY_CONFIG)

    @staticmethod
    def table_format(statuses: dict) -> str:
        table = ""
        table += "-" * 68 + "\n"
        table += "|" + "Component".center(50, " ") + "|" + "Status".center(15, " ") + "|\n"
        table += "-" * 68 + "\n"

        for key, value in statuses.items():
            if key == "dr_status":
                continue
            table += "|" + key.replace("_", " ").capitalize().center(50, " ") + "|" + value.center(15, " ") + "|\n"

        table += "-" * 68 + "\n"
        table += "|" + "DR Status".center(50, " ") + "|" + statuses["dr_status"].center(15, " ") + "|\n"
        table += "-" * 68 + "\n"

        return table

    def init_storage_opt(self):
        """Initialize storage operations from the configuration file."""
        dm_ip = self.dr_deploy_info.get("dm_ip")
        dm_user = self.dr_deploy_info.get("dm_user")
        self.dm_passwd = input("Enter DM password: \n")
        storage_opt = StorageInf((dm_ip, dm_user, self.dm_passwd))
        storage_opt.login()
        self.dr_deploy_opt = DRDeployCommon(storage_opt)

    def query_domain_status(self) -> str:
        hyper_domain_id = self.dr_deploy_info.get("hyper_domain_id")
        try:
            domain_info = self.dr_deploy_opt.query_hyper_metro_domain_info(hyper_domain_id)
            if domain_info:
                domain_running_status = domain_info.get("RUNNINGSTATUS")
                if domain_running_status == MetroDomainRunningStatus.Normal:
                    return "Normal"
                else:
                    return "Abnormal"
            return "Unknown"
        except Exception:
            return "Unknown"

    def query_vstore_pair_status(self) -> str:
        vstore_pair_id = self.dr_deploy_info.get("vstore_pair_id")
        try:
            vstore_pair_info = self.dr_deploy_opt.query_hyper_metro_vstore_pair_info(vstore_pair_id)
            if vstore_pair_info:
                vstore_running_status = vstore_pair_info.get("RUNNINGSTATUS")
                if (vstore_running_status == VstorePairRunningStatus.Normal and
                        vstore_pair_info.get("HEALTHSTATUS") == HealthStatus.Normal):
                    if vstore_pair_info.get("CONFIGSTATUS") == VstorePairConfigStatus.Synchronizing:
                        return "Running"
                    if vstore_pair_info.get("CONFIGSTATUS") == VstorePairConfigStatus.Normal:
                        return "Normal"
                else:
                    return "Abnormal"
            return "Unknown"
        except Exception:
            return "Unknown"

    def query_ulog_fs_pair_status(self) -> str:
        filesystem_pair_id = self.dr_deploy_info.get("ulog_fs_pair_id")
        try:
            filesystem_pair_info = self.dr_deploy_opt.query_hyper_metro_filesystem_pair_info_by_pair_id(
                pair_id=filesystem_pair_id)
            if filesystem_pair_info:
                ulog_fs_running_status = filesystem_pair_info.get("RUNNINGSTATUS")
                if (ulog_fs_running_status == VstorePairRunningStatus.Normal and
                        filesystem_pair_info.get("HEALTHSTATUS") == HealthStatus.Normal):
                    if filesystem_pair_info.get("CONFIGSTATUS") == VstorePairConfigStatus.Synchronizing:
                        return "Runing"
                    if filesystem_pair_info.get("CONFIGSTATUS") == VstorePairConfigStatus.Normal:
                        return "Normal"
                else:
                    return "Abnormal"
            return "Unknown"
        except Exception:
            return "Unknown"

    def query_page_fs_pair_status(self) -> str:
        dbstore_page_fs_name = self.dr_deploy_info.get("storage_dbstore_page_fs")
        try:
            dbstore_page_fs_info = self.dr_deploy_opt.storage_opt.query_filesystem_info(dbstore_page_fs_name)
            dbstore_page_fs_id = dbstore_page_fs_info.get("ID")
            page_fs_pair_info = self.dr_deploy_opt.query_remote_replication_pair_info(dbstore_page_fs_id)
            if page_fs_pair_info:
                if page_fs_pair_info[0].get("HEALTHSTATUS") == HealthStatus.Normal:
                    return "Normal"
                else:
                    return "Abnormal"
            return "Unknown"
        except Exception:
            return "Unknown"

    def query_dr_status_file(self):
        file_dir = "/opt/cantian/config"
        file_name = "dr_deploy_param.json"
        try:
            if not os.path.exists(os.path.join(file_dir, file_name)):
                return "Abnormal"
            deploy_mode = self.dr_deploy_info.get("deploy_mode")
            deploy_user = self.dr_deploy_info.get("deploy_user").strip().split(":")[0]
            if deploy_mode == "dbstor":
                storage_fs = self.dr_deploy_info.get("storage_share_fs")
                cmd = (f"su -s /bin/bash - {deploy_user} -c 'dbstor --query-file "
                       f"--fs-name={storage_fs} --file-dir=/' | grep 'dr_deploy_param.json' | wc -l")
            else:
                storage_fs = self.dr_deploy_info.get("storage_metadata_fs")
                if os.path.exists(f"/mnt/dbdata/remote/metadata_{storage_fs}/dr_deploy_param.json"):
                    return "Normal"
                return "Abnormal"
            code, count, err = exec_popen(cmd)
            if code:
                return "Unknown"
            if count == "1":
                return "Normal"
            return "Abnormal"
        except Exception as ignor:
            return "Unknown"

    def update_dr_status_file(self, statuses: dict):
        """Update the DR status information to a JSON file."""
        try:
            os.makedirs(os.path.dirname(DR_STATUS), exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            mode = stat.S_IWUSR | stat.S_IRUSR
            with os.fdopen(os.open(DR_STATUS, flags, mode), "w", encoding='utf-8') as file:
                json.dump(statuses, file, indent=4)
            os.chmod(DR_STATUS, 0o640)
        except Exception as e:
            print(f"Error updating DR status file: {e}")

    def execute(self, display) -> str:
        is_json_display = display != "table"
        self.init_storage_opt()

        statuses = {
            "domain_status": "Unknown",
            "vstore_pair_status": "Unknown",
            "ulog_fs_pair_status": "Unknown",
            "page_fs_pair_status": "Unknown",
            "dr_status_file": "Unknown",
            "dr_status": "Abnormal"
        }

        statuses["domain_status"] = self.query_domain_status()
        if statuses["domain_status"] in ["Unknown", "Abnormal"]:
            self.update_dr_status_file(statuses)
            return json.dumps(statuses, indent=4) if is_json_display else self.table_format(statuses)

        statuses["vstore_pair_status"] = self.query_vstore_pair_status()
        if statuses["vstore_pair_status"] in ["Unknown", "Abnormal", "Running"]:
            self.update_dr_status_file(statuses)
            return json.dumps(statuses, indent=4) if is_json_display else self.table_format(statuses)

        statuses["ulog_fs_pair_status"] = self.query_ulog_fs_pair_status()
        if statuses["ulog_fs_pair_status"] in ["Unknown", "Abnormal", "Running"]:
            self.update_dr_status_file(statuses)
            return json.dumps(statuses, indent=4) if is_json_display else self.table_format(statuses)

        statuses["page_fs_pair_status"] = self.query_page_fs_pair_status()
        if statuses["page_fs_pair_status"] in ["Unknown", "Abnormal"]:
            self.update_dr_status_file(statuses)
            return json.dumps(statuses, indent=4) if is_json_display else self.table_format(statuses)

        statuses["dr_status_file"] = self.query_dr_status_file()
        if statuses["dr_status_file"] in ["Abnormal"]:
            self.update_dr_status_file(statuses)
            return json.dumps(statuses, indent=4) if is_json_display else self.table_format(statuses)

        if all(status == "Normal" for status in list(statuses.values())[:-1]):
            statuses["dr_status"] = "Normal"
        if any(status == "Running" for status in list(statuses.values())[:-1]):
            statuses["dr_status"] = "Running"

        self.update_dr_status_file(statuses)

        return json.dumps(statuses, indent=4) if is_json_display else self.table_format(statuses)


class FullSyncProgress(DrDeployQuery):
    def __init__(self):
        super(FullSyncProgress, self).__init__()
        self.record_file = FULL_SYNC_PROGRESS

    @staticmethod
    def check_process() -> bool:
        process_name = "/storage_operate/dr_operate_interface.py full_sync"
        cmd = "ps -ef | grep -v grep | grep '%s'" % process_name
        return_code, output, stderr = exec_popen(cmd)
        if return_code or not output:
            return False
        return True

    def execute(self, display) -> str:
        process_status = self.check_process()
        is_json_display = False if display == "table" else True
        if os.path.exists(self.record_file):
            process_data = read_json_config(self.record_file)
            data = process_data.get("data")
            error = process_data.get("error")
            description = process_data.get("description")
            if data.get("full_sync") != "success" and not process_status:
                data["full_sync"] = "failed"
                error["code"] = -1
                if description == "":
                    error["description"] = "The process exits abnormally," \
                                           "see /opt/cantian/log/deploy/om_deploy/dr_deploy.log for more details."
            table_data = self.table_format(process_data)
            json_data = json.dumps(process_data, indent=4)
            return json_data if is_json_display else table_data
        else:
            return "Full sync has not started yet."


class ProgressQuery(object):
    @staticmethod
    def execute(action=None, display=None):
        parse_params = argparse.ArgumentParser()
        parse_params.add_argument("--action", dest="action", required=False, default="deploy")
        parse_params.add_argument("--display", dest="display", required=False, default="json")
        args = parse_params.parse_args()
        if action is None:
            action = args.action
        if display is None:
            display = args.display
        if action == "deploy":
            dr_deploy_progress = DrDeployQuery()
            result = dr_deploy_progress.execute(display)
        elif action == "check":
            dr_deploy_progress = DrStatusCheck()
            result = dr_deploy_progress.execute(display)
        elif action == "full_sync":
            full_sync_progress = FullSyncProgress()
            result = full_sync_progress.execute(display)
        else:
            result = "Invalid input."
        print(result)
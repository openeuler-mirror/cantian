#!/usr/bin/python3
# coding=utf-8
import datetime
import json
import os
import argparse
from logic.common_func import read_json_config
from logic.common_func import exec_popen

CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
LOCAL_PROCESS_RECORD_FILE = os.path.join(CURRENT_PATH, "../../../config/dr_process_record.json")
FULL_SYNC_PROGRESS = os.path.join(CURRENT_PATH, "../../../config/full_sync_progress.json")
DR_DEPLOY_CONFIG = os.path.join(CURRENT_PATH, "../../../config/dr_deploy_param.json")


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
                                           "see /opt/cantian/deploy/om_deploy/dr_deploy.log for more details."
            table_data = self.table_format(process_data)
            json_data = json.dumps(process_data, indent=4)
            return json_data if is_json_display else table_data
        else:
            return "Dr deploy has not started yet."


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
                                           "see /opt/cantian/deploy/om_deploy/dr_deploy.log for more details."
            table_data = self.table_format(process_data)
            json_data = json.dumps(process_data, indent=4)
            return json_data if is_json_display else table_data
        else:
            return "Full sync has not started yet."


class ProgressQuery(object):
    @staticmethod
    def execute():
        parse_params = argparse.ArgumentParser()
        parse_params.add_argument("--action", dest="action", required=False, default="deploy")
        parse_params.add_argument("--display", dest="display", required=False, default="json")
        args = parse_params.parse_args()
        if args.action == "deploy":
            dr_deploy_progress = DrDeployQuery()
            result = dr_deploy_progress.execute(args.display)
        elif args.action == "full_sync":
            full_sync_progress = FullSyncProgress()
            result = full_sync_progress.execute(args.display)
        else:
            result = "Invalid input."
        print(result)

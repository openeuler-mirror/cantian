# -*- coding: UTF-8 -*-
import os
import re
import json
from pathlib import Path
from display_as_table import DisplayAsTable
from params_factory.param_config import PARAM_PREPARE

cur_abs_path, _ = os.path.split(os.path.abspath(__file__))
NORMAL_STATE = 0
ABNORMAL_STATE = 1
HELP_STATE = 1


def json_data_reader(data_path):
    with open(data_path, "r", encoding="utf-8") as file:
        info = file.read()
        info = json.loads(info)
    return info


class HandleInfo:
    def __init__(self):
        self.has_format = False
        self.cmd = None
        self.data_to_uds = dict()
        self.print_table = DisplayAsTable()
        self.commands_info = json_data_reader(str(Path(cur_abs_path, "commands.json")))
        self.input_process_method = {
            'common': self.common_params_handler,
            'logs_collection': self.logs_collection_handler
        }

    @staticmethod
    def _reg_match_dir(log_dir):
        reg_string = r'(/[-\w~]+)'
        reg_res = re.findall(reg_string, log_dir)
        connector = ''.join(reg_res)
        return connector == log_dir or '{}/'.format(connector) == log_dir

    @staticmethod
    def basic_params_check(right_params, input_params):
        if isinstance(input_params, dict):
            input_params = input_params.keys()

        method, param_val = right_params.get("type"), right_params.get("param_val")
        params = param_val if method == "direct" else json_data_reader(param_val).keys()

        for spec_param in input_params:
            if spec_param not in params:
                err_msg = "input params '{}' not supported".format(spec_param)
                return err_msg, ABNORMAL_STATE

        return "", NORMAL_STATE

    def format_param_check(self, input_params):
        format_key = input_params.get("format")
        if not format_key or format_key not in ("json", "table"):
            err_msg = "format param type must be one of ('json', table), not {}".format(format_key)
            return err_msg, ABNORMAL_STATE
        if format_key == "table":
            self.has_format = True

        return "", NORMAL_STATE

    def common_params_handler(self, params):
        self.data_to_uds.update({"command": str(self.cmd)})

        str_params = [param for param in params if "=" in param]
        params_to_uds = {param.split("=")[0]: param.split("=")[1] for param in str_params}

        if self.commands_info.get(self.cmd).get("params check") == 'True':
            check_res, err_code = self.basic_params_check(self.commands_info.get(self.cmd).get("check value"),
                                                          params_to_uds)
            if err_code:
                return self._params_exception_handler(err_type="params name check error", err_detail=check_res)

        if "format" in params_to_uds:
            check_res, err_code = self.format_param_check(params_to_uds)
            if err_code:
                return self._params_exception_handler(err_type="format param error", err_detail=check_res)

            params_to_uds.pop("format")

        self.data_to_uds.update({"param": params_to_uds})
        return self.data_to_uds, NORMAL_STATE

    def logs_collection_handler(self, input_params):
        params_item = [(item_idx, item_val) for item_idx, item_val in enumerate(input_params) if '=' in item_val]
        if len(params_item) > 2 or len(params_item) <= 1:
            return self._params_exception_handler(err_type="wrong logs collection params number",
                                                  err_detail="The input parameter names "
                                                             "can only be 'log_dir' and 'type'")

        head_idx, tail_idx = params_item[0][0], params_item[-1][0]
        if (tail_idx - head_idx) > 1:
            err_msg = "input log_dir '{}' is invalid".format(" ".join(input_params[head_idx:tail_idx]))
            return self._params_exception_handler(err_type="invalid input log dir", err_detail=err_msg)

        log_dir_param = input_params[head_idx]
        type_param = ''.join(input_params[tail_idx:])
        params_to_uds = {param.split("=")[0]: param.split("=")[1] for param in [log_dir_param, type_param]}

        check_res, err_code = self.basic_params_check(self.commands_info.get(self.cmd).get("check value"),
                                                      params_to_uds.keys())
        if err_code:
            return self._params_exception_handler(err_type="params name check error", err_detail=check_res)

        log_dir, log_collection_type = params_to_uds.get('log_dir'), params_to_uds.get('type')
        if not self._reg_match_dir(log_dir):
            return self._params_exception_handler(err_type="input log dir invalid",
                                                  err_detail="input log dir '{}' invalid".format(log_dir))
        if log_collection_type not in ('all', 'recent'):
            return self._params_exception_handler(err_type="logs collection type error",
                                                  err_detail="logs collection type must be one of [all, recent]"
                                                             " not '{}'".format(log_collection_type))

        self.data_to_uds = {"command": self.cmd, "param": params_to_uds}
        return self.data_to_uds, NORMAL_STATE

    def is_unilateral_execution(self):
        """commands processed only on the ctcli side"""
        info_dict = {cmd: cmd_detail.get("description") for cmd, cmd_detail in self.commands_info.items()}
        self.print_table.display_single_table(info_dict, mode="help")

    def input_params_handler(self, params):
        if len(params) == 1 and params[0] == "help":
            self.is_unilateral_execution()
            return self.data_to_uds, HELP_STATE

        params_item = [(idx, val) for idx, val in enumerate(params) if "=" in val]
        if not params_item:
            self.cmd = " ".join(params)
        else:
            self.cmd = " ".join(params[:params_item[0][0]])

        if self.cmd not in self.commands_info:
            return self._params_exception_handler(err_type="input commands error",
                                                  err_detail="'ctctl {}' not supported".format(self.cmd))

        handler_method = self.commands_info.get(self.cmd).get("handler")
        return self.input_process_method.get(handler_method)(params)

    def high_risk_command_judgement(self):
        if self.commands_info[self.cmd]["high risk command"] == "False":
            return True
        return input("yes or no(default no): ") == "yes"

    def receipt_info_handler(self, ctmgr_info):
        if ctmgr_info:
            receipt_info = json.loads(ctmgr_info)
            status = int(receipt_info["error"]["code"])
            if status:
                self.print_table.display_table(receipt_info.get("error"))
            else:
                self.receipt_data_processing(receipt_info.get("data"))
        else:
            err_msg = "[ctctl {}] may fail, the receipt info is {}, which is an empty string, " \
                      "does not conform to the format returned by ctmgr, " \
                      "check logs for more details.".format(self.cmd, ctmgr_info)
            self.print_table.display_table(err_msg)

    def receipt_data_processing(self, data_info):
        if "ctmgr_common_output" in data_info:
            data_info = data_info.get("ctmgr_common_output")
        if self.cmd in PARAM_PREPARE:
            data_info = PARAM_PREPARE.get(self.cmd)(data_info, self.has_format)
            self.print_table.display_table(data_info, flag=self.has_format)

    def _params_exception_handler(self, err_type, err_detail=""):
        self.print_table.print_exception_info(err_type, err_detail)
        return "", ABNORMAL_STATE

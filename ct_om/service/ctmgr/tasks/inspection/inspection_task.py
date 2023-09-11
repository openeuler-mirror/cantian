import os
import stat
import subprocess
from pathlib import Path
from datetime import datetime
from datetime import timezone
import json

from task_obj import TASK
from log_tool.om_log import TASK_LOG  # 定位日志
from common.output_tool import CommonResult
from common.common_tool import TimeTool

MAX_AUDIT_NUM = 10
DIR_NAME, _ = os.path.split(os.path.abspath(__file__))
INSPECTION_PATH = str(Path('{}/../../inspections'.format(DIR_NAME)))
FAIL = 'fail'
SUCCESS = 'success'
SUCCESS_ENUM = [0, '0']
INSPECTION_JSON_FILE = "/opt/cantian/ct_om/service/ctmgr/tasks/inspection/inspection_config.json"


class InspectionTask(TASK):
    def __init__(self, task_name, handler, params_check_dict):
        super().__init__(task_name, handler, params_check_dict)
        self.time_out = 5
        self.inspection_map = self.read_inspection_config()
        self.inspection_result = []
        self.audit_path = INSPECTION_PATH
        self.output_data = {}
        self.success_list = []
        self.fail_list = []

    @staticmethod
    def read_inspection_config():
        with open(INSPECTION_JSON_FILE, encoding='utf-8') as file:
            inspection_map = json.load(file)

        return inspection_map

    @staticmethod
    def format_single_inspection_result(inspection_item, inspection_detail, execute_result, inspection_result):
        return_value = {
            'inspection_item': inspection_item,
            'component': inspection_detail.get("component"),
            'inspection_result': execute_result,
            'inspection_detail': inspection_result.get('data'),
            'description_zn': inspection_detail.get("description_zn"),
            'description_en': inspection_detail.get("description_en")
        }

        if inspection_result and isinstance(inspection_result, dict):
            err_info = inspection_result.get('error', {})
            error_code = err_info.get('code')
            if error_code is None:
                return return_value

            if error_code not in SUCCESS_ENUM:
                return_value['inspection_result'] = FAIL

        return return_value

    def task_execute(self, input_params_dict, task_logger):
        """
        :param input_params_dict:
            inspection_items：字符串all：全部采集；列表：采集列表内巡检项，
            pwd：切用户执行巡检命令时候需要的密码
        :param task_logger:
        :return:
        """
        self.clear_history_data()

        result = CommonResult()
        input_params = input_params_dict.get("inspection_items")
        inspection_items = input_params
        if input_params == "all":
            inspection_items = list(self.inspection_map.keys())

        if not isinstance(input_params, list) and input_params != 'all':
            TASK_LOG.error("inspection input error, input value is: " + str(input_params))
            result = CommonResult(output_data="inspection input error, input value is: " + str(input_params),
                                  error_code=1,
                                  description="input must be string \"all\" or [xxx, xxx]")
            task_logger.set_finish_time(TimeTool.get_current_time())
            task_logger.info(self.task_name, FAIL)
            return result

        for inspection_item in inspection_items:
            inspection_detail = self.inspection_map.get(inspection_item)

            single_check_result, single_result = self.param_check_single(inspection_item,
                                                                         inspection_detail, task_logger)
            if not single_check_result:
                if single_result:
                    return single_result

                continue

            try:
                single_inspection_result = json.loads(self.task_execute_single(inspection_detail))
            except Exception as err:
                TASK_LOG.error("excute %s inspection failed with error: %s" % (inspection_item, str(err)))
                formated_inspection_result = self.format_single_inspection_result(inspection_item,
                                                                                  inspection_detail, FAIL, {})
                self.inspection_result.append(formated_inspection_result)
                self.fail_list.append(inspection_item)
                continue

            formated_inspection_result = self.format_single_inspection_result(inspection_item, inspection_detail,
                                                                              SUCCESS, single_inspection_result)
            if formated_inspection_result.get('inspection_result') == FAIL:
                self.inspection_result.append(formated_inspection_result)
                self.fail_list.append(inspection_item)
                continue

            self.inspection_result.append(formated_inspection_result)
            self.success_list.append(inspection_item)

        if not self.success_list:
            result.set_output_data("inspection item: %s failed" % ' '.join(self.fail_list))
        elif not self.fail_list:
            result.set_output_data("inspection item: %s success" % ' '.join(self.success_list))
        else:
            result.set_output_data("inspection item: %s success, inspection item: %s failed"
                                   % (' '.join(self.success_list), ' '.join(self.fail_list)))

        self.write_audit()

        task_logger.set_finish_time(TimeTool.get_current_time())
        task_logger.info(self.task_name, SUCCESS)
        return result

    def param_check_single(self, inspection_item, inspection_detail, task_logger):
        result = None

        if not inspection_detail:
            TASK_LOG.error("inspection item %s not exist" % inspection_item)
            result = CommonResult(output_data=inspection_item + " not exist", error_code=1,
                                  description="please check input, inspection item %s not exist"
                                              % inspection_item)
            task_logger.set_finish_time(TimeTool.get_current_time())
            task_logger.info(self.task_name, FAIL)
            return False, result

        if not os.path.exists(inspection_detail.get('inspection_file_path')):
            TASK_LOG.error("inspection file: %s not exist" % str(inspection_detail.get('inspection_file_path')))
            formated_inspection_result = self.format_single_inspection_result(inspection_item,
                                                                              inspection_detail, FAIL, None)
            self.inspection_result.append(formated_inspection_result)
            self.fail_list.append(inspection_item)
            return False, result

        return True, result

    def task_execute_single(self, inspection_detail):
        inspection_item_file = inspection_detail.get('inspection_file_path')
        inspection_item_input = inspection_detail.get('input_param')

        single_inspection_popen = subprocess.Popen(['/usr/bin/python3', inspection_item_file, inspection_item_input],
                                                    stdout=subprocess.PIPE, shell=False)
        single_inspection_result = single_inspection_popen.communicate(timeout=self.time_out)[0].decode('utf-8')
        single_inspection_result = single_inspection_result.replace("\'", "\"")

        return single_inspection_result

    def clear_history_data(self):
        self.output_data = {}
        self.inspection_result = []
        self.success_list = []
        self.fail_list = []

    def format_inspection_result(self):
        """
        :param inspection_output: 调用巡检项脚本的输出
        整理一键巡检格式, 结果写到 self.output_data
        """
        self.output_data['data'] = self.inspection_result

    def write_audit(self):
        self.format_inspection_result()

        if not os.path.exists(self.audit_path):
            os.mkdir(self.audit_path)

        audit_list = sorted(os.listdir(self.audit_path))
        while len(audit_list) >= MAX_AUDIT_NUM:
            os.remove(str(Path(self.audit_path + "/" + str(audit_list[0]))))
            audit_list.pop(0)

        modes = stat.S_IWRITE | stat.S_IRUSR
        flags = os.O_WRONLY | os.O_TRUNC | os.O_CREAT
        utc_now = datetime.utcnow()
        cur_time = utc_now.replace(tzinfo=timezone.utc).astimezone(tz=None)
        audit_file = 'inspection_{}'.format(str(cur_time.strftime("%Y%m%d%H%M%S")))
        audit_file_path = str(Path(self.audit_path + '/' + audit_file))
        with os.fdopen(os.open(audit_file_path, flags, modes), 'w', encoding='utf-8') as file:
            file.write(json.dumps(self.output_data, indent=4, separators=(',', ': '), ensure_ascii=False))

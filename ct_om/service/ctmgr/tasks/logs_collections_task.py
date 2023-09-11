import os
import subprocess
import shlex
from pathlib import Path

from task_obj import TASK
from log_tool.om_log import LOGGER, DEPLOY_LOG, TASK_LOG
from common.output_tool import CommonResult
from common.common_tool import TimeTool

SUCCESS, FAIL = 'success', 'fail'
cur_abs_path, _ = os.path.split(os.path.abspath(__file__))


class LogsCollectionTask(TASK):

    def __init__(self, task_name, handler, file_path, py_input, params_check_dict):
        super().__init__(task_name, handler, params_check_dict)
        self.file_path = str(Path(file_path))
        self.py_input = py_input
        self.time_out = 2
        if not self.basic_check():
            DEPLOY_LOG.error('[error] {} not exist, init ShellTask failed, please check param in cmd {}'.format(
                self.file_path, self.task_name))
            raise Exception

    def basic_check(self):
        return os.path.exists(self.file_path)

    def task_execute(self, input_params, task_logger):
        params_format_save = self.py_input
        exec_cmd = 'python3 {}'.format(self.file_path)

        for param_key in input_params.keys():
            self.py_input = self.py_input.replace('${%s}' % param_key, str(input_params.get(param_key)))
        exec_cmd = exec_cmd + ' ' + str(self.py_input)

        result = CommonResult()
        TASK_LOG.info('task: {} calling py file: {}, using cmd: {}'.format(self.task_name, self.file_path, exec_cmd))
        task_logger.set_request_time(TimeTool.get_current_time())
        try:
            py_result = subprocess.Popen(shlex.split(exec_cmd), stdout=subprocess.PIPE, shell=False)
        except Exception as err:
            TASK_LOG.error('task: {} calling py file: {}, using cmd: {} fail, '
                           'error: {}'.format(self.task_name, self.file_path, exec_cmd, err))
            task_logger.set_finish_time(TimeTool.get_current_time())
            task_logger.info(self.task_name, FAIL)
            result = CommonResult(output_data='', error_code=1,
                                  description='{} call py file: {} with params: {} failed \n [ERROR] {}'.format(
                                      self.task_name, self.file_path, self.py_input, err))
            self.py_input = params_format_save

            return result

        try:
            std_res, std_err = py_result.communicate(timeout=self.time_out)
        except Exception as err:
            TASK_LOG.info('task: {} background execution start'.format(self.task_name))
            result.set_output_data(str(err))
            task_logger.set_finish_time(TimeTool.get_current_time())
            task_logger.info(self.task_name, SUCCESS)
            self.py_input = params_format_save
            return result

        self.py_input = params_format_save

        # 日志采集脚本执行过程中异常退出
        if not std_res or std_err:
            err_msg = 'cmd: {} itself failed'.format(exec_cmd)
            TASK_LOG.error('task: {} calling py file: {}, using cmd: {} fail, '
                           'error: {}'.format(self.task_name, self.file_path, exec_cmd, err_msg))
            task_logger.set_finish_time(TimeTool.get_current_time())
            task_logger.info(self.task_name, FAIL)
            result = CommonResult(output_data='', error_code=1,
                                  description='{} call py file: {} failed, [ERROR] {}'.format(
                                      self.task_name, self.file_path, err_msg))
            return result

        result.set_output_data(std_res.decode('utf-8'))
        task_logger.set_finish_time(TimeTool.get_current_time())
        task_logger.info(self.task_name, SUCCESS)
        return result

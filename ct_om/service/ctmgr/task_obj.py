import subprocess
import os
import json
from abc import ABCMeta, abstractmethod
from pathlib import Path

import uds_client
from log_tool.om_log import LOGGER, DEPLOY_LOG, TASK_LOG
from checkers import CHECKER
from common.output_tool import CommonResult
from common.common_tool import TimeTool

FAIL = 'fail'
SUCCESS = 'success'


class TASK(metaclass=ABCMeta):
    """
    变量：
    task_name为cli具体指令
    handler为cli指令执行方式：rest请求，uds请求，执行cmd指令，调用sh脚本，调用py脚本

    方法：
    参数校验：param_check, 需要在校验中把具体错误记录到日志，方便定位
    cli指令执行：task_execute
    """

    def __init__(self, task_name, handler, param_check_dict):
        self.task_name = task_name
        self.handler = handler
        self.param_check_dict = param_check_dict

    def param_check(self, input_params_dict):
        for check_key, check_value in self.param_check_dict.items():
            for param_key, param_value in check_value.items():
                if not CHECKER.get(param_key, None):
                    TASK_LOG.error("check function %s not exist" % param_key)
                    continue

                if not CHECKER.get(param_key)(input_params_dict, check_key, param_value):
                    TASK_LOG.error("%s check %s not pass" % (check_key, param_key))
                    return False

        return True

    @abstractmethod
    def task_execute(self, input_params, task_logger: LOGGER):
        """
        :param input_params: ctcli下发的命令执行参数
        :param task_logger: 用于记录审计日志的类
        :return:
        """
        pass


class UdsTask(TASK):
    """
    task_execute中执行方法为下发unix domain service请求
    """

    def __init__(self, task_name, handler, param_check_dict):
        super().__init__(task_name, handler, param_check_dict)

    def task_execute(self, input_params, task_logger):
        result = CommonResult()

        output_data = json.dumps(input_params)

        task_logger.set_request_time(TimeTool.get_current_time())
        try:
            res = uds_client.client_socket(output_data)
        except Exception as error:
            result = CommonResult(output_data='cmd {} send uds request failed'.format(self.task_name), error_code=1,
                                  description='cmd {} send uds request failed \n [ERROR] {}'.format(
                                      self.task_name, error))
            return result

        result.set_output_data(res)
        task_logger.set_finish_time(TimeTool.get_current_time())

        error_code = eval(result.__str__()).get('error', {}).get('code', '')
        if str(error_code) != '0':
            task_logger.error(self.task_name, FAIL)
        else:
            task_logger.info(self.task_name, SUCCESS)

        return result


class CmdTask(TASK):
    """
    任务执行方法执行cmd指令
    """

    def __init__(self, task_name, handler, cmd_line, param_check_dict):
        super().__init__(task_name, handler, param_check_dict)
        self.cmd_line = cmd_line
        self.time_out = 5

    def task_execute(self, input_params, task_logger):
        result = CommonResult()

        for param_key in input_params.keys():
            self.cmd_line = self.cmd_line.replace('${%s}' % param_key, str(input_params[param_key]))

        task_logger.set_request_time(TimeTool.get_current_time())
        try:
            command_result = subprocess.Popen(self.cmd_line.split(' '), stdout=subprocess.PIPE, shell=False)
        except Exception as error:
            task_logger.set_finish_time(TimeTool.get_current_time())
            task_logger.info(self.task_name, FAIL)
            result = CommonResult(output_data='{} execute cmd {} failed'.format(self.task_name, self.cmd_line),
                                  error_code=1,
                                  description='{} execute cmd {} failed \n [ERROR] {}'.format(
                                      self.task_name, self.cmd_line, error))

            return result

        res = command_result.communicate(timeout=self.time_out)[0].decode('utf-8')
        result.set_output_data(res)
        task_logger.set_finish_time(TimeTool.get_current_time())
        task_logger.info(self.task_name, SUCCESS)

        return result


class ShellTask(TASK):
    """
    任务执行方法为调用shell脚本

    变量：
    file_path为任务执行时调用的.sh脚本位置
    """

    def __init__(self, task_name, handler, file_path, sh_input, param_check_dict):
        super().__init__(task_name, handler, param_check_dict)
        self.file_path = str(Path(file_path))
        self.sh_input = sh_input
        self.time_out = 5

        if not self.basic_check():
            DEPLOY_LOG.error('[error] {} not exist, init ShellTask failed, please check param in cmd {}'.format(
                self.file_path, self.task_name))
            raise Exception

    def basic_check(self):
        return os.path.exists(self.file_path)

    def task_execute(self, input_params, task_logger):
        params_format_save = self.sh_input
        cmd_line = 'sh {}'.format(self.file_path)

        for param_key in input_params.keys():
            self.sh_input = self.sh_input.replace('${%s}' % param_key, str(input_params[param_key]))
        cmd_line = cmd_line + ' ' + str(self.sh_input)

        result = CommonResult()

        task_logger.set_request_time(TimeTool.get_current_time())
        try:
            sh_result = subprocess.Popen(cmd_line.split(' '), stdout=subprocess.PIPE, shell=False)
        except Exception as error:
            task_logger.set_finish_time(TimeTool.get_current_time())
            task_logger.info(self.task_name, FAIL)
            result.set_output_data('call shell file: {} failed'.format(self.file_path))
            result.set_error_code(1)
            result.set_description('{} call shell file: {} with params: {} failed \n [ERROR] {}'.format(
                self.task_name, self.file_path, self.sh_input, error))
            self.sh_input = params_format_save
            return result

        res = sh_result.communicate(timeout=self.time_out)[0].decode('utf-8')
        result.set_output_data(res)
        task_logger.set_finish_time(TimeTool.get_current_time())
        task_logger.info(self.task_name, SUCCESS)
        self.sh_input = params_format_save

        return result


class PyTask(TASK):
    """
    任务执行方法为调用python脚本

    变量：
    file_path为任务执行时调用的.py脚本位置
    """

    def __init__(self, task_name, handler, file_path, py_input, param_check_dict):
        super().__init__(task_name, handler, param_check_dict)
        self.file_path = str(Path(file_path))
        self.py_input = py_input
        self.time_out = 5
        if not self.basic_check():
            DEPLOY_LOG.error('[error] {} not exist, init ShellTask failed, please check param in cmd {}'.format(
                self.file_path, self.task_name))
            raise Exception

    def basic_check(self):
        return os.path.exists(self.file_path)

    def task_execute(self, input_params, task_logger):
        params_format_save = self.py_input
        cmd_line = 'python3 {}'.format(self.file_path)

        for param_key in input_params.keys():
            self.py_input = self.py_input.replace('${%s}' % param_key, str(input_params[param_key]))
        cmd_line = cmd_line + ' ' + str(self.py_input)

        result = CommonResult()
        TASK_LOG.info('task: {} calling py file: {}, using cmd: {}'.format(self.task_name, self.file_path, cmd_line))
        task_logger.set_request_time(TimeTool.get_current_time())
        try:
            py_result = subprocess.Popen(cmd_line.split(' '), stdout=subprocess.PIPE, shell=False)
        except Exception as error:
            TASK_LOG.error('task: {} calling py file: {}, using cmd: {} fail, error: {}'.format(
                self.task_name, self.file_path, cmd_line, error))
            task_logger.set_finish_time(TimeTool.get_current_time())
            task_logger.info(self.task_name, FAIL)
            result = CommonResult(output_data='{} call py file: {} failed'.format(self.task_name, self.file_path),
                                  error_code=1,
                                  description='{} call py file: {} with params: {} failed \n [ERROR] {}'.format(
                                      self.task_name, self.file_path, self.py_input, error))
            self.py_input = params_format_save
            return result

        try:
            res = py_result.communicate(timeout=self.time_out)[0].decode('utf-8')
        except Exception as error:
            TASK_LOG.error('task: {} calling py file: {} fail to obtain result, error: {}'.format(
                self.task_name, self.file_path, error))
            task_logger.set_finish_time(TimeTool.get_current_time())
            task_logger.info(self.task_name, FAIL)
            result = CommonResult(output_data='execute file: {} failed'.format(self.file_path),
                                  error_code=1,
                                  description='{} call py file: {} with params: {} failed \n [ERROR] {}'.format(
                                      self.task_name, self.file_path, self.py_input, error))
            self.py_input = params_format_save
            return result

        result.set_output_data(res)
        task_logger.set_finish_time(TimeTool.get_current_time())
        task_logger.info(self.task_name, SUCCESS)
        self.py_input = params_format_save

        return result

import os
from pathlib import Path
import json
from importlib import import_module

from task_obj import CmdTask, UdsTask, ShellTask, PyTask
from tasks.audit_task import AuditTask
from tasks.log_query import QueryLogTask
from tasks.inspection.inspection_task import InspectionTask
from tasks.log_progress_query import QueryLogProgressTask
from tasks.logs_collections_task import LogsCollectionTask
from log_tool.om_log import DEPLOY_LOG

task_dir = {}  # 用于保存任务类，格式：{命令: 命令对应的类}


def build_uds_obj(recv_commend, commend_data):
    param_check = commend_data.get('paramCheck', {})
    rest_obj = UdsTask(task_name=recv_commend, handler='cantian', param_check_dict=param_check)

    param_check = commend_data.get('checkFunc')
    try:
        check_func = get_check_func(param_check)
    except Exception as error:
        DEPLOY_LOG.error('paramCheck format error in tasks.json element: {}'.format(recv_commend))
        raise error

    if check_func:
        rest_obj.param_check = check_func

    return rest_obj


def build_cmd_obj(recv_commend, commend_data):
    cmd_line = commend_data.get('cmd')
    param_check = commend_data.get('paramCheck', {})
    rest_obj = CmdTask(task_name=recv_commend, handler='cmd', cmd_line=cmd_line, param_check_dict=param_check)

    param_check = commend_data.get('checkFunc')
    try:
        check_func = get_check_func(param_check)
    except Exception as error:
        DEPLOY_LOG.error('paramCheck format error in tasks.json element: {}'.format(recv_commend))
        raise error

    if check_func:
        rest_obj.param_check = check_func

    return rest_obj


def build_shell_obj(recv_commend, commend_data):
    file_path = commend_data.get('filePath')
    sh_input = commend_data.get('sh_input')
    param_check = commend_data.get('paramCheck', {})
    rest_obj = ShellTask(task_name=recv_commend, handler='shell', file_path=file_path, sh_input=sh_input,
                         param_check_dict=param_check)

    param_check = commend_data.get('checkFunc')
    try:
        check_func = get_check_func(param_check)
    except Exception as error:
        DEPLOY_LOG.error('paramCheck format error in tasks.json element: {}'.format(recv_commend))
        raise error

    if check_func:
        rest_obj.param_check = check_func

    return rest_obj


def build_py_obj(recv_commend, commend_data):
    file_path = commend_data.get('filePath')
    py_input = commend_data.get('py_input')
    param_check = commend_data.get('paramCheck', {})
    rest_obj = PyTask(task_name=recv_commend, handler='py', file_path=file_path, py_input=py_input,
                      param_check_dict=param_check)

    param_check = commend_data.get('checkFunc')
    try:
        check_func = get_check_func(param_check)
    except Exception as error:
        DEPLOY_LOG.error('paramCheck format error in tasks.json element: {}'.format(recv_commend))
        raise error

    if check_func:
        rest_obj.param_check = check_func

    return rest_obj


def build_audit_obj(recv_commend, commend_data):
    file_path = commend_data.get('filePath')
    param_check = commend_data.get('paramCheck', {})
    rest_obj = AuditTask(task_name=recv_commend, handler='audit_py', file_path=file_path, py_input='',
                         params_check_dict=param_check)

    return rest_obj


def build_log_obj(recv_commend, commend_data):
    param_check = commend_data.get('paramCheck', {})
    rest_obj = QueryLogTask(task_name=recv_commend, handler='log', params_check_dict=param_check)
    return rest_obj


def build_inspection_obj(recv_commend, commend_data):
    param_check = commend_data.get('paramCheck', {})
    rest_odj = InspectionTask(task_name=recv_commend, handler="inspection_py", params_check_dict=param_check)
    return rest_odj


def build_log_progress_query_obj(recv_commend, commend_data):
    param_check = commend_data.get('paramCheck', {})
    query_obj = QueryLogProgressTask(task_name=recv_commend, handler='log_progress', params_check_dict=param_check)
    return query_obj


def build_logs_collection_obj(recv_commend, commend_data):
    log_path, input_param = commend_data.get('filePath'), commend_data.get('py_input')
    param_check = commend_data.get('paramCheck', {})
    logs_collect_obj = LogsCollectionTask(task_name=recv_commend,
                                          handler='log_py',
                                          file_path=log_path,
                                          py_input=input_param,
                                          params_check_dict=param_check)

    param_check = commend_data.get('checkFunc')
    try:
        check_func = get_check_func(param_check)
    except Exception as error:
        DEPLOY_LOG.error('paramCheck format error in tasks.json element: {}'.format(recv_commend))
        raise error

    if check_func:
        logs_collect_obj.param_check = check_func

    return logs_collect_obj


def get_check_func(param_check):
    check_path = param_check.split('.')
    if len(check_path) == 2:
        check_file_name, check_class_name = check_path
        check_func = getattr(import_module('checker.{}'.format(check_file_name)), check_class_name).check
        return check_func
    elif len(check_path) == 1 and not check_path[0]:
        return ''
    else:
        DEPLOY_LOG.error('filePath: {} in tasks.json with error format'.format(param_check))
        raise Exception('filePath: {} in tasks.json with error format'.format(param_check))


def load_tasks():
    dir_name, _ = os.path.split(os.path.abspath(__file__))
    task_config = str(Path('{}/tasks.json'.format(dir_name)))
    with open(task_config, 'r', encoding='utf8') as file_path:
        json_data = json.load(file_path)
        for recv_commend, commend_data in json_data.items():
            handler = commend_data.get('handler')

            try:
                task_dir[recv_commend] = BUILD_OBJ_FUNCS.get(handler)(recv_commend, commend_data)
            except Exception as error:
                DEPLOY_LOG.error('load task.json fail, error: {}'.format(error))
                raise error

    DEPLOY_LOG.info("load task.json success")


BUILD_OBJ_FUNCS = {
    'cantian': build_uds_obj,
    'cmd': build_cmd_obj,
    'shell': build_shell_obj,
    'py': build_py_obj,
    'audit_py': build_audit_obj,
    'log': build_log_obj,
    'inspection_py': build_inspection_obj,
    'log_progress': build_log_progress_query_obj,
    'log_py': build_logs_collection_obj
}

if __name__ == '__main__':
    input_params = {'key1': 'path/path/xxx.log', 'key2': 0}

    load_tasks()

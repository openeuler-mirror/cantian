import os
import json
import subprocess
import signal
from pathlib import Path
from logs_tool.log import LOGS_HANDLER_LOG as LOG

CUR_PATH, _ = os.path.split(os.path.abspath(__file__))
TIME_OUT = 300
FAIL = 1
DEPLOY_CONFIG = "/opt/cantian/config/deploy_param.json"


def file_reader(data_path):
    with open(data_path, 'r', encoding='utf-8') as file:
        info = file.read()
    return json.loads(info)


def get_param_value(key):
    config_param = file_reader(DEPLOY_CONFIG)
    return config_param.get(key)


def get_file_creation_time(file_path):
    ori_create_time = os.path.getctime(file_path)
    return int(round(ori_create_time * 1000))


def close_child_process(proc):
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError as err:
        _ = err
        return 'success'
    except Exception as err:
        return str(err)

    return 'success'


def shell_task(exec_cmd):
    """
    subprocess.Popen in python3.
    param cmd: commands need to execute
    return: status code, standard output, error output
    """
    bash_cmd = ["bash"]
    pobj = subprocess.Popen(bash_cmd, shell=False, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)
    pobj.stdin.write(exec_cmd.encode())
    pobj.stdin.write(os.linesep.encode())
    try:
        stdout, stderr = pobj.communicate(timeout=TIME_OUT)
    except Exception as err:
        return pobj.returncode, "", str(err)
    finally:
        return_code = pobj.returncode
        close_child_process(pobj)

    stdout, stderr = stdout.decode(), stderr.decode()
    if stdout[-1:] == os.linesep:
        stdout = stdout[:-1]
    if stderr[-1:] == os.linesep:
        stderr = stderr[:-1]

    return return_code, stdout, stderr


class LogsHandler:
    def __init__(self):
        self.config_params = file_reader(str(Path(CUR_PATH, 'config.json')))
        self.deploy_user = get_param_value("deploy_user")
        self.user_name = None

    def execute(self):
        for item in self.config_params:
            user = item.get('userandgroup') if \
                item.get('userandgroup') != "deploy_user" else self.deploy_user
            self.user_name = user.split(':')[0]
            log_file_dir, max_log_vol = item.get('log_file_dir'), int(item.get('max_log_vol'))

            # 分离日志目录和日志名
            log_content, log_name = os.path.split(log_file_dir)
            if not os.path.exists(log_content):
                continue
            files_names = os.listdir(log_content)
            log_name_pre = log_name.split(".")[0]
            for file_name in files_names:
                if log_name_pre in file_name and not file_name.endswith("tar.gz") and len(file_name) > len(log_name):
                    # 判断当前是否新新产生的归档日志，有就退出循环进行打包操作
                    break
            else:
                continue
            exec_cmd = f"su - {self.user_name} -s /bin/bash -c 'python3 {CUR_PATH}/do_compress_and_archive.py " \
                       f"{log_content} {log_name} {max_log_vol} {self.user_name}' "
            return_code, stdout, stderr = shell_task(exec_cmd)

            if return_code or stderr:
                LOG.error(f'failed to execute log cleanup of {log_content}, '
                          f'return_code: {return_code}, stderr: {stderr}')

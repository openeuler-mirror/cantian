import json
import os
import signal
import stat
import subprocess
import time
from functools import wraps


FAIL = 1
TIME_OUT = 5
cur_abs_path, _ = os.path.split(os.path.abspath(__file__))


def close_child_process(proc):
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError as err:
        _ = err
        return 'success'
    except Exception as err:
        return str(err)

    return 'success'


def retry(retry_times, log, task, wait_times):
    def decorate(func):

        @wraps(func)
        def wrapper(*args, **kwargs):
            err = ""
            for i in range(retry_times):
                try:
                    return func(*args, **kwargs)
                except Exception as _err:
                    log.info("Execute task[%s] %s/%s times", task, i + 1, retry_times)
                    err = _err
                    time.sleep(wait_times)
                    continue
            else:
                raise err
        return wrapper
    return decorate


def exec_popen(cmd, timeout=TIME_OUT):
    """
    subprocess.Popen in python3.
    param cmd: commands need to execute
    return: status code, standard output, error output
    """
    bash_cmd = ["bash"]
    pobj = subprocess.Popen(bash_cmd, shell=False, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)
    pobj.stdin.write(cmd.encode())
    pobj.stdin.write(os.linesep.encode())
    try:
        stdout, stderr = pobj.communicate(timeout=timeout)
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


def read_json_config(file_path):
    with open(file_path, "r") as f:
        return json.loads(f.read())


def write_json_config(file_path, data):
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    modes = stat.S_IWUSR | stat.S_IRUSR
    with os.fdopen(os.open(file_path, flags, modes), 'w') as fp:
        json.dump(data, fp, indent=4)


def file_reader(file_path):
    with open(file_path, 'r') as file:
        return file.read()


def get_status(status: str, status_class: object) -> str:
    for key, value in status_class.__dict__.items():
        if value == status:
            return key
    return status

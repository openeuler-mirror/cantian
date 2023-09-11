# -*- coding: UTF-8 -*-
import os
import stat
import json
import fcntl
import signal
import functools


def timeout(sec):
    def decorator(func):
        @functools.wraps(func)
        def wrapped_func(*args):
            def handle_timeout(signum, frame):
                err_msg = 'err_type: execution timeout, err_msg: ' \
                          'cmd "ctctl collection logs" timed out after {} minutes'.format(sec // 60)
                raise TimeoutError(err_msg)
            signal.signal(signal.SIGALRM, handle_timeout)
            signal.alarm(sec)
            try:
                result = func(*args)
            finally:
                signal.alarm(0)
            return result
        return wrapped_func
    return decorator


class LockFile:
    """持锁状态下对文件标识符进行修改"""
    @staticmethod
    def lock(handle):
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)

    @staticmethod
    def unlock(handle):
        fcntl.flock(handle, fcntl.LOCK_UN)


class RecordLogPackingProgress:
    def __init__(self, cur_path):
        self.record_file = os.path.join(cur_path, "log_packing_progress.json")
        self.clear_original_data()

    def clear_original_data(self):
        modes = stat.S_IWRITE | stat.S_IRUSR
        flags = os.O_WRONLY | os.O_TRUNC | os.O_CREAT
        with os.fdopen(os.open(self.record_file, flags, modes), "w", encoding="utf-8") as file:
            file.truncate()

    def record_cur_progress(self, time_interval, module, generate_type, state):
        start_time, end_time = time_interval
        status, err_type, percentage = state

        info_dict = dict()
        modes = stat.S_IWUSR | stat.S_IRUSR
        flags = os.O_WRONLY | os.O_CREAT
        with os.fdopen(os.open(self.record_file, flags, modes), "a", encoding="utf-8") as file:
            info_dict.update({"start_time": start_time})
            info_dict.update({"end_time": end_time})
            info_dict.update({"module_name": module})
            info_dict.update({"generate_type": generate_type})
            info_dict.update({"status": status})
            info_dict.update({"err_type":  err_type})
            info_dict.update({"percentage": percentage})
            file.write(json.dumps(info_dict) + "\n")

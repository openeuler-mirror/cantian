# -*- coding: UTF-8 -*-
import os
import sys
import argparse
from functools import wraps
from pathlib import Path

sys.path.append('/opt/cantian/ct_om/service')
sys.path.append('/opt/cantian/ct_om/service/ctmgr')

from ctmgr.logs_collection.tools import LockFile
from ctmgr.log_tool.om_log import LOGS_COLLECTION as LOG
from ctmgr.logs_collection.logs_collection import LogsCollection

parser = argparse.ArgumentParser(description='Required parameters for running this script')
parser.add_argument('--path', '-p', help='path to save all tar.gz bags', required=True)
parser.add_argument('--type', '-t', help='recent: recent logs, all: all logs', required=True)
p_args = parser.parse_args()

cur_abs_path, _ = os.path.split(os.path.abspath(__file__))


def exter_attack(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    return wrapper


@exter_attack
def main(target_path, mode):
    file_flag_path = str(Path(cur_abs_path, "file_flag"))

    lock_file = LockFile()
    file_handler = open(file_flag_path, "r")
    try:
        lock_file.lock(file_handler)
    except IOError:
        LOG.info('there is already a log collection process, another process[pid:{}]'
                 'try to lock the file, but failed.'.format(os.getpid()))
        print('there is already a log collection process, please try again later...')
    else:
        LOG.info('success to lock the file, current process id:{}'.format(os.getpid()))
        execute(mode, target_path)
        print('log collection ends, use [ctctl logs progress query] to get log collection details')
    finally:
        lock_file.unlock(file_handler)
        file_handler.close()


def execute(mode, target_path):
    logs_collection = LogsCollection()
    try:
        logs_collection.execute(target_path, mode)
    except TimeoutError as err:
        LOG.error("[logs collection timeout], error_msg: {}".format(str(err)))
        logs_collection.exception_handler(target_path)


if __name__ == "__main__":
    target, mode_flag = p_args.path, p_args.type
    main(target, mode_flag)

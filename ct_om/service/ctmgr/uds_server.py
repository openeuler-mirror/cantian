import socket
import sys
import os
import ast
import time
import struct
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

import task
from log_tool.om_log import LOGGER, DEPLOY_LOG, TASK_LOG
from common.output_tool import CommonResult

threadPool = ThreadPoolExecutor(max_workers=5)
task_dir = task.task_dir

dir_name, _ = os.path.split(os.path.abspath(__file__))
SERVER_ADDRESS = str(Path('{}/../ct_om.sock'.format(dir_name)))
SOCKET_FAMILY = socket.AF_UNIX
SOCKET_TYPE = socket.SOCK_STREAM

KEEP_LISTEN = True
RECEIVE_DATA_SIZE = 1024
USER_UID = (6004,)


def get_socket_msg(conn, client_addr):
    credit = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
    # input_json为字符串类型json："{'command': 'show cantina statu', 'param': {}}"
    input_json = conn.recv(RECEIVE_DATA_SIZE).decode()

    pid, uid, gid = struct.unpack('3i', credit)
    if int(uid) not in USER_UID:
        result = CommonResult(output_data='uid from client is not correct', error_code=1,
                              description='current uid from client is {}'.format(uid))
        conn.sendall(result.__str__().encode())
    else:
        begin_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
        task_log = LOGGER(client_pid=pid, client_uid=uid, begin_time=begin_time)
        result = execute_task(input_json, task_log)  # 接收cli命令并进行预检验，执行
        conn.sendall(result.__str__().encode())


def server_socket():
    sock = socket.socket(SOCKET_FAMILY, SOCKET_TYPE)
    # 如果套接字存在，删除套接字
    if os.path.exists(SERVER_ADDRESS):
        os.unlink(SERVER_ADDRESS)
    # 绑定套接字
    if sock.bind(SERVER_ADDRESS):
        DEPLOY_LOG.error('socket bind error, SERVER_ADDRESS: {}'.format(SERVER_ADDRESS))
        raise Exception('socket bind error, SERVER_ADDRESS: {}'.format(SERVER_ADDRESS))
    else:
        DEPLOY_LOG.info('socket bind success, address is {}'.format(SERVER_ADDRESS))

    if sock.listen(1):
        DEPLOY_LOG.error('socket listen error')
        raise Exception('socket listen error')

    DEPLOY_LOG.info('socket listen begin')

    while KEEP_LISTEN:
        connection, client_address = sock.accept()
        threadPool.submit(get_socket_msg, connection, client_address)

    sock.close()


def execute_task(input_data, task_log):
    input_data_dict = ast.literal_eval(input_data)
    command = input_data_dict.get('command')
    input_params_dict = input_data_dict.get('param')

    if command not in task_dir.keys():
        task_log.error(cmd=command, result='fail')
        result = CommonResult(output_data='execute {} failed'.format(command), error_code=1,
                              description='cli command: {} not valid'.format(command))
        return result

    task_obj = task_dir[command]
    if task_obj.param_check(input_params_dict):
        try:
            result = task_obj.task_execute(input_params_dict, task_log)
        except Exception as err:
            exc_type, exc_value, exc_tb = sys.exc_info()
            TASK_LOG.error("exece command: %s faild, inner error is: %s, detial is %s" %
                           (command, str(err), str((exc_type, exc_value, exc_tb))))
            task_log.error(cmd=command, result='fail')
            result = CommonResult(output_data='execute {} failed'.format(command), error_code=1,
                                  description='param check failed for command: {}'.format(command))
            return result

    else:
        task_log.error(cmd=command, result='fail')
        result = CommonResult(output_data='execute {} failed'.format(command), error_code=1,
                              description='param check failed for command: {}'.format(command))

    return result


if __name__ == '__main__':
    task.load_tasks()
    server_socket()

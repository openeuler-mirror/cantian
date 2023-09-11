import json
import socket

from log_tool.om_log import TASK_LOG
from common.output_tool import CommonResult

SERVER_ADDRESS = ''
SOCKET_TYPE = socket.SOCK_STREAM
SOCKET_FAMILY = socket.AF_UNIX

RECEIVE_DATA_SIZE = 1024


def client_socket(send_data):
    result = CommonResult()

    sock = socket.socket(SOCKET_FAMILY, SOCKET_TYPE)

    try:
        sock.connect(SERVER_ADDRESS)
    except socket.error as error:
        TASK_LOG.error('client connect failed, error: {}'.format(error))
        return CommonResult(output_data='client connect failed', error_code=1,
                            description='connect failed, error: {}'.format(error))

    try:
        sock.sendall(json.dumps(send_data).encode())
    except socket.error as error:
        result = CommonResult(output_data='uds request failed', error_code=1,
                              description='send data error: {}'.format(error))
        return result

    try:
        recv_data = sock.recv(RECEIVE_DATA_SIZE).decode()
    except socket.error as error:
        result = CommonResult(output_data='uds request failed', error_code=1,
                              description='receive data error: {}'.format(error))
        TASK_LOG.error('send/receive data error: {}'.format(error))
        return result

    result.set_output_data(recv_data)
    TASK_LOG.info("recv data from server '{}': {}".format(SERVER_ADDRESS, recv_data))

    sock.close()
    return result


if __name__ == '__main__':
    client_socket('{"command": "show cantina status", "param": {}}')

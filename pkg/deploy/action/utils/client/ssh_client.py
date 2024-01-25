import time
import os
import sys
import pathlib
import paramiko

CUR_PATH, _ = os.path.split(os.path.abspath(__file__))
sys.path.append(str(pathlib.Path(CUR_PATH).parent.parent))

from om_log import REST_LOG as logger


SSH_RECV_BUFFER = 65535


def convert(code):
    """
    python3 bytes字符转str
    :param code:
    :return:
    """
    code = code.decode('utf-8', errors='ignore') if isinstance(code, bytes) else code
    return code


class SshClient(object):
    def __init__(self, ip, username, passwd, root_passwd=None, port=22):
        self.username = username
        self.passwd = passwd
        self.root_pwd = root_passwd
        self.ip = ip
        self.port = port
        self.ssh_client = dict()

    @staticmethod
    def _ssh_client_close(trans):
        try:
            if trans:
                trans.close()
        except Exception as ex:
            logger.error("failed to close connection after creating SSH client failed: {}."
                         .format(ex))

    def create_client(self, timeout=180, width=300):
        trans = None
        try:
            trans = self._ssh_client_create(timeout, width)
        except Exception as err:
            self._ssh_client_close(trans)
            err_msg = "Creating SSH failed, the error is %s" % str(err)
            raise Exception(err_msg) from err

    def execute_cmd(self, cmd, expect, timeout=180):
        output = ""
        session = self.ssh_client["channel"]
        session.send(cmd + "\n")
        time.sleep(1)
        t = 0
        interval = 0.5
        while not output.endswith(expect) and t < timeout:
            time.sleep(interval)
            t += interval
            if session.closed:
                output += convert(session.recv(SSH_RECV_BUFFER).decode('utf-8')).\
                    replace(' \r', '\r').replace('\r', '')
                break
            if not session.recv_ready():
                continue
            output += convert(session.recv(SSH_RECV_BUFFER).decode('utf-8')).\
                replace(' \r', '\r').replace('\r', '')
        return output

    def close_client(self):
        try:
            if self.ssh_client and isinstance(self.ssh_client, dict) and 'client' in self.ssh_client:
                self.ssh_client['client'].close()
            if self.ssh_client and isinstance(self.ssh_client, dict) and 'sshClient' in self.ssh_client:
                self.ssh_client['sshClient'].close()
        except Exception as err:
            err_msg = "Close ssh client err, details:%s" % str(err)
            logger.error(err_msg)
            raise Exception(err_msg) from err

    def _ssh_client_create(self, timeout, width):
        logger.info("Create ssh client host[%s]" % self.ip)
        trans = paramiko.Transport((self.ip, self.port))
        try:
            trans.connect(username=self.username, password=self.passwd)
        except Exception as err:
            err_mgs = "Create ssh client failed, details: %s" % str(err)
            logger.info(err_mgs)
            raise Exception(err_mgs) from err
        trans.set_keepalive(30)
        channel = trans.open_session()
        channel.settimeout(timeout)
        channel.get_pty(width=width)
        channel.invoke_shell()
        stdout = channel.makefile('r', -1)
        self.ssh_client['ip'] = self.ip
        self.ssh_client['port'] = self.port
        self.ssh_client['username'] = self.username
        self.ssh_client['timeout'] = timeout
        self.ssh_client['width'] = width
        self.ssh_client['client'] = trans
        self.ssh_client['channel'] = channel
        self.ssh_client['stdout'] = stdout
        logger.info("Create ssh client host[%s] success" % self.ip)
        return trans

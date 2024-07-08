import os
import pty
import subprocess
import sys
import time
import select
import argparse
import getpass
import shlex

LOCK_INSTANCE_FOR_BACKUP_TIMEOUT = 100000

class MysqlShell:
    def __init__(self, mysql_cmd, user, password='', database=None, host=None, port=None, socket=None):
        self.mysql_cmd = mysql_cmd
        self.user = user
        self.password = password
        self.database = database
        self.host = host
        self.port = port
        self.socket = socket
        self.master_fd = None
        self.process = None

    def start_session(self, timeout=10):
        cmd = shlex.split(self.mysql_cmd) + ['-u', self.user]
        if self.password:
            cmd.append('-p' + self.password)
        else:
            cmd.append('--skip-password')
        if self.database:
            cmd.extend(['-D', self.database])
        if self.host:
            cmd.extend(['--host', self.host])
        if self.port:
            cmd.extend(['--port', str(self.port)])
        if self.socket:
            cmd.extend(['--socket', self.socket])

        self.master_fd, slave_fd = pty.openpty()
        self.process = subprocess.Popen(cmd, stdin=slave_fd, stdout=slave_fd, stderr=slave_fd, close_fds=True)

        # 检查连接是否成功
        try:
            self._read_output(timeout)
        except TimeoutError:
            raise TimeoutError("Failed to connect to MySQL: connection timed out.")
        except Exception as e:
            raise Exception(f"Failed to connect to MySQL: {e}")

    def _read_output(self, timeout=None):
        output = []
        start_time = time.time()
        while True:
            if timeout and (time.time() - start_time) > timeout:
                raise TimeoutError("Command execution timed out.")
            try:
                if self.master_fd in select.select([self.master_fd], [], [], 1)[0]:
                    data = os.read(self.master_fd, 1024).decode()
                    output.append(data)
                    if 'mysql>' in data:
                        break
                    elif 'Access denied' in data:
                        raise Exception("Access denied for user.")
            except OSError:
                break
            time.sleep(0.1)
        return ''.join(output)

    def execute_command(self, command, timeout=None):
        if self.process is not None:
            os.write(self.master_fd, (command + ";\n").encode())
            return self._read_output(timeout=timeout)
        else:
            raise Exception("MySQL session is not started")

    def close_session(self, timeout=10):
        try:
            if self.process is not None:
                os.write(self.master_fd, b'exit\n')
                start_time = time.time()
                while self.process.poll() is None:
                    if (time.time() - start_time) > timeout:
                        raise TimeoutError("Closing session timed out.")
                    time.sleep(0.1)
        except TimeoutError as e:
            print(f"Error: {e}, forcefully terminating the process")
            self.process.kill()
            self.process.wait()
        finally:
            os.close(self.master_fd)
            self.master_fd = None


def lock_instance_for_backup():
    parser = argparse.ArgumentParser(description='Lock MySQL instance for backup.')
    parser.add_argument('--mysql_cmd', type=str, required=True, help='Path to mysql executable')
    parser.add_argument('--user', type=str, required=True, help='MySQL username')
    parser.add_argument('--host', type=str, help='MySQL host')
    parser.add_argument('--port', type=int, help='MySQL port')
    parser.add_argument('--database', type=str, help='Database name')
    parser.add_argument('--socket', type=str, help='MySQL socket')

    args = parser.parse_args()

    # 从标准输入读取密码
    password = input("Enter MySQL password: ").strip()

    # 创建 MySQL shell 会话,启动会话
    mysql_shell = MysqlShell(
        mysql_cmd=args.mysql_cmd,
        user=args.user,
        password=password,
        database=args.database,
        host=args.host,
        port=args.port,
        socket=args.socket
    )
    try:
        mysql_shell.start_session()
    except Exception as e:
        print(f"Error: Failed to start MySQL shell session: {e}")
        sys.exit(1)

    print(f"Process ID: {os.getpid()}")

    try:
        output = mysql_shell.execute_command("set @ctc_ddl_enabled=true", timeout=3)
        print("output: ", output, flush=True)
        if "Query OK" not in output:
            mysql_shell.close_session()
            sys.exit(1)
        output = mysql_shell.execute_command("lock instance for backup", timeout=3)
        print("output: ", output, flush=True)
        if "Query OK" not in output:
            mysql_shell.close_session()
            sys.exit(1)
    except TimeoutError as e:
        print("Error: LOCK INSTANCE FOR BACKUP timed out.")
        mysql_shell.close_session()
        sys.exit(1)

    start_time = time.time()

    try:
        while time.time() - start_time < LOCK_INSTANCE_FOR_BACKUP_TIMEOUT:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Session terminated by user.")

    output = mysql_shell.execute_command("UNLOCK INSTANCE")
    print("UNLOCK INSTANCE output:\n", output)

    mysql_shell.close_session(timeout=10)


if __name__ == '__main__':
    lock_instance_for_backup()

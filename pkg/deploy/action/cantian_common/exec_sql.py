import subprocess
import sys
import os
import signal
CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(CURRENT_PATH, "../"))
from cantian_common.crypte_adapter import KmcResolve


ZSQL_INI_PATH = '/mnt/dbdata/local/cantian/tmp/data/cfg/ctsql.ini'
TIME_OUT = 5


def file_reader(file_path):
    with open(file_path, 'r') as file:
        return file.read()


def close_child_process(proc):
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError as err:
        _ = err
        return 'success'
    except Exception as err:
        return str(err)

    return 'success'


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


class ExecSQL(object):
    def __init__(self, sql):
        self.sql = sql

    def decrypted(self):
        ctsql_ini_data = file_reader(ZSQL_INI_PATH)
        encrypt_pwd = ctsql_ini_data[ctsql_ini_data.find('=') + 1:].strip()
        ctsql_passwd = KmcResolve.kmc_resolve_password("decrypted", encrypt_pwd)
        return ctsql_passwd

    def execute(self):
        ctsql_passwd = self.decrypted()
        sql = ("source ~/.bashrc && echo -e \"%s\" | "
               "ctsql sys@127.0.0.1:1611 -q -c \"%s\"") % (ctsql_passwd, self.sql)
        return_code, stdout, stderr = exec_popen(sql)
        if return_code:
            output = stdout + stderr
            err_msg = "Exec [%s] failed, details: %s" % (self.sql, output.replace(ctsql_passwd, "***"))
            raise Exception(err_msg)
        return stdout


if __name__ == '__main__':
    _sql_cmd = input()
    exec_sql = ExecSQL(_sql_cmd)
    try:
        print(exec_sql.execute())
    except Exception as e:
        exit(str(e))


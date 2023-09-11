import os
import signal
import subprocess
from exporter.log import EXPORTER_LOG as LOG

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


def _exec_popen(cmd):
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
        stdout, stderr = pobj.communicate(timeout=TIME_OUT)
    except Exception as err:
        return pobj.returncode, "", str(err)
    finally:
        return_code = pobj.returncode
        kill_fork_process_res = close_child_process(pobj)

    if kill_fork_process_res != "success":
        return FAIL, "", "kill fork process failed, err_details: {}".format(kill_fork_process_res)

    stdout, stderr = stdout.decode(), stderr.decode()
    if stdout[-1:] == os.linesep:
        stdout = stdout[:-1]
    if stderr[-1:] == os.linesep:
        stderr = stderr[:-1]

    return return_code, stdout, stderr


class SimpleSql:
    def __init__(self):
        self.sql_statement = None
        self.node_id = None
        self.sql_sh_path = None
        self.time_out = 5
        self.zsql_ip_addr = '127.0.0.1'
        self.zsql_port = '1611'

    def update_sys_data(self, cur_node_id):
        self.node_id = cur_node_id

    def query(self, select, source_from, where=None):
        select_item = [item.upper() for item in select]
        source_item = 'FROM {}'.format(source_from.upper())
        where_item = " WHERE {}='{}'".format(where[0], where[1]) if where else ''
        self.sql_statement = 'SELECT {} {}{};'.format(','.join(select_item), source_item, where_item)

        exec_cmd = "zsql sys@{}:{} -q -c \"{}\"".format(self.zsql_ip_addr,
                                                        self.zsql_port, self.sql_statement)
        return_code, stdout, stderr = _exec_popen('source ~/.bashrc&&{}'.format(exec_cmd))

        if return_code:
            LOG.error("[sql shell task] node {} execute cmd '{}' "
                      "failed, err: {}".format(self.node_id, self.sql_statement, str(stderr)))

        return return_code, stdout

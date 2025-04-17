import os
import signal
import subprocess

TIME_OUT = 60
FAIL = 1


def close_child_process(proc):
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError as err:
        _ = err
        return 'success'
    except Exception as err:
        return str(err)

    return 'success'


def exec_popen(cmd):
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
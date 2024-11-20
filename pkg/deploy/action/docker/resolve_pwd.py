import sys
import os
import subprocess

CUR_PATH = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CUR_PATH, "../dbstor"))
from kmc_adapter import CApiWrapper

NEW_MARK = "/"


def _exec_popen(cmd, values=None):
    """
    subprocess.Popen in python2 and 3.
    :param cmd: commands need to execute
    :return: status code, standard output, error output
    """
    if not values:
        values = []
    bash_cmd = ["bash"]
    pobj = subprocess.Popen(bash_cmd, shell=False, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    pobj.stdin.write(cmd.encode())
    pobj.stdin.write(os.linesep.encode())
    for value in values:
        pobj.stdin.write(value.encode())
        pobj.stdin.write(os.linesep.encode())
    try:
        stdout, stderr = pobj.communicate(timeout=1800)
    except subprocess.TimeoutExpired as err_cmd:
        pobj.kill()
        return -1, "Time Out.", str(err_cmd)
    stdout = stdout.decode()
    stderr = stderr.decode()
    if stdout[-1:] == os.linesep:
        stdout = stdout[:-1]
    if stderr[-1:] == os.linesep:
        stderr = stderr[:-1]

    return pobj.returncode, stdout, stderr


def resolve_kmc_pwd(encrypt_pwd):
    primary_keystore = "/opt/cantian/common/config/primary_keystore_bak.ks"
    standby_keystore = "/opt/cantian/common/config/standby_keystore_bak.ks"
    kmc_adapter = CApiWrapper(primary_keystore, standby_keystore)
    kmc_adapter.initialize()
    try:
        passwd = kmc_adapter.decrypt(encrypt_pwd)
    except Exception as error:
        raise Exception("Failed to decrypt password of user [sys]. Error: %s" % str(error)) from error
    split_env = os.environ['LD_LIBRARY_PATH'].split(":")
    filtered_env = [single_env for single_env in split_env if "/opt/cantian/dbstor/lib" not in single_env]
    os.environ['LD_LIBRARY_PATH'] = ":".join(filtered_env)
    return passwd


def resolve_check_cert_pwd(encrypt_pwd):
    passwd = resolve_kmc_pwd(encrypt_pwd)
    cmd = f"echo -e '{passwd}' | python3 -B '{CUR_PATH}'/../implement/check_pwd.py check_cert_pwd"
    ret_code, _, stderr = _exec_popen(cmd)
    stderr = str(stderr)
    stderr.replace(passwd, "****")
    if ret_code:
        raise Exception("Cert file or passwd check failed. output:%s" % str(stderr))


def kmc_to_ctencrypt_pwd(encrypt_pwd):
    passwd = resolve_kmc_pwd(encrypt_pwd)
    cmd = f"source ~/.bashrc && echo -e \"{passwd}\\n{passwd}\" | ctencrypt -e PBKDF2 | awk -F 'Cipher:' '{{print $2}}'"
    ret_code, stdout, stderr = _exec_popen(cmd)
    stderr = str(stderr)
    stderr.replace(passwd, "****")
    if ret_code:
        raise Exception("failed to get _SYS_PASSWORD by ctencrypt. output:%s" % str(stderr))
    return stdout


def run_upgrade_modify_sys_tables_ctsql(encrypt_pwd):
    sql_file_path = input()
    ip = input()
    port = input()
    passwd = resolve_kmc_pwd(encrypt_pwd)
    try:
        with open(sql_file_path, 'r') as sql_file:
            sql = ""
            line = sql_file.readline()
            while line:
                if line == NEW_MARK:
                    cmd = "ctsql sys/{}@{}:{} -q -c {}".format(passwd, ip, port, sql)
                    ret_code, stdout, stderr = _exec_popen(cmd)
                    # for reupdate sys table when crashed, if the error code represents that an entry already exists, do not return error
                    # CT-00743 is like: entry id 1044 already exists, this is not caused by reupdate,
                    # but because of wrong sys table id (wrong sql), thus still need to return error
                    if ret_code:
                        if (not "exist" in stderr) or (stderr.startswith("CT-00743")):
                            return str(stderr)
                    sql = ""
                else:
                    sql += line
                line = sql_file.readline()
    except Exception as err:
        return "Error when running upgrade modify sys tables ctsql, {}".format(str(err))


if __name__ == "__main__":
    action = sys.argv[1]
    encrypt_pwd = sys.argv[2]
    options = {
        "resolve_check_cert_pwd": resolve_check_cert_pwd,
        "kmc_to_ctencrypt_pwd": kmc_to_ctencrypt_pwd,
        "run_upgrade_modify_sys_tables_ctsql": run_upgrade_modify_sys_tables_ctsql,
        "resolve_kmc_pwd": resolve_kmc_pwd
    }
    print(options.get(action)(encrypt_pwd.strip()))
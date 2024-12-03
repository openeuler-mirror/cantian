import getpass
import json
import os
import shutil
import sys
import time
import importlib.util
import signal
import subprocess
import traceback
import pwd
import grp

from get_config_info import get_value
from resolve_pwd import resolve_kmc_pwd

CUR_PATH = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(CUR_PATH, ".."))
from om_log import LOGGER as LOG


OPT_CONFIG_PATH = "/opt/cantian/config"
SCRIPT_PATH = os.path.join(CUR_PATH, "..")
CONFIG_PATH = os.path.join(SCRIPT_PATH, "../config")
DORADO_CONF_PATH = "/ctdb/cantian_install/cantian_connector/config/container_conf/dorado_conf"
DM_USER = "DMUser"
DM_PWD = "DMPwd"


def init_get_info_fun():
    try:
        get_info_path = os.path.join(CUR_PATH, "../get_config_info.py")
        spec = importlib.util.spec_from_file_location("get_info_from_config", get_info_path)
        get_info_from_config = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(get_info_from_config)
        get_info = get_info_from_config.get_value
        return get_info
    except Exception as e:
        LOG.error(f"init get_info fun failed {e}, traceback: {traceback.format_exc(limit=-1)}")
        return None


get_info = init_get_info_fun()
if get_info is None:
    LOG.error("init get_info fun failed")


def copy_file(source, dest):
    if os.path.exists(dest):
        os.remove(dest)
    shutil.copy(source, dest)


def get_file_content(file_path):
    with open(file_path, "r") as f:
        return f.read()


def get_file_json(file_path):
    with open(file_path, "r") as f:
        return json.load(f)


def chown(file_path, u_id, g_id):
    os.chown(file_path, u_id, g_id)
    if os.path.isdir(file_path):
        for root, dirs, files in os.walk(file_path):
            for dir in dirs:
                chown(os.path.join(root, dir), u_id, g_id)
            for file in files:
                os.chown(os.path.join(root, file), u_id, g_id)


def close_child_process(proc):
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError as err:
        _ = err
        return 'success'
    except Exception as err:
        return str(err)

    return 'success'


def exec_popen(cmd, timeout=None):
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
    if not timeout:
        stdout, stderr = pobj.communicate()
        return_code = pobj.returncode
    else:
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


def execute_command(command, raise_flag=False, timeout=None):
    code, out, err = exec_popen(command, timeout=timeout)
    if code:
        if "echo" in command:
            command = command.split("|", 1)[1]
        LOG.error(f"execute cmd[{command}] failed, err[{err}], out[{out}].")
        if raise_flag:
            raise Exception(f"execute cmd[{command}] failed, err[{err}], out[{out}.")
    print(out)
    return code, out, err


def get_dm_password():
    password_file = os.path.join(DORADO_CONF_PATH, DM_PWD)
    if not os.path.exists(password_file):
        LOG.error("DM password file not found.")
        raise Exception("get dm password file not found.")

    encode_dm_password = get_file_content(password_file)
    decode_dm_password = resolve_kmc_pwd(encode_dm_password)
    return decode_dm_password


def get_dr_status(dm_password=None):
    if not dm_password:
        dm_password = get_dm_password()
    if dm_password == "":
        LOG.error("DM Password is empty.")
    cmd = (f"echo -e '{dm_password}' | sh {SCRIPT_PATH}/appctl.sh dr_operate progress_query "
           f"--action=check --display=table 2>&1 | grep -E '^\-|^\|'")
    execute_command(cmd, raise_flag=True, timeout=30)
    data_json = get_file_json(os.path.join(CONFIG_PATH, "dr_status.json"))
    return data_json.get("dr_status")


def check_dr_deploy_process_completed(role):
    max_iterations = 180
    if role == "standby":
        max_iterations *= 10
    count = 1
    last_status = ""
    dr_process_file = os.path.join(CONFIG_PATH, "dr_process_record.json")
    step = 0
    while count <= max_iterations:
        time.sleep(5)
        process_data = get_file_json(dr_process_file)
        dr_status = process_data.get("data").get("dr_deploy")

        if dr_status == "success":
            LOG.info("executing dr_deploy success.")
            return True
        elif dr_status == "failed":
            LOG.info("executing dr_deploy failed.")
            return False
        elif dr_status == "running":
            for index, key in enumerate(list(process_data.get("data").keys())[:-1]):
                status = process_data.get("data").get(key)
                if last_status:
                    if index < step:
                        continue
                if status != "default":
                    if status == "failed":
                        LOG.error(f"dr_deploy {key}: {status}.")
                        return False
                    if last_status != status:
                        LOG.info(f"dr_deploy {key}: {status}")
                        last_status = status
                        step = index
                        continue
                    elif step != index:
                        LOG.info(f"dr_deploy {key}: {status}")
                        step = index
                        continue
                    break
        else:
            LOG.info("Unexpected status for dr_deploy.")
            return False
        count += 1
    LOG.info("Timeout reached without success.")
    return False


def dr_deploy(role=None, dm_password=None, mysql_pwd=''):
    if not dm_password:
        dm_password = get_dm_password()
    if dm_password == "":
        LOG.error("DM Password is empty.")
        raise Exception("get dm_password failed.")
    if not role:
        role = get_value("dr_deploy.role")
    cmd = (f"echo -e '{dm_password}' | sh {SCRIPT_PATH}/appctl.sh dr_operate pre_check {role} "
           f"--conf=/opt/cantian/config/deploy_param.json")
    execute_command(cmd, raise_flag=True, timeout=300)
    LOG.info("dr_operate pre_check success.")

    dr_process_file = os.path.join(CONFIG_PATH, "dr_process_record.json")
    if os.path.exists(dr_process_file):
        os.remove(dr_process_file)

    cmd = (f"echo -e '{dm_password}\n{mysql_pwd}' | sh {SCRIPT_PATH}/appctl.sh dr_operate deploy {role} "
           f"--mysql_cmd='mysql' --mysql_user=root")
    execute_command(cmd, raise_flag=True)

    if check_dr_deploy_process_completed(role):
        LOG.info("dr_deploy succeeded.")
        sys.exit(0)
    sys.exit(1)


def copy_version_yaml(deploy_user, deploy_group):
    deploy_user_info = pwd.getpwnam(deploy_user)
    deploy_group_info = grp.getgrnam(deploy_group)
    u_id = deploy_user_info.pw_uid
    g_id = deploy_group_info.gr_gid
    version_file = os.path.join(SCRIPT_PATH, "../versions.yml")
    chown(version_file, u_id, g_id)
    storage_share_fs = get_value("storage_share_fs")
    cmd = (f'su -s /bin/bash - "{deploy_user}" -c "dbstor --create-file '
           f'--fs-name={storage_share_fs} --source-dir={version_file} --file-name=versions.yml"')
    execute_command(cmd, timeout=180)


def start_mysqld(deploy_user=None, deploy_group=None):
    if not deploy_user:
        deploy_user = get_value("deploy_user")
    if not deploy_group:
        deploy_group = get_info("deploy_group")
    LOG.info(f"Begin to start mysqld.")
    cmd = (f"su -s /bin/bash - {deploy_user} -c 'python3 "
           f"-B /opt/cantian/image/cantian_connector/CantianKernel/Cantian-DATABASE-CENTOS-64bit/install.py "
           f"-U {deploy_user}:{deploy_group} -l /home/{deploy_user}/logs/install.log "
           f"-M mysqld -m /opt/cantian/image/cantian_connector/cantian-connector-mysql/scripts/my.cnf -g withoutroot'")
    execute_command(cmd, raise_flag=True, timeout=300)
    LOG.info(f"start mysqld success.")


def dr_start_deploy():
    role = get_value("dr_deploy.role")
    dm_password = get_dm_password()
    deploy_mode = get_value("deploy_mode")
    deploy_user = get_value("deploy_user")
    deploy_group = get_info("deploy_group")
    count = 0
    if deploy_mode == "dbstor":
        storage_fs = get_value("storage_share_fs")
        cmd = (f"su -s /bin/bash - {deploy_user} -c 'dbstor --query-file "
               f"--fs-name={storage_fs} --file-path=/' | grep 'dr_deploy_param.json' | wc -l")
        code, count, err = execute_command(cmd, timeout=180)
    else:
        storage_fs = get_value("storage_metadata_fs")
        if os.path.exists(f"/mnt/dbdata/remote/metadata_{storage_fs}/dr_deploy_param.json"):
            count = 1
    if not count.isdigit():
        LOG.error("get file count failed.")
        sys.exit(1)

    if int(count) > 0:
        deploy_user_info = pwd.getpwnam(deploy_user)
        deploy_group_info = grp.getgrnam(deploy_group)
        u_id = deploy_user_info.pw_uid
        g_id = deploy_group_info.gr_gid
        os.chown(OPT_CONFIG_PATH, u_id, g_id)
        if deploy_mode == "dbstor":
            cmd = (f"su -s /bin/bash - {deploy_user} -c 'dbstor --copy-file --fs-name={storage_fs} "
                   f"--source-dir=/ --target-dir={OPT_CONFIG_PATH} --file-name=dr_deploy_param.json'")
            execute_command(cmd, timeout=180)
        else:
            copy_file(f"/mnt/dbdata/remote/metadata_{storage_fs}/dr_deploy_param.json",
                      f"{OPT_CONFIG_PATH}/dr_deploy_param.json")
        copy_file(f"{OPT_CONFIG_PATH}/dr_deploy_param.json", f"{CONFIG_PATH}/dr_deploy_param.json")
        if get_dr_status(dm_password) != "Normal":
            msg = ("DR status is Abnormal. If you need, "
                   "please enter the container and manually execute the Dr_deploy process.")
            LOG.error(msg)

        cmd = f"sh {SCRIPT_PATH}/appctl.sh start"
        execute_command(cmd, raise_flag=True, timeout=3600)
        if get_value("cantian_in_container") == "1" and get_value("M_RUNING_MODE") != "cantiand_with_mysql_in_cluster":
            start_mysqld(deploy_user, deploy_group)
    else:
        if role == "active":
            cmd = f"sh {SCRIPT_PATH}/appctl.sh start"
            execute_command(cmd, raise_flag=True, timeout=3600)
            if (get_value("cantian_in_container") == "1" and
                    get_value("M_RUNING_MODE") != "cantiand_with_mysql_in_cluster"):
                start_mysqld(deploy_user, deploy_group)
            copy_version_yaml(deploy_user, deploy_group)
        LOG.info("dr_setup is True, executing dr_deploy tasks.")
        dr_deploy(role=role, dm_password=dm_password)
    LOG.info("DR_deploy Already executed.")
    sys.exit(0)


def main():
    split_env = os.environ['LD_LIBRARY_PATH'].split(":")
    if "/opt/cantian/dbstor/lib" not in split_env:
        LOG.error(f"cantian-dbstor-lib not found, current envpath[{os.environ['LD_LIBRARY_PATH']}]")
        raise Exception("cantian-dbstor-lib not found")

    action_dict = {
        "get_dm_password": get_dm_password,
        "get_dr_status": get_dr_status,
        "start": dr_start_deploy
    }
    mysql_pwd = ''
    if len(sys.argv) == 1:
        mysql_pwd = getpass.getpass("Please input mysql login passwd:")

    if len(sys.argv) > 1:
        if sys.argv[1] in action_dict:
            return action_dict[sys.argv[1]]()
    dr_deploy(mysql_pwd=mysql_pwd)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        LOG.error(f"execute failed, err[{str(e)}], traceback: [{traceback.format_exc(limit=-1)}]")
        sys.exit(1)


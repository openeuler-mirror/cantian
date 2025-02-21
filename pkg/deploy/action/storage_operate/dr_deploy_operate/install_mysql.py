import tarfile
import shutil
import os
import re
import pwd
import grp

from get_config_info import get_value
from cantian_common.exec_sql import exec_popen
from om_log import DR_DEPLOY_LOG as LOG

CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(CURRENT_PATH, "../../../../"))
MYSQL_INSTALL_PATH = "/opt/cantian/mysql/install"
WORKDIR = '/opt/cantian/image/cantian_connector/cantian-connector-mysql/mysql_bin/'

def get_file_name(file_patten):
    files = os.listdir(ROOT_DIR)
    for file in files:
        match_files = re.findall(file_patten, file)
        if match_files:
            return match_files[0]
    else:
        err_msg = "Path[%s] has no package[%s], please check." % (ROOT_DIR, file_patten)
        LOG.error(err_msg)
        raise Exception(err_msg)


def get_u_g_id():
    deploy_user = get_value("deploy_user")
    deploy_group = get_value("deploy_group")
    deploy_user_info = pwd.getpwnam(deploy_user)
    deploy_group_info = grp.getgrnam(deploy_group)
    u_id = deploy_user_info.pw_uid
    g_id = deploy_group_info.gr_gid
    return u_id, g_id


def execute_meta():
    LOG.info("Begin to install mysql, deploy mode meta.")
    try:
        u_id, g_id = get_u_g_id()
    except Exception as e:
        LOG.error("Obtain u_id or g_id failed, details: %s", str(e))
        raise e
    file_name = get_file_name(r'Mysql_server_single.*.tgz')
    source_path = os.path.join(ROOT_DIR, file_name)
    try:
        with tarfile.open(source_path) as tar_ref:
            tar_ref.extractall(WORKDIR)
    except Exception as e:
        LOG.error("Extractall failed, details: %s", str(e))
        raise e
    LOG.info("Begin to copy mysql files, deploy mode meta.")
    cmd = "rm -rf %s/lib/plugin/ha_ctc.so" % os.path.join(WORKDIR, 'Mysql_server/mysql')
    return_code, stdout, stderr = exec_popen(cmd, timeout=30)
    LOG.info("Execute cmd[%s], return_code[%s], stdout[%s], stderr[%s]" % (cmd, return_code, stdout, stderr))
    cmd = "cp -arf %s %s" % (os.path.join(WORKDIR, 'Mysql_server/mysql'), WORKDIR)
    return_code, stdout, stderr = exec_popen(cmd, timeout=180)
    LOG.info("Execute cmd[%s], return_code[%s], stdout[%s], stderr[%s]" % (cmd, return_code, stdout, stderr))
    cmd = "cp -arf %s %s" % (os.path.join(WORKDIR, 'mysql'), MYSQL_INSTALL_PATH)
    return_code, stdout, stderr = exec_popen(cmd, timeout=180)
    LOG.info("Execute cmd[%s], return_code[%s], stdout[%s], stderr[%s]" % (cmd, return_code, stdout, stderr))
    cmd = f"cp -pf {MYSQL_INSTALL_PATH}/mysql/bin/mysql /usr/bin/"
    return_code, stdout, stderr = exec_popen(cmd, timeout=30)
    LOG.info("Execute cmd[%s], return_code[%s], stdout[%s], stderr[%s]" % (cmd, return_code, stdout, stderr))
    os.chown('/opt/cantian/mysql/install/mysql', u_id, g_id)
    for root, dirs, files in os.walk('/opt/cantian/mysql/install/mysql'):
        for d in dirs:
            os.chown(os.path.join(root, d), u_id, g_id)
        for f in files:
            os.chown(os.path.join(root, f), u_id, g_id)
    if os.path.exists('/usr/local/mysql'):
        shutil.rmtree('/usr/local/mysql')
    shutil.copytree('/opt/cantian/mysql/install/mysql', '/usr/local/mysql')
    LOG.info("Success to install mysql, deploy mode meta.")


""" cd /opt/cantian/image/cantian_connector/cantian-connector-mysql/mysql_bin/ && \
    tar -zxf /ctdb/cantian_install/mysql_release_8.0.26_aarch64.tar.gz && \
    tar -zxf /ctdb/cantian_install/mysql_release_8.0.26_aarch64.tar.gz -C /opt/cantian/mysql/install/ && \
    chown 5000:5000 /opt/cantian/mysql/install/mysql -R && \
    cp -pf /opt/cantian/mysql/install/mysql/bin/mysql /usr/bin/ && \
    cp -prf /opt/cantian/mysql/install/mysql /usr/local/
"""


def execute_nometa():
    LOG.info("Begin to install mysql, deploy mode nometa.")
    try:
        u_id, g_id = get_u_g_id()
    except Exception as e:
        LOG.error("Obtain u_id or g_id failed, details: %s", str(e))
        raise e
    file_name = get_file_name(r'mysql_release_.*.tar.gz')
    source_path = os.path.join(ROOT_DIR, file_name)
    with tarfile.open(source_path) as tar_ref:
        tar_ref.extractall(WORKDIR)
        tar_ref.extractall('/opt/cantian/mysql/install/')
    os.chown('/opt/cantian/mysql/install/mysql', u_id, g_id)
    for root, dirs, files in os.walk('/opt/cantian/mysql/install/mysql'):
        for d in dirs:
            os.chown(os.path.join(root, d), u_id, g_id)
        for f in files:
            os.chown(os.path.join(root, f), u_id, g_id)
    shutil.copyfile('/opt/cantian/mysql/install/mysql/bin/mysql', '/usr/bin/mysql')
    if os.path.exists('/usr/local/mysql'):
        shutil.rmtree('/usr/local/mysql')
    shutil.copytree('/opt/cantian/mysql/install/mysql', '/usr/local/mysql')
    LOG.info("Success to install mysql, deploy mode nometa.")

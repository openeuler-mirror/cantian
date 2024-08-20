import tarfile
import shutil
import os
import re
import pwd
import grp

from get_config_info import get_value
from om_log import DR_DEPLOY_LOG as LOG

CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(CURRENT_PATH, "../../../../"))
""" cd /opt/cantian/image/cantian_connector/cantian-connector-mysql/mysql_bin/ && \
    tar -zxf /ctdb/cantian_install/Cantian_connector_mysql_aarch64_RELEASE.tgz && \
    cp -arf mysql/lib/plugin/meta/ha_ctc.so Cantian_connector_mysql/mysql/lib/plugin/ && \
    rm -rf mysql && mv Cantian_connector_mysql/mysql . && \
    cp -arf mysql /opt/cantian/mysql/install/ && \
    chown 5000:5000 /opt/cantian/mysql/install/mysql -R && \
    cp -pf /opt/cantian/mysql/install/mysql/bin/mysql /usr/bin/ && \
    cp -prf /opt/cantian/mysql/install/mysql /usr/local/
"""


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
    workdir = '/opt/cantian/image/cantian_connector/cantian-connector-mysql/mysql_bin/'
    file_name = get_file_name(r'Cantian_connector_mysql_single.*.tgz')
    source_path = os.path.join(ROOT_DIR, file_name)
    try:
        with tarfile.open(source_path) as tar_ref:
            tar_ref.extractall(workdir)
    except Exception as e:
        LOG.error("Extractall failed, details: %s", str(e))
        raise e
    LOG.info("Begin to copy mysql files, deploy mode meta.")
    shutil.copyfile(os.path.join(workdir, 'mysql/lib/plugin/meta/ha_ctc.so'),
                    os.path.join(workdir, 'Cantian_connector_mysql/mysql/lib/plugin/ha_ctc.so'))
    # 支持重入
    shutil.move(os.path.join(workdir, 'mysql/lib/plugin/meta'),
                os.path.join(workdir, 'Cantian_connector_mysql/mysql/lib/plugin/'))
    if os.path.exists(os.path.join(workdir, 'mysql')):
        shutil.rmtree(os.path.join(workdir, 'mysql'))
    shutil.move(os.path.join(workdir, 'Cantian_connector_mysql/mysql'), workdir)
    if os.path.exists('/opt/cantian/mysql/install/mysql'):
        shutil.rmtree('/opt/cantian/mysql/install/mysql')
    shutil.copytree(os.path.join(workdir, 'mysql'), '/opt/cantian/mysql/install/mysql')
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
    workdir = '/opt/cantian/image/cantian_connector/cantian-connector-mysql/mysql_bin/'
    file_name = get_file_name(r'mysql_release_.*.tar.gz')
    source_path = os.path.join(ROOT_DIR, file_name)
    with tarfile.open(source_path) as tar_ref:
        tar_ref.extractall(workdir)
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

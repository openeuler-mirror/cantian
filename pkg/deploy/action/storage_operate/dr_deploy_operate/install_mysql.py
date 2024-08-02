import zipfile
import shutil
import os

""" cd /opt/cantian/image/cantian_connector/cantian-connector-mysql/mysql_bin/ && \
    tar -zxf /ctdb/cantian_install/Cantian_connector_mysql_aarch64_RELEASE.tgz && \
    cp -arf mysql/lib/plugin/meta/ha_ctc.so Cantian_connector_mysql/mysql/lib/plugin/ && \
    rm -rf mysql && mv Cantian_connector_mysql/mysql . && \
    cp -arf mysql /opt/cantian/mysql/install/ && \
    chown 5000:5000 /opt/cantian/mysql/install/mysql -R && \
    cp -pf /opt/cantian/mysql/install/mysql/bin/mysql /usr/bin/ && \
    cp -prf /opt/cantian/mysql/install/mysql /usr/local/
"""

def execute_meta():
    workdir = '/opt/cantian/image/cantian_connector/cantian-connector-mysql/mysql_bin/'
    source_path = '/ctdb/cantian_install/Cantian_connector_mysql_single*.tgz'

    with zipfile.ZipFile(source_path) as zip_ref:
        zip_ref.extractall(workdir)
    shutil.copytree(os.path.join(workdir, 'mysql/lib/plugin/meta/ha_ctc.so'), os.path.join(workdir, 'Cantian_connector_mysql/mysql/lib/plugin/'), symlinks=True, dirs_exist_ok=True)
    shutil.rmtree(os.path.join(workdir, 'mysql'))
    shutil.move(os.path.join(workdir, 'Cantian_connector_mysql/mysql'), workdir)
    shutil.copytree(os.path.join(workdir, 'mysql'), '/opt/cantian/mysql/install/', symlinks=True, dirs_exist_ok=True)
    os.chown('/opt/cantian/mysql/install/mysql', 5000, 5000)
    for root, dirs, files in os.walk('/opt/cantian/mysql/install/mysql'):
        for d in dirs:
            os.chown(os.path.join(root, d), 5000, 5000)
        for f in files:
            os.chown(os.path.join(root, f), 5000, 5000)
    shutil.copy2('/opt/cantian/mysql/install/mysql/bin/mysql', '/usr/bin/')
    shutil.copytree('/opt/cantian/mysql/install/mysql', '/usr/local/', dirs_exist_ok=True)

""" cd /opt/cantian/image/cantian_connector/cantian-connector-mysql/mysql_bin/ && \
    tar -zxf /ctdb/cantian_install/mysql_release_8.0.26_aarch64.tar.gz && \
    tar -zxf /ctdb/cantian_install/mysql_release_8.0.26_aarch64.tar.gz -C /opt/cantian/mysql/install/ && \
    chown 5000:5000 /opt/cantian/mysql/install/mysql -R && \
    cp -pf /opt/cantian/mysql/install/mysql/bin/mysql /usr/bin/ && \
    cp -prf /opt/cantian/mysql/install/mysql /usr/local/
"""

def execute_nometa():
    workdir = '/opt/cantian/image/cantian_connector/cantian-connector-mysql/mysql_bin/'
    source_path = '/ctdb/cantian_install/mysql_release_*.tar.gz'

    with zipfile.ZipFile(source_path) as zip_ref:
        zip_ref.extractall(workdir)
        zip_ref.extractall('/opt/cantian/mysql/install/')
    os.chown('/opt/cantian/mysql/install/mysql', 5000, 5000)
    for root, dirs, files in os.walk('/opt/cantian/mysql/install/mysql'):
        for d in dirs:
            os.chown(os.path.join(root, d), 5000, 5000)
        for f in files:
            os.chown(os.path.join(root, f), 5000, 5000)
    shutil.copy2('/opt/cantian/mysql/install/mysql/bin/mysql', '/usr/bin/')
    shutil.copytree('/opt/cantian/mysql/install/mysql', '/usr/local/', dirs_exist_ok=True)
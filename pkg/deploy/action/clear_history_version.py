import os
import time
from pathlib import Path

VERSION_PATH = '/opt/cantian/upgrade_backup'


def format_creation_time(file_path):
    ori_create_time = os.path.getctime(file_path)
    return time.strftime('%Y%m%d%H%M%S', time.localtime(ori_create_time))


def delete_version(version_path):
    """递归删除"""
    if os.path.isdir(version_path):
        for file_name in os.listdir(version_path):
            file_to_remove = os.path.join(version_path, file_name)
            delete_version(file_to_remove)
        if os.path.exists(version_path):
            os.rmdir(version_path)
    else:
        if os.path.exists(version_path):
            os.remove(version_path)


def execute():
    version_names = os.listdir(VERSION_PATH)
    version_info = [(str(Path(VERSION_PATH, name)), format_creation_time(str(Path(VERSION_PATH, name))))
                    for name in version_names
                    if name.startswith('cantian_upgrade_bak')]
    version_info.sort(key=lambda x: x[1], reverse=False)
    for version_path, _ in version_info[:-2]:
        delete_version(version_path)


if __name__ == "__main__":
    execute()

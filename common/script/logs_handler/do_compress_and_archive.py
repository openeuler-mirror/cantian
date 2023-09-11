import os
import sys
import json
import tarfile
from pathlib import Path
from pwd import getpwnam

CUR_PATH, _ = os.path.split(os.path.abspath(__file__))


def file_reader(data_path):
    with open(data_path, 'r', encoding='utf-8') as file:
        info = file.read()
    return json.loads(info)


def get_file_creation_time(file_path):
    ori_create_time = os.path.getctime(file_path)
    return int(round(ori_create_time * 1000))


def compress_bak_files(main_path, file_names):
    for file_name, _ in file_names:
        ori_log_file = os.path.join(main_path, file_name)
        # 切换工作目录，确保仅压缩日志文件本身
        cwd = os.getcwd()
        os.chdir(main_path)
        with tarfile.open(f'{ori_log_file}.tar.gz', 'w:gz') as tar:
            tar.add(file_name)
        os.chdir(cwd)
        os.remove(ori_log_file)


def reg_handler(log_name_prefix, log_name_tail, log_name, match_string):
    """匹配出待压缩的文件"""
    if 'tar.gz' in match_string or len(match_string) <= len(log_name):
        return False
    if log_name_prefix in match_string and log_name_tail in match_string:
        return True
    return False


def change_file_mod(bak_path, file_names, user_name):
    """改变日志定时清理进程创建的压缩文件权限"""
    uid, gid = getpwnam(user_name)[2:4]
    for file_name, _ in file_names:
        tar_file_name = f'{str(Path(bak_path, file_name))}.tar.gz'
        os.chmod(tar_file_name, 0o440)
        os.chown(tar_file_name, uid=uid, gid=gid)


def get_total_log(main_path, log_name):
    """递归获取main_path目录下前缀名为log_name的日志总量."""
    total_log_size = 0
    for file_name in os.listdir(main_path):
        if file_name.startswith(log_name):
            total_log_size += os.path.getsize(str(Path(main_path, file_name)))

    return total_log_size


def delete_old_bak_logs(main_path, log_name, max_log_val):
    total_log_size = get_total_log(main_path=main_path, log_name=log_name)
    if total_log_size <= max_log_val:
        return

    # 统计main_path目录下所有以log_name的压缩文件
    tar_files = [(str(Path(main_path, file_item)), get_file_creation_time(str(Path(main_path, file_item))))
                 for file_item in os.listdir(main_path)
                 if file_item.startswith(log_name) and file_item.endswith('tar.gz')]
    tar_files.sort(key=lambda x: x[1], reverse=False)

    for tar_file, _ in tar_files:
        if total_log_size <= max_log_val:
            return
        total_log_size -= int(os.path.getsize(tar_file))
        os.remove(tar_file)


def bak_logs_handler(log_content, log_name, ori_bak_files, max_log_vol, user_name):
    compress_bak_files(log_content, ori_bak_files)
    change_file_mod(log_content, ori_bak_files, user_name)
    delete_old_bak_logs(log_content, log_name, max_log_vol * pow(1024, 2))


def main(log_content, log_name, max_log_vol, user_name):
    log_name_prefix, log_name_tail = log_name.split('.')[0], log_name.split('.')[1]
    ori_bak_files = []
    for name in os.listdir(log_content):
        if reg_handler(log_name_prefix, log_name_tail, log_name, name):
            ori_bak_files.append((str(Path(log_content, f'{name}')),
                                  get_file_creation_time(str(Path(log_content, f'{name}')))))

    if not ori_bak_files:
        return

    ori_bak_files.sort(key=lambda x: x[1], reverse=False)
    bak_logs_handler(log_content, log_name_prefix, ori_bak_files, max_log_vol, user_name)


if __name__ == "__main__":
    logs_content, logs_name, max_logs_vol, user = sys.argv[1:]
    main(logs_content, logs_name, int(max_logs_vol), user)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import json
import csv
import signal
import fcntl
import shutil
import sys
import pwd
import grp
import stat
CUR_PATH = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CUR_PATH, "../../"))
from cantian.get_config_info import get_value


def timeout_handler():
    """超时处理函数，直接抛出异常"""
    raise Exception("Operation timed out, releasing lock")


class LockFile:
    """阻塞式文件锁实现，支持超时机制，避免死等"""

    @staticmethod
    def lock_with_timeout(handle, timeout=20):
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(timeout)

        try:
            fcntl.flock(handle, fcntl.LOCK_EX)
        except Exception as e:
            raise Exception(f"Failed to acquire lock: {str(e)}") from e
        finally:
            signal.alarm(0)

    @staticmethod
    def unlock(handle):
        """释放文件锁"""
        fcntl.flock(handle, fcntl.LOCK_UN)

    @staticmethod
    def is_locked(file_path):
        try:
            with open(file_path, 'a') as f:
                try:
                    fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fcntl.flock(f, fcntl.LOCK_UN)
                    return False
                except IOError:
                    return True
        except Exception as e:
            raise Exception(f"Error checking lock status of {file_path}: {str(e)}") from e


def open_and_lock_json(filepath, timeout=20):
    """加载或初始化 JSON 文件，并使用文件锁保护文件操作，结合超时机制。"""
    directory = os.path.dirname(filepath)
    if not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)

    fd = None
    file = None

    try:
        fd = os.open(filepath, os.O_RDWR | os.O_CREAT, 0o644)
        file = os.fdopen(fd, 'r+')

        LockFile.lock_with_timeout(file, timeout=timeout)

        file.seek(0)
        if os.path.getsize(filepath) > 0:
            return json.load(file), file
        else:
            return {}, file
    except Exception as e:
        if file:
            LockFile.unlock(file)
            file.close()
        if fd:
            os.close(fd)
        raise RuntimeError(f"Failed to load or initialize JSON file: {filepath}") from e


def write_and_unlock_json(data, file):
    """写入 JSON 文件，操作完成后释放锁并关闭文件。"""
    try:
        file.seek(0)
        json.dump(data, file, indent=4)
        file.truncate()
    finally:
        LockFile.unlock(file)
        file.close()


def open_and_lock_csv(filepath, timeout=20):
    """加载或初始化 CSV 文件，并使用文件锁保护文件操作，结合超时机制。"""
    directory = os.path.dirname(filepath)
    if not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)

    fd = None
    file = None

    try:
        fd = os.open(filepath, os.O_RDWR | os.O_CREAT, 0o644)
        file = os.fdopen(fd, 'r+')

        LockFile.lock_with_timeout(file, timeout=timeout)

        file.seek(0)
        if os.path.getsize(filepath) > 0:
            reader = csv.reader(file)
            return list(reader), file
        else:
            return [], file
    except Exception as e:
        if file:
            LockFile.unlock(file)
            file.close()
        if fd:
            os.close(fd)
        raise RuntimeError(f"Failed to load or initialize CSV file: {filepath}") from e


def write_and_unlock_csv(rows, file):
    """将记录写入 CSV 文件，并使用文件锁保护文件操作。"""
    try:
        file.seek(0)
        writer = csv.writer(file)
        writer.writerows(rows)
        file.truncate()
    finally:
        LockFile.unlock(file)
        file.close()


def read_file(filepath):
    """
    Read the content of a file if it exists, otherwise return an empty list.
    """
    try:
        if os.path.exists(filepath):
            flags = os.O_RDONLY
            with os.fdopen(os.open(filepath, flags), 'r') as f:
                fcntl.flock(f, fcntl.LOCK_SH)
                content = f.readlines()
                fcntl.flock(f, fcntl.LOCK_UN)
            return content
        return []
    except Exception as e:
        raise RuntimeError(f"Failed to read file {filepath}: {e}")


def write_file(filepath, content):
    """
    Write content to a file safely:
    - Use a temporary file.
    - Lock the file during write.
    - Preserve original permissions and ownership.
    """
    temp_file = f"{filepath}.tmp"
    try:
        if os.path.exists(filepath):
            stat_info = os.stat(filepath)
            original_mode = stat_info.st_mode
            original_uid = stat_info.st_uid
            original_gid = stat_info.st_gid
        else:
            original_mode = stat.S_IWUSR | stat.S_IRUSR
            original_uid = os.getuid()
            original_gid = os.getgid()

        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        modes = original_mode

        with os.fdopen(os.open(temp_file, flags, modes), 'w') as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            f.writelines(content)
            fcntl.flock(f, fcntl.LOCK_UN)

        # Replace the original file with the temporary file
        shutil.move(temp_file, filepath)

        # Restore permissions and ownership
        os.chmod(filepath, original_mode)
        os.chown(filepath, original_uid, original_gid)

    except Exception as e:
        raise RuntimeError(f"Failed to write file {filepath}: {e}")
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)


def mkdir(path, permissions=0o750):
    """
    Ensure the directory for the given path exists, creating it if necessary.

    :param path: The path to ensure exists (file or directory).
    :param permissions: The permissions to set on the created directory (default: 0o750).
    :raises: RuntimeError if directory creation or permission setting fails.
    """
    try:
        if not os.path.exists(path):
            os.makedirs(path, exist_ok=True)
            os.chmod(path, permissions)

            deploy_user = get_value("deploy_user")
            deploy_group = get_value("deploy_group")

            if deploy_user and deploy_group:
                uid = pwd.getpwnam(deploy_user).pw_uid
                gid = grp.getgrnam(deploy_group).gr_gid
                os.chown(path, uid, gid)

    except Exception as e:
        raise RuntimeError(f"Failed to create directory '{path}': {e}")
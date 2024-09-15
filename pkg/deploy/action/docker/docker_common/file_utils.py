#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import json
import fcntl


class LockFile:
    """持锁状态下对文件标识符进行修改，使用阻塞模式等待锁释放"""

    @staticmethod
    def lock(handle):
        fcntl.flock(handle, fcntl.LOCK_EX)

    @staticmethod
    def unlock(handle):
        fcntl.flock(handle, fcntl.LOCK_UN)


def load_or_initialize_json(filepath):
    """
    加载或初始化 JSON 文件，并使用文件锁保护文件操作
    """
    directory = os.path.dirname(filepath)
    if not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)

    fd = os.open(filepath, os.O_RDWR | os.O_CREAT, 0o644)
    with os.fdopen(fd, 'r+') as file:
        LockFile.lock(file)
        try:
            file.seek(0)
            if os.path.getsize(filepath) > 0:
                return json.load(file)
            else:
                return {}
        finally:
            LockFile.unlock(file)


def write_json(filepath, data):
    """
    写入 JSON 文件并使用文件锁保护文件操作
    """
    fd = os.open(filepath, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    with os.fdopen(fd, 'w') as file:
        LockFile.lock(file)
        try:
            json.dump(data, file, indent=4)
        finally:
            LockFile.unlock(file)
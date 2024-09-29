#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import json
import csv
import fcntl
import signal


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
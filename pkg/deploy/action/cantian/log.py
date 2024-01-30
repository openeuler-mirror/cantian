import json
import os
import re
import logging
from pathlib import Path
from logging import handlers
from logging import LogRecord


CUR_PATH, _ = os.path.split(os.path.abspath(__file__))
with open(os.path.join(CUR_PATH, "install_config.json"), "r") as f:
    install_config = json.loads(f.read())

LOG_FILE = install_config.get("l_LOG_FILE")

CONSOLE_CONF = {
    "log": {
        "use_syslog": False,
        "debug": False,
        "log_dir": os.path.dirname(LOG_FILE),
        "log_file_max_size": 6291456,
        "log_file_backup_count": 5,
        "log_date_format": "%Y-%m-%d %H:%M:%S",
        "logging_default_format_string": "%(asctime)s %(levelname)s [pid:%(process)d] [%(threadName)s] "
                                         "[tid:%(thread)d] [%(filename)s:%(lineno)d %(funcName)s] %(message)s",
        "logging_context_format_string": "%(asctime)s %(levelname)s [pid:%(process)d] [%(threadName)s] "
                                         "[tid:%(thread)d] [%(filename)s:%(lineno)d %(funcName)s] %(message)s"
    }
}


log_config = CONSOLE_CONF.get("log")


def _get_log_file_path(project):
    logger_file = log_config.get("log_file")
    logger_dir = log_config.get("log_dir")

    if logger_file:
        if not logger_dir:
            return logger_file
        else:
            return os.path.join(logger_dir, logger_file)

    if logger_dir:
        if not os.path.exists(logger_dir):
            os.makedirs(logger_dir)
        return os.path.join(logger_dir, "{}.log".format(project))

    return ''


SENSITIVE_STR = [
    'Password', 'passWord', 'PASSWORD', 'password', 'Pswd',
    'PSWD', 'pwd', 'signature', 'HmacSHA256', 'newPasswd',
    'private', 'certfile', 'secret', 'token', 'Token', 'pswd',
    'passwd', 'mysql -u', 'session', 'cookie'
]


class DefaultLogFilter(logging.Filter):
    def filter(self, record: LogRecord) -> int:
        msg_upper = record.getMessage().upper()
        for item in SENSITIVE_STR:
            if item.upper() in msg_upper:
                return False
        return True


def setup(project_name):
    """
    init log config
    :param project_name:
    """

    log_root = logging.getLogger(project_name)
    for handler in list(log_root.handlers):
        log_root.removeHandler(handler)

    log_path = _get_log_file_path(project_name)
    if log_path:
        file_log = handlers.RotatingFileHandler(
            log_path, maxBytes=log_config.get("log_file_max_size"),
            backupCount=log_config.get("log_file_backup_count"))
        log_root.addHandler(file_log)
        log_root.addFilter(DefaultLogFilter())

    for handler in log_root.handlers:
        handler.setFormatter(
            logging.Formatter(
                fmt=log_config.get("logging_context_format_string"),
                datefmt=log_config.get("log_date_format")))

    if log_config.get("debug"):
        log_root.setLevel(logging.DEBUG)
    else:
        log_root.setLevel(logging.INFO)
    return log_root


LOGGER = setup(os.path.basename(LOG_FILE).split(".")[0])
log_directory = log_config.get("log_dir")
os.chmod(log_directory, 0o750)
os.chmod(f'{str(Path(log_directory, os.path.basename(LOG_FILE)))}', 0o640)

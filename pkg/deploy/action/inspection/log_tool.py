import logging
import os
import getpass
from logging import handlers

CUR_PATH = os.path.dirname(os.path.realpath(__file__))
CONSOLE_CONF = {
    "log": {
        "use_syslog": False,
        "debug": False,
        "log_dir": f"{CUR_PATH}/inspection_task_log",
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
    logger_dir = log_config.get("log_dir")
    username = getpass.getuser()
    if logger_dir:
        if not os.path.exists(logger_dir):
            os.makedirs(logger_dir)
        file_stat = os.stat(os.path.basename(__file__))
        owner_uid = file_stat.st_uid
        owner_gid = file_stat.st_gid
        os.chown(logger_dir, owner_uid, owner_gid)
        logger_file = os.path.join(logger_dir, "{}.log".format(project))
        if os.path.exists(logger_file):
            os.chown(logger_file, owner_uid, owner_gid)
        return logger_file

    return ''


def setup(project_name):
    """
    init log config
    :param project_name:
    """
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)

    log_root = logging.getLogger()
    for handler in list(log_root.handlers):
        log_root.removeHandler(handler)

    log_path = _get_log_file_path(project_name)
    if log_path:
        file_log = handlers.RotatingFileHandler(
            log_path, maxBytes=log_config.get("log_file_max_size"),
            backupCount=log_config.get("log_file_backup_count"))
        log_root.addHandler(file_log)
        log_root.addHandler(console)

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


CREATE_LOG_PATH = _get_log_file_path

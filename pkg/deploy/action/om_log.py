import os
import logging
from pathlib import Path
from logging import handlers
from om_log_config import CONSOLE_CONF

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


def setup(project_name):
    """
    init log config
    :param project_name:
    """
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)

    log_root = logging.getLogger(project_name)
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


LOGGER = setup("om_deploy")
SNAPSHOT_LOGS = setup("snapshot_log")
log_directory = log_config.get("log_dir")
os.chmod(log_directory, 0o750)
os.chmod(f'{str(Path(log_directory, "om_deploy.log"))}', 0o640)
os.chmod(f'{str(Path(log_directory, "snapshot_log.log"))}', 0o640)

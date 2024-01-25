# -*- coding: UTF-8 -*-
import json
from params_factory.tools import table_log_reader
from params_factory.tools import json_file_reader


def log_query(log_path, *args):
    info = table_log_reader(log_path)
    if args[0]:
        return info
    tmp = json.dumps(info)
    tmp = "{" + tmp[1: len(tmp) - 1] + "}"
    return tmp


def collection_logs(receipt_info, *args):
    if not receipt_info:
        return "[ctctl collection logs] may fail, the receipt info is {}, " \
               "which is an empty string".format(receipt_info)

    if "timed out" in receipt_info:
        return "start log collection successful, " \
               "use [ctctl logs progress query] to get current collection progress"

    return receipt_info


def logs_progress_query(log_progress_path, *args):
    if log_progress_path:
        load_info = json_file_reader(log_progress_path)
        if not load_info:
            return "no log collection information, " \
                   "may be the log is still being generated or " \
                   "no log collection has been performed"

        return [json.loads(item) for item in load_info.split("\n") if item]

    return "did not get the path of the json file which records logs progress"


PARAM_PREPARE = {
    "help": "direct execution",
    "log query": log_query,
    "collection logs": collection_logs,
    "logs progress query": logs_progress_query
}

# -*- coding: UTF-8 -*-
def json_file_reader(file_path):
    with open(file_path, "r", encoding="utf-8") as file:
        info = file.read()
    return info


def table_log_reader(log_path, size=0):
    """
    :params log_path: 日志路径
    :params size: 用户指定最近日志打印条数，默认全量打印
    """
    ori_log_info = json_file_reader(log_path)
    tmp_list_info = [item.split(",") for item in ori_log_info.split("\n") if item]
    key_set = ("client_pid", "client_uid", "command", "running_status", "begin_time")

    info_dict = [{item.split("=")[0].strip(): item.split("=")[1][1:-1]
                  for item in log
                  if item.split("=")[0].strip() in key_set}
                 for log in tmp_list_info]

    if size:
        res_size = min(size, len(info_dict))
        return info_dict[len(info_dict) - res_size:]

    return info_dict

# -*- coding: UTF-8 -*-
class DisplayAsTable:
    """以表格形式回显数据"""

    @staticmethod
    def print_exception_info(err_type, err_detail=""):
        print(("[result] command execution failed, [err_type] {}, [err_detail] {}, "
              "use [ctctl help] to get the commands we support.").format(err_type, err_detail))

    @staticmethod
    def print_info(dict_info, key_header, key_max_len):
        for dict_item in dict_info:
            print("\r")
            for idx, val in enumerate(key_header):
                dict_item_size = key_max_len[val] + 4
                data_str = str(dict_item[val]).center(dict_item_size, '-' if dict_item[val] == '-' else ' ')
                icon = "|"
                if dict_item[val] == "-":
                    icon = "+"
                data_str = (icon if idx == 0 else '') + data_str[1: len(data_str)] + icon
                print(data_str, end="")
        print("\r")

    @staticmethod
    def display_single_table(dict_info, mode=None):
        """打印仅有单个字典元素的反执信息"""
        split_format = "{0:<25}\t{1:<25}"
        if mode == "help":
            print("The commands we support are as follows:")
            print(split_format.format("[commands]", "[description]"))
        else:
            print(split_format.format("[key]", "[value]"))
        for key, val in dict_info.items():
            if not val:
                val = "None"
            print(split_format.format(key, val))

    def display_mutil_table(self, list_info):
        """打印有多个字典元素的反执信息"""
        key_header = list_info[0].keys()
        # 存放每列的最大长度
        key_max_len_dict = dict()
        for dict_item in list_info:
            for _, val in enumerate(key_header):
                max_size = max(len(val), len(str(dict_item[val])))
                if val in key_max_len_dict:
                    max_size = max(max_size, key_max_len_dict.get(val))
                key_max_len_dict[val] = max_size
        # 占位项
        tag = dict()
        for _, val in enumerate(key_header):
            tag[val] = "-"
        list_info.insert(0, tag)
        list_info.append(tag)
        # 打印表
        self.print_info([tag], list(key_header), key_max_len_dict)
        for idx, val in enumerate(key_header):
            item_size = key_max_len_dict.get(val) + 4
            data_str = val.center(item_size)
            data_str = ('|' if idx == 0 else '') + data_str[1:len(data_str)] + '|'
            print(data_str, end="")
        self.print_info(list_info, list(key_header), key_max_len_dict)

    def display_table(self, info, flag=False):
        """
        :params info: dict/list
        :params flag: False：直接打印; True：table打印
        """
        if not flag or isinstance(info, str):
            print(info)
        elif isinstance(info, dict):
            self.display_single_table(info)
        else:
            self.display_mutil_table(info)

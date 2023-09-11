import re
from collections import Counter


def check_none(value):
    return value is None or value == ""


def check_required(input_dict, check_item, check_rule):
    check_value = input_dict.get(check_item, '')
    if check_rule:
        return len(str(check_value)) > 0

    return True


def check_type(input_dict, check_item, check_rule):
    type_list = {
        'int': int,
        'string': str,
        'list': list,
        'tuple': tuple,
        'dict': dict,
        'float': float,
        'bool': bool,
    }
    check_value = input_dict.get(check_item, None)
    if check_none(check_value):
        return True

    return isinstance(check_value, type_list.get(check_rule))


def check_int_string(input_dict, check_item, check_rule):
    if not check_rule:
        return True

    check_value = input_dict.get(check_item, None)
    if check_none(check_value):
        return True

    if isinstance(check_value, str):
        return check_value.isdigit()
    else:
        return False


def check_regexp(input_dict, check_item, check_rule):
    check_value = input_dict.get(check_item, None)
    if check_none(check_value):
        return True

    return re.match(check_rule, str(check_value)) is not None


def check_enum(input_dict, check_item, check_rule):
    check_value = input_dict.get(check_item, None)
    if check_none(check_value):
        return True

    enum_list = check_rule.split('|')

    if isinstance(check_value, bool):
        check_value = str(check_value).upper()
        enum_list = [x.upper() for x in enum_list]

    return str(check_value) in enum_list


def check_int_range(input_dict, check_item, check_rule):
    check_value = input_dict.get(check_item, None)
    if check_none(check_value):
        return True

    min_value, max_value = [int(x) for x in check_rule.split('~')]

    return min_value <= int(check_value) <= max_value


def check_str_length_range(input_dict, check_item, check_rule):
    check_value = input_dict.get(check_item, None)
    if check_none(check_value):
        return True

    min_value, max_value = [int(x) for x in check_rule.split('~')]

    return min_value <= len(str(check_value)) <= max_value


def check_non_empty_str(input_dict, check_item, check_rule):
    if not check_rule:
        return True

    check_value = input_dict.get(check_item, None)
    if check_none(check_value):
        return True

    return check_value != ""


def check_str_list(input_dict, check_item, check_rule):
    if not check_rule:
        return True

    check_value = input_dict.get(check_item, None)
    if check_none(check_value):
        return True

    if not isinstance(check_value, list):
        return False

    # 不能为空列表
    if not check_value:
        return False

    if any(not isinstance(val, str) for val in check_value):
        return False

    return True


def check_str_list_range(input_dict, check_item, check_rule):
    """
    不能为空列表且列表成员为str，且列表长度范围在[min,max]之间
    """
    check_value = input_dict.get(check_item, None)
    if check_none(check_value):
        return True

    if not check_str_list(input_dict=input_dict, check_item=check_item, check_rule=check_rule):
        return False

    min_value, max_value = [int(x) for x in check_rule.split('~')]

    return min_value <= len(check_value) <= max_value


def check_int_list(input_dict, check_item, check_rule):
    if not check_rule:
        return True

    check_value = input_dict.get(check_item, None)
    if check_none(check_value):
        return True

    try:
        if isinstance(check_value, list):
            if not check_value:
                return False
            else:
                sum(check_value)
        else:
            return False

    except Exception as error:
        _ = error
        return False

    return True


def check_int_list_range(input_dict, check_item, check_rule):
    check_value = input_dict.get(check_item, None)
    if check_none(check_value):
        return True

    if not check_int_list(input_dict=input_dict, check_item=check_item, check_rule=check_rule):
        return False

    min_value, max_value = [int(x) for x in check_rule.split('~')]

    return min_value <= len(check_value) <= max_value


def check_non_repeat_list(input_dict, check_item, check_rule):
    if not check_rule:
        return True

    check_value = input_dict.get(check_item, None)
    if check_none(check_value):
        return True

    return all([val == 1 for val in Counter(check_value).values()])


def check_array_length(input_dict, check_item, check_rule):
    check_value = input_dict.get(check_item, None)
    if check_none(check_value):
        return True

    if not isinstance(check_value, list):
        return False

    min_value, max_value = [int(x) for x in check_rule.split('~')]

    return min_value <= len(check_value) <= max_value


CHECKER = {
    "required": check_required,
    "type": check_type,
    "intString": check_int_string,
    "regexp": check_regexp,
    "enum": check_enum,
    "intRange": check_int_range,
    "strLengthRange": check_str_length_range,
    "nonEmptyStr": check_non_empty_str,
    "StrList": check_str_list,
    "strListRange": check_str_list_range,
    "intList": check_int_list,
    "intListRange": check_int_list_range,
    "nonRepeatList": check_non_repeat_list,
    "arrayLength": check_array_length
}
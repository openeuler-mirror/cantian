#!/bin/bash

CURRENT_PATH=$(dirname $(readlink -f $0))

# CTOM_BASIC_FILE_MODE_MAP会覆盖CTOM_FILE_R_MODE_MAP设置的权限，CTOM_FILE_R_MODE_MAP会覆盖CTOM_FILE_MODE_MAP的权限
declare -A CTOM_BASIC_FILE_MODE_MAP  # 基础权限配置map，最先运行
declare -A CTOM_FILE_R_MODE_MAP # 递归权限配置map，其次运行
declare -A CTOM_FILE_MODE_MAP # 单独路径、文件配置map，最后运行

CTOM_BASIC_FILE_MODE_MAP["${CURRENT_PATH}"]="400"

CTOM_FILE_MODE_MAP["${CURRENT_PATH}"]="755"
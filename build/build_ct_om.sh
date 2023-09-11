#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_TOP_DIR=$(cd ${CURRENT_PATH}; pwd)

CI_TOP_DIR=$(cd ${SCRIPT_TOP_DIR}/..; pwd)
CT_OM_ROOT=$(cd ${CURRENT_PATH}/../ct_om; pwd)
CT_REQUIREMENTS_PATH=${CT_OM_ROOT}/requirements.txt

SERVICE_NAME=cantian
MODULE_NAME=ct_om

TEMP_PATH="${CI_TOP_DIR}/temp/cantian/package/temp"
CT_OM_COMPONENT_PATH="/opt/cantian/ct_om"
CT_OM_SITE_PACKAGES_PATH="${TEMP_PATH}/venv/lib64/python*/site-packages"


# 清理环境，ct_om编译临时路径
function init_temp_dir()
{
    echo "Begin to initialize temporary dir. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    if [ -d ${TEMP_PATH} ]; then
        rm -rf ${TEMP_PATH}
    fi
    mkdir -p "${TEMP_PATH}" && mkdir -p "${CT_OM_COMPONENT_PATH}"
    return 0
}

# 创建虚拟环境，会与ct_om目录同级创建venv文件夹
function create_virtual_env()
{
    echo "Begin to create virtualenv. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    if [ -d ${TEMP_PATH} ]; then
        cd ${TEMP_PATH}

        # 创建一个干净的不带任何三方依赖的python环境
        python3 -m venv --copies venv

        # 虚拟环境16.1.0之后版本的lib64软链接了绝对路径，要删除后，重新链接相对路径
        cd venv
        rm -rf lib64
        ln -s lib lib64

        # 创建完成之后，激活虚拟环境
        source bin/activate
    else
        echo "${CT_OM_COMPONENT_PATH} is not exist. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi
    return 0
}

# 在虚拟环境中安装Flask需要的三方文件
function setup_python_3rd()
{

    # 增加安全编译
    export LDFLAGS="-Wl,-z,relro,-z,now,-z,noexecstack -s"
    export CFLAGS="-fstack-protector-all -fPIC -D_FORTIFY_SOURCE=2 -O2 -ftrapv -fstack-check"

    TRUSTED_HOST_HW=cmc.centralrepo.rnd.huawei.com
    TRUSTED_PYPI="https://${TRUSTED_HOST_HW}/pypi/simple"
    pip install --trusted-host "${TRUSTED_HOST_HW}" -i "${TRUSTED_PYPI}" -r "${CT_REQUIREMENTS_PATH}"
    if [ $? -ne 0 ]; then
        echo "Failed to setup_python_3rd. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi
    python -m pip uninstall -y pip

    echo "Succeed in setting up python 3rd package. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    return 0
}

# 删除无用的三方文件,主要是第三方中的示例文件，如证书等
function remove_useless_packages_file()
{
    if [ -d ${CT_OM_SITE_PACKAGES_PATH} ]; then
        cd ${CT_OM_SITE_PACKAGES_PATH}
        # 删除certifi中的证书文件
        rm -rf pip/_vendor/certifi/cacert.pem
        rm -rf werkzeug/debug
        # 删除测试脚本
    else
        echo "${CT_OM_SITE_PACKAGES_PATH} is not exist. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    fi
    return 0
}

# 拷贝ct_om下的ct_om文件夹
function copy_ct_om_src()
{
    if [ -d ${CT_OM_ROOT} ]; then
        cp -rf ${CT_OM_ROOT}/. ${CT_OM_COMPONENT_PATH}
        if [ $? -ne 0 ]; then
            echo "Failed to copy ct_om source code. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            return 1
        fi
        return 0
    else
        echo "${CT_OM_ROOT} is not exist. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi
}

# 拷贝ct_om下的ct_om文件夹
function copy_site_package()
{
    if [ -d ${TEMP_PATH}/venv ]; then
        cp -rf ${TEMP_PATH}/venv/lib64/python*/site-packages ${CT_OM_COMPONENT_PATH}/
        if [ $? -ne 0 ]; then
            echo "Failed to copy ct_om source code. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            return 1
        fi
        return 0
    else
        echo "${TEMP_PATH}/venv is not exist. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi
}

# 退出虚拟环境
function exit_virtual_env()
{
    echo "Begin to deactivate virtualenv. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    if [ -d ${CT_OM_COMPONENT_PATH} ]; then

        # 修改之前，退出虚拟环境
        deactivate

        cd ${CT_OM_COMPONENT_PATH}
        cd venv/bin
        rm -f python
        rm -f python3
        # 删除三方组件测试脚本
        rm -rf ${CT_OM_COMPONENT_PATH}/venv/lib/python3.7/site-packages/distutils/tests
        rm -rf ${CT_OM_COMPONENT_PATH}/venv/lib/python3.7/site-packages/werkzeug/debug
        # 清空cacert.pem证书内容
        > ${CT_OM_COMPONENT_PATH}/venv/lib/python3.7/site-packages/certifi/cacert.pem
        # 删除pyc文件
        find ${CT_OM_COMPONENT_PATH}/venv -name '*.pyc' -delete
    else
        echo "${CT_OM_COMPONENT_PATH} is not exist. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi
    return 0
}

function main()
{
    echo "Begin to build ct_om. [Line:${LINENO}, File:${SCRIPT_NAME}]"

    # 准备环境
    init_temp_dir
#
#    # 创建
#    create_virtual_env
#    if [ $? -ne 0 ]; then
#        echo "Failed to create virtualenv. [Line:${LINENO}, File:${SCRIPT_NAME}]"
#        return 1
#    fi
#
#    # 安装全部的三方插件
#    setup_python_3rd
#    if [ $? -ne 0 ]; then
#        echo "Failed to setup python 3rd packages. [Line:${LINENO}, File:${SCRIPT_NAME}]"
#        return 1
#    fi
#
#    # 退出虚拟环境
#    exit_virtual_env
#    if [ $? -ne 0 ]; then
#        echo "Failed to exit virtualenv. [Line:${LINENO}, File:${SCRIPT_NAME}]"
#        return 1
#    fi

    # 复制ct_om库的src
    copy_ct_om_src
    if [ $? -ne 0 ]; then
        echo "Failed to copy ct_om src. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi


    
#    # 复制ct_om库的三方包
#    copy_site_package
#    if [ $? -ne 0 ]; then
#        echo "Failed to copy ct_om src. [Line:${LINENO}, File:${SCRIPT_NAME}]"
#        return 1
#    fi

    echo "Succeed in building ct_om. [Line:${LINENO}, File:${SCRIPT_NAME}]"

    return 0
}

main
exit $?
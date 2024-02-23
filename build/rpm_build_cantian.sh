#!/bin/bash
set +x
umask 0022
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${CURRENT_PATH}/$(basename $0)
MODULE_NAME=cantian
cantian_component_path="/opt/cantian/image"
SPEC_FILE="${CURRENT_PATH}/${MODULE_NAME}.spec"

CANTIANDB_BIN=$(echo $(dirname $(pwd)))/output/bin


#构建cantian rpm包
function build_cantian_rpm()
{
    echo "Begin to build rpm ${MODULE_NAME}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    local name="$(getSpecParamVal "${SPEC_FILE}" Name)"
    local RPM_TOP_DIR="${CANTIANDB_BIN}/rpm"

    echo "Begin to mkdir ${RPM_TOP_DIR}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    if [ -d ${RPM_TOP_DIR} ]; then
        rm -rf ${RPM_TOP_DIR}
    fi

    mkdir -p ${RPM_TOP_DIR}/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
    if [ $? -ne 0 ]; then
        echo "Failed to mkdir ${RPM_TOP_DIR}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    echo "Begin to copy files: ${name}.tar.gz to ${RPM_TOP_DIR}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    cp -rf ${cantian_component_path}/${name}.tar.gz ${RPM_TOP_DIR}/SOURCES && cp -rf ${SPEC_FILE} ${RPM_TOP_DIR}/SPECS/
    if [ $? -ne 0 ]; then
        echo "Failed to copy files: ${name} to ${RPM_TOP_DIR}, [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    echo "Begin to build rpm to ${RPM_TOP_DIR}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    cd ${RPM_TOP_DIR}/SPECS


    echo "rpmbuild --define '_topdir ${RPM_TOP_DIR}' --define '_build_id_links none' -bb ${MODULE_NAME}.spec"
    eval "rpmbuild --define '_topdir ${RPM_TOP_DIR}' --define '_build_id_links none' -bb ${MODULE_NAME}.spec"
    if [ $? -ne 0 ]; then
        echo "Failed to build rpm package to ${RPM_TOP_DIR}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi
    echo "Succeed in building rpm package. [Line:${LINENO}, File:${SCRIPT_NAME}"
    return 0
}

###############################################################################################
## 获取spec文件的参数值
###############################################################################################
function getSpecParamVal()
{
    local specFile="$1"
    local paraName="$2"
    local paraVal=""

    [ -f "${specFile}" ] || { return 1; }

    paraVal=$(grep -w  ^"${paraName}" "${specFile}" | awk -F":" '{print $2}')
    echo ${paraVal}
    return 0
}


function main()
{
    build_cantian_rpm
    if [ $? -ne 0 ]; then
        echo "Failed to build rpm. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    return 0
}

main
ret=$?
if [ $ret -eq 0 ]; then
    echo "Succeed in building oam-console rpm. [Line:${LINENO}, File:${SCRIPT_NAME}]"
else
    echo "Failed to build oam-console rpm. [Line:${LINENO}, File:${SCRIPT_NAME}]"
fi
exit $ret
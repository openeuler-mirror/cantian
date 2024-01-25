#!/bin/bash
# Copyright Huawei Technologies Co., Ltd. 2010-2018. All rights reserved.
# This script is used for compiling code via CMake and making packages

set -e
PS4=':${LINENO}+'
declare VERSION_DESCRIP=""
declare PACK_PREFIX=""
declare PROJECT_VERSION=""
declare RUN_PACK_DIR_NAME=""
declare LOGICREP_DIR_NAME=""
declare ALL_PACK_DIR_NAME=""
declare SYMBOL_PACK_DIR_NAME=""
declare TOOLS_PACK_DIR_NAME=""
declare COMPILE_OPTS=""
declare SHARDING_INNER_TOOLS_PACK_NAME=""
declare MYSQL_BUILD_TYPE=""
declare JDRIVER_PACK_DIR_NAME=""
export BUILD_MODE=""
export PYTHON_INCLUDE_DIR=""
export WORKSPACE=$(dirname $(dirname $(pwd)))
DFT_WORKSPACE="/home/regress"

source ./common.sh
source ./function.sh

CONFIG_IN_FILE=${CANTIANDB_BUILD}/include/config.h

PYTHON3_HOME=${PYTHON3_HOME}
MYSQL_CODE_PATH=${WORKSPACE}/mysql-server/mysql-source
INSTALL_DIR=/opt/cantiandb
INITSQL_DIR=../
func_prepare_git_msg
PROJECT_VERSION=$(cat ${CONFIG_IN_FILE} | grep 'PROJECT_VERSION' | awk '{print $3}')
CANTIAND_BIN=cantiand-${PROJECT_VERSION}
JDBC_DIR=${CANTIANDB_HOME}/src/jdbc/cantian-jdbc/build/Cantian_PKG
LOGICREP_DIR=${CANTIANDB_HOME}/src/zlogicrep/build/Cantian_PKG
LOGICREP_FILE_DIR=${CANTIANDB_HOME}/src/zlogicrep/build/Cantian_PKG/file
JAR_NAME=com.huawei.gauss.jdbc.ZenithDriver-*.jar
JAR_ETCD=com.huawei.gauss.jdbc.etcd-*.jar
LOGICREP_GZ_NAME=com.huawei.cantian.logicrep.tar.gz
GODRIVER_NAME=go-cantian-driver
ZEBRATOOL_DIR=${CANTIANDB_HOME}/src/zebratool
MYSQL_DIR=${CANTIANDB_HOME}/../../mysql-server/mysql-source
DAAC_LIB_DIR=${CANTIANDB_HOME}/../daac_lib
DAAC_LIB_DIR_TMP=${CANTIANDB_HOME}/../daac_lib/tmp/
MYSQL_BUILD_MODE=${MYSQL_BUILD_MODE:-"multiple"}
HOME_PATH=${MYSQL_DIR}/..
BOOST_PATH=/tools/boost_1_73_0
ENABLE_LLT_GCOV="NO"
ENABLE_LLT_ASAN="NO"
BUILD_MYSQL_SO=${BUILD_MYSQL_SO:-"YES"}
if [[ ${OS_ARCH} =~ "x86_64" ]]; then
    export CPU_CORES_NUM=`cat /proc/cpuinfo |grep "cores" |wc -l`
    LIB_OS_ARCH="lib_x86"
elif [[ ${OS_ARCH} =~ "aarch64" ]]; then 
    export CPU_CORES_NUM=`cat /proc/cpuinfo |grep "architecture" |wc -l`
    LIB_OS_ARCH="lib_arm"
else 
    echo "OS_ARCH: ${OS_ARCH} is unknown, set CPU_CORES_NUM=16 "
    export CPU_CORES_NUM=16
fi

WITH_TSE_STORAGE_ENGINE=1
if [ "${branch}" == "develop_616_finale" ]; then
    branch=develop_616_finale_dbstore
fi

if [ "${BUILD_MYSQL_SO}" == "YES" ]; then
  WITH_TSE_STORAGE_ENGINE=0
fi

echo ${CANTIANDB_HOME}
func_prepare_pkg_name()
{
    cd ${CANTIANDB_HOME}

    if [[ ! -e "${CONFIG_IN_FILE}" ]]; then
        echo "config file not exist..."
        exit 1
    fi

    VERSION_DESCRIP=$(cat ${CONFIG_IN_FILE} | grep 'VERSION_DESCRIP' | awk '{print $3}')
    PACK_PREFIX=$(cat ${CONFIG_IN_FILE} | grep 'PACK_PREFIX' | awk '{print $3}')
    PROJECT_VERSION=$(cat ${CONFIG_IN_FILE} | grep 'PROJECT_VERSION' | awk '{print $3}')
    
    # arm_euler临时规避
    if [[ ${OS_ARCH} =~ "aarch64" ]]; then
        OS_SUFFIX=CENTOS
    fi

    RUN_PACK_DIR_NAME=${PACK_PREFIX}-RUN-${OS_SUFFIX}-${ARCH}bit
    LOGICREP_DIR_NAME=${PACK_PREFIX}-LOGICREP
    ALL_PACK_DIR_NAME=${PACK_PREFIX}-DATABASE-${OS_SUFFIX}-${ARCH}bit
    SYMBOL_PACK_DIR_NAME=${PACK_PREFIX}-DATABASE-${OS_SUFFIX}-${ARCH}bit-SYMBOL
    CTBOX_DIR_NAME=${PACK_PREFIX}-CTBOX
    TOOLS_PACK_DIR_NAME=${PACK_PREFIX}-TOOLS
    JDRIVER_PACK_DIR_NAME=${PACK_PREFIX}-CLIENT-JDBC
    LOGICREP_AGENT_DIR_NAME=${PACK_PREFIX}-LOGICREP-AGENT
    CTSQL_PACK_DIR_NAME=${PACK_PREFIX}-CTSQL-${OS_SUFFIX}-${ARCH}bit

    if [[ ! -d "${CANTIANDB_BIN}" ]]; then
        echo "bin dir not exist"
        exit 1
    else
        echo "chmod 755"
        chmod -R 755 ${CANTIANDB_BIN}/*
    fi

    cd ${CANTIANDB_BIN}
    rm -rf ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}*
    mkdir -p ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}
    mkdir -p ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}/bin
    mkdir -p ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}/lib
    mkdir -p ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}/add-ons
    mkdir -p ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}/data
    mkdir -p ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}/log
    mkdir -p ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}/protect
    mkdir -p ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}/var
}


func_prepare_no_clean_debug()
{
    export BUILD_MODE=Debug
    cd ${CANTIANDB_BUILD}
    cmake -DCMAKE_BUILD_TYPE=Debug -DUSE32BIT=OFF ${COMPILE_OPTS} ..
}

func_prepare_no_clean_release()
{
    export BUILD_MODE=Release
    cd ${CANTIANDB_BUILD}
    cmake -DCMAKE_BUILD_TYPE=Release -DUSE32BIT=OFF ${COMPILE_OPTS} ..
    sed -i "s/-O3/-O2/g" CMakeCache.txt
}

func_prepare_debug()
{
    export PYTHON_INCLUDE_DIR=${PYTHON3_HOME}
    func_prepare_no_clean_debug
}


func_prepare_release()
{
    export PYTHON_INCLUDE_DIR=${PYTHON3_HOME}
    func_prepare_no_clean_release
}

func_all()
{
    ## download dependency:
    func_prepare_dependency

    local build_mode=$1
    if [[ -z "${build_mode}" ]]; then
        build_mode='Debug'
    fi

    if [[ "${build_mode}" = 'Debug' ]]; then
        func_prepare_debug
    else
        func_prepare_release
    fi

    cd ${CT_SRC_BUILD_DIR}
    set +e
    make all -sj 8
    if [ $? -ne 0 ]; then
        ls -al ${CANTIANDB_LIB}
        ls -al /home/regress
        ls -al /home/regress/CantianKernel/build
        exit 1
    fi 
    set -e 

    if [[ -e "${CANTIANDB_BIN}"/cantiand ]]; then
        cd ${CANTIANDB_BIN}
        if [ -e "${CANTIAND_BIN}" ]; then
          rm ${CANTIAND_BIN}
        fi
        ln cantiand ${CANTIAND_BIN}
    fi
}

func_jdriver()
{
    echo "make jdbc driver"
    rm -rf ${CANTIANDB_HOME}/${JDRIVER_PACK_DIR_NAME}*
    rm -rf ${JDBC_DIR}/file
    cd ${JDBC_DIR} && sh build_package_unix.sh
    mkdir -p ${CANTIANDB_HOME}/${JDRIVER_PACK_DIR_NAME}
    cp ${JDBC_DIR}/file/${JAR_NAME} ${CANTIANDB_HOME}/${JDRIVER_PACK_DIR_NAME}/
    cp ${JDBC_DIR}/file/${JAR_ETCD} ${CANTIANDB_HOME}/${JDRIVER_PACK_DIR_NAME}/
    chmod 500 ${CANTIANDB_HOME}/${JDRIVER_PACK_DIR_NAME}/${JAR_NAME}
    chmod 500 ${CANTIANDB_HOME}/${JDRIVER_PACK_DIR_NAME}/${JAR_ETCD}
    cd ${CANTIANDB_HOME} && tar --owner=root --group=root -zcf ${JDRIVER_PACK_DIR_NAME}.tar.gz ${JDRIVER_PACK_DIR_NAME}
    sha256sum ${CANTIANDB_HOME}/${JDRIVER_PACK_DIR_NAME}.tar.gz | cut -c1-64 > ${CANTIANDB_HOME}/${JDRIVER_PACK_DIR_NAME}.sha256
    echo "make jdbc driver finished"
}

func_logic_rep()
{
    if [[ -d "${LOGICREP_FILE_DIR}" ]]; then
        chmod -R 700 ${LOGICREP_FILE_DIR}/*
    fi
    rm -rf ${LOGICREP_DIR}/file

    cd ${LOGICREP_DIR} && sh build_package_unix.sh
    rm -rf ${LOGICREP_DIR}/file/${LOGICREP_GZ_NAME}
    chmod 700 ${LOGICREP_DIR}/file/*
    chmod 500 ${LOGICREP_DIR}/file/*.sh
    chmod 600 ${LOGICREP_DIR}/file/*.ini
    chmod 500 ${LOGICREP_DIR}/file/*.jar
    chmod 500 ${LOGICREP_DIR}/file/*.py
    chmod -R 700 ${LOGICREP_DIR}/file/conf/*
    chmod 600 ${LOGICREP_DIR}/file/conf/*.xml
    chmod 600 ${LOGICREP_DIR}/file/conf/*.properties
    chmod 600 ${LOGICREP_DIR}/file/conf/repconf/*.xml
    chmod 600 ${LOGICREP_DIR}/file/conf/topicconf/*.properties
    chmod 600 ${LOGICREP_DIR}/file/conf/sec/*.properties
    chmod -R 500 ${LOGICREP_DIR}/file/lib/*
    chmod -R 500 ${LOGICREP_DIR}/file/plugin/*

    rm -rf ${CANTIANDB_BIN}/${LOGICREP_DIR_NAME}*
    mkdir -p ${CANTIANDB_BIN}/${LOGICREP_DIR_NAME}/logicrep
    chmod 700 ${CANTIANDB_BIN}/${LOGICREP_DIR_NAME}/logicrep
    cp /home/repo1/com/huawei/gauss/com.huawei.gauss.jdbc.ZenithDriver/Cantian/com.huawei.gauss.jdbc.ZenithDriver-Cantian.jar ${LOGICREP_DIR}/file/lib/
    cd ${LOGICREP_DIR}/file/lib/
    mv com.huawei.gauss.jdbc.ZenithDriver-Cantian.jar com.huawei.cantian.jdbc.CantianDriver-Cantian.jar
    cp -r ${LOGICREP_DIR}/file/* ${CANTIANDB_BIN}/${LOGICREP_DIR_NAME}/logicrep/
    cd ${CANTIANDB_BIN}/${LOGICREP_DIR_NAME}/logicrep/ && ln -s com.huawei.cantian.logicrep-*.jar com.huawei.cantian.logicrep.jar
    cd ${CANTIANDB_BIN} && tar --owner=root --group=root -zcf ${LOGICREP_DIR_NAME}.tar.gz ${LOGICREP_DIR_NAME}
    sha256sum ${CANTIANDB_BIN}/${LOGICREP_DIR_NAME}.tar.gz | cut -c1-64 > ${CANTIANDB_BIN}/${LOGICREP_DIR_NAME}.sha256
}

func_toolkit()
{
    func_jdriver
    func_logic_rep
    rm -rf ${CANTIANDB_BIN}/${TOOLS_PACK_DIR_NAME}
    mkdir -p ${CANTIANDB_BIN}/${TOOLS_PACK_DIR_NAME}
    mv ${CANTIANDB_BIN}/${LOGICREP_DIR_NAME}.tar.gz ${CANTIANDB_BIN}/${TOOLS_PACK_DIR_NAME}
    cd ${CANTIANDB_BIN} && tar --owner=root --group=root -zcf ${TOOLS_PACK_DIR_NAME}.tar.gz ${TOOLS_PACK_DIR_NAME}
    sha256sum ${CANTIANDB_BIN}/${TOOLS_PACK_DIR_NAME}.tar.gz | cut -c1-64 > ${CANTIANDB_BIN}/${TOOLS_PACK_DIR_NAME}.sha256
}

func_release_symbol()
{
    if [ "${ENABLE_LLT_ASAN}" == "NO" ]; then
        echo "release symbol"
        mkdir -p ${CANTIANDB_SYMBOL}
        sh  ${CANTIANDB_BUILD}/${DBG_SYMBOL_SCRIPT} ${CANTIANDB_LIB}/libzeclient.so
        sh  ${CANTIANDB_BUILD}/${DBG_SYMBOL_SCRIPT} ${CANTIANDB_LIB}/libzecommon.so
        sh  ${CANTIANDB_BUILD}/${DBG_SYMBOL_SCRIPT} ${CANTIANDB_LIB}/libzeprotocol.so
        mv -f ${CANTIANDB_LIB}/libzeclient.${SO}.${SYMBOLFIX} ${CANTIANDB_SYMBOL}/libzeclient.${SO}.${SYMBOLFIX}
        mv -f ${CANTIANDB_LIB}/libzecommon.${SO}.${SYMBOLFIX} ${CANTIANDB_SYMBOL}/libzecommon.${SO}.${SYMBOLFIX}
        mv -f ${CANTIANDB_LIB}/libzeprotocol.${SO}.${SYMBOLFIX} ${CANTIANDB_SYMBOL}/libzeprotocol.${SO}.${SYMBOLFIX}

        sh  ${CANTIANDB_BUILD}/${DBG_SYMBOL_SCRIPT} ${CANTIANDB_BIN}/${CANTIAND_BIN}
        sh  ${CANTIANDB_BUILD}/${DBG_SYMBOL_SCRIPT} ${CANTIANDB_BIN}/cms
        sh  ${CANTIANDB_BUILD}/${DBG_SYMBOL_SCRIPT} ${CANTIANDB_BIN}/ctencrypt
        sh  ${CANTIANDB_BUILD}/${DBG_SYMBOL_SCRIPT} ${CANTIANDB_BIN}/ctsql
        sh  ${CANTIANDB_BUILD}/${DBG_SYMBOL_SCRIPT} ${CANTIANDB_BIN}/ctbox
        sh  ${CANTIANDB_BUILD}/${DBG_SYMBOL_SCRIPT} ${CANTIANDB_BIN}/ctbackup
        mv -f ${CANTIANDB_BIN}/${CANTIAND_BIN}.${SYMBOLFIX} ${CANTIANDB_SYMBOL}/${CANTIAND_BIN}.${SYMBOLFIX}
        mv -f ${CANTIANDB_BIN}/cms.${SYMBOLFIX} ${CANTIANDB_SYMBOL}/cms.${SYMBOLFIX}
        mv -f ${CANTIANDB_BIN}/ctencrypt.${SYMBOLFIX} ${CANTIANDB_SYMBOL}/ctencrypt.${SYMBOLFIX}
        mv -f ${CANTIANDB_BIN}/ctsql.${SYMBOLFIX} ${CANTIANDB_SYMBOL}/ctsql.${SYMBOLFIX}
        mv -f ${CANTIANDB_BIN}/ctbox.${SYMBOLFIX} ${CANTIANDB_SYMBOL}/ctbox.${SYMBOLFIX}
        mv -f ${CANTIANDB_BIN}/ctbackup.${SYMBOLFIX} ${CANTIANDB_SYMBOL}/ctbackup.${SYMBOLFIX}

        ##opensource library
        sh  ${CANTIANDB_BUILD}/${DBG_SYMBOL_SCRIPT} ${LZ4_LIB_PATH}/liblz4.so.1.9.4
        sh  ${CANTIANDB_BUILD}/${DBG_SYMBOL_SCRIPT} ${Z_LIB_PATH}/libz.so.1.2.13
        sh  ${CANTIANDB_BUILD}/${DBG_SYMBOL_SCRIPT} ${PCRE_LIB_PATH}/libpcre2-8.so.0.11.0
        sh  ${CANTIANDB_BUILD}/${DBG_SYMBOL_SCRIPT} ${ZSTD_LIB_PATH}/libzstd.so.1.5.2
        mv -f ${LZ4_LIB_PATH}/liblz4.so.1.9.4.${SYMBOLFIX}   ${CANTIANDB_SYMBOL}/liblz4.so.1.9.4.${SYMBOLFIX}
        mv -f ${Z_LIB_PATH}/libz.so.1.2.13.${SYMBOLFIX}       ${CANTIANDB_SYMBOL}/libz.so.1.2.13.${SYMBOLFIX}
        mv -f ${PCRE_LIB_PATH}/libpcre2-8.so.0.11.0.${SYMBOLFIX} ${CANTIANDB_SYMBOL}/libpcre2-8.so.0.11.0.${SYMBOLFIX}
        mv -f ${ZSTD_LIB_PATH}/libzstd.so.1.5.2.${SYMBOLFIX} ${CANTIANDB_SYMBOL}/libzstd.so.1.5.2.${SYMBOLFIX}

        sh ${CANTIANDB_BUILD}/${DBG_SYMBOL_SCRIPT} ${ZSTD_LIB_PATH}/../bin/zstd
        mv -f ${ZSTD_LIB_PATH}/../bin/zstd.${SYMBOLFIX} ${CANTIANDB_SYMBOL}/zstd.${SYMBOLFIX}

        func_pkg_symbol
    fi
}

func_version()
{
    echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" > ${CANTIANDB_BIN}/package.xml
    echo "<PackageInfo>" >> ${CANTIANDB_BIN}/package.xml
    echo "name=\"CantianDB 100\"" >> ${CANTIANDB_BIN}/package.xml
    echo "version=\"${VERSION_DESCRIP} ${BUILD_MODE}\"" >> ${CANTIANDB_BIN}/package.xml
    echo "desc=\"CantianDB 100 install\"" >> ${CANTIANDB_BIN}/package.xml
    merge_time=$(cat ${CANTIANDB_BUILD}/conf/git_message.in | grep merge_time |  awk -F'=' '{print  $2}')
    echo "createDate=\"${merge_time}\"" >> ${CANTIANDB_BIN}/package.xml
    WHOLE_COMMIT_ID=$(cat ${CANTIANDB_BUILD}/conf/git_message.in | grep gitVersion |  awk -F'=' '{print  $2}')
    echo "gitVersion=\"${WHOLE_COMMIT_ID}\"" >> ${CANTIANDB_BIN}/package.xml
    echo "</PackageInfo>" >> ${CANTIANDB_BIN}/package.xml
}

func_version_run_pkg()
{
    func_version
    cp  ${CANTIANDB_BIN}/package.xml ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}
}

func_version_ctsql_pkg()
{
    func_version
    cp  ${CANTIANDB_BIN}/package.xml ${CANTIANDB_BIN}/${CTSQL_PACK_DIR_NAME}
}

func_pkg_run_basic()
{
    func_version_run_pkg

    cd ${CANTIANDB_BIN}
    cp ctsql cantiand ctencrypt cms ctbackup ctbox ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}/bin/
    
    cp -d ${ZSTD_LIB_PATH}/../bin/zstd ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}/bin/
    cd ${CANTIANDB_HOME}
    cp ${CANTIANDB_INSTALL}/installdb.sh  ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}/bin/
    cp ${CANTIANDB_INSTALL}/shutdowndb.sh  ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}/bin/
    cp ${CANTIANDB_INSTALL}/uninstall.py  ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}/bin/
    cp ${CANTIANDB_INSTALL}/script/cluster/cluster.sh  ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}/bin/
    cp ${CANTIANDB_INSTALL}/sql_process.py  ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}/bin/
    cp ${CANTIANDB_INSTALL}/Common.py  ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}/bin/
    cp -d ${CANTIANDB_LIB}/libzeclient.so  ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}/lib/
    cp -d ${CANTIANDB_LIB}/libzecommon.so  ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}/lib/
    cp -d ${CANTIANDB_LIB}/libzeprotocol.so  ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}/lib/

    cp -d ${PCRE_LIB_PATH}/libpcre2-8.so*  ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}/add-ons/
    cp -d ${Z_LIB_PATH}/libz.so*  ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}/add-ons/
    cp -d ${ZSTD_LIB_PATH}/libzstd.so*  ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}/add-ons/
    cp -d ${LZ4_LIB_PATH}/liblz4.so*  ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}/add-ons/
    
    cp -R ${CANTIANDB_HOME}/admin  ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}/
    cp -R ${CANTIANDB_HOME}/cfg  ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}/
    if [ "${ENABLE_LLT_ASAN}" == "YES" ]; then
        if [[ ${OS_ARCH} =~ "x86_64" ]]; then
            cp -d /usr/lib64/libubsan.so* ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}/add-ons/
            cp -d /usr/lib64/libasan.so* ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}/add-ons/
        elif [[ ${OS_ARCH} =~ "aarch64" ]]; then 
            cp -d ${CANTIANDB_HOME}/../library/protobuf/${LIB_OS_ARCH}/libubsan.so* ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}/add-ons/
            cp -d ${CANTIANDB_HOME}/../library/protobuf/${LIB_OS_ARCH}/libasan.so* ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}/add-ons/
        else 
            echo "OS_ARCH: ${OS_ARCH} is unknown."
        fi
    fi

    chmod -R 700 ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}/*
    chmod 500 ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}/add-ons/*
    chmod 500 ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}/bin/*
    chmod 600 ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}/cfg/*
    chmod 500 ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}/lib/*
    chmod 500 ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}/add-ons/*
    chmod 400 ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}/package.xml
}

fun_pkg_mysql_lib()
{
    echo "DAAC_LIB_DIR:${DAAC_LIB_DIR}"
    echo "DAAC_LIB_DIR_TMP:${DAAC_LIB_DIR_TMP}"
    rm -rf ${DAAC_LIB_DIR}
    mkdir -p ${DAAC_LIB_DIR}
    mkdir -p ${DAAC_LIB_DIR_TMP}

    cp -d ${CANTIANDB_HOME}/../output/lib/*.a ${DAAC_LIB_DIR_TMP}
    cp -d ${CANTIANDB_HOME}/../library/huawei_security/lib/*.a ${DAAC_LIB_DIR_TMP}
    
    cd ${DAAC_LIB_DIR_TMP} && find . -name '*.a' -exec ar -x {} \;
    cd ${DAAC_LIB_DIR_TMP} && rm -rf *.a
    cd ${DAAC_LIB_DIR_TMP} && rm -rf tse_mysql_proxy.o
    cd ${DAAC_LIB_DIR_TMP} && ar cru libdaac.a *
    cd ${DAAC_LIB_DIR_TMP} && ranlib libdaac.a

    #删除.a里面的main函数
    strip -N main ${DAAC_LIB_DIR_TMP}/libdaac.a

    #dsw_boot.static_o中的print_version会跟mysql里面的print_version符号重复 这里需要重命名一下
    objcopy --redefine-sym print_version=daac_print_version ${DAAC_LIB_DIR_TMP}/libdaac.a
        
    cd ${DAAC_LIB_DIR_TMP} && ranlib libdaac.a
    cp ${DAAC_LIB_DIR_TMP}/libdaac.a ${DAAC_LIB_DIR}
    rm -rf ${DAAC_LIB_DIR_TMP}/

    cd ${CANTIANDB_HOME}/../library/protobuf/lib/ && cp *.a ${DAAC_LIB_DIR}
    cd ${CANTIANDB_HOME}/../build/pkg/src/tse/CMakeFiles/zectc.dir/message_queue/ && ar cr libmessage_queue.a *.o && cp libmessage_queue.a ${DAAC_LIB_DIR}

    cp -d ${CANTIANDB_HOME}/../library/pcre/lib/libpcre2-8.so* ${DAAC_LIB_DIR}
    cp -d ${CANTIANDB_HOME}/../output/lib/*.so ${DAAC_LIB_DIR}
    if [ "${ENABLE_LLT_ASAN}" == "YES" ]; then
        if [[ ${OS_ARCH} =~ "x86_64" ]]; then
            cp -d /usr/lib64/libubsan.so* ${DAAC_LIB_DIR}
            cp -d /usr/lib64/libasan.so* ${DAAC_LIB_DIR}
        elif [[ ${OS_ARCH} =~ "aarch64" ]]; then 
            cp -d ${CANTIANDB_HOME}/../library/protobuf/lib_arm/libubsan.so* ${DAAC_LIB_DIR}
            cp -d ${CANTIANDB_HOME}/../library/protobuf/lib_arm/libasan.so* ${DAAC_LIB_DIR}
        else 
            echo "OS_ARCH: ${OS_ARCH} is unknown."
        fi
    fi
    chmod -R 755 ${DAAC_LIB_DIR}
}

func_pkg_run()
{
    fun_pkg_mysql_lib
    func_pkg_run_basic
    find ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}/admin/scripts/ -type f -print0 | xargs -0 chmod 400
    find ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}/admin/scripts/ -type d -print0 | xargs -0 chmod 700
    cd ${CANTIANDB_BIN} && tar --owner=root --group=root -zcf ${RUN_PACK_DIR_NAME}.tar.gz ${RUN_PACK_DIR_NAME}
    rm -rf ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}/bin/script
}

func_pkg_symbol()
{
    echo "pkg symbol"

    rm -rf ${CANTIANDB_BIN}/${SYMBOL_PACK_DIR_NAME}*
    mkdir -p ${CANTIANDB_BIN}/${SYMBOL_PACK_DIR_NAME}
    cp -rf ${CANTIANDB_SYMBOL}/*.${SYMBOLFIX} ${CANTIANDB_BIN}/${SYMBOL_PACK_DIR_NAME}/
    chmod 500 ${CANTIANDB_BIN}/${SYMBOL_PACK_DIR_NAME}/*
    cd ${CANTIANDB_BIN} && tar --owner=root --group=root -zcf ${SYMBOL_PACK_DIR_NAME}.tar.gz ${SYMBOL_PACK_DIR_NAME}
    sha256sum ${CANTIANDB_BIN}/${SYMBOL_PACK_DIR_NAME}.tar.gz | cut -c1-64 > ${CANTIANDB_BIN}/${SYMBOL_PACK_DIR_NAME}.sha256
}

func_make_debug()
{
    echo "make debug"
    func_all Debug
    func_prepare_pkg_name
    func_pkg_run
}

func_make_release()
{
    echo "make release"
    func_all Release
    func_prepare_pkg_name
    func_release_symbol   
    func_pkg_run
}

func_collect_mysql_target()
{
  local node_id=$1
  if [ "${node_id}" == "node0" ]; then
    mkdir -p ${MYSQL_DIR}/mysql_bin/mysql
    cp -arf /usr/local/mysql/* ${MYSQL_DIR}/mysql_bin/mysql/
  elif [ "${node_id}" == "node1" ]; then
    cp -arf ${MYSQL_DIR}/daac_lib/libsecurec.so /usr/lib64/
  else
    echo "input error node_id, please check!"
    exit 1
  fi
}

func_make_mysql_debug()
{
  echo "Start build Mysql Debug..."
  rm -rf ${MYSQL_CODE_PATH}/daac_lib
  mkdir -p ${MYSQL_CODE_PATH}/daac_lib
  cp -arf ${DAAC_LIB_DIR}/* ${MYSQL_CODE_PATH}/daac_lib/
  mkdir -p ${MYSQL_CODE_PATH}/bld_debug
  local LLT_TEST_TYPE="NORMAL"
  if [ "${ENABLE_LLT_GCOV}" == "YES" ]; then
    LLT_TEST_TYPE="GCOV"
  elif [ "${ENABLE_LLT_ASAN}" == "YES" ]; then
    LLT_TEST_TYPE="ASAN"
  fi
  prepareGetMysqlClientStaticLibToDaaclib ${MYSQL_CODE_PATH} "DEBUG" ${LLT_TEST_TYPE} ${BOOST_PATH} ${CPU_CORES_NUM} ${MYSQL_CODE_PATH}/bld_debug

  cd ${MYSQL_CODE_PATH}/bld_debug
  cp -arf "${CANTIANDB_LIBRARY}"/shared_lib/lib/libsecurec.so /usr/lib64/
  if [ "${MYSQL_BUILD_MODE}" == "multiple" ]; then
    if [ "${ENABLE_LLT_GCOV}" == "YES" ]; then
      cmake .. -DCMAKE_CXX_COMPILER=/usr/bin/g++ -DCMAKE_C_COMPILER=/usr/bin/gcc -DENABLE_GCOV=1 -DWITH_TSE_STORAGE_ENGINE=${WITH_TSE_STORAGE_ENGINE} -DCMAKE_BUILD_TYPE=Debug -DWITH_BOOST=${BOOST_PATH} -DWITHOUT_SERVER=OFF
    elif [ "${ENABLE_LLT_ASAN}" == "YES" ]; then
      cmake .. -DCMAKE_CXX_COMPILER=/usr/bin/g++ -DCMAKE_C_COMPILER=/usr/bin/gcc -DWITH_ASAN=ON -DWITH_ASAN_SCOPE=ON -DWITH_TSE_STORAGE_ENGINE=${WITH_TSE_STORAGE_ENGINE} -DCMAKE_BUILD_TYPE=Debug -DWITH_BOOST=${BOOST_PATH} -DWITHOUT_SERVER=OFF
    else
      cmake .. -DWITH_TSE_STORAGE_ENGINE=${WITH_TSE_STORAGE_ENGINE} -DCMAKE_BUILD_TYPE=Debug -DWITH_BOOST=${BOOST_PATH} -DWITHOUT_SERVER=OFF
    fi
  elif [ "${MYSQL_BUILD_MODE}" == "single" ]; then
    cmake .. -DWITH_DAAC=1 -DWITH_TSE_STORAGE_ENGINE=${WITH_TSE_STORAGE_ENGINE} -DCMAKE_BUILD_TYPE=Debug -DWITH_BOOST=${BOOST_PATH} -DWITHOUT_SERVER=OFF
  fi

  MYSQL_BUILD_TYPE="debug"

  if [ -f ${MYSQL_BINARY_CODE_PATH}/mysql_${MYSQL_BUILD_TYPE}_${OS_ARCH}_${MYSQL_COMMIT_ID}.tar.gz ]; then
      cd  ${MYSQL_CODE_PATH}/bld_debug/storage/tianchi && make -j${CPU_CORES_NUM} && make install
      cd ${MYSQL_BINARY_CODE_PATH} && tar -xzf mysql_${MYSQL_BUILD_TYPE}_${OS_ARCH}_${MYSQL_COMMIT_ID}.tar.gz -C /usr/local/
      echo "mysql binary code untar succeed"
      chmod +x /usr/local/mysql/bin/*
      cp -arf /${MYSQL_CODE_PATH}/mysql-test /usr/local/mysql/
  else
      make -j${CPU_CORES_NUM}
      make install
  fi
  cp -r -f -p ${MYSQL_CODE_PATH}/daac_lib/libctc_proxy.so /usr/lib64
  echo 'log_raw=ON' >> /usr/local/mysql/mysql-test/include/default_mysqld.cnf
  cd -
}

func_separate_mysql_symbol()
{
  local bin_dir=$1
  local symbol_dir=$2
  mkdir -p ${symbol_dir}
  rm -f ${symbol_dir}/*
  local file_list=("mysqld" "mysql")
  cd ${bin_dir}
  for file in ${file_list[@]}
  do
    cp ${file} ${file}.debug
    mv ${file}.debug ${symbol_dir}
    objcopy --strip-debug ${file}
  done
  cd -
}

func_make_mysql_release()
{
  echo "Start build Mysql Release..."
  rm -rf ${MYSQL_CODE_PATH}/daac_lib
  mkdir -p ${MYSQL_CODE_PATH}/daac_lib
  cp -arf ${DAAC_LIB_DIR}/* ${MYSQL_CODE_PATH}/daac_lib/
  mkdir -p ${MYSQL_CODE_PATH}/bld_debug
  local LLT_TEST_TYPE="NORMAL"
  if [ "${ENABLE_LLT_GCOV}" == "YES" ]; then
    LLT_TEST_TYPE="GCOV"
  elif [ "${ENABLE_LLT_ASAN}" == "YES" ]; then
    LLT_TEST_TYPE="ASAN"
  fi
  prepareGetMysqlClientStaticLibToDaaclib ${MYSQL_CODE_PATH} "RELEASE" ${LLT_TEST_TYPE} ${BOOST_PATH} ${CPU_CORES_NUM} ${MYSQL_CODE_PATH}/bld_debug

  cd ${MYSQL_CODE_PATH}/bld_debug
  cp -arf "${CANTIANDB_LIBRARY}"/shared_lib/lib/libsecurec.so /usr/lib64/
  if [ "${MYSQL_BUILD_MODE}" == "multiple" ]; then
    cmake .. -DWITH_TSE_STORAGE_ENGINE=${WITH_TSE_STORAGE_ENGINE} -DCMAKE_BUILD_TYPE=Release -DWITH_BOOST=${BOOST_PATH} -DCMAKE_C_FLAGS=-g -DCMAKE_CXX_FLAGS=-g -DWITHOUT_SERVER=OFF
  elif [ "${MYSQL_BUILD_MODE}" == "single" ]; then
    cmake .. -DWITH_DAAC=1 -DWITH_TSE_STORAGE_ENGINE=${WITH_TSE_STORAGE_ENGINE} -DCMAKE_BUILD_TYPE=Release -DWITH_BOOST=${BOOST_PATH} -DCMAKE_C_FLAGS=-g -DCMAKE_CXX_FLAGS=-g -DWITHOUT_SERVER=OFF
  fi

  MYSQL_BUILD_TYPE="release"
  if [ -f ${MYSQL_BINARY_CODE_PATH}/mysql_${MYSQL_BUILD_TYPE}_${OS_ARCH}_${MYSQL_COMMIT_ID}.tar.gz ]; then
      cd  ${MYSQL_CODE_PATH}/bld_debug/storage/tianchi && make -j${CPU_CORES_NUM} && make install
      cd ${MYSQL_BINARY_CODE_PATH} && tar -xzf mysql_${MYSQL_BUILD_TYPE}_${OS_ARCH}_${MYSQL_COMMIT_ID}.tar.gz -C /usr/local/
      echo "mysql binary code untar succeed"
      chmod +x /usr/local/mysql/bin/*
      cp -arf /${MYSQL_CODE_PATH}/mysql-test /usr/local/mysql/
  else
      make -j${CPU_CORES_NUM}
      make install
  fi
  cp -r -f -p ${MYSQL_CODE_PATH}/daac_lib/libctc_proxy.so /usr/lib64
  echo 'log_raw=ON' >> /usr/local/mysql/mysql-test/include/default_mysqld.cnf
  func_separate_mysql_symbol /usr/local/mysql/bin ${MYSQL_CODE_PATH}/mysql_bin/symbol
  cd -
}

func_test()
{
    echo "make test"
    func_all Debug
    strip -N main ${CANTIANDB_LIB}/libzeserver.a
    cd ${CT_TEST_BUILD_DIR}
    make -sj 8 

    if [[ -e "${CANTIANDB_BIN}"/cantiand ]]; then
        cd ${CANTIANDB_BIN}
        rm -rf ${CANTIAND_BIN} && ln cantiand ${CANTIAND_BIN}
    fi

    if [[ ! -d "${CANTIANDB_HOME}"/add-ons ]]; then
        mkdir -p  ${CANTIANDB_HOME}/add-ons
    fi

    cp -d ${ZSTD_LIB_PATH}/libzstd.so*  ${CANTIANDB_HOME}/add-ons/
    cp -d ${LZ4_LIB_PATH}/liblz4.so* ${CANTIANDB_HOME}/add-ons/
    cp -rf ${CANTIANDB_BIN} ${CANTIANDB_HOME}
    cp -rf ${CANTIANDB_LIB} ${CANTIANDB_HOME}
    cp -rf ${CANTIANDB_LIBRARY} ${CANTIANDB_HOME}

}

prepare_bazel_dependency()
{
    echo "prepare_bazel_dependency"
    func_prepare_dependency

    if [[ ! -d "${CANTIANDB_HOME}"/add-ons ]]; then
        mkdir -p  ${CANTIANDB_HOME}/add-ons
    fi

    cp -d ${ZSTD_LIB_PATH}/libzstd.so*  ${CANTIANDB_HOME}/add-ons/
    cp -d ${LZ4_LIB_PATH}/liblz4.so* ${CANTIANDB_HOME}/add-ons/
    cp -rf ${CANTIANDB_BIN} ${CANTIANDB_HOME}
    cp -rf ${CANTIANDB_LIB} ${CANTIANDB_HOME}
    cp -rf ${CANTIANDB_LIBRARY} ${CANTIANDB_HOME}

}

func_clean()
{
    echo "make clean"
    func_prepare_debug
    func_prepare_pkg_name

    cd ${CANTIANDB_BUILD}
    make clean

    cd ${CT_TEST_BUILD_DIR}
    make clean

    if [[ -d "${CANTIANDB_BIN}" ]];then
        echo ${CANTIANDB_BIN}
        chmod -R 700 ${CANTIANDB_BIN}
    fi

    echo ${CANTIANDB_OUTPUT}
    
    rm -rf ${CANTIANDB_OUTPUT}/*
    rm -rf ${CANTIANDB_HOME}/../${ALL_PACK_DIR_NAME}

    cd ${CANTIANDB_BUILD}
    rm -rf pkg
    rm -rf CMakeFiles
    rm -f Makefile
    rm -f cmake_install.cmake
    rm -f CMakeCache.txt

    rm -rf ${MYSQL_DIR}/bld_debug/*
}

func_pkg_ctsql()
{
    echo "make pkg ctsql"

    rm -rf ${CANTIANDB_BIN}/${CTSQL_PACK_DIR_NAME}*
    mkdir -p ${CANTIANDB_BIN}/${CTSQL_PACK_DIR_NAME}
    mkdir -p ${CANTIANDB_BIN}/${CTSQL_PACK_DIR_NAME}/bin
    mkdir -p ${CANTIANDB_BIN}/${CTSQL_PACK_DIR_NAME}/lib
    mkdir -p ${CANTIANDB_BIN}/${CTSQL_PACK_DIR_NAME}/add-ons

    func_version_ctsql_pkg

    cp ${CANTIANDB_BIN}/ctsql ${CANTIANDB_BIN}/${CTSQL_PACK_DIR_NAME}/bin/ctsql
    cp -d ${CANTIANDB_LIB}/libzeclient.so ${CANTIANDB_BIN}/${CTSQL_PACK_DIR_NAME}/lib/
    cp -d ${CANTIANDB_LIB}/libzecommon.so ${CANTIANDB_BIN}/${CTSQL_PACK_DIR_NAME}/lib/
    cp -d ${CANTIANDB_LIB}/libzeprotocol.so ${CANTIANDB_BIN}/${CTSQL_PACK_DIR_NAME}/lib/
    
    cp -d ${Z_LIB_PATH}/libz.so* ${CANTIANDB_BIN}/${CTSQL_PACK_DIR_NAME}/add-ons/
    cp -d ${PCRE_LIB_PATH}/libpcre2-8.so* ${CANTIANDB_BIN}/${CTSQL_PACK_DIR_NAME}/add-ons/

    chmod -R 700 ${CANTIANDB_BIN}/${CTSQL_PACK_DIR_NAME}/*
    chmod 500 ${CANTIANDB_BIN}/${CTSQL_PACK_DIR_NAME}/add-ons/*
    chmod 500 ${CANTIANDB_BIN}/${CTSQL_PACK_DIR_NAME}/bin/*
    chmod 500 ${CANTIANDB_BIN}/${CTSQL_PACK_DIR_NAME}/lib/*
    chmod 400 ${CANTIANDB_BIN}/${CTSQL_PACK_DIR_NAME}/package.xml

    cd ${CANTIANDB_BIN} && tar --owner=root --group=root -zcf ${CTSQL_PACK_DIR_NAME}.tar.gz ${CTSQL_PACK_DIR_NAME}
    sha256sum ${CANTIANDB_BIN}/${CTSQL_PACK_DIR_NAME}.tar.gz | cut -c1-64 > ${CANTIANDB_BIN}/${CTSQL_PACK_DIR_NAME}.sha256

}


func_making_package()
{
    build_package_mode=$1
    if [[ -z "${build_package_mode}" ]]; then
        build_package_mode = 'Debug'
    fi

    if [[ "${build_package_mode}" = 'Debug' ]] || [[ "${build_package_mode}" = 'Shard_Debug' ]]; then
        func_make_debug
    else
        echo "make release"
        func_all Release
        func_prepare_pkg_name        
    fi
    
    if [[ "${build_package_mode}" = 'Release' ]] || [[ "${build_package_mode}" = 'Shard_Release' ]]; then
        func_release_symbol
        func_pkg_run
    fi

    func_toolkit

    rm -rf ${CANTIANDB_HOME}/../${ALL_PACK_DIR_NAME}
    rm -rf ${CANTIANDB_BIN}/${ALL_PACK_DIR_NAME}
    rm -rf ${CANTIANDB_BIN}/${ALL_PACK_DIR_NAME}.tar.gz
    mkdir -p ${CANTIANDB_BIN}/${ALL_PACK_DIR_NAME}
    cp ${CANTIANDB_HOME}/install/install.py ${CANTIANDB_BIN}/${ALL_PACK_DIR_NAME}/
    cp ${CANTIANDB_HOME}/install/funclib.py ${CANTIANDB_BIN}/${ALL_PACK_DIR_NAME}/
    cp ${CANTIANDB_HOME}/install/installdb.sh ${CANTIANDB_BIN}/${ALL_PACK_DIR_NAME}/
    mkdir -p ${CANTIANDB_LIBRARY}/shared_lib/lib/
    cp -f ${CANTIANDB_HOME}/../platform/HuaweiSecureC/lib/* ${CANTIANDB_LIBRARY}/shared_lib/lib/

    chmod -R 500 ${CANTIANDB_BIN}/${ALL_PACK_DIR_NAME}/install.py
    chmod -R 500 ${CANTIANDB_BIN}/${ALL_PACK_DIR_NAME}/funclib.py
    chmod -R 500 ${CANTIANDB_BIN}/${ALL_PACK_DIR_NAME}/installdb.sh
    mv ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}.tar.gz ${CANTIANDB_BIN}/${ALL_PACK_DIR_NAME}/
    sha256sum ${CANTIANDB_BIN}/${ALL_PACK_DIR_NAME}/${RUN_PACK_DIR_NAME}.tar.gz | cut -c1-64 > ${CANTIANDB_BIN}/${ALL_PACK_DIR_NAME}/${RUN_PACK_DIR_NAME}.sha256
    chmod 400 ${CANTIANDB_BIN}/${ALL_PACK_DIR_NAME}/${RUN_PACK_DIR_NAME}.sha256
    cd ${CANTIANDB_BIN} && tar --owner=root --group=root -zcf ${ALL_PACK_DIR_NAME}.tar.gz ${ALL_PACK_DIR_NAME}
    sha256sum ${CANTIANDB_BIN}/${ALL_PACK_DIR_NAME}.tar.gz | cut -c1-64 > ${CANTIANDB_BIN}/${ALL_PACK_DIR_NAME}.sha256
    func_pkg_ctsql
    
    find ${CANTIANDB_BIN} -name "*.sha256" -exec chmod 400 {} \;
    cp -arf ${CANTIANDB_BIN}/${ALL_PACK_DIR_NAME} ${CANTIANDB_HOME}/../${ALL_PACK_DIR_NAME}
}

func_download_3rdparty()
{
    if [[ "${WORKSPACE}" == *"regress"* ]]; then
        DOWNLOAD_PATH=$DFT_WORKSPACE"/CantianKernel"
    else
        DOWNLOAD_PATH=${WORKSPACE}"/cantian"
    fi

    mkdir -p ${WORKSPACE}/3rdPartyPkg
    cd ${WORKSPACE}/3rdPartyPkg
    if [[ ! -e "cantian3.0.0.zip" ]]; then
        wget https://gitee.com/solid-yang/cantian-test/repository/archive/cantian3.0.0.zip
        unzip cantian3.0.0.zip
        mv cantian-test-cantian3.0.0/* ./
        rm -rf cantian-test-cantian3.0.0
    fi
    cd -

    lib_name_list=("huawei_security" "lz4" "openssl" "pcre" "protobuf" "protobuf-c" "zlib" "Zstandard")
    
    mkdir -p ${DOWNLOAD_PATH}/platform

    for lib_name in ${lib_name_list[@]}; do
    echo ${lib_name}
    mkdir -p ${DOWNLOAD_PATH}/open_source/${lib_name}/include
    mkdir -p ${DOWNLOAD_PATH}/library/${lib_name}/lib
    done
 
    cp -f ${WORKSPACE}/3rdPartyPkg/pcre2-10.40.tar.gz ${DOWNLOAD_PATH}/open_source/pcre/
    cp -f ${WORKSPACE}/3rdPartyPkg/lz4-1.9.4.tar.gz ${DOWNLOAD_PATH}/open_source/lz4/
    cp -f ${WORKSPACE}/3rdPartyPkg/zstd-1.5.2.tar.gz ${DOWNLOAD_PATH}/open_source/Zstandard/
    cp -f ${WORKSPACE}/3rdPartyPkg/protobuf-all-3.13.0.tar.gz ${DOWNLOAD_PATH}/open_source/protobuf/
    cp -f ${WORKSPACE}/3rdPartyPkg/protobuf-c-1.4.1.tar.gz ${DOWNLOAD_PATH}/open_source/protobuf-c/
    cp -f ${WORKSPACE}/3rdPartyPkg/openssl-3.0.7.tar.gz ${DOWNLOAD_PATH}/open_source/openssl/
    cp -f ${WORKSPACE}/3rdPartyPkg/zlib-1.2.13.tar.gz ${DOWNLOAD_PATH}/open_source/zlib/
    cp -f ${WORKSPACE}/3rdPartyPkg/huawei_secure_c.zip ${DOWNLOAD_PATH}/platform/

    echo "start compile 3rdparty : "
    sh compile_opensource_new.sh
}
 
## download 3rd-party lib and platform lib
func_prepare_dependency()
{
    echo "Prepare LCRP_HOME dependency func : "
    if [[ ! -d ${CANTIANDB_LIBRARY} ]]; then
        echo "library dir not exist"
        mkdir -p ${CANTIANDB_LIBRARY}
    fi

    if [[ ! -d ${CANTIANDB_OPEN_SOURCE} ]]; then
        echo "open_source dir not exist"
        mkdir -p ${CANTIANDB_OPEN_SOURCE}
    fi

    if [[ ! -d ${CANTIANDB_OUTPUT} ]]; then
        echo "output dir not exist"
        mkdir -p ${CANTIANDB_OUTPUT}
    fi

    if [[ ! -d ${CANTIANDB_PLATFORM} ]]; then
        echo "platform dir not exist"
        mkdir -p ${CANTIANDB_PLATFORM}
    fi

    if [[ ! -d ${MYSQL_BINARY_CODE_PATH} ]]; then
            echo "mysql binary code dir not exist"
            mkdir -p ${MYSQL_BINARY_CODE_PATH}
    fi
    
    #下载三方库并编译
    func_download_3rdparty

    chmod 755 ${CANTIANDB_HOME}/../library/protobuf/lib/libprotobuf-c.a
}

func_prepare_LLT_dependency()
{
    echo "Prepare LCRP_HOME dependency func : "
    if [[ ! -d ${CANTIANDB_LIBRARY} ]]; then
        echo "library dir not exist"
        mkdir -p ${CANTIANDB_LIBRARY}
    fi

    if [[ ! -d ${CANTIANDB_OPEN_SOURCE} ]]; then
        echo "open_source dir not exist"
        mkdir -p ${CANTIANDB_OPEN_SOURCE}
    fi

    if [[ ! -d ${CANTIANDB_OUTPUT} ]]; then
        echo "output dir not exist"
        mkdir -p ${CANTIANDB_OUTPUT}
    fi

    if [[ ! -d ${CANTIANDB_PLATFORM} ]]; then
        echo "platform dir not exist"
        mkdir -p ${CANTIANDB_PLATFORM}
    fi

    if [[ ! -d ${MYSQL_BINARY_CODE_PATH} ]]; then
            echo "mysql binary code dir not exist"
            mkdir -p ${MYSQL_BINARY_CODE_PATH}
    fi

    echo ${LCRP_HOME}
    mkdir -p /root/.ArtGet/conf
    cp -f ${CANTIANDB_CI_PATH}/CMC/Setting.xml /root/.ArtGet/conf
    OS_Version=`sh ${CANTIANDB_CI_PATH}/CMC/get_OS_Version.sh`

    #下载三方库并编译
    if [[ "${WORKSPACE}" == *"regress"* ]]; then
        DOWNLOAD_PATH=$DFT_WORKSPACE"/CantianKernel"
    else
        DOWNLOAD_PATH=${WORKSPACE}"/cantian"
    fi

    echo "start download 3rdparty : ${DOWNLOAD_PATH}"
    python ${CANTIANDB_CI_PATH}/CMC/manifest_opensource_download.py manifest_opensource.xml ${DOWNLOAD_PATH}
    sh download_opensource_cmc.sh
    echo "start download 3rdparty lib: "
    artget pull -d ${CANTIANDB_CI_PATH}/CMC/CantianKernel_opensource_dependency.xml -p "{'OS_Version':'${OS_Version}'}"  -user ${cmc_username} -pwd ${cmc_password}

    artget pull -d ${CANTIANDB_CI_PATH}/CMC/CantianKernel_dependency_new.xml -p "{'OS_Version':'${OS_Version}'}"  -user ${cmc_username} -pwd ${cmc_password}
    if [[ $? -ne 0 ]]; then
        echo "dependency download failed"
        exit 1
    else
        echo "dependency download succeed"
    fi 

    chmod 755 ${CANTIANDB_HOME}/../library/protobuf/lib/libprotobuf-c.a
}

#获取最新包地址
function expect_ssh_get_latest_tar_file_path() {   
	local ip=$1
    local file_path=$2
    /usr/bin/expect << EOF
    spawn ssh aa_release@${ip} "ls ~${file_path} | sort | uniq | tail -n 1"
    expect {
        "*yes/no" { send "yes\r"; exp_continue }
        "*password:*" { send "aa_release\r"}
    }
    expect eof
EOF
}

# 从sftp服务器上下载包
function down_client_file() {
    local ip=$1
    local file_path=$2
    local local_file=$3
    /usr/bin/expect << EOF
    set timeout -1
    spawn scp -rp aa_release@${ip}:${file_path} ${local_file}
    expect {
        "*yes/no" { send "yes\r"; exp_continue }
        "*password:*" { send "aa_release\r"}
    }
    expect eof
EOF
}

func_make_raft()
{
    ## download dependency:
    func_prepare_dependency

    echo "make raft"
    
    raft_build_mode=$1
    if [[ -z "${raft_build_mode}" ]]; then
        raft_build_mode='Debug'
    fi

    if [[ "${raft_build_mode}" = 'Debug' ]]; then
        func_prepare_debug
    else
        func_prepare_release
    fi

    cd ${CT_SRC_BUILD_DIR}/raft && make -sj 8
}

func_regress_test()
{
    echo "make debug"
    ## download dependency:
    func_prepare_LLT_dependency
    func_prepare_debug
    cd ${CT_SRC_BUILD_DIR}
    set +e
    make all -sj 8
    if [ $? -ne 0 ]; then
        ls -al ${CANTIANDB_LIB}
        ls -al /home/regress
        ls -al /home/regress/CantianKernel/build
        exit 1
    fi 
    set -e 

    if [[ -e "${CANTIANDB_BIN}"/cantiand ]]; then
        cd ${CANTIANDB_BIN}
        if [ -e "${CANTIAND_BIN}" ]; then
          rm ${CANTIAND_BIN}
        fi
        ln cantiand ${CANTIAND_BIN}
    fi
}

func_make_test_debug()
{
    echo "make debug"
    ## download dependency:
    func_prepare_LLT_dependency
    func_prepare_debug
    cd ${CT_SRC_BUILD_DIR}
    set +e
    make all -sj 8
    if [ $? -ne 0 ]; then
        ls -al ${CANTIANDB_LIB}
        ls -al /home/regress
        ls -al /home/regress/CantianKernel/build
        exit 1
    fi 
    set -e 

    if [[ -e "${CANTIANDB_BIN}"/cantiand ]]; then
        cd ${CANTIANDB_BIN}
        if [ -e "${CANTIAND_BIN}" ]; then
          rm ${CANTIAND_BIN}
        fi
        ln cantiand ${CANTIAND_BIN}
    fi
    func_prepare_pkg_name
    func_pkg_run_basic
    chmod 400 ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}/admin/scripts/*
    #chmod 700 ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}/admin/scripts/upgrade
    #chmod 400 ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}/admin/scripts/upgrade/*
    cd ${CANTIANDB_BIN} && tar --owner=root --group=root -zcf ${RUN_PACK_DIR_NAME}.tar.gz ${RUN_PACK_DIR_NAME}
    rm -rf ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}/bin/script
}

func_making_package_test()
{
    build_package_mode=$1
    if [[ -z "${build_package_mode}" ]]; then
        build_package_mode = 'Debug'
    fi
 
    func_make_test_debug
 
    rm -rf ${CANTIANDB_HOME}/../${ALL_PACK_DIR_NAME}
    rm -rf ${CANTIANDB_BIN}/${ALL_PACK_DIR_NAME}
    rm -rf ${CANTIANDB_BIN}/${ALL_PACK_DIR_NAME}.tar.gz
    mkdir -p ${CANTIANDB_BIN}/${ALL_PACK_DIR_NAME}
    cp ${CANTIANDB_HOME}/install/install.py ${CANTIANDB_BIN}/${ALL_PACK_DIR_NAME}/
    cp ${CANTIANDB_HOME}/install/funclib.py ${CANTIANDB_BIN}/${ALL_PACK_DIR_NAME}/
    cp ${CANTIANDB_HOME}/install/installdb.sh ${CANTIANDB_BIN}/${ALL_PACK_DIR_NAME}/
 
    chmod -R 500 ${CANTIANDB_BIN}/${ALL_PACK_DIR_NAME}/install.py
    chmod -R 500 ${CANTIANDB_BIN}/${ALL_PACK_DIR_NAME}/funclib.py
    chmod -R 500 ${CANTIANDB_BIN}/${ALL_PACK_DIR_NAME}/installdb.sh
    mv ${CANTIANDB_BIN}/${RUN_PACK_DIR_NAME}.tar.gz ${CANTIANDB_BIN}/${ALL_PACK_DIR_NAME}/
    sha256sum ${CANTIANDB_BIN}/${ALL_PACK_DIR_NAME}/${RUN_PACK_DIR_NAME}.tar.gz | cut -c1-64 > ${CANTIANDB_BIN}/${ALL_PACK_DIR_NAME}/${RUN_PACK_DIR_NAME}.sha256
    chmod 400 ${CANTIANDB_BIN}/${ALL_PACK_DIR_NAME}/${RUN_PACK_DIR_NAME}.sha256
    cd ${CANTIANDB_BIN} && tar --owner=root --group=root -zcf ${ALL_PACK_DIR_NAME}.tar.gz ${ALL_PACK_DIR_NAME}
    sha256sum ${CANTIANDB_BIN}/${ALL_PACK_DIR_NAME}.tar.gz | cut -c1-64 > ${CANTIANDB_BIN}/${ALL_PACK_DIR_NAME}.sha256
    
    find ${CANTIANDB_BIN} -name "*.sha256" -exec chmod 400 {} \;
    cp -arf ${CANTIANDB_BIN}/${ALL_PACK_DIR_NAME} ${CANTIANDB_HOME}/../${ALL_PACK_DIR_NAME}
}

main()
{
    echo "Main Function : "
    arg0=$0
    arg1=$1

    until [[ -z "$2" ]]
    do {
        echo $2
        arg2=$2

        case "${arg2}" in
        'test_cbo=1')
            echo "test_cbo enable"
            COMPILE_OPTS="${COMPILE_OPTS} -DUSE_CBOTEST=ON"
            ;;
        'protect_buf=1')
            echo "protect_buf enable"
            COMPILE_OPTS="${COMPILE_OPTS} -DUSE_PROTECT_BUF=ON"
            ;;
        'crc=1')
            echo "crc enable"
            COMPILE_OPTS="${COMPILE_OPTS} -DUSE_CRC=ON"
            ;;
        'protect_vm=1')
            echo "protect_vm enable"
            COMPILE_OPTS="${COMPILE_OPTS} -DUSE_PROTECT_VM=ON"
            ;;
        'cantiand_cn=1')
            echo "cantiand_cn enable"
            COMPILE_OPTS="${COMPILE_OPTS} -DUSE_CANTIAND_CN=ON"
            ;;
        'test_mem=1')
            echo "test_mem enable"
            COMPILE_OPTS="${COMPILE_OPTS} -DUSE_TEST_MEM=ON"
            ;;
        'lcov=1')
            echo "lcov enable"
            ENABLE_LLT_GCOV="YES"
            COMPILE_OPTS="${COMPILE_OPTS} -DUSE_LCOV=ON"
            ;;
        'llt=1')
            echo "llt enable"
            COMPILE_OPTS="${COMPILE_OPTS} -DUSE_LLT=ON"
            ;;
        'asan=1')
            echo "ASAN enable"
            ENABLE_LLT_ASAN="YES"
            COMPILE_OPTS="${COMPILE_OPTS} -DUSE_ASAN=ON"
            ;;
        'fuzzasan=1')
            echo "FUZZ ASAN ENABLE"
            mkdir -p ${CANTIANDB_LIB}
            cp -f ${CANTIANDB_LIBRARY}/secodefuzz/lib/* ${CANTIANDB_LIB}
            COMPILE_OPTS="${COMPILE_OPTS} -DUSE_ASAN=ON"
            COMPILE_OPTS="${COMPILE_OPTS} -DUSE_FUZZASAN=ON"
            COMPILE_OPTS="${COMPILE_OPTS} -DUSE_LCOV=ON"
            ;;
        'tsan=1')
            echo "TSAN enable"
            COMPILE_OPTS="${COMPILE_OPTS} -DUSE_TSAN=ON"
            ;;
        'canalyze=1')
            echo "Canalyze enable"
            COMPILE_OPTS="${COMPILE_OPTS} -DCMAKE_EXPORT_COMPILE_COMMANDS=1 "
            ;;
        'h1620=1')
            echo "h1620 enable"
            COMPILE_OPTS="${COMPILE_OPTS} -DUSE_H1620=ON"
            ;;
        'no_shm=1')
            echo "build with out shm"
            COMPILE_OPTS="${COMPILE_OPTS} -DNO_SHM=ON"
            ;;
        'DAAC_READ_WRITE=1')
            echo "build with DAAC_READ_WRITE"
            COMPILE_OPTS="${COMPILE_OPTS} -DDAAC_READ_WRITE=ON"
            ;;
        *)
            echo "Wrong compile options"
            exit 1
            ;;
        esac
        shift
    }
    done

    case "${arg1}" in
    'all')
        COMPILE_OPTS="${COMPILE_OPTS} -DUSE_PROTECT_VM=ON"
        func_all Debug
        ;;
    'debug')
        COMPILE_OPTS="${COMPILE_OPTS} -DUSE_PROTECT_VM=ON"
        func_make_debug
        ;;
    'release')
        func_make_release
        ;;
    'mysqllib')
        fun_pkg_mysql_lib
        ;;
    'mysql'|'mysql_debug')
        func_make_mysql_debug
        ;;
    'mysql_release')
        func_make_mysql_release
        ;;
    'mysql_package_node0')
        func_collect_mysql_target node0
        ;;
    'mysql_package_node1')
        func_collect_mysql_target node1
        ;;
    'clean')
        func_clean
        ;;
    'test')
	    COMPILE_OPTS="${COMPILE_OPTS} -DCMS_UT_TEST=ON"
        func_test
        ;;
    'package'|'package-debug')
        COMPILE_OPTS="${COMPILE_OPTS} -DUSE_PROTECT_VM=ON"
        func_making_package Debug
        ;;
    'package-release')
        func_making_package Release
        ;;
    'bazel_dependency')
        prepare_bazel_dependency
        ;;
    'make_regress_test')
        COMPILE_OPTS="${COMPILE_OPTS} -DUSE_PROTECT_VM=ON -DCMS_UT_TEST=ON"
        func_regress_test
        ;;
    'make_cantian_pkg_test')
        COMPILE_OPTS="${COMPILE_OPTS} -DUSE_PROTECT_VM=ON"
        func_making_package_test Debug
        ;;
    *)
    
        echo "Wrong parameters"
        exit 1
        ;;
    esac
}

main $@

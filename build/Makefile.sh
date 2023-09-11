#!/bin/bash
# Copyright Huawei Technologies Co., Ltd. 2010-2018. All rights reserved.
# This script is used for compiling code via CMake and making packages

set -e
declare VERSION_DESCRIP=""
declare PACK_PREFIX=""
declare PROJECT_VERSION=""
declare RUN_PACK_DIR_NAME=""
declare ALL_PACK_DIR_NAME=""
declare SYMBOL_PACK_DIR_NAME=""
declare COMPILE_OPTS=""
declare MYSQL_BUILD_TYPE=""
export BUILD_MODE=""
export PYTHON_INCLUDE_DIR=""
export WORKSPACE=$(dirname $(dirname $(pwd)))
DFT_WORKSPACE="/home/regress"
source ./common.sh
source ./function.sh
CONFIG_IN_FILE=${CANTIAN_BUILD}/include/config.h

PYTHON3_HOME=${PYTHON3_HOME}

func_prepare_git_msg
PROJECT_VERSION=$(cat ${CONFIG_IN_FILE} | grep 'PROJECT_VERSION' | awk '{print $3}')
CANTIAND_BIN=cantiand-${PROJECT_VERSION}
MYSQL_DIR=${CANTIAN_HOME}/../../mysql-server
DAAC_LIB_DIR=${CANTIAN_HOME}/../daac_lib
DAAC_LIB_DIR_TMP=${CANTIAN_HOME}/../daac_lib/tmp/
DAAC_SECURITY_LIB_PATH=${CANTIAN_HOME}/../library/huawei_security/lib
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
if [ "${BUILD_MYSQL_SO}" == "YES" ]; then
  WITH_TSE_STORAGE_ENGINE=0
fi

echo ${CANTIAN_HOME}
func_prepare_pkg_name()
{
    cd ${CANTIAN_HOME}

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
    ALL_PACK_DIR_NAME=${PACK_PREFIX}-DATABASE-${OS_SUFFIX}-${ARCH}bit
    SYMBOL_PACK_DIR_NAME=${PACK_PREFIX}-DATABASE-${OS_SUFFIX}-${ARCH}bit-SYMBOL
    ZTBOX_DIR_NAME=${PACK_PREFIX}-ZTBOX
    CTBOX_DIR_NAME=${PACK_PREFIX}-CTBOX
    CTCLIENT_PACK_DIR_NAME=${PACK_PREFIX}-CTCLIENT-${OS_SUFFIX}-${ARCH}bit

    if [[ ! -d "${CANTIAN_BIN}" ]]; then
        echo "bin dir not exist"
        exit 1
    else
        echo "chmod 700"
        chmod -R 700 ${CANTIAN_BIN}/*
    fi

    cd ${CANTIAN_BIN}
    rm -rf ${CANTIAN_BIN}/${RUN_PACK_DIR_NAME}*
    mkdir -p ${CANTIAN_BIN}/${RUN_PACK_DIR_NAME}
    mkdir -p ${CANTIAN_BIN}/${RUN_PACK_DIR_NAME}/bin
    mkdir -p ${CANTIAN_BIN}/${RUN_PACK_DIR_NAME}/lib
    mkdir -p ${CANTIAN_BIN}/${RUN_PACK_DIR_NAME}/add-ons
    mkdir -p ${CANTIAN_BIN}/${RUN_PACK_DIR_NAME}/data
    mkdir -p ${CANTIAN_BIN}/${RUN_PACK_DIR_NAME}/log
    mkdir -p ${CANTIAN_BIN}/${RUN_PACK_DIR_NAME}/protect
    mkdir -p ${CANTIAN_BIN}/${RUN_PACK_DIR_NAME}/var
}


func_prepare_no_clean_debug()
{
    export BUILD_MODE=Debug
    cd ${CANTIAN_BUILD}
    cmake -DCMAKE_BUILD_TYPE=Debug -DUSE32BIT=OFF ${COMPILE_OPTS} ..
}

func_prepare_no_clean_release()
{
    export BUILD_MODE=Release
    cd ${CANTIAN_BUILD}
    cmake -DCMAKE_BUILD_TYPE=Release -DUSE32BIT=OFF ${COMPILE_OPTS} ..
    sed -i "s/-O3/-O2/g" CMakeCache.txt
}

func_prepare_debug()
{
    func_prepare_no_clean_debug
}


func_prepare_release()
{
    func_prepare_no_clean_release
}
func_all()
{
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
        ls -al ${CANTIAN_LIB}
        ls -al /home/regress
        ls -al /home/regress/CantianKernel/build
        exit 1
    fi 
    set -e 

    if [[ -e "${CANTIAN_BIN}"/cantiand ]]; then
        cd ${CANTIAN_BIN}
        if [ -e "${CANTIAND_BIN}" ]; then
          rm ${CANTIAND_BIN}
        fi
        ln cantiand ${CANTIAND_BIN}
    fi
}


func_release_symbol()
{
    if [ "${ENABLE_LLT_ASAN}" == "NO" ]; then
        echo "release symbol"
        mkdir -p ${CANTIAN_SYMBOL}
        sh  ${CANTIAN_BUILD}/${DBG_SYMBOL_SCRIPT} ${CANTIAN_LIB}/libzeclient.so
        sh  ${CANTIAN_BUILD}/${DBG_SYMBOL_SCRIPT} ${CANTIAN_LIB}/libzecommon.so
        sh  ${CANTIAN_BUILD}/${DBG_SYMBOL_SCRIPT} ${CANTIAN_LIB}/libzeprotocol.so
        mv -f ${CANTIAN_LIB}/libzeclient.${SO}.${SYMBOLFIX} ${CANTIAN_SYMBOL}/libzeclient.${SO}.${SYMBOLFIX}
        mv -f ${CANTIAN_LIB}/libzecommon.${SO}.${SYMBOLFIX} ${CANTIAN_SYMBOL}/libzecommon.${SO}.${SYMBOLFIX}
        mv -f ${CANTIAN_LIB}/libzeprotocol.${SO}.${SYMBOLFIX} ${CANTIAN_SYMBOL}/libzeprotocol.${SO}.${SYMBOLFIX}

        sh  ${CANTIAN_BUILD}/${DBG_SYMBOL_SCRIPT} ${CANTIAN_BIN}/${CANTIAND_BIN}
        sh  ${CANTIAN_BUILD}/${DBG_SYMBOL_SCRIPT} ${CANTIAN_BIN}/cms
        sh  ${CANTIAN_BUILD}/${DBG_SYMBOL_SCRIPT} ${CANTIAN_BIN}/zencrypt
        sh  ${CANTIAN_BUILD}/${DBG_SYMBOL_SCRIPT} ${CANTIAN_BIN}/ctclient
        #sh  ${CANTIAN_BUILD}/${DBG_SYMBOL_SCRIPT} ${CANTIAN_BIN}/ztbox

        mv -f ${CANTIAN_BIN}/${CANTIAND_BIN}.${SYMBOLFIX} ${CANTIAN_SYMBOL}/${CANTIAND_BIN}.${SYMBOLFIX}
        mv -f ${CANTIAN_BIN}/cms.${SYMBOLFIX} ${CANTIAN_SYMBOL}/cms.${SYMBOLFIX}
        mv -f ${CANTIAN_BIN}/zencrypt.${SYMBOLFIX} ${CANTIAN_SYMBOL}/zencrypt.${SYMBOLFIX}
        mv -f ${CANTIAN_BIN}/ctclient.${SYMBOLFIX} ${CANTIAN_SYMBOL}/ctclient.${SYMBOLFIX}
        #mv -f ${CANTIAN_BIN}/ztbox.${SYMBOLFIX} ${CANTIAN_SYMBOL}/ztbox.${SYMBOLFIX}

        ##opensource library
        sh  ${CANTIAN_BUILD}/${DBG_SYMBOL_SCRIPT} ${LZ4_LIB_PATH}/liblz4.so.1.9.3
        sh  ${CANTIAN_BUILD}/${DBG_SYMBOL_SCRIPT} ${Z_LIB_PATH}/libz.so.1.2.11
        sh  ${CANTIAN_BUILD}/${DBG_SYMBOL_SCRIPT} ${PCRE_LIB_PATH}/libpcre2-8.so.0.11.0
        sh  ${CANTIAN_BUILD}/${DBG_SYMBOL_SCRIPT} ${ZSTD_LIB_PATH}/libzstd.so.1.5.2
        mv -f ${LZ4_LIB_PATH}/liblz4.so.1.9.3.${SYMBOLFIX}   ${CANTIAN_SYMBOL}/liblz4.so.1.9.3.${SYMBOLFIX}
        mv -f ${Z_LIB_PATH}/libz.so.1.2.11.${SYMBOLFIX}       ${CANTIAN_SYMBOL}/libz.so.1.2.11.${SYMBOLFIX}
        mv -f ${PCRE_LIB_PATH}/libpcre2-8.so.0.11.0.${SYMBOLFIX} ${CANTIAN_SYMBOL}/libpcre2-8.so.0.11.0.${SYMBOLFIX}
        mv -f ${ZSTD_LIB_PATH}/libzstd.so.1.5.2.${SYMBOLFIX} ${CANTIAN_SYMBOL}/libzstd.so.1.5.2.${SYMBOLFIX}

        sh ${CANTIAN_BUILD}/${DBG_SYMBOL_SCRIPT} ${ZSTD_LIB_PATH}/../bin/zstd
        mv -f ${ZSTD_LIB_PATH}/../bin/zstd.${SYMBOLFIX} ${CANTIAN_SYMBOL}/zstd.${SYMBOLFIX}

        func_pkg_symbol
    fi
}

func_version()
{
    echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" > ${CANTIAN_BIN}/package.xml
    echo "<PackageInfo>" >> ${CANTIAN_BIN}/package.xml
    echo "name=\"CANTIAN\"" >> ${CANTIAN_BIN}/package.xml
    echo "version=\"${VERSION_DESCRIP} ${BUILD_MODE}\"" >> ${CANTIAN_BIN}/package.xml
    echo "desc=\"CANTIAN install\"" >> ${CANTIAN_BIN}/package.xml
    merge_time=$(cat ${CANTIAN_BUILD}/conf/git_message.in | grep merge_time |  awk -F'=' '{print  $2}')
    echo "createDate=\"${merge_time}\"" >> ${CANTIAN_BIN}/package.xml
    WHOLE_COMMIT_ID=$(cat ${CANTIAN_BUILD}/conf/git_message.in | grep gitVersion |  awk -F'=' '{print  $2}')	
    echo "gitVersion=\"${WHOLE_COMMIT_ID}\"" >> ${CANTIAN_BIN}/package.xml
    echo "</PackageInfo>" >> ${CANTIAN_BIN}/package.xml
}

func_version_run_pkg()
{
    func_version
    cp  ${CANTIAN_BIN}/package.xml ${CANTIAN_BIN}/${RUN_PACK_DIR_NAME}
}

func_version_ctclient_pkg()
{
    func_version
    cp  ${CANTIAN_BIN}/package.xml ${CANTIAN_BIN}/${CTCLIENT_PACK_DIR_NAME}
}

func_pkg_run_basic()
{
    func_version_run_pkg

    cd ${CANTIAN_BIN}
    cp ctclient cantiand zencrypt ztbox cms ${CANTIAN_BIN}/${RUN_PACK_DIR_NAME}/bin/
    
    cp -d ${ZSTD_LIB_PATH}/../bin/zstd ${CANTIAN_BIN}/${RUN_PACK_DIR_NAME}/bin/
    
    cd ${CANTIAN_HOME}

    cp -d ${CANTIAN_LIB}/libzeclient.so  ${CANTIAN_BIN}/${RUN_PACK_DIR_NAME}/lib/
    cp -d ${CANTIAN_LIB}/libzecommon.so  ${CANTIAN_BIN}/${RUN_PACK_DIR_NAME}/lib/
    cp -d ${CANTIAN_LIB}/libzeprotocol.so  ${CANTIAN_BIN}/${RUN_PACK_DIR_NAME}/lib/

    cp -d ${PCRE_LIB_PATH}/libpcre2-8.so*  ${CANTIAN_BIN}/${RUN_PACK_DIR_NAME}/add-ons/
    cp -d ${Z_LIB_PATH}/libz.so*  ${CANTIAN_BIN}/${RUN_PACK_DIR_NAME}/add-ons/
    cp -d ${ZSTD_LIB_PATH}/libzstd.so*  ${CANTIAN_BIN}/${RUN_PACK_DIR_NAME}/add-ons/
    cp -d ${LZ4_LIB_PATH}/liblz4.so*  ${CANTIAN_BIN}/${RUN_PACK_DIR_NAME}/add-ons/
    
    ls -al ${CANTIAN_HOME}/../library/shared_lib
    cp -R ${CANTIAN_HOME}/admin  ${CANTIAN_BIN}/${RUN_PACK_DIR_NAME}/
    cp -R ${CANTIAN_HOME}/cfg  ${CANTIAN_BIN}/${RUN_PACK_DIR_NAME}/
    if [ "${ENABLE_LLT_ASAN}" == "YES" ]; then
        if [[ ${OS_ARCH} =~ "x86_64" ]]; then
            cp -d /usr/lib64/libubsan.so* ${CANTIAN_BIN}/${RUN_PACK_DIR_NAME}/add-ons/
            cp -d /usr/lib64/libasan.so* ${CANTIAN_BIN}/${RUN_PACK_DIR_NAME}/add-ons/
        elif [[ ${OS_ARCH} =~ "aarch64" ]]; then 
            cp -d ${CANTIAN_HOME}/../library/protobuf/${LIB_OS_ARCH}/libubsan.so* ${CANTIAN_BIN}/${RUN_PACK_DIR_NAME}/add-ons/
            cp -d ${CANTIAN_HOME}/../library/protobuf/${LIB_OS_ARCH}/libasan.so* ${CANTIAN_BIN}/${RUN_PACK_DIR_NAME}/add-ons/
        else 
            echo "OS_ARCH: ${OS_ARCH} is unknown."
        fi
    fi

    chmod -R 700 ${CANTIAN_BIN}/${RUN_PACK_DIR_NAME}/*
    chmod 500 ${CANTIAN_BIN}/${RUN_PACK_DIR_NAME}/add-ons/*
    chmod 500 ${CANTIAN_BIN}/${RUN_PACK_DIR_NAME}/bin/*
    chmod 600 ${CANTIAN_BIN}/${RUN_PACK_DIR_NAME}/cfg/*
    chmod 500 ${CANTIAN_BIN}/${RUN_PACK_DIR_NAME}/lib/*
    chmod 500 ${CANTIAN_BIN}/${RUN_PACK_DIR_NAME}/add-ons/*
    chmod 400 ${CANTIAN_BIN}/${RUN_PACK_DIR_NAME}/package.xml
}

fun_pkg_mysql_lib()
{
    echo "DAAC_LIB_DIR:${DAAC_LIB_DIR}"
    echo "DAAC_LIB_DIR_TMP:${DAAC_LIB_DIR_TMP}"
    rm -rf ${DAAC_LIB_DIR}
    mkdir -p ${DAAC_LIB_DIR}
    mkdir -p ${DAAC_LIB_DIR_TMP}

    cp -d ${CANTIAN_HOME}/../output/lib/*.a ${DAAC_LIB_DIR_TMP}
    cp -d ${CANTIAN_HOME}/../library/huawei_security/lib/*.a ${DAAC_LIB_DIR_TMP}
    
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

    cd ${CANTIAN_HOME}/../library/protobuf/lib/ && cp *.a ${DAAC_LIB_DIR}
    cd ${CANTIAN_HOME}/../build/pkg/src/tse/CMakeFiles/zectc.dir/message_queue/ && ar cr libmessage_queue.a *.o && cp libmessage_queue.a ${DAAC_LIB_DIR}

    cp -d ${CANTIAN_HOME}/../library/pcre/lib/libpcre2-8.so* ${DAAC_LIB_DIR}
    cp -d ${CANTIAN_HOME}/../output/lib/*.so ${DAAC_LIB_DIR}
    if [ "${ENABLE_LLT_ASAN}" == "YES" ]; then
        if [[ ${OS_ARCH} =~ "x86_64" ]]; then
            cp -d /usr/lib64/libubsan.so* ${DAAC_LIB_DIR}
            cp -d /usr/lib64/libasan.so* ${DAAC_LIB_DIR}
        elif [[ ${OS_ARCH} =~ "aarch64" ]]; then 
            cp -d ${CANTIAN_HOME}/../library/protobuf/lib_arm/libubsan.so* ${DAAC_LIB_DIR}
            cp -d ${CANTIAN_HOME}/../library/protobuf/lib_arm/libasan.so* ${DAAC_LIB_DIR}
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
    chmod 400 ${CANTIAN_BIN}/${RUN_PACK_DIR_NAME}/admin/scripts/*
    cd ${CANTIAN_BIN} && tar --owner=root --group=root -zcf ${RUN_PACK_DIR_NAME}.tar.gz ${RUN_PACK_DIR_NAME}
    rm -rf ${CANTIAN_BIN}/${RUN_PACK_DIR_NAME}/bin/script
}

func_pkg_symbol()
{
    echo "pkg symbol"

    rm -rf ${CANTIAN_BIN}/${SYMBOL_PACK_DIR_NAME}*
    mkdir -p ${CANTIAN_BIN}/${SYMBOL_PACK_DIR_NAME}
    cp -rf ${CANTIAN_SYMBOL}/*.${SYMBOLFIX} ${CANTIAN_BIN}/${SYMBOL_PACK_DIR_NAME}/
    chmod 500 ${CANTIAN_BIN}/${SYMBOL_PACK_DIR_NAME}/*
    cd ${CANTIAN_BIN} && tar --owner=root --group=root -zcf ${SYMBOL_PACK_DIR_NAME}.tar.gz ${SYMBOL_PACK_DIR_NAME}
    sha256sum ${CANTIAN_BIN}/${SYMBOL_PACK_DIR_NAME}.tar.gz | cut -c1-64 > ${CANTIAN_BIN}/${SYMBOL_PACK_DIR_NAME}.sha256
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
    cp -r -f -p ${MYSQL_DIR}/daac_lib/* /usr/lib64
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
  cp -arf ${DAAC_SECURITY_LIB_PATH}/* ${MYSQL_CODE_PATH}/daac_lib/
  mkdir -p ${MYSQL_DIR}/bld_debug
  cd ${MYSQL_DIR}/bld_debug

  cp -r -f -p ${MYSQL_DIR}/daac_lib/* /usr/lib64
  if [ "${MYSQL_BUILD_MODE}" == "multiple" ]; then
    if [ "${ENABLE_LLT_GCOV}" == "YES" ]; then
      cmake .. -DCMAKE_CXX_COMPILER=/usr/bin/g++ -DCMAKE_C_COMPILER=/usr/bin/gcc -DENABLE_GCOV=1 -DWITH_TSE_STORAGE_ENGINE=${WITH_TSE_STORAGE_ENGINE} -DCMAKE_BUILD_TYPE=Debug -DWITH_BOOST=${BOOST_PATH}
    elif [ "${ENABLE_LLT_ASAN}" == "YES" ]; then
      cmake .. -DCMAKE_CXX_COMPILER=/usr/bin/g++ -DCMAKE_C_COMPILER=/usr/bin/gcc -DWITH_ASAN=ON -DWITH_ASAN_SCOPE=ON -DWITH_TSE_STORAGE_ENGINE=${WITH_TSE_STORAGE_ENGINE} -DCMAKE_BUILD_TYPE=Debug -DWITH_BOOST=${BOOST_PATH}
    else
      cmake .. -DWITH_TSE_STORAGE_ENGINE=${WITH_TSE_STORAGE_ENGINE} -DCMAKE_BUILD_TYPE=Debug -DWITH_BOOST=${BOOST_PATH}
    fi
  elif [ "${MYSQL_BUILD_MODE}" == "single" ]; then
    cmake .. -DWITH_DAAC=1 -DWITH_TSE_STORAGE_ENGINE=${WITH_TSE_STORAGE_ENGINE} -DCMAKE_BUILD_TYPE=Debug -DWITH_BOOST=${BOOST_PATH}
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
  cp -arf ${DAAC_SECURITY_LIB_PATH}/* ${MYSQL_CODE_PATH}/daac_lib/
  mkdir -p ${MYSQL_DIR}/bld_debug
  cd ${MYSQL_DIR}/bld_debug
  cp -r -f -p ${MYSQL_DIR}/daac_lib/* /usr/lib64
  if [ "${MYSQL_BUILD_MODE}" == "multiple" ]; then
    cmake .. -DWITH_TSE_STORAGE_ENGINE=${WITH_TSE_STORAGE_ENGINE} -DCMAKE_BUILD_TYPE=Release -DWITH_BOOST=${BOOST_PATH} -DCMAKE_C_FLAGS=-g -DCMAKE_CXX_FLAGS=-g
  elif [ "${MYSQL_BUILD_MODE}" == "single" ]; then
    cmake .. -DWITH_DAAC=1 -DWITH_TSE_STORAGE_ENGINE=${WITH_TSE_STORAGE_ENGINE} -DCMAKE_BUILD_TYPE=Release -DWITH_BOOST=${BOOST_PATH} -DCMAKE_C_FLAGS=-g -DCMAKE_CXX_FLAGS=-g
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

  func_separate_mysql_symbol /usr/local/mysql/bin ${MYSQL_CODE_PATH}/mysql_bin/symbol
  cd -
}

func_test()
{
    echo "make test"
    func_all Debug
    strip -N main ${CANTIAN_LIB}/libzeserver.a
    cd ${CT_TEST_BUILD_DIR}
    make -sj 8 

    if [[ -e "${CANTIAN_BIN}"/cantiand ]]; then
        cd ${CANTIAN_BIN}
        rm -rf ${CANTIAND_BIN} && ln cantiand ${CANTIAND_BIN}
    fi

    if [[ ! -d "${CANTIAN_HOME}"/add-ons ]]; then
        mkdir -p  ${CANTIAN_HOME}/add-ons
    fi

    cp -d ${ZSTD_LIB_PATH}/libzstd.so*  ${CANTIAN_HOME}/add-ons/
    cp -d ${LZ4_LIB_PATH}/liblz4.so* ${CANTIAN_HOME}/add-ons/
    cp -rf ${CANTIAN_BIN} ${CANTIAN_HOME}
    cp -rf ${CANTIAN_LIB} ${CANTIAN_HOME}
    cp -rf ${CANTIAN_LIBRARY} ${CANTIAN_HOME}

}

func_clean()
{
    echo "make clean"
    func_prepare_debug
    func_prepare_pkg_name

    cd ${CANTIAN_BUILD}
    make clean

    cd ${CT_TEST_BUILD_DIR}
    make clean

    if [[ -d "${CANTIAN_BIN}" ]];then
        echo ${CANTIAN_BIN}
        chmod -R 700 ${CANTIAN_BIN}
    fi

    echo ${CANTIAN_OUTPUT}
    
    rm -rf ${CANTIAN_OUTPUT}/*
    rm -rf ${CANTIAN_HOME}/../${ALL_PACK_DIR_NAME}

    cd ${CANTIAN_BUILD}
    rm -rf pkg
    rm -rf CMakeFiles
    rm -f Makefile
    rm -f cmake_install.cmake
    rm -f CMakeCache.txt

    rm -rf ${MYSQL_DIR}/bld_debug/*
}

func_pkg_ctclient()
{
    echo "make pkg ctclient"

    rm -rf ${CANTIAN_BIN}/${CTCLIENT_PACK_DIR_NAME}*
    mkdir -p ${CANTIAN_BIN}/${CTCLIENT_PACK_DIR_NAME}
    mkdir -p ${CANTIAN_BIN}/${CTCLIENT_PACK_DIR_NAME}/bin
    mkdir -p ${CANTIAN_BIN}/${CTCLIENT_PACK_DIR_NAME}/lib
    mkdir -p ${CANTIAN_BIN}/${CTCLIENT_PACK_DIR_NAME}/add-ons

    func_version_ctclient_pkg

    cp ${CANTIAN_BIN}/ctclient ${CANTIAN_BIN}/${CTCLIENT_PACK_DIR_NAME}/bin/ctclient
    cp -d ${CANTIAN_LIB}/libzeclient.so ${CANTIAN_BIN}/${CTCLIENT_PACK_DIR_NAME}/lib/
    cp -d ${CANTIAN_LIB}/libzecommon.so ${CANTIAN_BIN}/${CTCLIENT_PACK_DIR_NAME}/lib/
    cp -d ${CANTIAN_LIB}/libzeprotocol.so ${CANTIAN_BIN}/${CTCLIENT_PACK_DIR_NAME}/lib/
    
    cp -d ${Z_LIB_PATH}/libz.so* ${CANTIAN_BIN}/${CTCLIENT_PACK_DIR_NAME}/add-ons/
    cp -d ${PCRE_LIB_PATH}/libpcre2-8.so* ${CANTIAN_BIN}/${CTCLIENT_PACK_DIR_NAME}/add-ons/

    chmod -R 700 ${CANTIAN_BIN}/${CTCLIENT_PACK_DIR_NAME}/*
    chmod 500 ${CANTIAN_BIN}/${CTCLIENT_PACK_DIR_NAME}/add-ons/*
    chmod 500 ${CANTIAN_BIN}/${CTCLIENT_PACK_DIR_NAME}/lib/*
    chmod 400 ${CANTIAN_BIN}/${CTCLIENT_PACK_DIR_NAME}/package.xml

    cd ${CANTIAN_BIN} && tar --owner=root --group=root -zcf ${CTCLIENT_PACK_DIR_NAME}.tar.gz ${CTCLIENT_PACK_DIR_NAME}
    sha256sum ${CANTIAN_BIN}/${CTCLIENT_PACK_DIR_NAME}.tar.gz | cut -c1-64 > ${CANTIAN_BIN}/${CTCLIENT_PACK_DIR_NAME}.sha256

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
        func_pkg_run
    fi
	
    # func_toolkit ${build_package_mode}

    rm -rf ${CANTIAN_HOME}/../${ALL_PACK_DIR_NAME}
    rm -rf ${CANTIAN_BIN}/${ALL_PACK_DIR_NAME}
    rm -rf ${CANTIAN_BIN}/${ALL_PACK_DIR_NAME}.tar.gz
    mkdir -p ${CANTIAN_BIN}/${ALL_PACK_DIR_NAME}

    mv ${CANTIAN_BIN}/${RUN_PACK_DIR_NAME}.tar.gz ${CANTIAN_BIN}/${ALL_PACK_DIR_NAME}/
    sha256sum ${CANTIAN_BIN}/${ALL_PACK_DIR_NAME}/${RUN_PACK_DIR_NAME}.tar.gz | cut -c1-64 > ${CANTIAN_BIN}/${ALL_PACK_DIR_NAME}/${RUN_PACK_DIR_NAME}.sha256
    chmod 400 ${CANTIAN_BIN}/${ALL_PACK_DIR_NAME}/${RUN_PACK_DIR_NAME}.sha256
    cd ${CANTIAN_BIN} && tar --owner=root --group=root -zcf ${ALL_PACK_DIR_NAME}.tar.gz ${ALL_PACK_DIR_NAME}
    sha256sum ${CANTIAN_BIN}/${ALL_PACK_DIR_NAME}.tar.gz | cut -c1-64 > ${CANTIAN_BIN}/${ALL_PACK_DIR_NAME}.sha256
    func_pkg_ctclient
    
    find ${CANTIAN_BIN} -name "*.sha256" -exec chmod 400 {} \;
    cp -arf ${CANTIAN_BIN}/${ALL_PACK_DIR_NAME} ${CANTIAN_HOME}/../${ALL_PACK_DIR_NAME}
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
            mkdir -p ${CANTIAN_LIB}
            cp -f ${CANTIAN_LIBRARY}/secodefuzz/lib/* ${CANTIAN_LIB}
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
        'ignore_assert=1')
            echo "build with ignore_assert"
            COMPILE_OPTS="${COMPILE_OPTS} -DIGNORE_ASSERT=ON"
            ;;
        'CANTIAN_READ_WRITE=1')
            echo "build with CANTIAN_READ_WRITE"
            COMPILE_OPTS="${COMPILE_OPTS} -DCANTIAN_READ_WRITE=ON"
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
    *)
        echo "Wrong parameters"
        exit 1
        ;;
    esac
}

main $@

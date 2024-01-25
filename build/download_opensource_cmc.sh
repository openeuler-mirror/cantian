#!/bin/bash
# Copyright Huawei Technologies Co., Ltd. 2010-2018. All rights reserved.
set -e

declare BEP

export WORKSPACE=$(dirname $(dirname $(pwd)))
export OPEN_SOURCE=${WORKSPACE}/CantianKernel/open_source
export LIBRARY=${WORKSPACE}/CantianKernel/library
export OS_ARCH=$(uname -i)
DFT_WORKSPACE="/home/regress"

echo $DFT_WORKSPACE " " $WORKSPACE
if [[ "$WORKSPACE" == *"regress"* ]]; then
    echo $DFT_WORKSPACE " eq " $WORKSPACE
else
    export OPEN_SOURCE=${WORKSPACE}/daac/open_source
    export LIBRARY=${WORKSPACE}/daac/library
fi

#pcre
cd ${OPEN_SOURCE}/pcre/pcre2-10.40
touch configure.ac aclocal.m4  Makefile.in configure config.h.in
mkdir -p pcre-build;chmod 755 -R ./*
aclocal;autoconf;autoreconf -vif
#判断系统是否是centos，并且参数bep是否为true，都是则删除。
if [[ ! -z ${BEP} ]]; then
    if [[ -n "$(cat /etc/os-release | grep CentOS)" ]] && [[ ${BEP} == "true" ]] && [[ "${BUILD_TYPE}" == "RELEASE" ]];then
    sed -i "2656,2690d" configure  #从2656到2690行是构建环境检查，检查系统时间的。做bep固定时间戳时，若是centos系统，系统时间固定，必须删除构建环境检查，才能编译，才能保证两次出包bep一致；若是euler系统，可不用删除，删除了也不影响编译。
    fi
fi
./configure
mkdir -p ${OPEN_SOURCE}/pcre/include/
cp ${OPEN_SOURCE}/pcre/pcre2-10.40/src/pcre2.h ${OPEN_SOURCE}/pcre/include/

#lz4
cd ${OPEN_SOURCE}/lz4/lz4-1.9.4/lib
mkdir -p ${OPEN_SOURCE}/lz4/include/
cp lz4frame.h lz4.h ${OPEN_SOURCE}/lz4/include

#zstd
cd ${OPEN_SOURCE}/Zstandard/zstd-1.5.2-h1
mkdir -p ${OPEN_SOURCE}/Zstandard/include
cp lib/zstd.h ${OPEN_SOURCE}/Zstandard/include
cd lib/;rm -f libzstd.so libzstd.so.1
ln -s libzstd.so.1.5.2 libzstd.so
ln -s libzstd.so.1.5.2 libzstd.so.1


#protobuf 
# cd ${OPEN_SOURCE}/protobuf/protobuf.3.13.0
# ./autogen.sh
# # 流水线是否设置BEP
# if [[ ! -z ${BEP} ]]; then
#     if [[ -n "$(cat /etc/os-release | grep CentOS)" ]] && [[ ${BEP} == "true" ]] && [[ "${BUILD_TYPE}" == "RELEASE" ]];then
#     sed -i "2915,2949d" configure
#     fi
# fi
# ./configure
# if [[ ${OS_ARCH} =~ "x86_64" ]]; then
#     export CPU_CORES_NUM_x86=`cat /proc/cpuinfo |grep "cores" |wc -l`
#     make -j${CPU_CORES_NUM_x86}
# elif [[ ${OS_ARCH} =~ "aarch64" ]]; then 
#     export CPU_CORES_NUM_arm=`cat /proc/cpuinfo |grep "architecture" |wc -l`
#     make -j${CPU_CORES_NUM_arm}
# else 
#     echo "OS_ARCH: ${OS_ARCH} is unknown, set CPU_CORES_NUM=16 "
#     export CPU_CORES_NUM=16
#     make -j${CPU_CORES_NUM}
# fi
# make install

#protobuf-c
mkdir -p ${OPEN_SOURCE}/protobuf-c/include/
mkdir -p ${LIBRARY}/protobuf/protobuf-c/
cp ${OPEN_SOURCE}/protobuf-c/protobuf-c.1.4.1/protobuf-c/protobuf-c.h ${OPEN_SOURCE}/protobuf-c/include/
cp ${OPEN_SOURCE}/protobuf-c/protobuf-c.1.4.1/protobuf-c/protobuf-c.h ${LIBRARY}/protobuf/protobuf-c/

#openssl
cd  ${OPEN_SOURCE}/openssl/openssl-3.0.7-h14/
./config shared
if [[ ${OS_ARCH} =~ "x86_64" ]]; then
    export CPU_CORES_NUM_x86=`cat /proc/cpuinfo |grep "cores" |wc -l`
    make -j${CPU_CORES_NUM_x86}
elif [[ ${OS_ARCH} =~ "aarch64" ]]; then 
    export CPU_CORES_NUM_arm=`cat /proc/cpuinfo |grep "architecture" |wc -l`
    make -j${CPU_CORES_NUM_arm}
else 
    echo "OS_ARCH: ${OS_ARCH} is unknown, set CPU_CORES_NUM=16 "
    export CPU_CORES_NUM=16
    make -j${CPU_CORES_NUM}
fi
mkdir -p ${OPEN_SOURCE}/openssl/include/
mkdir -p ${LIBRARY}/openssl/lib/
cp -rf ${OPEN_SOURCE}/openssl/openssl-3.0.7-h14/include/* ${OPEN_SOURCE}/openssl/include/
cp -rf ${OPEN_SOURCE}/openssl/openssl-3.0.7-h14/*.a ${LIBRARY}/openssl/lib
echo "copy lib finished"

#zlib
cd ${OPEN_SOURCE}/zlib/zlib-1.2.11-h5
mkdir -p ${OPEN_SOURCE}/zlib/include
cp zconf.h zlib.h ${OPEN_SOURCE}/zlib/include

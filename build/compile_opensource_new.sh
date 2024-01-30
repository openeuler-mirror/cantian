#!/bin/bash
# Copyright Huawei Technologies Co., Ltd. 2010-2018. All rights reserved.
set -e

declare BEP

export WORKSPACE=$(dirname $(dirname $(pwd)))
export OPEN_SOURCE=${WORKSPACE}/CantianKernel/open_source
export LIBRARY=${WORKSPACE}/CantianKernel/library
export PLATFORM=${WORKSPACE}/CantianKernel/platform
export OS_ARCH=$(uname -i)
DFT_WORKSPACE="/home/regress"

echo $DFT_WORKSPACE " " $WORKSPACE
if [[ "$WORKSPACE" == *"regress"* ]]; then
    echo $DFT_WORKSPACE " eq " $WORKSPACE
else
    export OPEN_SOURCE=${WORKSPACE}/cantian/open_source
    export LIBRARY=${WORKSPACE}/cantian/library
    export PLATFORM=${WORKSPACE}/cantian/platform
fi

#pcre  
cd ${OPEN_SOURCE}/pcre
tar -zxvf pcre2-10.40.tar.gz
cd ${OPEN_SOURCE}/pcre/pcre2-10.40
touch configure.ac aclocal.m4  Makefile.in configure config.h.in
mkdir -p pcre-build;chmod 755 -R ./*
aclocal;autoconf;autoreconf -vif
#判断系统是否是centos，并且参数bep是否为true，都是则删除。
if [[ ! -z ${BEP} ]]; then
    if [[ -n "$(cat /etc/os-release | grep CentOS)" ]] && [[ ${BEP} == "true" ]] && [[ "${BUILD_TYPE}" == "RELEASE" ]];then
    sed -i "2653,2692d" configure  #从2653到2692行是构建环境检查，检查系统时间的。做bep固定时间戳时，若是centos系统，系统时间固定，必须删除构建环境检查，才能编译，才能保证两次出包bep一致；若是euler系统，可不用删除，删除了也不影响编译。
    fi
fi
./configure
CFLAGS='-Wall -Wtrampolines -fno-common -fvisibility=default -fstack-protector-strong -fPIC --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -O2 -Wl,-z,relro,-z,now,-z,noexecstack' ./configure --enable-utf8 --enable-unicode-properties --prefix=${OPEN_SOURCE}/pcre/pcre2-10.40/pcre-build --disable-stack-for-recursion
make;make check;make install
cd .libs/;tar -cvf libpcre.tar libpcre2-8.so*;mkdir -p ${LIBRARY}/pcre/lib/;cp libpcre.tar libpcre2-8.so* ${LIBRARY}/pcre/lib/
mkdir -p ${OPEN_SOURCE}/pcre/include/
cp ${OPEN_SOURCE}/pcre/pcre2-10.40/src/pcre2.h ${OPEN_SOURCE}/pcre/include/

#lz4
cd ${OPEN_SOURCE}/lz4
tar -zxvf lz4-1.9.4.tar.gz
cd ${OPEN_SOURCE}/lz4/lz4-1.9.4/lib
CFLAGS='-D_FORTIFY_SOURCE=2 -O2 -fstack-protector-strong -fPIC' LDFLAGS='-Wl,-z,relro,-z,now -Wl,-z,noexecstack' make V=1 -sj
tar -cvf liblz4.tar liblz4.so*
mkdir -p ${OPEN_SOURCE}/lz4/include/
mkdir -p ${LIBRARY}/lz4/lib/
cp liblz4.so* ${LIBRARY}/lz4/lib/
cp liblz4.tar ${LIBRARY}/lz4/lib/
cp lz4frame.h lz4.h ${OPEN_SOURCE}/lz4/include

#zstd
cd ${OPEN_SOURCE}/Zstandard
tar -zxvf zstd-1.5.2.tar.gz
cd ${OPEN_SOURCE}/Zstandard/zstd-1.5.2
CFLAGS='-Wall -Wtrampolines -fno-common -fvisibility=default -fstack-protector-strong -fPIC -fPIE -pie --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -O2 -Wl,-z,relro,-z,now,-z,noexecstack' make -sj
CFLAGS='-Wall -Wtrampolines -fno-common -fvisibility=default -fstack-protector-strong -fPIC -fPIE -pie --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -O2 -Wl,-z,relro,-z,now,-z,noexecstack' make lib -sj
mkdir -p ${OPEN_SOURCE}/Zstandard/include
mkdir -p ${LIBRARY}/Zstandard/lib
cp lib/zstd.h ${OPEN_SOURCE}/Zstandard/include
cd lib/;rm -f libzstd.so libzstd.so.1
ln -s libzstd.so.1.5.2 libzstd.so
ln -s libzstd.so.1.5.2 libzstd.so.1
tar -cvf libzstd.tar libzstd.so*;cp libzstd.tar libzstd.so* ${LIBRARY}/Zstandard/lib/
mkdir -p ${LIBRARY}/Zstandard/bin;cp ${OPEN_SOURCE}/Zstandard/zstd-1.5.2/zstd ${LIBRARY}/Zstandard/bin/

#protobuf 
cd ${OPEN_SOURCE}/protobuf
tar -zxvf protobuf-all-3.13.0.tar.gz
cd ${OPEN_SOURCE}/protobuf/protobuf-3.13.0
./autogen.sh
# 流水线是否设置BEP
if [[ ! -z ${BEP} ]]; then
    if [[ -n "$(cat /etc/os-release | grep CentOS)" ]] && [[ ${BEP} == "true" ]] && [[ "${BUILD_TYPE}" == "RELEASE" ]];then
    sed -i "2915,2949d" configure
    fi
fi
./configure
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
make install

#protobuf-c 
cd ${OPEN_SOURCE}/protobuf-c
tar -zxvf protobuf-c-1.4.1.tar.gz
cd ${OPEN_SOURCE}/protobuf-c/protobuf-c-1.4.1
# ./autogen.sh
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
# 流水线是否设置BEP
if [[ ! -z ${BEP} ]]; then
    if [[ -n "$(cat /etc/os-release | grep CentOS)" ]] && [[ ${BEP} == "true" ]] && [[ "${BUILD_TYPE}" == "RELEASE" ]];then
    sed -i "2692,2726d" configure
    fi
fi
./configure CFLAGS="-fPIC" CXXFLAGS="-fPIC" --enable-static=yes --enable-shared=no

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
make install
mkdir -p ${LIBRARY}/protobuf/lib
cp ${OPEN_SOURCE}/protobuf-c/protobuf-c-1.4.1/protobuf-c/.libs/libprotobuf-c.a ${LIBRARY}/protobuf/lib/
mkdir -p ${OPEN_SOURCE}/protobuf-c/include/
mkdir -p ${LIBRARY}/protobuf/protobuf-c/
cp ${OPEN_SOURCE}/protobuf-c/protobuf-c-1.4.1/protobuf-c/protobuf-c.h ${OPEN_SOURCE}/protobuf-c/include/
cp ${OPEN_SOURCE}/protobuf-c/protobuf-c-1.4.1/protobuf-c/protobuf-c.h ${LIBRARY}/protobuf/protobuf-c/

#openssl
cd ${OPEN_SOURCE}/openssl
tar -zxvf openssl-3.0.7.tar.gz
cd ${OPEN_SOURCE}/openssl/openssl-3.0.7/
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
cp -rf ${OPEN_SOURCE}/openssl/openssl-3.0.7/include/* ${OPEN_SOURCE}/openssl/include/
cp -rf ${OPEN_SOURCE}/openssl/openssl-3.0.7/*.a ${LIBRARY}/openssl/lib
echo "copy lib finished"

#zlib
cd ${OPEN_SOURCE}/zlib
tar -zxvf zlib-1.2.13.tar.gz
cd ${OPEN_SOURCE}/zlib/zlib-1.2.13
mkdir -p ${OPEN_SOURCE}/zlib/include
mkdir -p ${LIBRARY}/zlib/lib
cp zconf.h zlib.h ${OPEN_SOURCE}/zlib/include
CFLAGS='-Wall -Wtrampolines -fno-common -fvisibility=default -fstack-protector-strong -fPIC --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -O2 -Wl,-z,relro,-z,now,-z,noexecstack' ./configure;make -sj
tar -cvf libz.tar libz.so*;cp libz.tar libz.so* ${LIBRARY}/zlib/lib/

#huawei_secure_c
cd ${PLATFORM}
unzip -o huawei_secure_c.zip
rm -rf HuaweiSecureC
mv huawei_secure_c-master HuaweiSecureC
cd ${PLATFORM}/HuaweiSecureC/src
make lib
make
mkdir -p ${PLATFORM}/huawei_security/include
mkdir -p ${LIBRARY}/huawei_security/lib
cp ${PLATFORM}/HuaweiSecureC/lib/* ${LIBRARY}/huawei_security/lib/
cp ${PLATFORM}/HuaweiSecureC/include/* ${PLATFORM}/huawei_security/include/

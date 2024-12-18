#!/bin/bash

set -e
ENV_TYPE=$(uname -p)
CURRENT_PATH=$(dirname $(readlink -f $0))
CTDB_CODE_PATH="${CURRENT_PATH}"/..
BUILD_TYPE=$1
if [[ ! -d ${CTDB_CODE_PATH} ]];then
    mkdir -p ${CTDB_CODE_PATH}
fi

if [[ ${BUILD_TYPE} == "release" ]] || [[ x"${BUILD_TYPE}" == x"" ]];then
    BUILD_TYPE="Release"
else
    BUILD_TYPE="Debug"
    sed -i 's/"_LOG_LEVEL": 7,/"_LOG_LEVEL": 255,/g' "${CTDB_CODE_PATH}"/pkg/deploy/action/dss/config.py
fi
echo "BUILD_TYPE:${BUILD_TYPE}"

function download_source() {
    echo "Clone source start"
    if [[ x"${proxy_user}" != x"" ]];then
        export http_proxy=http://${proxy_user}:${proxy_pwd}@${proxy_url}
        export https_proxy=${http_proxy}
        export no_proxy=127.0.0.1,.huawei.com,localhost,local,.local
    fi
    git clone -b 6.0.0 https://gitee.com/opengauss/CBB.git
    git clone -b 6.0.0 https://gitee.com/opengauss/DSS.git
    if [[ ${ENV_TYPE} == "aarch64" ]];then
        wget --no-check-certificate https://opengauss.obs.cn-south-1.myhuaweicloud.com/6.0.0/binarylibs/gcc10.3/openGauss-third_party_binarylibs_openEuler_2203_arm.tar.gz
        tar -zxf openGauss-third_party_binarylibs_openEuler_2203_arm.tar.gz
    else
        wget --no-check-certificate https://opengauss.obs.cn-south-1.myhuaweicloud.com/6.0.0/binarylibs/gcc10.3/openGauss-third_party_binarylibs_Centos7.6_x86_64.tar.gz
        tar -zxf openGauss-third_party_binarylibs_Centos7.6_x86_64.tar.gz
    fi

    echo "Clone source success"
}

function build_package() {
    export THIRD_PATH=${CTDB_CODE_PATH}/openGauss-third_party_binarylibs_Centos7.6_x86_64
    if [[ ${ENV_TYPE} == "aarch64" ]];then
        export THIRD_PATH=${CTDB_CODE_PATH}/openGauss-third_party_binarylibs_openEuler_2203_arm
    fi
    export CC=${THIRD_PATH}/buildtools/gcc10.3/gcc/bin/gcc
    export cc=${THIRD_PATH}/buildtools/gcc10.3/gcc/bin/gcc
    export GCCFOLDER=${THIRD_PATH}/buildtools/gcc10.3
    export LD_LIBRARY_PATH=${THIRD_PATH}/buildtools/gcc10.3/gcc/lib64:$LD_LIBRARY_PATH
    export LD_LIBRARY_PATH=$GCCFOLDER/gcc/lib64:$GCCFOLDER/isl/lib:$GCCFOLDER/mpc/lib/:$GCCFOLDER/mpfr/lib/:$GCCFOLDER/gmp/lib/:$LD_LIBRARY_PATH
    export PATH=${THIRD_PATH}/buildtools/gcc10.3/gcc/bin:${PATH}
    echo "Start to compile CBB."
    cd ${CTDB_CODE_PATH}/CBB
    sed -i "s/OPTION(ENABLE_EXPORT_API \"Enable hidden internal api\" OFF)/OPTION(ENABLE_EXPORT_API \"Enable hidden internal api\" ON)/g" ${CTDB_CODE_PATH}/CBB/CMakeLists.txt
    sh build.sh -3rd ${THIRD_PATH}  -m ${BUILD_TYPE} -t cmake
    cd -
    echo "Start to compile DSS."
    cd ${CTDB_CODE_PATH}/DSS/build/linux/opengauss
    sh build.sh -3rd ${THIRD_PATH}  -m ${BUILD_TYPE} -t cmake
    cd -
    echo "Start to copy bin/lib source."
    mkdir -p "${CTDB_CODE_PATH}"/dss/{lib,bin}
    cp -arf ${CTDB_CODE_PATH}/CBB/output/bin/* "${CTDB_CODE_PATH}"/dss/bin/
    cp -arf ${CTDB_CODE_PATH}/CBB/output/lib/* "${CTDB_CODE_PATH}"/dss/lib/
    cp -arf ${CTDB_CODE_PATH}/DSS/output/bin/* "${CTDB_CODE_PATH}"/dss/bin/
    cp -arf ${CTDB_CODE_PATH}/DSS/output/lib/* "${CTDB_CODE_PATH}"/dss/lib/
    echo "end to copy bin/lib source."
}
echo "build dss start."
cd ${CTDB_CODE_PATH}
download_source
build_package
cd -
echo "build dss success."
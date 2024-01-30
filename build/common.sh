#!/bin/bash
# Copyright Huawei Technologies Co., Ltd. 2010-2018. All rights reserved.
set -e

declare OS_SUFFIX=""
declare OS_MAJOR_VERSION=""
declare OS_MINOR_VERSION=""

declare OPENSSL_LIB_PATH=""
declare SECUREC_LIB_PATH=""
declare PCRE_LIB_PATH=""
declare Z_LIB_PATH=""
declare ZSTD_LIB_PATH=""
declare LZ4_LIB_PATH=""
declare XNET_LIB_PATH=""
declare OS_ARCH=""
declare WHOLE_COMMIT_ID=""
declare git_id=""
declare driver_commit_id=""
declare jdbc_commit_id=""
declare logicrep_commit_id=""
declare ctsql_commit_id=""

OS_NAME=$(uname -s)
ARCH=$(getconf LONG_BIT)

SYMBOLFIX=symbol
SO=so

SUSE_VERSION_PATH=/etc/SuSE-release
REDHAT_VERSION_PATH=/etc/redhat-release
CENTOS_VERSION_PATH=/etc/centos-release
KYLIN_VERSION_PATH=/etc/kylin-release
NEOKYLIN_VERSION_PATH=neokylin-release
EULER_VERSION_PATH=/etc/euleros-release
OPENEULER_VERSION_PATH=/etc/openEuler-release

CODE_HOME_PATH=$(echo $(dirname $(pwd)))
CANTIANDB_CI_PATH=${CODE_HOME_PATH}/CI
CANTIANDB_HOME=${CODE_HOME_PATH}/pkg

CANTIANDB_SRC=${CANTIANDB_HOME}/src
CANTIANDB_INSTALL=${CANTIANDB_HOME}/install
CANTIANDB_BUILD=${CODE_HOME_PATH}/build
CANTIANDB_LIBRARY=${CODE_HOME_PATH}/library
CANTIANDB_OPEN_SOURCE=${CODE_HOME_PATH}/open_source
CANTIANDB_PLATFORM=${CODE_HOME_PATH}/platform
CANTIANDB_OUTPUT=${CODE_HOME_PATH}/output
MYSQL_BINARY_CODE_PATH=${CODE_HOME_PATH}/library/mysql_pkg
CANTIANDB_LIB=${CANTIANDB_OUTPUT}/lib
CANTIANDB_SYMBOL=${CANTIANDB_OUTPUT}/symbol
CANTIANDB_OBJ=${CANTIANDB_OUTPUT}/obj
CANTIANDB_BIN=${CANTIANDB_OUTPUT}/bin

CT_SRC_BUILD_DIR=${CANTIANDB_BUILD}/pkg/src
CT_TEST_BUILD_DIR=${CANTIANDB_BUILD}/pkg/test

DBG_SYMBOL_SCRIPT=seperate_dbg_symbol.sh

if [[ "${OS_NAME}" -ne "Linux" ]]; then
    echo "Not on Linux OS"
    exit 1
else
    OS_ARCH=$(uname -i)
fi

OPENSSL_LIB_PATH=${CANTIANDB_LIBRARY}/openssl/lib
PCRE_LIB_PATH=${CANTIANDB_LIBRARY}/pcre/lib
Z_LIB_PATH=${CANTIANDB_LIBRARY}/zlib/lib
ODBC_LIB_PATH=${CANTIANDB_LIBRARY}/odbc/lib
ZSTD_LIB_PATH=${CANTIANDB_LIBRARY}/Zstandard/lib
LZ4_LIB_PATH=${CANTIANDB_LIBRARY}/lz4/lib
SECUREC_LIB_PATH=${CANTIANDB_LIBRARY}/security/lib
KMC_LIB_PATH=${CANTIANDB_LIBRARY}/kmc/lib
XNET_LIB_PATH=${CANTIANDB_LIBRARY}/xnet/lib

if [[ -f "${SUSE_VERSION_PATH}" ]]; then
    OS_MAJOR_VERSION=$(cat ${SUSE_VERSION_PATH} | grep VERSION |cut -d ' ' -f 3)
    OS_MINOR_VERSION=$(cat ${SUSE_VERSION_PATH} | grep PATCHLEVEL |cut -d ' ' -f 3)
    OS_SUFFIX=SUSE"${OS_MAJOR_VERSION}SP${OS_MINOR_VERSION}"
elif [[ -f "${KYLIN_VERSION_PATH}" ]]; then
        if [[ -n $(cat ${KYLIN_VERSION_PATH} | grep 'Kylin') ]]; then
            OS_SUFFIX=KYLIN
        fi
elif [[ -f "${NEOKYLIN_VERSION_PATH}" ]]; then
        if [[ -n $(cat ${NEOKYLIN_VERSION_PATH} | grep 'NeoKylin') ]]; then
            OS_SUFFIX=NEOKYLINREDHAT
        fi
elif [[ -f "${REDHAT_VERSION_PATH}" ]]; then
    if [[ -n $(cat ${REDHAT_VERSION_PATH} | grep 'Red Hat') ]]; then
        OS_SUFFIX=REDHAT
    elif [[ -n $(cat ${REDHAT_VERSION_PATH} | grep '2.0 (SP3)') ]]; then
        OS_SUFFIX=EULER20SP3
    elif [[ -n $(cat ${REDHAT_VERSION_PATH} | grep '2.0 (SP5)') ]]; then
        OS_SUFFIX=EULER20SP5
    elif [[ -n $(cat ${REDHAT_VERSION_PATH} | grep '2.0 (SP8)') ]]; then
        OS_SUFFIX=EULER20SP8
    elif [[ -n $(cat ${REDHAT_VERSION_PATH} | grep '2.0 (SP9') ]]; then
        OS_SUFFIX=EULER20SP9
    elif [[ -n $(cat ${REDHAT_VERSION_PATH} | grep '2.0 (SP10') ]]; then
        OS_SUFFIX=EULER20SP10
    elif [[ -f "${CENTOS_VERSION_PATH}" ]]; then
        cent_os_str=$(cat ${CENTOS_VERSION_PATH} | grep 'CentOS')
        if [[ -n "${cent_os_str}" ]]; then
            OS_SUFFIX=CENTOS
        fi
    fi
elif [[ -f "${CENTOS_VERSION_PATH}" ]]; then
        cent_os_str=$(cat ${CENTOS_VERSION_PATH} | grep 'CentOS')
        if [[ -n "${cent_os_str}" ]]; then
            OS_SUFFIX=CENTOS
        fi
elif [[ -f "${EULER_VERSION_PATH}" ]]; then
    if [[ -n $(cat ${EULER_VERSION_PATH} | grep '2.0 (SP10') ]]; then
        OS_SUFFIX=EULER20SP10
    fi
elif [[ -f "${OPENEULER_VERSION_PATH}" ]]; then
    if [[ -n $(cat ${OPENEULER_VERSION_PATH} | grep '22.03 (LTS-SP1') ]]; then
        OS_SUFFIX=""
    fi
else
    echo "Unsupported OS System"
    exit 1
fi


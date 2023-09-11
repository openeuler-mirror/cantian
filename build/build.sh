#!/bin/bash
# Copyright Huawei Technologies Co., Ltd. 2010-2018. All rights reserved.
# This script is used for compiling code via CMake and making packages
set -e

BEPKIT_HOME=/opt/buildtools/sepCloud/Bep_Env_For_Linux

${BEPKIT_HOME}/bep_env.sh -i
ldconfig
cp -r ${BEPKIT_HOME}/bep_env.conf  /home/
source ${BEPKIT_HOME}/bep_env.sh -s /home/bep_env.conf

sh Makefile.sh package-release
#!/bin/bash
# Copyright Huawei Technologies Co., Ltd. 2010-2018. All rights reserved.
# This script is used for compiling code via CMake and making packages
set -e

func_prepare_git_msg()
{
  git_id=$(git rev-parse --short HEAD)
  WHOLE_COMMIT_ID=$(git rev-parse HEAD)
  merge_time=$(git log | grep Date | sed -n '1p' | sed 's/^Date:\s*//g')
  driver_commit_id=$(git log --pretty=format:%h -n 1 ${CANTIAN_SRC}/driver/)
  gsql_commit_id=$(git log --pretty=format:%h -n 1 ${CANTIAN_SRC}/utils/gsql)
  cat /dev/null > ${CANTIAN_BUILD}/conf/git_message.in
  echo "git_id=${git_id}" >> ${CANTIAN_BUILD}/conf/git_message.in
  echo "gitVersion=${WHOLE_COMMIT_ID}" >> ${CANTIAN_BUILD}/conf/git_message.in
  echo "merge_time=${merge_time}" >> ${CANTIAN_BUILD}/conf/git_message.in
  echo "driver_commit_id=${driver_commit_id}" >> ${CANTIAN_BUILD}/conf/git_message.in
  echo "gsql_commit_id=${gsql_commit_id}" >> ${CANTIAN_BUILD}/conf/git_message.in
}

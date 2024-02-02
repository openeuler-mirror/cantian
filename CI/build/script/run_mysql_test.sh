#!/bin/bash

BUILD_MODE=${BUILD_MODE:-"multiple"}
HOME_PATH="/home/regress"
CTDB_CODE_PATH=${HOME_PATH}/CantianKernel
if [ "${WORKSPACE}" != "" ]; then
    HOME_PATH=${WORKSPACE}
    CTDB_CODE_PATH=${HOME_PATH}/daac
    MYSQL_CODE_PATH=${HOME_PATH}/cantian-connector-mysql/mysql-source
    CTC_CODE_PATH=/hactc_libctcproxy_dir/mysql-source
else
    HOME_PATH="/home/regress"
    CTDB_CODE_PATH=${HOME_PATH}/CantianKernel
    MYSQL_CODE_PATH=${HOME_PATH}/cantian-connector-mysql
    CTC_CODE_PATH=/hactc_libctcproxy_dir
fi
MYSQL_LCOV_OUT_PATH=${WORKSPACE}/cantian-connector-mysql/lcovout
LLT_TEST_TYPE=${1}
LLT_CFG_FILE="enableCases_gcov.list"
if [ "${LLT_TEST_TYPE}" == "ASAN" ]; then
  LLT_CFG_FILE=enableCases_asan${2}.list
fi
echo "run_mysql_test.sh LLT_TEST_TYPE:${LLT_TEST_TYPE} LLT_CFG_FILE:${LLT_CFG_FILE}"
set -x

kill_process()
{
    while pgrep $1; do
        pkill -9 $1
    done
}

kill_name()
{
    set +e
    kill_process $1
    set -e
}

kill_all()
{
    kill_name cms
    kill_name cantiand
}

function run_daac() {
    echo "Start run_daac..."
    cantian_data_path="/home/regress/cantian_data"
    if [ ! -d $cantian_data_path ];then
      mkdir -p $cantian_data_path
    fi
    chmod 755 -R $cantian_data_path
    rm -rf /home/regress/cantian_data/*  /home/regress/install /home/regress/data /home/cantiandba/install/*
    sed -i '/regress/d' /home/cantiandba/.bashrc
    cd ${CTDB_CODE_PATH}/output/bin/Cantian-DATABASE-CENTOS-64bit
    mkdir -p /home/regress/logs
    python3 install.py -U cantiandba:cantiandba -R /home/regress/install/ -D /home/regress/data/ -l /home/regress/logs/install.log -g withoutroot -d -M cantiand -c -Z _SYS_PASSWORD=Huawei@123
}

function change_shm_size() {
  echo "change_shm_size..."
  mount -o size=10240M  -o remount /dev/shm
}

function gen_lcov_report() {
  cd ${CTC_CODE_PATH}/bld_debug/storage/tianchi/CMakeFiles/ctc.dir
  if ls *.gcda >/dev/null 2>&1; then
    echo "------------- GENERATING LCOV FILES -------------"
    lcov -d . -c -o mysqltest-lcov.info --rc lcov_branch_coverage=1
    lcov --extract mysqltest-lcov.info '*tianchi*' -o mysqltest-tianchi-lcov.info --rc lcov_branch_coverage=1
    lcov --remove mysqltest-tianchi-lcov.info '*tianchi/protobuf/*' -o mysqltest-tianchi-final-lcov.info --rc lcov_branch_coverage=1
    genhtml --branch-coverage mysqltest-tianchi-final-lcov.info -o MysqlTestLcovReport

    if [ ! -d "$MYSQL_LCOV_OUT_PATH" ]; then
      mkdir -p ${MYSQL_LCOV_OUT_PATH}
    fi
    cp -arf ${CTC_CODE_PATH}/bld_debug/storage/tianchi/CMakeFiles/ctc.dir/MysqlTestLcovReport ${MYSQL_LCOV_OUT_PATH}
  else
    echo "Generate gcda failed. Please check if Mysql-test process exit successfully. "
    return 1
  fi
}

function run_test() {
  echo "Start run_test..."
  if [ "${BUILD_MODE}" == "multiple" ]; then
    cp -arf ${MYSQL_CODE_PATH}/daac_lib/libsecurec.a /usr/lib64/
    cp -arf ${MYSQL_CODE_PATH}/daac_lib/libctc_proxy.so /usr/lib64/
    cp -arf /usr/local/mysql/lib/* /usr/lib64/
    cp -arf /usr/local/mysql/lib/private/* /usr/lib64/
    echo 'log_raw=ON' >> /usr/local/mysql/mysql-test/include/default_mysqld.cnf
    ldconfig
    chmod +x /usr/local/mysql/bin/*
    # 主干流程
    # cd /usr/local/mysql/mysql-test/ && ./mysql-test-run.pl --mysqld=--plugin_load="ctc_ddl_rewriter=ha_ctc.so;ctc=ha_ctc.so;" --mysqld=--check_proxy_users=ON --mysqld=--mysql_native_password_proxy_users=ON --mysqld=--default-storage-engine=CTC --do-test-list=${LLT_CFG_FILE} --noreorder
    
    # 元数据归一
    cd /usr/local/mysql/mysql-test/
    ls -l
    chmod 755 mysql-test-run-meta.pl
    ./mysql-test-run-meta.pl --mysqld=--default-storage-engine=CTC --mysqld=--check_proxy_users=ON --do-test-list=${LLT_CFG_FILE} --noreorder --nowarnings
    if [ $? -eq 0 ]; then
      echo "Execute mysql-test-run success."
    else
      echo "命令执行失败"
      cat /usr/local/mysql/mysql-test/var/log/bootstrap.log
    fi
  elif [ "${BUILD_MODE}" == "single" ]; then
    echo "Fail: single process test is not implement!"
    return 1
  fi
}

function check_user() {
  cat /etc/passwd | grep cantiandba
  if [ $? != 0 ]; then
    rm -rf /home/cantiandba
    useradd -m cantiandba -u 5000
  fi

  ls -a /home/cantiandba | grep .bashrc
  if [ $? != 0 ]; then
    rm -rf /home/cantiandba
    userdel cantiandba
    useradd -m cantiandba -u 5000
  fi
}

check_user
kill_all

change_shm_size
run_daac
run_test
if [ $? -eq 0 ] && [ "${LLT_TEST_TYPE}" == "GCOV" ]; then
  echo "------------- COLLECTING LLT LCOV INFO -------------"
  gen_lcov_report
fi

### 1. 修改代码：
脚本路径：`cantian/pkg/install/installdb.sh` 中 `function start_cantiand()`
```cpp
// 如果需要gdb MySQL初始化流程，则在初始化前sleep足够长时间，手动执行
echo "Init mysqld data dir ${MYSQL_DATA_DIR}"
sleep 100000 # add here
${MYSQL_BIN_DIR}/bin/mysqld --defaults-file=${MYSQL_CONFIG_FILE} --initialize-insecure --datadir=${MYSQL_DATA_DIR} --early-plugin-load="ha_ctc.so" --core-file

```

```cpp
// 如果需要gdb MySQL启动流程，则在启动前sleep足够长时间，手动执行
export CANTIAND_MODE="open"
echo "Start mysqld with conf ${MYSQL_CONFIG_FILE}"
sleep 100000 # add here
nohup ${MYSQL_BIN_DIR}/bin/mysqld --defaults-file=${MYSQL_CONFIG_FILE} --datadir=${MYSQL_DATA_DIR} --plugin-dir=${MYSQL_BIN_DIR}/lib/plugin \

```

### 2. 安装部署：
前期环境准备及编译流程省略，参考：[参天编译部署手册](https://gitee.com/openeuler/cantian/blob/master/docker/readme.md)
直至部署阶段。

流程如下继续：

**步骤1**：执行部署脚本
```bash 
# 执行指令后会卡住，卡在前面脚本中手动加上的sleep处
python3 install.py -U cantiandba:cantiandba -R /home/cantiandba/install/ -D /home/cantiandba/data/ -l /home/cantiandba/logs/install.log -Z _LOG_LEVEL=255 -g withoutroot -d -M cantiand_with_mysql -m /home/regress/cantian-connector-mysql/scripts/my.cnf -c -Z _SYS_PASSWORD=Huawei@123 -Z SESSIONS=1000
```
- 如果 gdb `MySQL初始化流程`, 则继续步骤`2-3`;
- 如果 gdb `MySQL启动流程`,则继续步骤`4`;

**步骤2**：新开窗口1设置环境变量并执行初始化指令
```bash 
su - cantiandba
export MYSQL_BUILD_MODE=single
export RUN_MODE=cantiand_with_mysql
export LD_LIBRARY_PATH=/usr/local/mysql/lib:/home/regress/cantian-connector-mysql/mysql-source/daac_lib:/usr/local/mysql/lib:/home/regress/cantian-connector-mysql/mysql-source/daac_lib:/usr/local/mysql/lib/private:/home/cantiandba/install/lib:/home/cantiandba/install/add-ons::/home/regress/cantian-connector-mysql/bld_debug/library_output_directory
export CANTIAND_MODE=nomount
export CANTIAND_HOME_DIR=/home/cantiandba/data
export CTDB_HOME=/home/cantiandba/install
export CMS_HOME=/home/cantiandba/data
export HOME=/home/cantiandba
```

```bash 
# initialization
gdb --args /usr/local/mysql/bin/mysqld --defaults-file=/home/regress/cantian-connector-mysql/scripts/my.cnf --initialize-insecure --datadir=/data/data --early-plugin-load=ha_ctc.so --core-file
# 打断点后run
```
-  注：在执行tse_init_func()期间，会等待参天执行创库创表，需要执行步骤3后继续

**步骤3**：新开窗口2登录ctsql创参天系统库/表等：
```bash
su - cantiandba -c '/home/cantiandba/install/bin/ctsql / as sysdba -q -D /home/cantiandba/data -f "/home/cantiandba/install/admin/scripts/create_database.sample.sql"'
```

**步骤4**
```bash 
su - cantiandba
export MYSQL_BUILD_MODE=single
export RUN_MODE=cantiand_with_mysql
export LD_LIBRARY_PATH=/usr/local/mysql/lib:/home/regress/cantian-connector-mysql/mysql-source/daac_lib:/usr/local/mysql/lib:/home/regress/cantian-connector-mysql/mysql-source/daac_lib:/usr/local/mysql/lib/private:/home/cantiandba/install/lib:/home/cantiandba/install/add-ons::/home/regress/cantian-connector-mysql/bld_debug/library_output_directory
export CANTIAND_MODE=open
export CANTIAND_HOME_DIR=/home/cantiandba/data
export CTDB_HOME=/home/cantiandba/install
export CMS_HOME=/home/cantiandba/data
export HOME=/home/cantiandba

```

```bash 
# start
gdb --args /usr/local/mysql/bin/mysqld --defaults-file=/home/regress/cantian-connector-mysql/scripts/my.cnf --datadir=/data/data --user=root --skip-innodb --early-plugin-load=ha_ctc.so --core-file
# 打断点后run
```
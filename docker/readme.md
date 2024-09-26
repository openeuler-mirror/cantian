# 容器开发编译部署手册

## 环境准备

### 目录组织

```
例：
新建编译目录ctdb_compile，后续操作均在此目录下展开
drwxr-xr-x  2 root root      4096 Aug 24 10:45 3rdPartyPkg // 三方依赖所用路径(protobuf等等)
drwxr-xr-x 16 root root      4096 Sep 25 18:10 cantian // cantian 源码目录
drwxr-xr-x  7 root root      4096 Sep 20 10:25 cantian-connector-mysql // cantian-connector-mysql 源码目录
drwxr-xr-x  4 root root      4096 Sep 25 18:11 cantian_data // cantian 数据文件目录
```

### 下载最新docker镜像

```shell
# x86版本
docker pull ykfnxx/cantian_dev:0.1.0
# arm版本
docker pull ykfnxx/cantian_dev:0.1.1
# x决定是arm/x86版本
docker tag ykfnxx/cantian_dev:0.1.[x] cantian_dev:latest
```

### 准备代码

```shell
git clone git@gitee.com:openeuler/cantian.git
git clone git@gitee.com:openeuler/cantian-connector-mysql.git

下载mysql-8.0.26源码
wget --no-check-certificate https://github.com/mysql/mysql-server/archive/refs/tags/mysql-8.0.26.tar.gz
tar -zxf mysql-8.0.26.tar.gz
mv mysql-server-mysql-8.0.26 cantian-connector-mysql/mysql-source

mkdir -p cantian_data
```

### 启动开发编译自验容器
需进入cantian代码目录
+ 单节点
```shell
sh docker/container.sh dev
sh docker/container.sh enterdev
```
+ 双节点
```shell
# 目前只支持双节点，node_id为0, 1代表0号节点或1号节点
sh docker/container.sh startnode [node_id]
sh docker/container.sh enternode [node_id]
```

[container.sh](https://gitee.com/openeuler/cantian/blob/master/docker/container.sh)按`startnode`和`dev`参数启动时会执行代码拷贝的操作，具体操作参考脚本中`sync_mysql_code`函数

**注：容器外修改代码后需要停掉docker容器后再重启容器内方能生效**
```shell
docker ps -a 查询当前启动cantian容器ID
docker stop [容器名或ID]
```

## 编译部署

### Cantian编译

以下命令在容器内使用。若为双节点，则只需在其中一个节点执行一次。为方便描述，后续双节点仅需在一个节点的操作默认在node0进行
```shell
cd /home/regress/CantianKernel/build
export local_build=true
# 若此前编译过第三方依赖，可以修改Makefile.sh文件中func_all函数，将func_prepare_dependency注释掉，避免重复编译三方依赖。
# debug
sh Makefile.sh package
# release
sh Makefile.sh package-release
```

### 单节点Cantian部署

```shell
cd /home/regress/CantianKernel/Cantian-DATABASE-CENTOS-64bit
mkdir -p /home/cantiandba/logs
# -Z SESSIONS=1000方便调试，需运行MTR时需要去掉此参数
# 如果需要部署非元数据归一版本，则需要加参数-Z MYSQL_METADATA_IN_CANTIAN=FALSE
python3 install.py -U cantiandba:cantiandba -R /home/cantiandba/install -D /home/cantiandba/data -l /home/cantiandba/logs/install.log -Z _LOG_LEVEL=255 -g withoutroot -d -M cantiand -c -Z _SYS_PASSWORD=Huawei@123 -Z SESSIONS=1000
```
### 双节点Cantian部署
```shell
#节点0，在容器内执行以下命令
# -Z SESSIONS=1000方便调试，需运行MTR时需要去掉此参数
cd /home/regress/CantianKernel/Cantian-DATABASE-CENTOS-64bit
mkdir -p /home/cantiandba/logs
python3 install.py -U cantiandba:cantiandba -R /home/cantiandba/install -D /home/cantiandba/data -l /home/cantiandba/logs/install.log -M cantiand_in_cluster -Z _LOG_LEVEL=255 -N 0 -W 192.168.0.1 -g withoutroot -d -c -Z _SYS_PASSWORD=Huawei@123 -Z SESSIONS=1000
```
```shell
#节点1，在容器内执行以下命令
cd /home/regress/CantianKernel/Cantian-DATABASE-CENTOS-64bit
mkdir -p /home/cantiandba/logs
python3 install.py -U cantiandba:cantiandba -R /home/cantiandba/install -D /home/cantiandba/data -l /home/cantiandba/logs/install.log -M cantiand_in_cluster -Z _LOG_LEVEL=255 -N 1 -W 192.168.0.1 -g withoutroot -d -c -Z _SYS_PASSWORD=Huawei@123 -Z SESSIONS=1000
```

#### 验证Cantian状态是否正常

```shell
su - cantiandba
cms stat
ctsql / as sysdba -q -c 'SELECT NAME, STATUS, OPEN_STATUS FROM DV_DATABASE'
```

### 卸载Cantian

```shell
cd /home/cantiandba/install/bin
python3 install.py -U cantiandba -F -D /home/cantiandba/data -g withoutroot -d
```

### MySQL-Connector编译

#### 元数据归一版本（MySQL元数据在cantian存放，修改了MySQL源码，需要应用patch生效）
##### 应用patch，修改源码
```shell
cd cantian-connector-mysql/mysql-source
patch --ignore-whitespace -p1 < mysql-scripts-meta.patch
patch --ignore-whitespace -p1 < mysql-test-meta.patch
patch --ignore-whitespace -p1 < mysql-source-code-meta.patch
```

##### 编译MySQL及Connector
```shell
cd /home/regress/CantianKernel/build
sh Makefile.sh mysql
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/regress/cantian-connector-mysql/bld_debug/library_output_directory
rm -rf /home/regress/mydata/*
```

双节点部署时，如果使用**手动部署**，则两个节点需要分别执行编译。若使用**脚本部署**，只需在一个节点编译即可  
特别地，若在node0完成cantian的编译，在node1编译mysql前需要先执行以下命令
```shell
mkdir /home/regress/cantian-connector-mysql/mysql-source/include/protobuf-c
cp /home/regress/CantianKernel/library/protobuf/protobuf-c/protobuf-c.h /home/regress/cantian-connector-mysql/mysql-source/include/protobuf-c
```

#### 非归一MySQL编译

双节点部署时，非元数据归一版本（MySQL元数据存放在InnoDB引擎）只需要在其中一个节点编译mysql即可

```shell
cd /home/regress/CantianKernel/build
sh Makefile.sh mysql
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/regress/cantian-connector-mysql/bld_debug/library_output_directory
```

### MySQL部署

#### 元数据归一(手动拉起)

初始化：
双节点仅需在其中一个节点执行初始化命令，且在初始化前，需保证`/home/regress/mydata`下没有文件需先执行

```shell
rm -rf /home/regress/mydata/*
```

```shell
初始化命令（datadir可自行调整，类似上步的清理命令也要修改）
/usr/local/mysql/bin/mysqld --defaults-file=/home/regress/cantian-connector-mysql/scripts/my.cnf --initialize-insecure --datadir=/home/regress/mydata --early-plugin-load="ha_ctc.so" --core-file
```

部署：
双节点在初始化后分别执行部署命令。若在node0完成初始化，则node1需先执行以下命令

```shell
rm -rf /home/regress/mydata/*
mkdir -p /home/regress/mydata/
mkdir -p /home/regress/mydata/mysql
```

部署命令为：
```shell
/usr/local/mysql/bin/mysqld --defaults-file=/home/regress/cantian-connector-mysql/scripts/my.cnf  --datadir=/home/regress/mydata --user=root --early-plugin-load="ha_ctc.so" --core-file
```

#### 元数据归一/非归一

双节点拉起前需分别执行以下命令

```shell
# node0
cd /home/regress/CantianKernel/build
sh Makefile.sh mysql_package_node0

# node1
cd /home/regress/CantianKernel/build
sh Makefile.sh mysql_package_node1
```

使用`install.py`脚本拉起

```shell
cd /home/regress/CantianKernel/Cantian-DATABASE-CENTOS-64bit
mkdir -p /home/regress/logs
python3 install.py -U cantiandba:cantiandba -l /home/cantiandba/logs/install.log -d -M mysqld -m /home/regress/cantian-connector-mysql/scripts/my.cnf
```

#### 拉起检验MySQL

```shell
/usr/local/mysql/bin/mysql -uroot
```
登录MySQL客户端后执行命令

### 环境卸载 & 清理

若脚本卸载执行失败或需要重新编译安装部署，可执行以下命令手动卸载后再重新从cantian部署部分开始执行（除编译及打patch步骤）

```shell
kill -9 $(pidof mysqld)
kill -9 $(pidof cantiand)
kill -9 $(pidof cms)
rm -rf /home/regress/cantian_data/* /home/regress/install /home/regress/data /home/cantiandba/install/* /data/data/* /home/cantiandba/data
sed -i '/cantiandba/d' /home/cantiandba/.bashrc
```

### 单进程部署文档
与双进程(cantiand+mysqld)不同，单进程部署形态只有mysqld进程
#### 编译参天

```Bash  
cd /home/regress/CantianKernel/build
export local_build=true 
export MYSQL_BUILD_MODE=single
sh Makefile.sh package DAAC_READ_WRITE=1 no_shm=1
```

#### 编译MySQL

```Bash  
cd /home/regress/CantianKernel/build
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/regress/cantian-connector-mysql/bld_debug/library_output_directory
sh Makefile.sh mysql no_shm=1
```

#### 部署

```Bash  
cd /home/regress/CantianKernel/build
sh Makefile.sh mysql_package_node0
cd /home/regress/CantianKernel/Cantian-DATABASE-CENTOS-64bit
mkdir -p /home/cantiandba/logs
# -Z SESSIONS=1000方便调试，需运行MTR时需要去掉此参数
# 如果需要部署非元数据归一版本，则需要加参数-Z MYSQL_METADATA_IN_CANTIAN=FALSE
python3 install.py -U cantiandba:cantiandba -R /home/cantiandba/install/ -D /home/cantiandba/data/ -l /home/cantiandba/logs/install.log -Z _LOG_LEVEL=255 -g withoutroot -d -M cantiand_with_mysql -m /home/regress/cantian-connector-mysql/scripts/my.cnf -c -Z _SYS_PASSWORD=Huawei@123 -Z SESSIONS=1000
```
卸载清理命令和单进程一致
注：单进程部署过后转双进程建议删除代码重新拉，否则仍会有代码残留导致形态无法切换

#### 进程调试

#### gdb调试
gdb调试cantian前请先设置心跳
``` Bash  
su cantiandba
cms res -edit db -attr HB_TIMEOUT=1000000000
cms res -edit db -attr CHECK_TIMEOUT=1000000000
```

```
进程运行中调试
gdb -p mysqld进程号
使用gdb拉起进程调试
gdb --args [mysql初始化或拉起命令]
```

如果有进程coredump问题，需要解析内存转储文件分析堆栈
##### 配置core_pattern
配置core_pattern后，即可在对应core_pattern目录生成coredump文件
```Bash  
echo "/home/core/core-%e-%p-%t" > /proc/sys/kernel/core_pattern
echo 2 > /proc/sys/fs/suid_dumpable
ulimit -c unlimited
```

##### 解析coredump

+ 双进程
```Bash
解cantiand
gdb /home/regress/CantianKernel/output/bin/cantiand /home/core/core文件名
解mysqld
gdb /usr/local/mysql/bin/mysqld /home/core/core文件名
```

+ 单进程
```Bash
解mysqld
gdb /usr/local/mysql/bin/mysqld /home/core/core文件名
```

##### 开发自验证MTR用例
``` Bash 
cd /usr/local/mysql/mysql-test
chmod 777 ./mysql-test-run-meta.pl
# 原主干执行MTR
./mysql-test-run.pl --mysql=--plugin_load="ctc_ddl_rewriter=ha_ctc.so;ctc=ha_ctc.so;" --mysql=--default-storage-engine=CTC --mysql=--check_proxy_users=ON --mysqld=--mysql_native_password_proxy_users=ON --do-test-list=enableCases.list --noreorder
# 元数据归一MySQL进程拉起后执行MTR命令
./mysql-test-run-meta.pl --mysqld=--default-engine=CTC --mysqld=--check_proxy_users=ON --do-test-list=enableCases.list --noreorder --nowarnings --extern host=127.0.0.1 --extern port=3306 --extern user=root
# 元数据归一MTR自拉起MySQL进程验证
./mysql-test-run-meta.pl --mysqld=--default-storage-engine=CTC --mysqld=--check_proxy_users=ON --do-test-list=enableCases.list --noreorder --nowarnings
```
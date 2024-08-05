# 容器开发编译部署手册

## 环境准备

### 下载最新docker镜像

```shell
# x86版本
docker pull ykfnxx/cantian_dev:0.1.0
# arm版本
docker pull ykfnxx/cantian_dev:0.1.1
# x取决于是哪个版本
docker tag ykfnxx/cantian_dev:0.1.[x] cantian_dev:latest
```

### 准备代码目录

```shell
git clone git@gitee.com:openeuler/cantian.git
git clone git@gitee.com:openeuler/cantian-connector-mysql.git

wget --no-check-certificate https://github.com/mysql/mysql-server/archive/refs/tags/mysql-8.0.26.tar.gz
tar -zxf mysql-8.0.26.tar.gz
mv mysql-server-mysql-8.0.26 cantian-connector-mysql/mysql-source

mkdir -p cantian_data
```

### 启动容器

+ 单节点
```shell
sh docker/container.sh dev
sh docker/container.sh enterdev
```
+ 双节点
```shell
# 目前只支持双节点，node_id为0, 1
sh docker/container.sh startnode [node_id]
sh docker/container.sh enternode [node_id]
```

[container.sh](https://gitee.com/openeuler/cantian/blob/master/docker/container.sh)按`startnode`和`dev`参数启动时会执行代码拷贝的操作，具体操作参考脚本中`sync_mysql_code`函数

## 编译部署

### cantian编包

以下命令在容器内使用。若为双节点，则只需在其中一个节点执行一次。为方便描述，后续双节点仅需在一个节点的操作默认在node0进行
```shell
cd /home/regress/CantianKernel/build
export local_build=true
# 若此前编译过第三方依赖，可以再加上--no-deps参数，跳过第三方依赖的编译
# debug
sh Makefile.sh package
# release
sh Makefile.sh package-release
```

### 单节点cantian部署

```shell
cd /home/regress/CantianKernel/Cantian-DATABASE-CENTOS-64bit
mkdir -p /home/cantiandba/logs
# -Z SESSIONS=1000方便调试，需运行MTR时需要去掉此参数
# 如果需要部署非元数据归一版本，则需要加参数-Z MYSQL_METADATA_IN_CANTIAN=FALSE
python3 install.py -U cantiandba:cantiandba -R /home/cantiandba/install -D /home/cantiandba/data -l /home/cantiandba/logs/install.log -Z _LOG_LEVEL=255 -g withoutroot -d -M cantiand -c -Z _SYS_PASSWORD=Huawei@123 -Z SESSIONS=1000
```
### 双节点cantian部署
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

#### 验证cantian状态是否正常

```shell
su - cantiandba
cms stat
ctsql / as sysdba -q -c 'SELECT NAME, STATUS, OPEN_STATUS FROM DV_DATABASE'
```

### 卸载cantian

```shell
cd /home/cantiandba/install/bin
python3 install.py -U cantiandba -F -D /home/cantiandba/data -g withoutroot -d
```

### mysql编译

#### 元数据归一
元数据归一需要应用patch，修改源码
```shell
cd cantian-connector-mysql/mysql-source
patch --ignore-whitespace -p1 < mysql-scripts-meta.patch
patch --ignore-whitespace -p1 < mysql-test-meta.patch
patch --ignore-whitespace -p1 < mysql-source-code-meta.patch
```

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

#### 非归一

双节点部署时，非归一版本只需要在其中一个节点编译mysql即可

```shell
cd /home/regress/CantianKernel/build
sh Makefile.sh mysql
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/regress/cantian-connector-mysql/bld_debug/library_output_directory
```

### mysql部署

#### 元数据归一(手动拉起)

初始化：
双节点仅需在其中一个节点执行初始化命令，且在初始化前，需保证`/home/regress/mydata`下没有文件需先执行

```shell
rm -rf /home/regress/mydata/*
```

```shell
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

#### 元数据归一/非归一（脚本）

双节点拉起前需分别执行以下命令

```shell
# node0
cd /home/regress/CantianKernel/build
sh Makefile.sh mysql_package_node0

# node1
cd /home/regress/CantianKernel/build
sh Makefile.sh mysql_package_node1
```

以下为使用`install.py`脚本拉起的命令

```shell
cd /home/regress/CantianKernel/Cantian-DATABASE-CENTOS-64bit
mkdir -p /home/regress/logs
python3 install.py -U cantiandba:cantiandba -l /home/cantiandba/logs/install.log -d -M mysqld -m /home/regress/cantian-connector-mysql/scripts/my.cnf
```

#### 拉起检验

```shell
/usr/local/mysql/bin/mysql -uroot
```

### 手动卸载

若脚本卸载执行失败，可执行以下命令手动卸载

```shell
kill -9 $(pidof mysqld)
kill -9 $(pidof cantiand)
kill -9 $(pidof cms)
rm -rf /home/regress/cantian_data/* /home/regress/install /home/regress/data /home/cantiandba/install/* /data/data/* /home/cantiandba/data
sed -i '/cantiandba/d' /home/cantiandba/.bashrc
```

# 单进程单节点部署文档

## 准备环节

按照gitee上的教程走到下载代码仓

```Bash  
mkdir -p /ctdb/cantian_compile
cd /ctdb/cantian_compile
# cantian
git clone https://gitee.com/hezijian1111/cantian.git

# cantian-connector-mysql

git clone https://gitee.com/hezijian1111/cantian-connector-mysql.git

# mysql源码
wget --no-check-certificate https://github.com/mysql/mysql-server/archive/refs/tags/mysql-8.0.26.tar.gz
tar -zxf mysql-8.0.26.tar.gz
mv mysql-server-mysql-8.0.26 cantian-connector-mysql/mysql-source

# catian_date
mkdir -p cantian_data
```
## 创建和进入节点

￮       每一次更新cantian代码的时候不需要重启容器，更新connector代码时需要重启容器

单节点

```Bash  
# 创建容器
sh /ctdb/cantian_compile/cantian/docker/container.sh dev
# 进入容器
sh /ctdb/cantian_compile/cantian/docker/container.sh enterdev
```
## 编译参天

```Bash  
cd /home/regress/CantianKernel/build
export local_build=true 
export MYSQL_BUILD_MODE=single
sh Makefile.sh package DAAC_READ_WRITE=1 no_shm=1
```
## 归一部署需要打patch

```Bash  
cd /home/regress/cantian-connector-mysql/mysql-source/  
patch --ignore-whitespace -p1 < mysql-scripts-meta.patch  
patch --ignore-whitespace -p1 < mysql-test-meta.patch  
patch --ignore-whitespace -p1 < mysql-source-code-meta.patch
```
## 重置patch

```Bash  
cd /ctdb/cantian_compile/cantian-connector-mysql
rm -rf mysql-source
tar -zxvf ../mysql-8.0.26.tar.gz
mv mysql-server-mysql-8.0.26 mysql-source
```
## 编译MySQL

```Bash  
cd /home/regress/CantianKernel/build
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/regress/cantian-connector-mysql/bld_debug/library_output_directory
sh Makefile.sh mysql no_shm=1
rm -rf /home/regress/mydata/*
```
## 配置core\_pattern

```Bash  
echo "/home/core/core-%e-%p-%t" > /proc/sys/kernel/core_pattern
echo 2 > /proc/sys/fs/suid_dumpable
ulimit -c unlimited
```
## 部署

￮       *\-Z SESSIONS=1000方便调试，需运行MTR时需要去掉此参数*

￮       *如果需要部署非元数据归一版本，则需要加参数**\-Z MYSQL\_METADATA\_IN\_CANTIAN=FALSE*

```Bash  
cd /home/regress/CantianKernel/build
sh Makefile.sh mysql_package_node0
cd /home/regress/CantianKernel/Cantian-DATABASE-CENTOS-64bit
mkdir -p /home/cantiandba/logs
python3 install.py -U cantiandba:cantiandba -R /home/cantiandba/install/ -D /home/cantiandba/data/ -l /home/cantiandba/logs/install.log -Z _LOG_LEVEL=255 -g withoutroot -d -M cantiand_with_mysql -m /home/regress/cantian-connector-mysql/scripts/my.cnf -c -Z _SYS_PASSWORD=Huawei@123 -Z SESSIONS=1000
```

## 拉起验证

``` Bash  
/usr/local/mysql/bin/mysql -uroot
```
## 卸载参天和mysqld

在容器内执行卸载命令：清除进程；删除安装日志目录等；删除.bashrc和cantian相关的行

```Bash  
kill -9 $(pidof mysqld)
kill -9 $(pidof cantiand)
kill -9 $(pidof gssd)
kill -9 $(pidof cms)
rm -rf /home/regress/cantian_data/* /home/cantiandba/data/ /home/regress/install /home/regress/data /home/cantiandba/install/* /data/data/*
sed -i '/cantiandba/d' /home/cantiandba/.bashrc
```
## MySQL拉起失败，执行一下操作后，重新在对应节点上部署

```Bash  
rm -rf /home/regress/mydata/*
mkdir -p /home/regress/mydata/
mkdir -p /home/regress/mydata/mysql
```
## PS.

单进程部署过后转双进程建议删除代码重新拉

## 日志和调试

￮       参天日志：

￮       GDB调试看corefile：gdb \[executable file\] \[coredump file\]

▪       executable file：/home/cantiandba/install/bin/cantiand

▪       coredump file：使用cat /proc/sys/kernel/core\_pattern 来查看，以上教程是配置在/home/core/\*

▪       符号表：cantian-.sysbol

￮       gdb attach 进入 cantiand进程调试需要设置心跳，否则会断连

``` Bash  
su cantiandba
cms res -edit db -attr HB_TIMEOUT=1000000000
cms res -edit db -attr CHECK_TIMEOUT=1000000000
```
￮       在部署mysql的情况下跑MTR用例

``` Bash 
# 跑MTR
cd /usr/local/mysql/mysql-test
chmod 777 ./mysql-test-run-meta.pl
# 原主干执行MTR
./mysql-test-run.pl --mysql=--plugin_load="ctc_ddl_rewriter=ha_ctc.so;ctc=ha_ctc.so;" --mysql=--default-storage-engine=CTC --mysql=--check_proxy_users=ON --mysqld=--mysql_native_password_proxy_users=ON --do-test-list=enableCases.list --noreorder
# 元数据归一执行MTR
./mysql-test-run-meta.pl --mysqld=--default-engine=CTC --mysqld=--check_proxy_users=ON --do-test-list=enableCases.list --noreorder --nowarnings --extern host=127.0.0.1 --extern port=3306 --extern user=root
```
# 单进程双节点部署文档

## 准备环节

按照gitee上的教程走到下载代码仓

```Bash  
mkdir -p /ctdb/cantian_compile
cd /ctdb/cantian_compile
# cantian
git clone https://gitee.com/hezijian1111/cantian.git

# cantian-connector-mysql

git clone https://gitee.com/hezijian1111/cantian-connector-mysql.git

# mysql源码
wget --no-check-certificate https://github.com/mysql/mysql-server/archive/refs/tags/mysql-8.0.26.tar.gz
tar -zxf mysql-8.0.26.tar.gz
mv mysql-server-mysql-8.0.26 cantian-connector-mysql/mysql-source

# catian_date
mkdir -p cantian_data
```
## 创建和进入节点

￮       每一次更新cantian代码的时候不需要重启容器，更新connector代码时需要重启容器

双节点

```Bash  
# 创建node0
sh /ctdb/cantian_compile/cantian/docker/container.sh startnode 0
# 进入node0
sh /ctdb/cantian_compile/cantian/docker/container.sh enternode 0
# 创建node1
sh /ctdb/cantian_compile/cantian/docker/container.sh startnode 1
# 进入node1
sh /ctdb/cantian_compile/cantian/docker/container.sh enternode 1
```
### IP问题
修改`/ctdb/cantian_compile/cantian/docker`中function create_network()的IP，修改为`192.168.0.0`
## 双节点编译参天，其中一个节点编译即可

```Bash  
cd /home/regress/CantianKernel/build
export local_build=true 
export MYSQL_BUILD_MODE=single
sh Makefile.sh package DAAC_READ_WRITE=1 no_shm=1
```
## 归一部署需要打patch

```Bash  
cd /home/regress/cantian-connector-mysql/mysql-source/  
patch --ignore-whitespace -p1 < mysql-scripts-meta.patch  
patch --ignore-whitespace -p1 < mysql-test-meta.patch  
patch --ignore-whitespace -p1 < mysql-source-code-meta.patch
```
## 重置patch

```Bash  
cd /ctdb/cantian_compile/cantian-connector-mysql
rm -rf mysql-source
tar -zxvf ../mysql-8.0.26.tar.gz
mv mysql-server-mysql-8.0.26 mysql-source
```
## 节点1编译MySQL前拷贝proto
```Bash  
cd /home/regress/cantian-connector-mysql/mysql-source/
mkdir /home/regress/cantian-connector-mysql/mysql-source/include/protobuf-c
cp /home/regress/CantianKernel/library/protobuf/protobuf-c/protobuf-c.h /home/regress/cantian-connector-mysql/mysql-source/include/protobuf-c
```

## 编译MySQL，双节点依次编译

```Bash  
cd /home/regress/CantianKernel/build
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/regress/cantian-connector-mysql/bld_debug/library_output_directory
sh Makefile.sh mysql no_shm=1
rm -rf /home/regress/mydata/*
```
## 配置core\_pattern

```Bash  
echo "/home/core/core-%e-%p-%t" > /proc/sys/kernel/core_pattern
echo 2 > /proc/sys/fs/suid_dumpable
ulimit -c unlimited
```
## 部署，双节点依次部署

￮       *\-Z SESSIONS=1000方便调试，需运行MTR时需要去掉此参数*

￮       *如果需要部署非元数据归一版本，则需要加参数**\-Z MYSQL\_METADATA\_IN\_CANTIAN=FALSE*
### 部署node0
```Bash  
cd /home/regress/CantianKernel/build
sh Makefile.sh mysql_package_node0
cd /home/regress/CantianKernel/Cantian-DATABASE-CENTOS-64bit
mkdir -p /home/cantiandba/logs
python3 install.py -U cantiandba:cantiandba -R /home/cantiandba/install/ -D /home/cantiandba/data/ -l /home/cantiandba/logs/install.log -Z _LOG_LEVEL=255 -g withoutroot -d -M cantiand_with_mysql_in_cluster -m /home/regress/cantian-connector-mysql/scripts/my.cnf -c -Z _SYS_PASSWORD=Huawei@123 -Z SESSIONS=1000 -W 192.168.0.1 -N 0
```
### 部署node1
```Bash  
cd /home/regress/CantianKernel/build
sh Makefile.sh mysql_package_node1
cd /home/regress/CantianKernel/Cantian-DATABASE-CENTOS-64bit
mkdir -p /home/cantiandba/logs
python3 install.py -U cantiandba:cantiandba -R /home/cantiandba/install/ -D /home/cantiandba/data/ -l /home/cantiandba/logs/install.log -Z _LOG_LEVEL=255 -g withoutroot -d -M cantiand_with_mysql_in_cluster -m /home/regress/cantian-connector-mysql/scripts/my.cnf -c -Z _SYS_PASSWORD=Huawei@123 -Z SESSIONS=1000 -W 192.168.0.1 -N 1
```
## 拉起验证

``` Bash  
/usr/local/mysql/bin/mysql -uroot
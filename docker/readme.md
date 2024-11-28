# 容器开发编译部署手册
## 大纲
 - [文档说明](#term)
 - [环境准备](#section1)
 - [双进程编译部署](#section2)
 - [卸载清理](#section3)
 - [单进程编译部署](#section4)
 - [调试](#section5)
 - [定位分析](#section6)
 - [开发自验](#section7)

<a id="term"></a>
## 文档说明及术语解释
此文档只涉及归一模式，非归一部署请参考非归一安装部署文档。
### 归一
又称元数据归一部署，是指通过[patch](#patch)对MySQL源码进行修改,将MySQL的系统表等元数据放置Cantian存储引擎当中
避免因为故障等失败场景导致Cantian引擎和MySQL引擎发生元数据不一致。因为MySQL元数据存放在Cantian引擎，所以通俗地讲，将MySQL元数据归一存放于Cantian引擎。
但Cantian只是存放MySQL的元数据，并不是真正地把两者的元数据归成一份，Cantian有独立的元数据。
### 非归一
又称非元数据归一部署，是指将MySQL部分的元数据存储到InnoDB引擎,因为MySQL存储了一份元数据，Cantian自身又存储了一份元数据，所以又称非归一模式。
### 单进程
Cantian和MySQL在同一个进程中，对外体现只有一个进程mysqld。
### 双进程
Cantian和MySQL位于不同进程，通过共享内存进行消息通信。对外体现有两个进程cantiand和mysqld。
<a id="section1"></a>
## 环境准备

### 目录组织

例：
新建编译目录ctdb_compile，后续操作均在此目录下展开
```
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
git clone https://gitee.com/openeuler/cantian.git
git clone https://gitee.com/openeuler/cantian-connector-mysql.git

#下载mysql-8.0.26源码
wget --no-check-certificate https://github.com/mysql/mysql-server/archive/refs/tags/mysql-8.0.26.tar.gz
tar -zxf mysql-8.0.26.tar.gz
mv mysql-server-mysql-8.0.26 cantian-connector-mysql/mysql-source

mkdir -p cantian_data
```

<a id="start_docker"></a>
### 启动开发编译自验容器
需进入cantian代码目录  
单节点
```shell
sh docker/container.sh dev
sh docker/container.sh enterdev
```
双节点
```shell
# 目前只支持双节点，node_id为0, 1（代表0号节点或1号节点）
sh docker/container.sh startnode [node_id]
sh docker/container.sh enternode [node_id]
```

**container.sh(https://gitee.com/openeuler/cantian/blob/master/docker/container.sh)按`startnode`和`dev`参数启动时会执行代码拷贝的操作，具体操作参考脚本中`sync_mysql_code`函数**

**注：容器外修改代码后需要重新进入容器内方能生效**
```shell
# 单节点：
sh docker/container.sh dev
# 双节点0：
sh docker/container.sh startnode [0]
sh docker/container.sh enternode [0]
# 双节点1：
sh docker/container.sh startnode [1]
sh docker/container.sh enternode [1]
```
**注：如果确实未能更新，可以将容器清掉后[重新创建](#start_docker)，再从[编译拉起](#section2)操作继续执行**
单节点
```shell
sh docker/container.sh stopode
```
双节点：
```shell
//docker stop [CONTAINER_ID]
docker stop cantian_dev-dev
```

<a id="section2"></a>
## 双进程编译部署

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

### Cantian部署
#### 残留文件清理
```shell
kill -9 $(pidof mysqld)
kill -9 $(pidof cantiand)
kill -9 $(pidof cms)
rm -rf /home/regress/cantian_data/* /home/regress/install /home/regress/data /home/cantiandba/install/* /data/data/* /home/cantiandba/data
sed -i '/cantiandba/d' /home/cantiandba/.bashrc
```

#### 单节点Cantian部署
```shell
cd /home/regress/CantianKernel/Cantian-DATABASE-CENTOS-64bit
mkdir -p /home/cantiandba/logs
# -Z SESSIONS=1000方便调试，需运行MTR时需要去掉此参数
python3 install.py -U cantiandba:cantiandba -R /home/cantiandba/install -D /home/cantiandba/data -l /home/cantiandba/logs/install.log -Z _LOG_LEVEL=255 -g withoutroot -d -M cantiand -c -Z _SYS_PASSWORD=Huawei@123 -Z SESSIONS=1000
```
#### 双节点Cantian部署
节点0，在容器内执行以下命令
```shell
# -Z SESSIONS=1000方便调试，需运行MTR时需要去掉此参数
cd /home/regress/CantianKernel/Cantian-DATABASE-CENTOS-64bit
mkdir -p /home/cantiandba/logs
python3 install.py -U cantiandba:cantiandba -R /home/cantiandba/install -D /home/cantiandba/data -l /home/cantiandba/logs/install.log -M cantiand_in_cluster -Z _LOG_LEVEL=255 -N 0 -W 192.168.0.1 -g withoutroot -d -c -Z _SYS_PASSWORD=Huawei@123 -Z SESSIONS=1000
```
节点1，在容器内执行以下命令
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

### MySQL-Connector编译

#### 元数据归一版本（MySQL元数据在cantian存放，修改了MySQL源码，需要应用patch生效）
<a id="patch"></a>
##### 应用patch，修改源码
***如果此前已经应用过，下次编译时，可以跳过这一步***

```shell
cd cantian-connector-mysql/mysql-source
patch --ignore-whitespace -p1 < mysql-scripts-meta.patch
patch --ignore-whitespace -p1 < mysql-test-meta.patch
patch --ignore-whitespace -p1 < mysql-source-code-meta.patch
```

##### 编译MySQL及Connector
```shell
cd /home/regress/CantianKernel/build
# debug
sh Makefile.sh mysql
# release
sh Makefile.sh mysql_release
```

双节点部署时，若使用**脚本部署**，只需在一个节点编译即可  

### MySQL部署
<a id="copy_mysql"></a>
#### 拷贝MySQL二进制
单节点拉起前需分别执行以下命令
```shell
# node0
cd /home/regress/CantianKernel/build
sh Makefile.sh mysql_package_node0
```

双节点拉起前需分别执行以下命令
```shell
# node0
cd /home/regress/CantianKernel/build
sh Makefile.sh mysql_package_node0

# node1
cd /home/regress/CantianKernel/build
sh Makefile.sh mysql_package_node1
```

##### MySQL拉起 & 重拉
使用`install.py`脚本拉起 & 重拉

```shell
cd /home/regress/CantianKernel/Cantian-DATABASE-CENTOS-64bit
mkdir -p /home/regress/logs
python3 install.py -U cantiandba:cantiandba -l /home/cantiandba/logs/install.log -d -M mysqld -m /home/regress/cantian-connector-mysql/scripts/my.cnf
```

#### 拉起检验MySQL
登录MySQL客户端后执行命令
```shell
/usr/local/mysql/bin/mysql -uroot
```


<a id="section3"></a>
## 卸载清理

若需要对Cantian进行重新编译安装部署，或者调试需要重拉，可执行以下命令手动卸载后再重新从[cantian部署](#section2)部分开始执行

```shell
kill -9 $(pidof mysqld)
kill -9 $(pidof cantiand)
kill -9 $(pidof cms)
rm -rf /home/regress/cantian_data/* /home/regress/install /home/regress/data /home/cantiandba/install/* /data/data/* /home/cantiandba/data
sed -i '/cantiandba/d' /home/cantiandba/.bashrc
```
<a id="section4"></a>
## 单进程编译部署
***注：单进程部署过后转双进程建议删除代码重新拉，否则仍会有代码残留导致形态无法切换***  
与双进程(cantiand+mysqld)不同，单进程部署形态只有mysqld进程
### 编译参天

```Bash  
cd /home/regress/CantianKernel/build
export local_build=true 
export MYSQL_BUILD_MODE=single
sh Makefile.sh package CANTIAN_READ_WRITE=1 no_shm=1
```

### 编译MySQL
```Bash  
cd /home/regress/CantianKernel/build
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/regress/cantian-connector-mysql/bld_debug/library_output_directory
### debug
sh Makefile.sh mysql no_shm=1
### release
sh Makefile.sh mysql_release no_shm=1
```

<a id="single_deploy"></a>
### 单进程部署

#### 拷贝MySQL二进制
见章节[拷贝MySQL二进制](#copy_mysql)
#### 安装部署
```Bash  
cd /home/regress/CantianKernel/Cantian-DATABASE-CENTOS-64bit
mkdir -p /home/cantiandba/logs

# -Z SESSIONS=1000方便调试，需运行MTR时需要去掉此参数
# 单节点：
python3 install.py -U cantiandba:cantiandba -R /home/cantiandba/install/ -D /home/cantiandba/data/ -l /home/cantiandba/logs/install.log -Z _LOG_LEVEL=255 -g withoutroot -d -M cantiand_with_mysql -m /home/regress/cantian-connector-mysql/scripts/my.cnf -c -Z _SYS_PASSWORD=Huawei@123 -Z SESSIONS=1000

# 如果是双节点，先拉起节点0，后拉节点1
# 双节点 节点0:
python3 install.py -U cantiandba:cantiandba -R /home/cantiandba/install/ -D /home/cantiandba/data/ -l /home/cantiandba/logs/install.log -Z _LOG_LEVEL=255 -g withoutroot -d -M cantiand_with_mysql_in_cluster -m /home/regress/cantian-connector-mysql/scripts/my.cnf -c -Z _SYS_PASSWORD=Huawei@123 -Z SESSIONS=1000 -W 192.168.0.1 -N 0
# 双节点 节点1:
python3 install.py -U cantiandba:cantiandba -R /home/cantiandba/install/ -D /home/cantiandba/data/ -l /home/cantiandba/logs/install.log -Z _LOG_LEVEL=255 -g withoutroot -d -M cantiand_with_mysql_in_cluster -m /home/regress/cantian-connector-mysql/scripts/my.cnf -c -Z _SYS_PASSWORD=Huawei@123 -Z SESSIONS=1000 -W 192.168.0.1 -N 1 
```
卸载清理命令和[双进程卸载清理](#section3)一致。
<a id="section5"></a>
## 进程调试

### gdb调试
gdb调试cantian前请先设置心跳
``` Bash  
su cantiandba
cms res -edit db -attr HB_TIMEOUT=1000000000
cms res -edit db -attr CHECK_TIMEOUT=1000000000
```

```
进程运行中调试
gdb -p mysqld进程号
使用gdb拉起进程调试,一般用于调试初始化流程
gdb --args [mysql初始化或拉起命令]
特别的，单进程如果需要调试，需要修改Cantian-DATABASE-CENTOS-64bit/installdb.sh
在start_cantiand方法中，Init mysqld data dir下面初始化mysqld命令前，加入sleep脚本，运行install.py拉起mysqld，执行到sleep后，使用下面命令进行初始化
su - cantiandba
gdb --args /usr/local/mysql/bin/mysqld --defaults-file=/home/regress/cantian-connector-mysql/scripts/my.cnf --initialize-insecure --datadir=/data/data --early-plugin-load=ha_ctc.so --core-file
等待mysqld卡住后，执行以下命令进行cantian创库操作
su - cantiandba
/home/cantiandba/install/bin/ctsql / as sysdba -q -D /home/cantiandba/data -f "home/cantiandba/install/admin/scripts/create_database.sample.sql"'

具体可参考documents/Cantian引擎debug单进程安装部署.md
```

如果有进程coredump问题，需要解析内存转储文件分析堆栈
<a id="section6"></a>
## 定位分析
### 配置core_pattern
配置core_pattern后，即可在对应core_pattern目录生成coredump文件
```Bash  
echo "/home/core/core-%e-%p-%t" > /proc/sys/kernel/core_pattern
echo 2 > /proc/sys/fs/suid_dumpable
ulimit -c unlimited
```

### 解析coredump

双进程
```Bash
解cantiand
gdb /home/regress/CantianKernel/output/bin/cantiand /home/core/core文件名
解mysqld
gdb /usr/local/mysql/bin/mysqld /home/core/core文件名
```

单进程
```Bash
解mysqld
gdb /usr/local/mysql/bin/mysqld /home/core/core文件名
```

### 分析日志

```
# mysql日志目录
/data/data/mysql.log
# cantian日志目录
/home/cantiandba/data/log/run/cantiand.rlog
# 打开cantiand debug日志
su - cantiandba
ctsql / as sysdba
show parameter LOG;
alter system set _LOG_LEVEL_MODE=FATAL即可生效
# cantian debug日志目录
/home/cantiandba/data/log/debug/cantiand.dlog
```

<a id="section7"></a>

## 开发自验
MTR可自己拉起MySQL进行初始话，如果已通过脚本拉起过MySQL，可[清理元数据](#mtr_rerun)之后再运行MTR。
### 双进程MTR
``` Bash 
cd /usr/local/mysql/mysql-test
chmod 777 ./mysql-test-run-meta.pl
# 元数据归一MTR自拉起MySQL进程验证
./mysql-test-run-meta.pl --mysqld=--default-storage-engine=CTC --mysqld=--check_proxy_users=ON --do-test-list=enableCases.list --noreorder --nowarnings
```

<a id="mtr_rerun"></a>
### MTR重跑
``` Bash
ctsql / as sysdba
select USERNAME from ADM_USERS where USERNAME not in('SYS','PUBLIC','tmp','LREP');
# 清理回显的这些MySQL系统库和用户库
drop user mysql cascade;
drop user sys cascade;
drop user test cascade;
drop user mtr cascade;
# 此处不尽显示,可能还存在cantian及其它MySQL用户库,需要开发者补充上述命令删除。
```

### 单进程MTR
``` Bash
cd /usr/local/mysql/mysql-test
chmod 777 ./mysql-test-run-meta.pl
# 元数据归一MTR自拉起MySQL进程验证
./mysql-test-run-meta-single.pl --mysqld=--check_proxy_users=ON --noreorder --nowarnings --force --retry=0 --do-test-list=enableCases.list

```

### UT测试
1. 在对应模块添加测试代码
``` Bash
# 对应模块目录
pkg/test/unit_test/ut/...
# 如增加测试文件则需要修改对应模块下的CMakeLists.txt
set(DEMO_SOURCE ${CMAKE_SOURCE_DIR}/pkg/test/unit_test/ut/cms/cms_test_main.cpp
                ${CMAKE_SOURCE_DIR}/pkg/test/unit_test/ut/cms/cms_disk_lock_test.cpp
                ...)
# (注意)项目中包含.c和.cpp的混合编译，注意编写 extern "C" 的合理使用。
```
2. 执行测试脚本[Dev_unit_test.sh](https://gitee.com/openeuler/cantian/blob/master/CI/script/Dev_unit_test.sh)
``` Bash
# 双进程
sh CI/script/Dev_unit_test.sh  
# 单进程
sh CI/script/Dev_unit_test.sh single 
# 如果已经编译过cantian，可以注释掉make_cantian_pkg。
```
3. 查看测试结果
```Bash
CantianKernel/output/bin  # UT二进制bin文件所在目录
CantianKernel/gtest_run.log  # 运行日志
CantianKernel/lcov_output    # 代码覆盖率测试结果(需要安装lcov)
CantianKernel/gtest_result   # 每个UT用例的xml结果
```
# 容器开发单节点单进程编译部署手册

## 大纲
 - [文档说明](#term)
 - [环境准备](#section1)
 - [容器启动](#section2)
 - [编译二进制](#section3)
 - [安装部署](#section4)
 - [卸载清理](#section5)
 - [调试](#section6)
 - [定位分析](#section7)
 - [停止容器](#section8)

<a id="term"></a>
## 文档说明及术语解释
此文档只涉及单进程、单节点归一模式，用于开放原子大赛环境容器化部署说明

<a id="section1"></a>
## 环境准备

### 工作目录

创建工作目录，环境共用，创建你的单独目录区分，后续操作在此目录下展开：
```shell
# your_work_dir为示例目录
mkdir /data/your_work_dir
cd /data/your_work_dir
```

### 准备代码

```shell
#获取代码
git clone -b cantian_openatom_comp https://gitee.com/openeuler/cantian.git
git clone -b cantian_openatom_comp https://gitee.com/openeuler/cantian-connector-mysql.git

#拷贝mysql-8.0.26源码包（/data目录下已提前准备）
cp /data/mysql-8.0.26.tar.gz .
tar -zxf mysql-8.0.26.tar.gz
mv mysql-server-mysql-8.0.26 cantian-connector-mysql/mysql-source

#创建本地数据目录
mkdir -p cantian_data
```

### 屏蔽编译警告
```shell
# 注释maintainer.cmake文件中两行
sed -i '/STRING_APPEND(MY_C_WARNING_FLAGS   " -Werror")/s/^/#/' cantian-connector-mysql/mysql-source/cmake/maintainer.cmake
sed -i '/STRING_APPEND(MY_CXX_WARNING_FLAGS " -Werror")/s/^/#/' cantian-connector-mysql/mysql-source/cmake/maintainer.cmake
```

<a id="section2"></a>
## 启动容器

### 启动开发编译自验容器
需进入cantian代码目录执行，-n docker_mark用于区分不同容器
```shell
cd cantian
sh docker/container.sh dev -n [docker_mark]
```
该命令执行成功后自动会进入容器，执行exit可退出；

### 重新进入容器
退出容器交互界面后可执行以下命令重新进入：
```shell
cd cantian
sh docker/container.sh enterdev -n [docker_mark]
```

<a id="section3"></a>
## 编译二进制
以下操作都在容器内执行：
### 编译Cantian

```shell  
cd /home/regress/CantianKernel/build
# 设置环境变量，单进程
export local_build=true 
export MYSQL_BUILD_MODE=single
# 编译
sh Makefile.sh package CANTIAN_READ_WRITE=1 no_shm=1
```

### 编译MySQL

#### 1、元数据归一版本（MySQL元数据在cantian存放，修改了MySQL源码，需要应用patch生效）
<a id="patch"></a>
***如果此前已经应用过，下次编译时，可以跳过这一步***

```shell
cd /home/regress/cantian-connector-mysql/mysql-source
patch --ignore-whitespace -p1 < mysql-scripts-meta.patch
patch --ignore-whitespace -p1 < mysql-test-meta.patch
patch --ignore-whitespace -p1 < mysql-source-code-meta.patch
```

#### 2、编译单进程MySQL
```shell
cd /home/regress/CantianKernel/build
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/regress/cantian-connector-mysql/bld_debug/library_output_directory
### debug
sh Makefile.sh mysql no_shm=1
```

#### 3、拷贝MySQL二进制
拉起前需执行以下命令
```shell
cd /home/regress/CantianKernel/build
sh Makefile.sh mysql_package_node0
```

<a id="section4"></a>
## 安装部署

### 1、拉起&重拉进程
```shell
cd /home/regress/CantianKernel/Cantian-DATABASE-CENTOS-64bit
mkdir -p /home/cantiandba/logs

# -Z SESSIONS=1000方便调试，需运行MTR时需要去掉此参数
python3 install.py -U cantiandba:cantiandba -R /home/cantiandba/install/ -D /home/cantiandba/data/ -l /home/cantiandba/logs/install.log -Z _LOG_LEVEL=255 -g withoutroot -d -M cantiand_with_mysql -m /home/regress/cantian-connector-mysql/scripts/my.cnf -c -Z _SYS_PASSWORD=Huawei@123 -Z SESSIONS=1000
```

### 2、验证Mysqld状态是否正常
ctsql可直接连接Cantian存储引擎，通过视图等方式，查看数据库状态
```shell
# 切换运行用户
su - cantiandba
# 检查数据库状态
cms stat
ctsql / as sysdba -q -c 'SELECT NAME, STATUS, OPEN_STATUS FROM DV_DATABASE'
```

### 3、拉起检验MySQL
拉起MySQL客户端
```shell
/usr/local/mysql/bin/mysql -uroot
```

<a id="section5"></a>
## 卸载清理

若需要对Cantian进行重新编译安装部署，或者调试需要重拉，可执行以下命令手动卸载后再重新从[编译](#section3)或[安装部署](#section4)部分开始执行
```shell
# 停止运行进程
kill -9 $(pidof mysqld)
kill -9 $(pidof cantiand)
kill -9 $(pidof cms)

# 清理旧数据
rm -rf /home/regress/cantian_data/* /home/regress/install /home/regress/data /home/cantiandba/install/* /data/data/* /home/cantiandba/data
# 清理用户环境变量
sed -i '/cantiandba/d' /home/cantiandba/.bashrc
```

<a id="section6"></a>
## 进程调试

### gdb调试
gdb调试cantian前请先设置心跳
``` Bash  
su cantiandba
cms res -edit db -attr HB_TIMEOUT=1000000000
cms res -edit db -attr CHECK_TIMEOUT=1000000000
```

```
# 进程运行中调试
gdb -p mysqld进程号
# 使用gdb拉起进程调试,一般用于调试初始化流程
gdb --args [mysql初始化或拉起命令]
特别的，单进程如果需要调试，需要修改Cantian-DATABASE-CENTOS-64bit/installdb.sh
在start_cantiand方法中，Init mysqld data dir下面初始化mysqld命令前，加入sleep脚本，运行install.py拉起mysqld，执行到sleep后，使用下面命令进行初始化
su - cantiandba
gdb --args /usr/local/mysql/bin/mysqld --defaults-file=/home/regress/cantian-connector-mysql/scripts/my.cnf --initialize-insecure --datadir=/data/data --early-plugin-load=ha_ctc.so --core-file
等待mysqld卡住后，执行以下命令进行cantian创库操作:
su - cantiandba
/home/cantiandba/install/bin/ctsql / as sysdba -q -D /home/cantiandba/data -f "home/cantiandba/install/admin/scripts/create_database.sample.sql"'
```

<a id="section7"></a>
## 定位分析
如果有进程coredump问题，需要解析内存转储文件分析堆栈

### 配置core_pattern
配置core_pattern后，即可在对应core_pattern目录生成coredump文件
```Bash  
echo "/home/core/core-%e-%p-%t" > /proc/sys/kernel/core_pattern
echo 2 > /proc/sys/fs/suid_dumpable
ulimit -c unlimited
```

### 解析coredump
```shell
# 指定对应二进制文件和core文件
gdb /usr/local/mysql/bin/mysqld /home/core/core文件名
```

### 分析日志

```
# cantian运行日志路径：
/home/cantiandba/data/log/run/cantiand.rlog
# 打开cantiand debug日志
su - cantiandba
ctsql / as sysdba
show parameter LOG;
alter system set _LOG_LEVEL_MODE=FATAL即可生效
# cantian debug日志路径：
/home/cantiandba/data/log/debug/cantiand.dlog
```

<a id="section8"></a>
## 停止容器

```shell
# 查看容器ID
docker ps
# 指定对应ID停止容器运行
docker stop [CONTAINER_ID]
```
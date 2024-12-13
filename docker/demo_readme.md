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
 - [开发辅助信息](#section8)
 - [停止容器](#section9)

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

### 1、首次拉起进程
```shell
cd /home/regress/CantianKernel/Cantian-DATABASE-CENTOS-64bit
mkdir -p /home/cantiandba/logs
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

### 4、进程重拉
进程停止后重新拉起，相比首次拉起，重拉命令新增-r参数
```shell
cd /home/regress/CantianKernel/Cantian-DATABASE-CENTOS-64bit
python3 install.py -U cantiandba:cantiandba -R /home/cantiandba/install/ -D /home/cantiandba/data/ -l /home/cantiandba/logs/install.log -Z _LOG_LEVEL=255 -g withoutroot -d -M cantiand_with_mysql -m /home/regress/cantian-connector-mysql/scripts/my.cnf -c -r -Z _SYS_PASSWORD=Huawei@123 -Z SESSIONS=1000
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
## 开发辅助

### 函数信息

（1）Cantian初始化函数：srv_instance_start
（2）MySQL自己创建的临时表表名都是以"#sql-"开头的
（3）创建一个新的session出来：ctc_get_new_session
（4）Cantian的histgram生成的起始函数：ctc_analyze_table (不是cantian-connector-mysql仓的同名函数)
（5）线程创建的函数(cm_therad.h): cm_create_thread
（6）copy算法的接口代码：
```
ha_ctc::check_if_supported_inplace_alter (this=0x7f38345824c8, altered_table=0x7f3834530b10, ha_alter_info=0x7f32e41b85f0)
ha_ctc::create (this=0x7f383456f788, name=0x7f32e41ba0f4 "./mydb/#sql-14799_8", form=0x7f32e41b7b50, create_info=0x7f32e41bb300, table_def=0x7f38348c91e8)
copy_data_between_tables (thd=0x7f3834014410, psi=0x0, from=0x7f383458cc20, to=0x7f3834530b10, create=..., copied=0x7f32e41b9358, deleted=0x7f32e41b9350, keys_onoff=Alter_info::LEAVE_AS_IS, alter_ctx=0x7f32e41b94d0)
while {
        ha_ctc::rnd_next (this=0x7f38345824c8, buf=0x7f3834596b88 "\377") at /home/regress/cantian-connector-mysql/mysql-source/storage/ctc/ha_ctc.cc:3287  
                        this->table.alias = 0x7f38345e6150 "sales"
        ha_ctc::write_row
                        this->table.alias = 0x7f3834563500 "#sql-14799_8"
}
ha_ctc::rename_table (this=0x7f38348a7688, from=0x7f32e41b80f0 "./mydb/sales", to=0x7f32e41b7ee0 "./mydb/#sql2-14799-8", from_table_def=0x7f38348c8df8, to_table_def=0x7f38348c44a8) at /home/regress/cantian-connector-mysql/mysql-source/storage/ctc/ha_ctc.cc:5489
ha_ctc::write_row  this->table.alias = 0x7f383456ef50 "tables"
ha_ctc::write_row  this->table.alias = 0x7f383403e6e0 "columns"
ha_ctc::write_row  this->table.alias = 0x7f383403e6e0 "columns"
ha_ctc::write_row  this->table.alias = 0x7f383403e6e0 "columns"
ha_ctc::write_row  this->table.alias = 0x7f383403e6e0 "columns"
ha_ctc::rename_table (this=0x7f38348a9178, from=0x7f32e41b80f0 "./mydb/#sql-14799_8", to=0x7f32e41b7ee0 "./mydb/sales", from_table_def=0x7f38345465e8, to_table_def=0x7f38348c91e8) at /home/regress/cantian-connector-mysql/mysql-source/storage/ctc/ha_ctc.cc:5489
ha_ctc::delete_table (this=0x7f38344465f8, full_path_name=0x7f32e41b8230 "./mydb/#sql2-14799-8", table_def=0x7f38348c44a8) at /home/regress/cantian-connector-mysql/mysql-source/storage/ctc/ha_ctc.cc:5138
```

### 操作过程说明

1、参照docker文档启动MySQL；
2、使用mysql client连接mysql:
```
/usr/local/mysql/bin/mysql -uroot
```
3、调用cantian_defs.sql脚本创建视图；
cantian_defs.sql脚本位于cantian代码仓的pkg/admin/scripts/目录下。例如：
```
mysql> source /home/regress/CantianKernel/pkg/admin/scripts/cantian_defs.sql
Query OK, 0 rows affected, 1 warning (0.00 sec)

Query OK, 0 rows affected, 1 warning (0.01 sec)

Query OK, 0 rows affected, 1 warning (0.00 sec)
... ...
```
4、创建完视图之后，退出MySQL客户端，重新进入MySQL客户端【重要】：
```
mysql> exit
Bye
[root@cantian regress]# /usr/local/mysql/bin/mysql -uroot
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 9
Server version: 8.0.26-debug Source distribution

Copyright (c) 2000, 2021, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> 

```

5、执行命令创建database
```
mysql> create database mydb;
Query OK, 1 row affected (0.15 sec)

mysql> use mydb;
Database changed
```

6、创建demo table；
```
CREATE TABLE sales (
        id INT PRIMARY KEY,
        age INT NOT NULL,
        height INT NOT NULL,
        perf INT NOT NULL,
        pay INT NOT NULL,
        KEY index_age (age) USING BTREE,
        KEY index_height (height) USING BTREE,
        KEY index_perf (perf) USING BTREE,
        KEY index_pay (pay) USING BTREE
);
```
创建完成之后，进行查看：
```
mysql> show tables;
+----------------+
| Tables_in_mydb |
+----------------+
| sales          |
+----------------+
1 row in set (0.01 sec)
```

7、使用脚本预置10K条数据进去；
将如下内容拷贝到一个新的脚本文件中，命名为insertSales.sql，存放在/home目录：
```
DELIMITER $$

CREATE PROCEDURE InsertSales(IN num INT)
BEGIN
  DECLARE i INT DEFAULT 0;
  DECLARE s_age INT DEFAULT 0;
  DECLARE s_height INT DEFAULT 0;
  DECLARE s_perf INT DEFAULT 0;
  DECLARE s_pay INT DEFAULT 0;

  WHILE i < num DO
        SET s_age = ROUND(18+RAND() * 40);
        SET s_height = ROUND(140+RAND() * 50);
        SET s_perf = ROUND(60+RAND() * 40);
        SET s_pay = ROUND(2000+RAND() * 10000);
    INSERT INTO sales (id, age, height, perf, pay) VALUES (
      i,
          s_age,
          s_height,
          s_perf,
          s_pay
    );
    SET i = i + 1;
  END WHILE;
END$$

DELIMITER ;
```
在SQL client中导入该脚本，并调用脚本中的函数插入数据：
```
mysql> source /home/insertSales.sql
Query OK, 0 rows affected (0.01 sec)

mysql> CALL InsertSales(10000);
Query OK, 1 row affected (23.23 sec)
```
8、创建HISTOGRAM：
```
ANALYZE TABLE sales UPDATE HISTOGRAM ON age, height, perf, pay WITH 128 BUCKETS;
```
7、执行查询，查看直方图信息：
```
mysql> select * from cantian.cantian_histgram_abstr where user_name='mydb';
+-------+-----------+------+------------+------+------------+---------+----------+---------------------+----------+----------+----------+------------------------+--------+--------+---------------------+--------+
| USER# | USER_NAME | TAB# | TABLE_NAME | COL# | BUCKET_NUM | ROW_NUM | NULL_NUM | ANALYZE_TIME        | MINVALUE | MAXVALUE | DIST_NUM | DENSITY                | SPARE1 | SPARE2 | SPARE3              | SPARE4 |
+-------+-----------+------+------------+------+------------+---------+----------+---------------------+----------+----------+----------+------------------------+--------+--------+---------------------+--------+
|     7 | mydb      |    1 | sales      |    0 |        254 |   10000 |        0 | 2024-12-12 14:22:08 | 0        | 9999     |    10000 |                 0.0001 |   NULL |   NULL |         17179879184 |   NULL |
|     7 | mydb      |    1 | sales      |    1 |         41 |   10000 |        0 | 2024-12-12 14:22:08 | 18       | 58       |       41 |   0.024390243902439025 |   NULL |   NULL | 4615908452315703056 |   NULL |
|     7 | mydb      |    1 | sales      |    2 |         51 |   10000 |        0 | 2024-12-12 14:22:08 | 140      | 190      |       51 |     0.0196078431372549 |   NULL |   NULL | 4615908435135833872 |   NULL |
|     7 | mydb      |    1 | sales      |    3 |         41 |   10000 |        0 | 2024-12-12 14:22:08 | 60       | 100      |       41 |   0.024390243902439025 |   NULL |   NULL | 4615908469495572240 |   NULL |
|     7 | mydb      |    1 | sales      |    4 |        254 |   10000 |        0 | 2024-12-12 14:22:08 | 2000     | 11998    |     6235 | 0.00016038492381716118 |   NULL |   NULL | 4615908452315703056 |   NULL |
+-------+-----------+------+------------+------+------------+---------+----------+---------------------+----------+----------+----------+------------------------+--------+--------+---------------------+--------+
5 rows in set (0.00 sec)

```
8、执行alter table，是直方图信息失效：
```
mysql> SET sql_mode='NO_ENGINE_SUBSTITUTION';
Query OK, 0 rows affected (0.00 sec)

mysql> ALTER TABLE sales ADD COLUMN salary INT;
Query OK, 0 rows affected (0.24 sec)
Records: 0  Duplicates: 0  Warnings: 0

mysql> ALTER TABLE sales DROP COLUMN salary;
Query OK, 10000 rows affected (1.73 sec)
Records: 10000  Duplicates: 0  Warnings: 0

mysql> select * from cantian.cantian_histgram_abstr where user_name='mydb';
Empty set (0.00 sec)

mysql> SET sql_mode=default;
Query OK, 0 rows affected (0.00 sec)
```

### 其他命令说明：
```
# 查询DB：
show databases;
# 删除DB:
drop database db_name;
# 查询Table:
show tables;
# 删除table: 
drop database table_name;
# 查询数据:
select * from sales;
# 删除histgram: 
ANALYZE TABLE tbl_name DROP HISTOGRAM ON col_name [, col_name];
```

<a id="section9"></a>
## 停止容器

```shell
# 查看容器ID
docker ps
# 指定对应ID停止容器运行
docker stop [CONTAINER_ID]
```
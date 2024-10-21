# 环境准备<a name="ZH-CN_TOPIC_0000001992154717"></a>




## 在云主机下载最新docker镜像<a name="ZH-CN_TOPIC_0000001992201189"></a>

-   对于X86服务器，请执行以下命令下载docker镜像。

    ```
    docker pull ykfnxx/cantian_dev:0.1.0
    docker tag ykfnxx/cantian_dev:0.1.0 cantian_dev:latest
    ```

-   对于ARM服务器，请执行以下命令下载docker镜像。

    ```
    docker pull ykfnxx/cantian_dev:0.1.1
    docker tag ykfnxx/cantian_dev:0.1.1 cantian_dev:latest
    ```

其中，“ykfnxx/cantian\_dev:0.1.0”和“ykfnxx/cantian\_dev:0.1.1”分别为当前上传的docker镜像名称。

## 在云主机下载Cantian引擎源码<a name="ZH-CN_TOPIC_0000001992201193"></a>

1.  <a name="li176239159138"></a>执行以下命令，在云主机上创建任一目录，并进入该目录。

    ```
    mkdir path
    cd path
    ```

    其中，“path”为创建的目录名称。以创建的目录为“Project”为例：

    ```
    mkdir /Project
    cd /Project
    ```

2.  执行以下命令，下载Cantian引擎源码。

    ```
    git clone git@gitee.com:openeuler/cantian.git
    ```

    执行后，在[1](#li176239159138)中创建的目录下，将会新生成用于存放Cantian引擎源码、名称为“cantian”的子目录。

3.  <a name="li33726194151"></a>执行以下命令，下载Cantian-Connector-MySQL源码，用于编译Cantian引擎对接MySQL的插件。

    ```
    git clone git@gitee.com:openeuler/cantian-connector-mysql.git
    ```

    执行后，在[1](#li176239159138)中创建的目录下，将会新生成用于存放Cantian-Connector-MySQL源码、名称为“cantian-connector-mysql”的子目录。

4.  下载MySQL-8.0.26版本源码，用于编译Cantian引擎对接MySQL的插件，并将MySQL-8.0.26版本源码拷贝到“cantian-connector-mysql/mysql-source”目录下。
    1.  在[3](#li33726194151)中生成的“cantian-connector-mysql”目录下，新创建一个名称为“mysql-source”的子目录。
    2.  执行以下命令，下载MySQL-8.0.26版本源码，并将该源码拷贝到“cantian-connector-mysql/mysql-source”目录下。

        ```
        wget --no-check-certificate https://github.com/mysql/mysql-server/archive/refs/tags/mysql-8.0.26.tar.gz 
        tar -zxf mysql-8.0.26.tar.gz 
        mv mysql-server-mysql-8.0.26 /Project/cantian-connector-mysql/mysql-source
        ```

5.  执行以下命令，创建与“cantian”和“cantian-connector-mysql”同级的目录“cantian\_data”。

    ```
    mkdir cantian_data
    ```

## 在云主机上创建并启动容器<a name="ZH-CN_TOPIC_0000001955721890"></a>

在云主机上，您可以选择只创建并启动一个容器，也可以选择同时创建并启动两个容器。

1.  执行以下命令，进入[2](在云主机下载Cantian引擎源码.md#li737213192158)中生成的Cantian引擎源码的目录。

    ```
    cd /Project/cantian
    ```

2.  创建并启动容器。

    -   创建并启动单个容器的场景。

        ```
        sh docker/container.sh dev
        ```

    -   创建并启动两个容器的场景。

        ```
        sh docker/container.sh startnode 0 
        exit
        sh docker/container.sh startnode 1 
        ```

    >![](public_sys-resources/icon-note.gif) **说明：** 
    >-   脚本[container.sh](https://gitee.com/openeuler/cantian/blob/master/docker/container.sh)中，只创建一个容器的场景，配置的该容器的id为“dev”；创建两个容器的场景，配置的两个容器的id分别为“node 0”和“node 1”。
    >-   [container.sh](https://gitee.com/openeuler/cantian/blob/master/docker/container.sh)按“dev”参数、“node 0”和“node 1”参数启动时，会执行代码拷贝的操作，具体操作参考脚本中的sync\_mysql\_code函数。
    >-   启动容器后，系统会自动进入容器界面。对于启动两个容器的场景，启动第一个容器后，系统会自动进入第一个容器，请执行“exit”退出容器界面后，再在云主机中执行命令启动第二个容器。

# 在容器内部署Cantian引擎<a name="ZH-CN_TOPIC_0000001992161001"></a>




## 编译Cantian引擎软件包<a name="ZH-CN_TOPIC_0000001992201197"></a>

要编译Cantian引擎软件包，需要先进入容器。对于部署了两个容器的场景，在任意一个容器内进行编译即可。

1.  执行以下命令，进入容器。

    ```
    sh docker/container.sh enternode_id 
    ```

    其中，“node\_id”为[在云主机上创建并启动容器](在云主机上创建并启动容器.md)中脚本[container.sh](https://gitee.com/openeuler/cantian/blob/master/docker/container.sh)里配置的容器id：

    -   单个容器的场景

        ```
        docker/container.sh enterdev
        ```

    -   两个容器的场景

        ```
        docker/container.sh enternode 0
        ```

        或者

        ```
        docker/container.sh enternode 1
        ```

2.  执行以下命令，编译生成Cantian引擎“debug”或“release”软件包。
    -   生成“debug”软件包：

        ```
        cd /home/regress/CantianKernel/build
        export local_build=true
        sh Makefile.sh package
        ```

    -   生成“release”软件包：

        ```
        cd /home/regress/CantianKernel/build 
        export local_build=true
        sh Makefile.sh package-release
        ```

## 部署Cantian引擎<a name="ZH-CN_TOPIC_0000001955721894"></a>

在容器里部署Cantian引擎前，请先参考[编译Cantian引擎软件包](编译Cantian引擎软件包.md)的[1](编译Cantian引擎软件包.md#li4228181833719)依次进入各个容器，并在各个容器内执行以下命令配置“core\_pattern”。

```
echo "/home/core/core-%e-%p-%t" > /proc/sys/kernel/core_pattern 
echo 2 > /proc/sys/fs/suid_dumpable 
ulimit -c unlimited
```




### 单个容器场景部署Cantian引擎<a name="ZH-CN_TOPIC_0000001992161005"></a>

在容器内执行以下命令，部署Cantian引擎。

-   共享系统表场景：

    ```
    cd /home/regress/CantianKernel/Cantian-DATABASE-CENTOS-64bit 
    mkdir -p /home/cantiandba/logs 
    python3 install.py -U cantiandba:cantiandba -R /home/cantiandba/install -D /home/cantiandba/data -l /home/cantiandba/logs/install.log -Z _LOG_LEVEL=Level -g withoutroot -d -M cantiand -c -Z _SYS_PASSWORD=Password -Z SESSIONS=Session
    ```

-   独立系统表场景：

    ```
    cd /home/regress/CantianKernel/Cantian-DATABASE-CENTOS-64bit 
    mkdir -p /home/cantiandba/logs 
    python3 install.py -U cantiandba:cantiandba -R /home/cantiandba/install -D /home/cantiandba/data -l /home/cantiandba/logs/install.log -Z _LOG_LEVEL=Level -g withoutroot -d -M cantiand -c -Z _SYS_PASSWORD=Password -Z SESSIONS=Session -Z MYSQL_METADATA_IN_CANTIAN=FALSE
    ```

参数说明：

-   Level：设置可以查看的日志级别，数字越大，可以查看的日志类型越多。范围为0\~255。
-   Password：数据库系统管理员sys用户的密码。
-   Session：Cantian引擎支持的会话数。

例如：

```
cd /home/regress/CantianKernel/Cantian-DATABASE-CENTOS-64bit 
mkdir -p /home/cantiandba/logs 
python3 install.py -U cantiandba:cantiandba -R /home/cantiandba/install -D /home/cantiandba/data -l /home/cantiandba/logs/install.log -Z _LOG_LEVEL=255 -g withoutroot -d -M cantiand -c -Z _SYS_PASSWORD=Test@1234 -Z SESSIONS=1000
```

### 双容器场景部署Cantian引擎<a name="ZH-CN_TOPIC_0000001992201201"></a>

请在两个容器内，分别执行以下命令部署Cantian引擎。

-   共享系统表场景：

    ```
    cd /home/regress/CantianKernel/Cantian-DATABASE-CENTOS-64bit
    mkdir -p /home/cantiandba/logs
    python3 install.py -U cantiandba:cantiandba -R /home/cantiandba/install -D /home/cantiandba/data -l /home/cantiandba/logs/install.log -M cantiand_in_cluster -Z _LOG_LEVEL=Level -N id -W 192.168.0.1 -g withoutroot -d -c -Z _SYS_PASSWORD=password  -Z SESSIONS=Session
    ```

-   独立系统表场景：

    ```
    cd /home/regress/CantianKernel/Cantian-DATABASE-CENTOS-64bit
    mkdir -p /home/cantiandba/logs
    python3 install.py -U cantiandba:cantiandba -R /home/cantiandba/install -D /home/cantiandba/data -l /home/cantiandba/logs/install.log -M cantiand_in_cluster -Z _LOG_LEVEL=Level -N id -W 192.168.0.1 -g withoutroot -d -c -Z _SYS_PASSWORD=password  -Z SESSIONS=Session -Z MYSQL_METADATA_IN_CANTIAN=FALSE
    ```

参数说明：

-   Level：设置可以查看的日志级别，数字越大，可以查看的日志类型越多。范围为0\~255。
-   id：容器编号。[在云主机上创建并启动容器](在云主机上创建并启动容器.md)中“node 0”的id为“0”、“node 1”的id为“1”。
-   Password：数据库系统管理员sys用户的密码。
-   Session：Cantian引擎支持的会话数。范围为0\~255。

>![](public_sys-resources/icon-notice.gif) **须知：** 
>对于参数“Level”、“password”和“Session”，在两个容器内设置的值应保持一致。

例如：

-   进入第一个容器后，执行以下命令：

    ```
    cd /home/regress/CantianKernel/Cantian-DATABASE-CENTOS-64bit
    mkdir -p /home/cantiandba/logs
    python3 install.py -U cantiandba:cantiandba -R /home/cantiandba/install -D /home/cantiandba/data -l /home/cantiandba/logs/install.log -M cantiand_in_cluster -Z _LOG_LEVEL=255 -N 0 -W 192.168.0.1 -g withoutroot -d -c -Z _SYS_PASSWORD=Test@1234 -Z SESSIONS=1000
    ```

-   进入第二个容器后，执行以下命令：

    ```
    cd /home/regress/CantianKernel/Cantian-DATABASE-CENTOS-64bit
    mkdir -p /home/cantiandba/logs
    python3 install.py -U cantiandba:cantiandba -R /home/cantiandba/install -D /home/cantiandba/data -l /home/cantiandba/logs/install.log -M cantiand_in_cluster -Z _LOG_LEVEL=255 -N 1 -W 192.168.0.1 -g withoutroot -d -c -Z _SYS_PASSWORD=Test@1234 -Z SESSIONS=1000
    ```

### 检查Cantian引擎状态是否正常<a name="ZH-CN_TOPIC_0000001955721898"></a>

在各个部署了Cantian引擎的容器内，检查各个容器部署的Cantian引擎状态是否正常。

1.  执行以下命令，切换为cantian用户后。

    ```
    su -s /bin/bash - cantian
    ```

2.  依次执行以下命令，查看Cantian引擎的集群状态是否正常。

    ```
    cms stat
    ```

    回显中，若集群里两台数据库服务器的“STAT”值为“ONLINE”、“WORK\_STAT”值为“1”、“ROLE”值为“REFORMER”，表示集群状态正常。例如：

    ```
    [root@host ~]# su -s /bin/bash - cantian 
    [cantian@host ~]$ cms stat
    NODE_ID  NAME      STAT    PRE_STAT    TARGET_STAT   WORK_STAT   SESSION_ID   INSTANCE_ID   ROLE     LAST_CHECK              HB_TIME                 STAT_CHANGE
          0  db        ONLINE  UNKNOWN     ONLINE                1            0             0   REFORMER 2024-02-06 02:42:32.753 2024-02-06 02:42:32.753 2024-02-05 05:44:30.578
          1  db        ONLINE  OFFLINE     ONLINE                1            0             1   REFORMER 2024-02-06 02:42:34.599 2024-02-06 02:42:34.599 2024-02-05 05:47:06.742
    ```

## 卸载Cantian引擎<a name="ZH-CN_TOPIC_0000001992161009"></a>

1.  在Cantian引擎的容器内，执行以下命令，卸载Cantian引擎。

    ```
    cd /home/cantiandba/install/bin 
    python3 uninstall.py -U cantiandba -F -D /home/cantiandba/data -g withoutroot -d
    ```

2.  若卸载失败，请使用root用户，执行以下命令 手工删除各个目录。

    ```
    kill -9 $(pidof mysqld)
    kill -9 $(pidof cantiand)
    kill -9 $(pidof cms)
    rm -rf /home/regress/cantian_data/* /home/regress/install /home/regress/data /home/cantiandba/install/* /data/data/* /home/cantiandba/data sed -i '/cantiandba/d' /home/cantiandba/.bashrc
    ```

# MySQL编译部署<a name="ZH-CN_TOPIC_0000001992201205"></a>




## MySQL编译<a name="ZH-CN_TOPIC_0000001955721902"></a>



### 共享系统表场景<a name="ZH-CN_TOPIC_0000001992161013"></a>

1.  在云主机上执行以下命令，其中，“cantian-connector-mysql/mysql-source”为[在云主机下载Cantian引擎源码](在云主机下载Cantian引擎源码.md)中创建的目录。

    ```
    cd cantian-connector-mysql/mysql-source 
    patch --ignore-whitespace -p1 < mysql-scripts-meta.patch 
    patch --ignore-whitespace -p1 < mysql-test-meta.patch 
    patch --ignore-whitespace -p1 < mysql-source-code-meta.patch
    ```

2.  进入各个容器，执行以下命令，进行MySQL编译。
    -   对于只部署了一个容器的场景：

        ```
        cd /home/regress/CantianKernel/build
        sh Makefile.sh mysql 
        export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/regress/cantian-connector-mysql/bld_debug/library_output_directory 
        rm -rf /home/regress/mydata/*
        ```

    -   对于部署了两个容器的场景：

        >![](public_sys-resources/icon-note.gif) **说明：** 
        >若后续规划使用手动方式部署MySQL，请依次执行步骤[2.a](#li12334046171411)到[2.c](#li123651343181511)；若规划使用脚本方式部署MySQL，只执行[2.a](#li12334046171411)即可。

        1.  <a name="li12334046171411"></a>进入第一个容器（node 0）后，执行以下命令：

            ```
            cd /home/regress/CantianKernel/build
            sh Makefile.sh mysql 
            export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/regress/cantian-connector-mysql/bld_debug/library_output_directory 
            rm -rf /home/regress/mydata/*
            ```

        2.  进入第二个容器（node 1）后，执行以下命令：

            ```
            mkdir /home/regress/cantian-connector-mysql/mysql-source/include/protobuf-c 
            cp /home/regress/CantianKernel/library/protobuf/protobuf-c/protobuf-c.h /home/regress/cantian-connector-mysql/mysql-source/include/protobuf-c
            ```

        3.  <a name="li123651343181511"></a>继续在第二个容器（node 1）内，执行以下命令：

            ```
            cd /home/regress/CantianKernel/build
            sh Makefile.sh mysql 
            export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/regress/cantian-connector-mysql/bld_debug/library_output_directory 
            rm -rf /home/regress/mydata/*
            ```

### 独立系统表场景<a name="ZH-CN_TOPIC_0000001992201209"></a>

进入云主机上部署的容器，执行以下命令编译MySQL。

>![](public_sys-resources/icon-note.gif) **说明：** 
>对于部署了两个容器的场景，只需要在“node 0”的容器内执行该命令即可。

```
cd /home/regress/CantianKernel/build 
sh Makefile.sh mysql 
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/regress/cantian-connector-mysql/bld_debug/library_output_directory
```

## MySQL部署<a name="ZH-CN_TOPIC_0000001955721906"></a>



### 手动方式部署MySQL<a name="ZH-CN_TOPIC_0000001992161017"></a>

只有共享系统表场景支持通过手动方式部署MySQL。

>![](public_sys-resources/icon-note.gif) **说明：** 
>此处以部署了两个容器的场景为例进行说明。若只部署了一个容器，只需在容器内执行[1](#li12953845131913)和[2](#li145121162712)的命令即可。

1.  <a name="li12953845131913"></a>进入第一个容器（node 0），执行以下命令，初始化MySQL。

    >![](public_sys-resources/icon-notice.gif) **须知：** 
    >执行前，请确保目录“/home/regress/mydata”内容为空。

    ```
    rm -rf /home/regress/mydata/*
    /usr/local/mysql/bin/mysqld --defaults-file=/home/regress/cantian-connector-mysql/scripts/my.cnf --initialize-insecure --datadir=/home/regress/mydata --early-plugin-load="ha_ctc.so" --core-file
    ```

2.  <a name="li145121162712"></a>执行以下命令，在第一个容器（node 0）上部署MySQL。

    ```
    mkdir -p /data/data 
    /usr/local/mysql/bin/mysqld --defaults-file=/home/regress/cantian-connector-mysql/scripts/my.cnf  --datadir=/home/regress/mydata --user=root --early-plugin-load="ha_ctc.so" --core-file >> /data/data/mysql.log 2>&1 &
    ```

3.  第进入第二个容器（node 1），执行以下命令，清理对应文件的内容。

    ```
    rm -rf /home/regress/mydata/*
    mkdir -p /home/regress/mydata/ 
    mkdir -p /home/regress/mydata/mysql
    ```

4.  执行以下命令，在第二个容器（node 1）上部署MySQL。

    ```
    mkdir -p /data/data 
    /usr/local/mysql/bin/mysqld --defaults-file=/home/regress/cantian-connector-mysql/scripts/my.cnf  --datadir=/home/regress/mydata --user=root --early-plugin-load="ha_ctc.so" --core-file >> /data/data/mysql.log 2>&1 &
    ```

### 脚本方式部署MySQL<a name="ZH-CN_TOPIC_0000001992201213"></a>

共享系统表和独立系统表场景均支持通过脚本方式部署MySQL。

>![](public_sys-resources/icon-note.gif) **说明：** 
>此处以部署了两个容器的场景为例进行说明。若只部署了一个容器，只需在容器内执行[1](#li12953845131913)和[2](#li16594181912113)的命令即可。

1.  <a name="li12953845131913"></a>进入第一个容器（node 0），执行以下命令，初始化MySQL。

    ```
    cd /home/regress/CantianKernel/build 
    sh Makefile.sh mysql_package_node0  
    ```

2.  <a name="li16594181912113"></a>执行以下命令，使用“install.py”部署MySQL。

    ```
    cd /home/regress/CantianKernel/Cantian-DATABASE-CENTOS-64bit 
    mkdir -p /home/regress/logs 
    python3 install.py -U cantiandba:cantiandba -l /home/cantiandba/logs/install.log -d -M mysqld -m /home/regress/cantian-connector-mysql/scripts/my.cnf
    ```

3.  进入第二个容器（node 1），执行以下命令，初始化MySQL。

    ```
    cd /home/regress/CantianKernel/build 
    sh Makefile.sh mysql_package_node1  
    ```

4.  执行以下命令，使用“install.py”部署MySQL。

    ```
    cd /home/regress/CantianKernel/Cantian-DATABASE-CENTOS-64bit 
    mkdir -p /home/regress/logs 
    python3 install.py -U cantiandba:cantiandba -l /home/cantiandba/logs/install.log -d -M mysqld -m /home/regress/cantian-connector-mysql/scripts/my.cnf
    ```

## MySQL部署后验证<a name="ZH-CN_TOPIC_0000001955721910"></a>

在各个容器内执行以下命令，检查MySQL是否部署成功

```
/usr/local/mysql/bin/mysql -uroot
```

执行样例如下：

```
[root@host ~]# /usr/local/mysql/bin/mysql -uroot
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 20
Server version: 8.0.26-debug Source distribution
Copyright (c) 2000, 2021, Oracle and/or its affiliates.
Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql>
```

# 日志和gdb调试<a name="ZH-CN_TOPIC_0000001992161021"></a>

Cantian引擎日志位置：

```
/home/cantiandba/data/log/run/cantiand.rlog
```

MySQL日志位置：

```
/data/data/mysql.log
```

对于在云主机上部署了两个容器的场景，如果要执行“gdb attach  _进程名_”的命令，请在要执行“gdb attach  _进程名_”的容器内，先执行以下命令同步心跳操作：

```
su cantiandba 
cms res -edit db -attr HB_TIMEOUT=1000000000 
cms res -edit db -attr CHECK_TIMEOUT=1000000000
```


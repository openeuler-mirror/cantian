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

```shell
sh docker/container.sh dev
sh docker/container.sh enterdev
```

## 编译部署

### cantian编包

以下命令在容器内使用
```shell
cd /home/regress/CantianKernel/build
export local_build=true
# 若此前编译过第三方依赖，可以再加上--no-deps参数，跳过第三方依赖的编译
# debug
sh Makefile.sh package
# release
sh Makefile.sh package-release
```

### cantian部署

```shell
cd /home/regress/CantianKernel/Cantian-DATABASE-CENTOS-64bit
mkdir -p /home/cantiandba/logs
# -Z SESSIONS=1000方便调试，需运行MTR时建议去掉此参数
# 如果需要部署非元数据归一版本，则需要加参数-Z MYSQL_METADATA_IN_CANTIAN=FALSE
python3 install.py -U cantiandba:cantiandba -R /home/cantiandba/install -D /home/cantiandba/data -l /home/cantiandba/logs/install.log -Z _LOG_LEVEL=255 -g withoutroot -d -M cantiand -c -Z _SYS_PASSWORD=Huawei@123 -Z SESSIONS=1000
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
元数据归一需要应用patch
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

#### 非归一

```shell
cd /home/regress/CantianKernel/build
sh Makefile.sh mysql
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/regress/cantian-connector-mysql/bld_debug/library_output_directory

cd /home/regress/CantianKernel/build
sh Makefile.sh mysql_package_node0
```

### mysql部署

#### 元数据归一
初始化：
```shell
/usr/local/mysql/bin/mysqld --defaults-file=/home/regress/cantian-connector-mysql/scripts/my.cnf --initialize-insecure --datadir=/home/regress/mydata --early-plugin-load="ha_ctc.so" --core-file
```

部署：
```shell
/usr/local/mysql/bin/mysqld --defaults-file=/home/regress/cantian-connector-mysql/scripts/my.cnf  --datadir=/home/regress/mydata --user=root --early-plugin-load="ha_ctc.so" --core-file
```

#### 非归一

```shell
cd /home/regress/CantianKernel/Cantian-DATABASE-CENTOS-64bit
mkdir -p /home/regress/logs
python3 install.py -U cantiandba:cantiandba -l /home/cantiandba/logs/install.log -d -M mysqld -m /home/regress/cantian-connector-mysql/scripts/my.cnf
```
#### 拉起检验

```shell
/usr/local/mysql/bin/mysql -uroot
```


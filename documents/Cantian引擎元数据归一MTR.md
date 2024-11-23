[1 MTR介绍](#section1)
[2 MTR 双进程](#section2)
[3 MTR 单进程](#section3)
[4 拉起MySQL后跑MTR](#section4)

## 1 MTR介绍<a id="section1"></a>
参天目前支持的MTR形态：双进程/单进程 + 归一/非归一
本文档中仅包含双进程/单进程 + 归一的执行流程。

## 2 MTR 双进程<a id="section2"></a>
### 2.1 环境准备
1. 编译部署拉起cantiand（参考 [双进程编译部署](https://gitee.com/openeuler/cantian/blob/master/docker/readme.md#section2))
2. 仅编译MySQL，但暂时不拉mysqld（交给MTR）

### 2.2 跑MTR <a id="section2.2"></a>
```bash
cd /usr/local/mysql/mysql-test/
chmod 777 ./mysql-test-run-meta.pl 
./mysql-test-run-meta.pl --mysqld=--default-storage-engine=CTC --mysqld=--check_proxy_users=ON --do-test-list=enableCases.list --noreorder --nowarnings
```

### 2.3 清理MySQL元数据（及执行MTR用例过程中未手动清理的数据）<a id="section2.3"></a>
```bash
# 登录ctsql
su - cantiandba
ctsql / as sysdba -q

# 查看需要清理的库：除 SYS, PUBLIC, LREP, tmp, cantian 外都需要清理
select * from ADM_USERS;

# 删MySQL库（同时级联删除其中的表）
drop user performance_schema cascade;
drop user mysql cascade;
drop user sys cascade;
drop user mtr cascade;
drop user test cascade;
drop user sys_audit cascade; # MySQL8.0.32版本
drop user sys_mac cascade; # MySQL8.0.32版本
drop user gdb_sys_mac cascade; # MySQL8.0.32版本

# 退出 cantiandba
exit
```

### 2.4 下一个用例

重复：
- [2.2 跑MTR](#section2.2) 
- [2.3 清理MySQL元数据](#section2.3) 


## 3 MTR 单进程<a id="section3"></a>
### 3.1 环境准备

1. 拉起单进程MySQL（参考 [单进程编译部署](https://gitee.com/openeuler/cantian/blob/master/docker/readme.md#%E5%8D%95%E8%BF%9B%E7%A8%8B%E7%BC%96%E8%AF%91%E9%83%A8%E7%BD%B2))
2. 清理MySQL元数据（参考 [2.3 清理MySQL元数据](#section2.3)）

### 3.2 跑MTR（在cantiandba用户下）<a id="section3.2"></a>
```bash
# 杀掉进程
kill -9 $(pidof mysqld); kill -9 $(pidof cantiand)

# 设置环境变量
su - cantiandba
cd /usr/local/mysql/mysql-test
export RUN_MODE=cantiand_with_mysql
export LD_LIBRARY_PATH=/usr/local/mysql/lib:/home/regress/cantian-connector-mysql/mysql-source/daac_lib:/usr/local/mysql/lib:/home/regress/cantian-connector-mysql/mysql-source/daac_lib:/usr/local/mysql/lib/private:/home/cantiandba/install/lib:/home/cantiandba/install/add-ons::/home/regress/cantian-connector-mysql/bld_debug/library_output_directory
export CANTIAND_MODE=open
export CANTIAND_HOME_DIR=/home/cantiandba/data

# 跑 MTR (不切换用户，继续执行）
cd /usr/local/mysql/mysql-test/
chmod 777 ./mysql-test-run-meta.pl 
./mysql-test-run-meta.pl --mysqld=--default-storage-engine=CTC --mysqld=--check_proxy_users=ON --do-test-list=enableCases.list --noreorder --nowarnings

# 退出 cantiandba
exit
```

### 3.3 重拉MySQL（在root用户下）<a id="section3.3"></a>
```bash
cd /home/regress/CantianKernel/Cantian-DATABASE-CENTOS-64bit
mkdir -p /home/cantiandba/logs
python3 install.py -U cantiandba:cantiandba -R /home/cantiandba/install/ -D /home/cantiandba/data/ -l /home/cantiandba/logs/install.log -Z _LOG_LEVEL=255 -g withoutroot -d -M cantiand_with_mysql -m /home/regress/cantian-connector-mysql/scripts/my.cnf -c -Z _SYS_PASSWORD=Huawei@123 -Z SESSIONS=1000 -r
```

### 3.4 清理MySQL元数据（及执行MTR用例过程中未手动清理的数据）<a id="section3.4"></a>
- 和 [2.3 清理MySQL元数据](#section2.3) 操作完全相同。
```bash
# 登录ctsql
su - cantiandba
ctsql / as sysdba -q

# 查看需要清理的库：除 SYS, PUBLIC, LREP, tmp, cantian 外都需要清理
select * from ADM_USERS;

# 删MySQL库（同时级联删除其中的表）
drop user performance_schema cascade;
drop user mysql cascade;
drop user sys cascade;
drop user mtr cascade;
drop user test cascade;
drop user sys_audit cascade; # MySQL8.0.32版本
drop user sys_mac cascade; # MySQL8.0.32版本
drop user gdb_sys_mac cascade; # MySQL8.0.32版本

# 退出 cantiandba
exit
```

### 3.5 下一个用例
重复：
- [3.2 跑MTR](#section3.2) 
- [3.3 重拉MySQL](#section3.3)
- [3.4 清理MySQL元数据](#section3.4)

## 4 拉起MySQL后跑MTR（单/双进程）<a id="section4"></a>
单进程/双进程均可以在拉起MySQL后，以连接的方式跑MTR。
1. 创库
```bash
# 登录MySQL执行
create database test;
create database mtr;
```
2. 跑 MTR
```bash
# 指定 host 和 port
cd /usr/local/mysql/mysql-test
chmod 777 ./mysql-test-run-meta.pl
./mysql-test-run-meta.pl --mysqld=--default-engine=CTC --mysqld=--check_proxy_users=ON --do-test-list=enableCases.list --noreorder --nowarnings --extern host=127.0.0.1 --extern port=3306 --extern user=root
```
3. 双节点跑 MTR
```bash
# 登录 MySQL 创建 host 为 % 的用户（localhost不能连远程用户）
CREATE USER 'root'@'%';
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%';
FLUSH PRIVILEGES;

# 连对端 MySQL
# 指定 host 和 port (节点 0/1 host 分别为 192.168.86.1/192.168.86.2)
cd /usr/local/mysql/mysql-test
chmod 777 ./mysql-test-run-meta.pl
./mysql-test-run-meta.pl --mysqld=--default-engine=CTC --mysqld=--check_proxy_users=ON --do-test-list=enableCases.list --noreorder --nowarnings --extern host=xxx --extern port=192.168.86.1 --extern user=root
```
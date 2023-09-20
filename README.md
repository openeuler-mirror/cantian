# Cantian Storage Engine
数据存储加速引擎

#### 一、工程说明
##### 1、编程语言：C
##### 2、编译工程：cmake或make，建议使用cmake
##### 3、目录说明：
-   Cantian：主目录，CMakeLists.txt为主工程入口；
-   build: 编译构建脚本；
-   common：管控面脚本；
-   ct_om：安装部署脚本；
-   pkg: 源代码目录，按子目录划分模块解耦；

#### 二、编译指导
##### 1、概述
在cantian项目根目录创建library、platform、open_source三个目录：  
-   open_source目录存放三方库代码及头文件  
-   platform存放huawei三方组件，如安全函数库  
-   library存放三方组件动态或静态链接库

##### 2、操作系统和软件依赖要求
###### 2.1 支持以下操作系统：
-   CentOS 8.2（x86）  
如需适配其他系统，可参照Cantian编译指导在相应操作系统上进行编译。  
###### 2.2 环境依赖
-   CMake(>=3.14.1)、automake、libtool、g++、libaio、pkgconfig、rpmbuild
###### 2.3 三方组件依赖
当前Cantian依赖第三方软件有securec、zlib、lz4、Zstandard、openssl、protobuf、protubuf-c、pcre; 
##### 3、下载Cantian及依赖组件
-   pcre2-10.40：https://github.com/PCRE2Project/pcre2.git  
-   openssl-1.1.1n：https://github.com/openssl/openssl  
-   lz4-1.9.3：https://github.com/lz4/lz4  
-   Zstandard-1.5.2：https://github.com/facebook/zstd.git  
-   protobuf-3.13.0：https://github.com/protocolbuffers/protobuf.git   
安装完成后需要执行ldconfig命令，否则提示  
protoc: error while loading shared libraries: libprotoc.so.24: cannot open shared object file: No such file or directory  
-   protobuf-c.1.4.1：https://github.com/protobuf-c/protobuf-c.git  
-   zlib-1.2.11：https://github.com/madler/zlib.git  
-   huawei安全函数库：https://gitee.com/Janisa/huawei_secure_c  
##### 4、编译第三方软件
1、在编译Cantian之前，需要先编译依赖的开源及第三方软件。在cantian根路径下，创建open_source目录，下载步骤3中所涉及的三方依赖组件。  
2、在open_source目录下创建各依赖组件头文件目录，如open_source/{component}/include/，并将组件源码中的头文件全部拷贝对应组件的include目录。  
**open_source目录组织结构**  
**huawei_security lz4 openssl pcre protobuf protobuf-c zlib Zstandard**  
3、创建library目录，将编译好的各组件库拷到library/{component}/lib目录。如：libpcre2-8.so*、liblz4.so*、libzstd.so*、libprotobuf-c.a、libcrypto.a、libssl.a、libz.so*拷贝到对应组件的lib目录。  
**注：protobuf需要执行make install安装默认动态库加载路径，安装protobuf之后再安装protobuf-c。**  
**library目录组织结构**   
**huawei_security lz4 openssl pcre protobuf protobuf-c zlib Zstandard**  
4、将编译好的安全函数库libsecurec.a拷贝到library/huawei_security/lib目录下。  
5、在根目录下创建platform/huawei_security/include目录，将securec.h、securectype.h安全函数头文件拷贝到此路径。
##### 5、代码编译
**Debug**:sh build_cantian.sh  
**Release**:修改bash Makefile.sh package为bash Makefile.sh package-release后执行sh build_cantian.sh  
完成编译后，安装包生成在/tmp/cantian_new目录中  
**注：报错无法找到protobuf-c.h的解决方案**  
**将protobuf-c目录下的protobuf-c.h头文件拷贝至library/protobuf/protobuf-c目录下**

#### 三、安装部署
##### 1、安装前准备
###### 1.1 网络规划
计算节点需要配置至少两个网络平面：
Cantian引擎心跳网络：用部署Cantian引擎的数据库服务器间通信
NAS共享网络：用作共享存储NAS共享
###### 1.2 存储规划
- 配置NFS服务：登录存储，启用NFSv4.0及NFSv4.1服务
- 创建文件系统：登录存储，创建文件系统与NFS共享，一共需要创建三个文件系统：用于存储cantian引擎数据的文件系统、cms共享文件系统、存储元数据的文件系统，如果开启归档需要额外创建用于归档的文件系统
- 创建逻辑端口用于文件系统挂载
###### 1.3 安装cantian引擎

1. 上传Cantian引擎安装包并解压，以把包放到目录/home/regress为例进行说明。
```angular2html
[root@host ~]# mkdir /home/regress
[root@host ~]# chmod 755 /home/regress
[root@host ~]# cd /home/regress/[root@host regress]# tar -zxvf cantian_connector_x86_64_RELEASE_*.tgz
```
2. 修改配置文件config_params.json，配置文件所在路径为/home/regress/cantian_connector/action/config_params.json，相关参数说明:
```angular2html
deploy_user: 数据库配置的“用户：用户组”，预安装时创建，例如：“ctdba:ctdba”。
cluster_id: 集群id，同一阵列中必须确保该id不重复。
cluster_name: Cantian引擎集群名，比如“cantian_cluster01”， **deploy_mode为"--dbstore"必填**
node_id: 部署Cantian引擎的数据库服务器ID，枚举：0|1，两个数据库服务器分别设置成0和1。
cantian_vlan_ip: 用户指定本地用于与存储建立连接的IP，属于RoCE存储网络，比如“172.16.55.4，172.16.66.4”，**deploy_mode为"--dbstore"必填**
storage_vlan_ip: 用户在存储上配置的VLAN IP，属于RoCE存储网络，比如“172.16.55.2，172.16.55.3，172.16.66.2，172.16.66.3”，**deploy_mode为"--dbstore"必填**
in_container: 是否容器化部署，默认为1，无需修改。
cms_ip:数据库服务器间通信IP，所有数据库服务器IP均需填入，属于Cantian引擎心跳网络，比如“192.168.20.2，192.168.20.3”。先填入node_id为0的数据库服务器的IP、再填入node_id为1的数据库服务器的IP。
kerberos_key:指定Kerberos认证的安全选项。取值包括：
             sys：使用UNIX UID和GID进行身份认证，不进行Kerberos加密保护;
             krb5：使用Kerberos v5进行身份认证;krb5i：使用Kerberos v5进行身份认证，并使用安全校验对NFS操作进行完整性检查，以防止数据篡改;
             krb5p：使用Kerberos v5进行身份认证、完整性检查，并加密NFS流量以防止流量嗅探。这是最安全的设置，但也需要更多的性能开销;
             Kerberos认证的性能从高到低为：krb5 > krb5i > krb5p。
             在NFS Kerberos服务使用场景中，这里的“kerberos_key”字段取值需要和4.3.3.2-2时设置的“Kerberos5权限”、“Kerberos5i权限”和“Kerberos5p权限”相匹配。
             例如，这里挂载NFS时，指定“kerberos_key”字段取值为“krb5i”，那为客户端设置权限时，至少需要设置“Kerberos5i权限”。
storage_dbstore_fs: cantian引擎使用的存储文件系统名称，比如“fs_storage”。每个文件系统，只能部署一个Cantian引擎。**deploy_mode为"--nas"需要存储打开NFS4.1协议**
storage_share_fs: cms共享数据使用的存储文件系统名称，使用NFS4.0协议挂载，因此需要存储打开NFS4.0。每个文件系统，只能部署一个Cantian引擎。
storage_archive_fs: 归档使用的存储文件系统名称，使用NFS4.1协议挂载，因此需要存储打开NFS4.1。每个文件系统，只能部署一个Cantian引擎。
storage_metadata_fs: mysql元数据使用的存储文件系统名称，使用NFS4.1协议挂载，因此需要存储打开NFS4.1。
share_logic_ip: 挂共享数据使用的逻辑IP，比如“172.16.77.2”。
archive_logic_ip: 挂载归档使用的逻辑IP，比如“172.16.77.2”。
metadata_logic_ip: 挂载mysql元数据使用的逻辑IP，比如“172.16.77.2”。
storage_logic_ip: 挂载cantian引擎使用的逻辑IP，比如“172.16.77.2”，**deploy_mode为"--nas"必填**
link_type: 访问存储dbstor的协议，“2”表示RDMA_1823，“1”表示RDMA，“0”表示TCP。默认使用“1”即可，**deploy_mode为"--dbstore"必填**
db_type: 数据库类型，“0”表示性能模式，“1”表示开启归档模式。默认值为“0”。
MAX_ARCH_FILES_SIZE: 归档的最大容量，建议设置为storage_archive_fs对应的归档使用的存储文件系统可用空间的90%。
deploy_mode: 部署模式，取值--nas：使用nas共享进行部署，--dbstore：使用dbstore模式进行部署
ca_path: ca证书存放路径，比如：/opt/certificate/ca.crt
crt_path: 证书存放路径， 比如：/opt/certificate/mes.crt
key_path: 证书key存储路径，比如：/opt/certificate/mes.key
```
3. 安装部署（deploy_mode为"--nas"为例）
- 若是首次安装Cantian引擎、或上次是通过override方式卸载了Cantian引擎，请执行以下命令进行安装。
```angular2html
[root@host ~]# sh /home/regress/cantian_connector/action/appctl.sh install /home/regress/cantian_connector/action/config_params.json
```
根据回显的提示，依次输入：
1) 创建cantian_sys密码。
2) 确认1)中创建的密码。脚本运行完成后，最后回显“install success”即安装成功
- 上次是通过reserve方式卸载了Cantian引擎，请执行以下命令进行安装。
```angular2html
[root@host ~]# sh /home/regress/cantian_connector/action/appctl.sh install reserve
```
脚本运行完成后，最后回显“install success”即安装成功。
4. 两台数据库服务器上均完成Cantian引擎的安装后，执行以下命令启动Cantian引擎
```angular2html
[root@host ~]# sh /home/regress/cantian_connector/action/appctl.sh start
```
根据提示输入cantian_sys密码

###### 1.4 卸载cantian引擎
1. 通过override方式卸载Cantian引擎
- 两台数据库服务器同时停止Cantian引擎集群。
```
[root@host ~]# sh /home/regress/cantian_connector/action/appctl.sh stop
```
- 两台数据库服务器分别使用override方式卸载Cantian引擎集群。
```
[root@host ~]# sh /home/regress/cantian_connector/action/appctl.sh uninstall override
```
- （可选）若卸载失败，请执行下列命令进行强制卸载。
```
[root@host ~]# sh /home/regress/cantian_connector/action/appctl.sh uninstall override force
```
2. 通过reserve方式卸载Cantian引擎(保留数据卸载重装)
- 两台数据库服务器分别进行数据备份。
```
[root@host ~]# sh /home/regress/cantian_connector/action/appctl.sh backup
```
- 两台- 数据库服务器同时停止Cantian引擎集群。
```
[root@host ~]# sh /home/regress/cantian_connector/action/appctl.sh stop
```
- 两台数据库服务器分别使用reserve方式卸载Cantian引擎集群。
```
[root@host ~]# sh /home/regress/cantian_connector/action/appctl.sh uninstall reserve
```

#### 四、系统维护
##### 4.1 巡检
1. 依次登录所有计算节点执行巡检指令(以ctdba用户为例)：
全部巡检项指令：su - ctdba -c "python3 /opt/cantian/action/inspection/inspection_task.py all"
部分巡检项指令：su - ctdba -c "python3 /opt/cantian/action/inspection/inspection_task.py [xxx,xxx,…]"\
说明：
   - ctdba用户为安装部署中配置文件中配置的deploy_user，参考config_params.json
   - "xxx"表示具体的巡检项，如“cantian_status”。
   - 各巡检项之间以逗号隔开，且无空格。 
   - 巡检项可通过/opt/cantian/action/inspection/inspection_config.json文件查看

2. 根据回显提示，输入ctclient数据库用户名、密码、IP和端口号:

3. 执行结果如下：
```angular2html
[cantiandba@node0-78 ~]$ python /opt/cantian/action/inspection/inspection_task.py all
Please input user: SYS
Please input password: 
2023-09-07 14:51:15 INFO [pid:4167258] [MainThread] [tid:139729935162240] [gs_check.py:597 run_check] Start to run CheckSession
2023-09-07 14:51:15 INFO [pid:4167258] [MainThread] [tid:139729935162240] [gs_check.py:599 run_check] finish to run CheckSession
2023-09-07 14:51:15 INFO [pid:4167264] [MainThread] [tid:140497172671360] [gs_check.py:597 run_check] Start to run CheckTransaction
2023-09-07 14:51:15 INFO [pid:4167264] [MainThread] [tid:140497172671360] [gs_check.py:599 run_check] finish to run CheckTransaction
2023-09-07 14:51:15 INFO [pid:4167270] [MainThread] [tid:139769953201024] [gs_check.py:597 run_check] Start to run CheckDBVersion
2023-09-07 14:51:15 INFO [pid:4167270] [MainThread] [tid:139769953201024] [gs_check.py:599 run_check] finish to run CheckDBVersion
2023-09-07 14:51:15 INFO [pid:4167276] [MainThread] [tid:140700553079680] [gs_check.py:597 run_check] Start to run CheckDRCResRatio
2023-09-07 14:51:15 INFO [pid:4167282] [MainThread] [tid:140069366741888] [cms_res_check.py:27 fetch_cms_hbtime] cms res check start!
2023-09-07 14:51:15 INFO [pid:4167282] [MainThread] [tid:140069366741888] [cms_res_check.py:49 fetch_cms_hbtime] cms res check succ!
2023-09-07 14:51:15 INFO [pid:4167288] [MainThread] [tid:139929375972224] [cms_stat_check.py:33 fetch_cms_stat] cms stat check start!
2023-09-07 14:51:16 INFO [pid:4167288] [MainThread] [tid:139929375972224] [cms_stat_check.py:65 fetch_cms_stat] cms stat check succ!
2023-09-07 14:51:16 INFO [pid:4167410] [MainThread] [tid:140576152152960] [cms_version_check.py:14 fetch_cms_version] cms version check start!
2023-09-07 14:51:16 INFO [pid:4167410] [MainThread] [tid:140576152152960] [cms_version_check.py:25 fetch_cms_version] cms version check succ!
2023-09-07 14:51:16 INFO [pid:4167415] [MainThread] [tid:140255170087808] [gs_check.py:597 run_check] Start to run CheckArchiveStatus
2023-09-07 14:51:18 INFO [pid:4167415] [MainThread] [tid:140255170087808] [gs_check.py:599 run_check] finish to run CheckArchiveStatus
Component: [ntp_server_check, cantian_status, db_version_check, cms_res_check, cms_stat_check, cms_version_check, archive_status_check] inspection execute success, 
component: [session_used_check, long_transaction_check, drc_res_ratio_check ]inspection execute failed; 
inspection result file is /opt/cantian/action/inspection/inspections_log/inspection_cantian_xxx_20230907145118
```
如果执行全部巡检或者部分巡检项涉及登录zsql数据库操作的，需要输入zsql数据库帐号、密码。不涉及登录zsql数据库操作的巡检无需输入以上信息。
查看巡检结果：
4. 巡检完成后，巡检结果将保存在目录“/opt/cantian/action/inspections_log”下，以“inspection_时间戳”命名，并且只保存最近十次的巡检结果文件。

#### 五、对接MySQL
##### 5.1 安装MySQL
当前支持MySQL-8.0.26，如果需要其它版本，请开发人员适配或联系cantian仓开发人员。

##### 5.2 加载ctc插件
###### 5.2.1 部署MySQL
1. 在环境上部署cantian
2. 确认/dev/shm下的**共享内存文件权限**，确保cantian安装部署的用户也可以访问及rw。
3. 确认ctc.so所依赖的库，系统加载时能找到。
4. 登录mysql,加载插件  

方法一：
```
install plugin ctc_ddl_rewriter soname 'ha_ctc.so'
install plugin CTC soname 'ha_ctc.so'
```
方法二：
```
/usr/local/mysql/bin/mysqld --defaults-file=/home/regress/mysql-server/scripts/my.cnf --initialize-insecure --datadir=/data/data
/usr/local/mysql/bin/mysqld --defaults-file=/home/regress/mysql-server/scripts/my.cnf --datadir=/data/data --plugin-dir=/usr/local/mysql/lib/plugin --plugin_load="ctc_ddl_rewriter=ha_ctc.so;ctc=ha_ctc.so;" --
check_proxy_users=ON --mysql_native_password_proxy_users=ON --default-storage-engine=CTC
```
#### 六、注意事项
##### 6.1 cantian引擎使用ssl认证时证书私钥密码
1. 现版本ssl证书私钥的密码经过base64编码加密保存至配置文件，并在程序中进行解密，如需替换其他的加密算法请按照下面步骤操作。
2. 现用的私钥密码加密步骤在pkg/deploy/action/install.sh中的copy_cert_files函数，将此步骤中的base64替换成相应的加密算法实现加密。
3. 现用的私钥密码解密步骤在pkg/src/mec/mes_tcp.c中的mes_ssl_decode_key_pwd函数，此函数的输入参数分别为密文的地址和长度，解密后明文的存放地址和长度，将此函数中的内容替换为步骤2中对应的解密算法的实现。

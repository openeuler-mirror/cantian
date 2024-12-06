## 1 环境搭建
### 1.1 docker pull镜像超时

解决方法：
```bash
配置镜像加速器
tee /etc/docker/daemon.json <<-'EOF'
{
  "registry-mirrors": ["https://docker.rainbond.cc"]
}
EOF
systemctl daemon-reload
systemctl restart docker
```

## 2 安装部署
### 2.1 计算云安装部署进入容器失败
```bash
docker: Error response from daemon: network mynetwork not found.
```
解决方法：
```bash
[root@cantian-0018-yuanyazhi cantian]# docker network create -d bridge --subnet 192.168.86.111/16 network
Error response from daemon: invalid network config:
invalid subnet 192.168.86.111/16: it should be 192.168.0.0/16
[root@cantian-0018-yuanyazhi cantian]# vim docker/container.sh
    docker network create -d bridge --subnet 192.168.0.0/16 ${network_name}
```

### 2.2 安装部署时报错IP相关问题（arm环境）

解决方法：
```bash
yum install iputils -y
yum install iproute -y
```

### 2.3 参天拉起失败（arm环境）
- 如果是关于共享内存初始化的报错（双进程）：修改 `srv_param.c` 或 `cantiand.ini` 中 `SHM_MEMORY_REDUCTION_RATIO` 的值为 `8`；
- 如果是参天系统表未创建完成（debug）：则修改 `cantian/build/Makefile.sh` 中 `-DUSE_PROTECT_VM=OFF`。

## 3 GDB相关
### 3.1 gdb: 无Debuginfo
```bash
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib64/libthread_db.so.1".
0x00007f8e2f6a6a41 in poll () from /lib64/libc.so.6
Missing separate debuginfos, use: yum debuginfo-install glibc-2.28-164.el8.x86_64 libaio-0.3.112-1.el8.x86_64 libgcc-8.5.0-4.el8_5.x86_64 libstdc++-8.5.0-4.el8_5.x86_64 openssl-libs-1.1.1k-5.el8_5.x86_64 zlib-1.2.11-17.el8.x86_64
```
解决方法：
```
# 配置CentOS-Debuginfo.repo  （一般云服务器上是没有该文件的，需要自己创建）
cat /etc/yum.repos.d/CentOS-Debug.repo

# Debug Info
[debug]
name=CentOS-$releasever - DebugInfo
baseurl=http://debuginfo.centos.org/$releasever/$basearch/
gpgcheck=0
enabled=1
protect=1
priority=1

# 然后执行报错信息中的yum指令
```

## 4 共享内存（双进程）
### 4.1 OOM
观察共享内存分片已使用统计情况：执行`show engine ctc status\G`（仅双进程有）;
![输入图片说明](https://foruda.gitee.com/images/1725540542409766114/237af3f2_10133320.png "屏幕截图")
![输入图片说明](https://foruda.gitee.com/images/1725540913063152155/ea751d2a_10133320.png "屏幕截图")
其中：
- `SIZE`为每个分片大小，分别从`8字节`，`16字节`依次增大到`4M`；
- `NUM`为每个文件中对应分片的总数，每个共享内存文件大小为`4G`；
- `FILE0, FILE1, ...` 分别为每个文件中每个分片已使用数量；

注意：
- 初次拉起，直接查看，共享内存使用最少；
- 当打开表未关闭时，申请的共享内存不会释放，可以通过执行`flush tables;`后再次观察：如果发现依旧占用很多共享内存，则可能有业务在下发，如果show processlist发现没有业务，则可能是bug，再继续定位。

### 4.2 卡住
如果发生卡住问题，且发生在共享内存，可能存在两种情况：
1. 和共享内存无关，只是消息通过共享内存发送到mysqld/cantiand后有任务没做完，卡在了加锁等其他地方；
2. 和共享内存有关，在发生故障等场景下消息发送后没回来，一直清理不掉。这个时候需要继续观察（堆栈/日志）首次发生问题时间、卡住的消息类型、有几个消息没回来等信息，帮助进一步分析。

## 5. mysql断连
### 5.1 debug调试模式下，含自增列的表在执行update操作时MySQL主动退出。
原因：在bin-log 未开启的情况下，MySQL在处理自增列的最大自增值时未将该列的read_set置位，MySQL认为本次操作没有写入bin-log会产生风险，会主动core。  
解决方法：在拉起时注释skip-log-bin，将bin-log打开。
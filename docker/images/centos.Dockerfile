FROM centos:8.2.2004

WORKDIR /ctdb/cantian_install

RUN touch /root/.curlrc && sed -i "$a insecure" /root/.curlrc
RUN rm -rf /etc/yum.repos.d/* && curl https://mirrors.huaweicloud.com/repository/conf/CentOS-8-anon.repo > /etc/yum.repos.d/CentOS-Base.repo && \
    yum clean all &> /dev/null && \
    echo 'sslverify=False' >> /etc/yum.conf && yum makecache > /dev/null

RUN yum install -y rpm linux-firmware perl-interpreter --nogpgcheck &> /dev/null

RUN wget https://yum.oracle.com/repo/OracleLinux/OL8/baseos/latest/x86_64/getPackage/kernel-4.18.0-193.el8.x86_64.rpm && \
    wget https://yum.oracle.com/repo/OracleLinux/OL8/baseos/latest/x86_64/getPackage/kernel-core-4.18.0-193.el8.x86_64.rpm && \
    wget https://yum.oracle.com/repo/OracleLinux/OL8/baseos/latest/x86_64/getPackage/kernel-cross-headers-4.18.0-193.el8.x86_64.rpm && \
    wget https://yum.oracle.com/repo/OracleLinux/OL8/baseos/latest/x86_64/getPackage/kernel-debug-4.18.0-193.el8.x86_64.rpm && \
    wget https://yum.oracle.com/repo/OracleLinux/OL8/baseos/latest/x86_64/getPackage/kernel-debug-core-4.18.0-193.el8.x86_64.rpm && \
    wget https://yum.oracle.com/repo/OracleLinux/OL8/baseos/latest/x86_64/getPackage/kernel-debug-devel-4.18.0-193.el8.x86_64.rpm && \
    wget https://yum.oracle.com/repo/OracleLinux/OL8/baseos/latest/x86_64/getPackage/kernel-debug-modules-4.18.0-193.el8.x86_64.rpm && \
    wget https://yum.oracle.com/repo/OracleLinux/OL8/baseos/latest/x86_64/getPackage/kernel-debug-modules-extra-4.18.0-193.el8.x86_64.rpm && \
    wget https://yum.oracle.com/repo/OracleLinux/OL8/baseos/latest/x86_64/getPackage/kernel-devel-4.18.0-193.el8.x86_64.rpm && \
    wget https://yum.oracle.com/repo/OracleLinux/OL8/baseos/latest/x86_64/getPackage/kernel-headers-4.18.0-193.el8.x86_64.rpm && \
    wget https://yum.oracle.com/repo/OracleLinux/OL8/baseos/latest/x86_64/getPackage/kernel-modules-4.18.0-193.el8.x86_64.rpm && \
    wget https://yum.oracle.com/repo/OracleLinux/OL8/baseos/latest/x86_64/getPackage/kernel-modules-extra-4.18.0-193.el8.x86_64.rpm

RUN rpm -ivh kernel*.rpm &> /dev/null && rm -rf kernel*.rpm
RUN yum install -y epel-release \
    vim make gcc gcc-c++ gcc-toolset-10 gcc-gfortran gdb gdb-gdbserver python2 python2-devel \
    python3 python3-devel git net-tools cmake wget \
    tree mlocate psmisc sudo perf gawk perl-open perl \
    ndctl ndctl-libs ndctl-devel ncurses ncurses-devel libtirpc-devel \
    jq libpmem libpmem-devel daxio nc libaio-devel openssl openssl-devel \
    libibverbs librdmacm libibumad libibmad rdma-core-devel \
    openssh-server dnf-plugins-core dnf-utils ant maven bison \
    createrepo yum-utils tcsh tk tcl pciutils-libs pciutils fuse-libs \
    lsof nfs-utils rpcgen libarchive &> /dev/null && \
    yum clean all &> /dev/null

RUN wget http://mirror.centos.org/centos/8-stream/AppStream/x86_64/os/Packages/sshpass-1.09-4.el8.x86_64.rpm &> /dev/null && \
    rpm -ivh sshpass-1.09-4.el8.x86_64.rpm && rm -rf sshpass-1.09-4.el8.x86_64.rpm

RUN yum install -y rsync libev perl-Digest-MD5 perl-DBD-MySQL &> /dev/null && \
    yum clean all &> /dev/null

RUN yum install -y https://repo.percona.com/yum/percona-release-latest.noarch.rpm && \
    percona-release enable-only tools release
RUN yum install -y percona-xtrabackup-80-8.0.26 --nogpgcheck

RUN wget http://content.mellanox.com/ofed/MLNX_OFED-5.5-1.0.3.2/MLNX_OFED_LINUX-5.5-1.0.3.2-rhel8.2-x86_64.tgz &> /dev/null && \
    tar -zxf MLNX_OFED_LINUX-5.5-1.0.3.2-rhel8.2-x86_64.tgz && rm -rf MLNX_OFED_LINUX-5.5-1.0.3.2-rhel8.2-x86_64.tgz && \
    echo -e "y" | MLNX_OFED_LINUX-5.5-1.0.3.2-rhel8.2-x86_64/mlnxofedinstall &> /dev/null && \
    wget https://github.com/thkukuk/rpcsvc-proto/releases/download/v1.4/rpcsvc-proto-1.4.tar.gz \
    && tar -zxvf rpcsvc-proto-1.4.tar.gz && rm -rf rpcsvc-proto-1.4.tar.gz && cd rpcsvc-proto-1.4 \
    && ./configure &> /dev/null && make &> /dev/null && make install &> /dev/null \
    && cd - && rm -rf rpcsvc-proto-1.4

RUN debuginfo-install -y libibverbs \
    librdmacm libibumad libibmad rdma-core-devel \
    libpmem libpmem-devel libarchive

RUN yum group install -y "Development Tools"

RUN mkdir /tools
WORKDIR /tools
RUN wget --progress=bar:force -O FlameGraph-master.zip https://github.com/brendangregg/FlameGraph/archive/master.zip && \
    wget --progress=bar:force -O fzf-master.zip https://github.com/junegunn/fzf/archive/master.zip && \
    wget --progress=bar:force https://boostorg.jfrog.io/artifactory/main/release/1.73.0/source/boost_1_73_0.tar.gz \
    && tar -zxf boost_1_73_0.tar.gz && \
    wget --progress=bar:force  https://github.com/doxygen/doxygen/releases/download/Release_1_9_2/doxygen-1.9.2.src.tar.gz \
    && tar -zxf doxygen-1.9.2.src.tar.gz && rm -rf doxygen-1.9.2.src.tar.gz \
    && cd doxygen-1.9.2 && rm -rf doxygen-1.9.2 && mkdir build && cd build \
    && cmake -G "Unix Makefiles" .. &> /dev/null && make &> /dev/null \
    && cd ../..

RUN wget --progress=bar:force -O /tmp/mysql80-community-release-el8-9.noarch.rpm https://dev.mysql.com/get/mysql80-community-release-el8-9.noarch.rpm && \
    yum install -y /tmp/mysql80-community-release-el8-9.noarch.rpm &> /dev/null && \
    rm -rf /tmp/mysql80-community-release-el8-9.noarch.rpm && \
    yum install -y mysql-connector-c++-devel git-clang-format libcap-devel expect --nogpgcheck &> /dev/null && \
    yum clean all &> /dev/null

RUN wget --progress=bar:force -O /tmp/libasan5-8.2.1-3.el7.x86_64.rpm http://mirror.centos.org/centos/7/sclo/x86_64/rh/Packages/l/libasan5-8.2.1-3.el7.x86_64.rpm &> /dev/null && \
    rpm -ivh /tmp/libasan5-8.2.1-3.el7.x86_64.rpm && rm -rf /tmp/libasan5-8.2.1-3.el7.x86_64.rpm && \
    mkdir /docker-entrypoint-initdb.d && \
    wget --progress=bar:force -O /tmp/docker-ce-cli-19.03.5-3.el7.x86_64.rpm https://download.docker.com/linux/centos/7/x86_64/stable/Packages/docker-ce-cli-19.03.5-3.el7.x86_64.rpm && \
    yum install -y /tmp/docker-ce-cli-19.03.5-3.el7.x86_64.rpm && \
    rm -rf /tmp/docker-ce-cli-19.03.5-3.el7.x86_64.rpm

RUN /usr/bin/ssh-keygen -A
RUN sed -i -e 's/^#Port 22/Port 2200/g' \
    -e 's/^SyslogFacility AUTHPRIV/#SyslogFacility AUTHPRIV/g' \
    -e 's/^#SyslogFacility AUTH/SyslogFacility AUTH/g' \
    -e 's/^UsePAM yes/UsePAM no/g' /etc/ssh/sshd_config

RUN wget --progress=bar:force -P /tools https://mirrors.huaweicloud.com/java/jdk/8u202-b08/jdk-8u202-linux-x64.tar.gz \
    && tar -zxvf jdk-8u202-linux-x64.tar.gz -C /usr/local && sed -i '$aexport JAVA_HOME=/usr/local/jdk1.8.0_202' /etc/profile \
    && sed -i '$aexport PATH=$JAVA_HOME/bin:$PATH' /etc/profile && source /etc/profile && \
    wget --progress=bar:force -P /tools https://go.dev/dl/go1.18.1.linux-amd64.tar.gz \
    && tar -zxvf go1.18.1.linux-amd64.tar.gz -C /usr/local && sed -i '$aexport GO_HOME=/usr/local/go' /etc/profile \
    && sed -i '$a export PATH=$GO_HOME/bin:$PATH' /etc/profile && source /etc/profile

RUN yum install -y nfs-utils &> /dev/null && yum clean all &> /dev/null && \
    pip3 install --upgrade pip && \
    pip3 install cryptography pyOpenSSL
RUN sed -i '$a export PYTHON3_HOME=/usr/include/python3.6m' /etc/profile && \
    ln -s /usr/bin/gcc /usr/local/bin/gcc && ln -s /usr/bin/g++ /usr/local/bin/g++ && \
    touch /opt/bashrc && sed -i '$a ln /dev/sdb /dev/gss-disk1 2>/dev/null' /opt/bashrc && \
    sed -i '$a chmod 777 /dev/gss-disk1' /opt/bashrc && \
    sed -i '$a chmod 666 /var/run/docker.sock' /opt/bashrc

RUN pip3 install requests paramiko

RUN mkdir /cores
VOLUME /var/lib/mysql

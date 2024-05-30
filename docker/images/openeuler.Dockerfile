FROM openeuler/openeuler:22.03-lts-sp1

WORKDIR /ctdb/cantian_install

RUN touch /root/.curlrc && sed -i "$a insecure" /root/.curlrc

RUN yum update -y

RUN yum install -y rpm linux-firmware perl-interpreter --nogpgcheck

RUN yum install -y \
    vim make gcc gcc-c++ gcc-gfortran gdb gdb-gdbserver\
    python3 python3-devel git net-tools cmake wget \
    tree mlocate psmisc sudo perf gawk perl-open perl \
    ndctl ndctl-libs ndctl-devel ncurses ncurses-devel libtirpc-devel \
    jq nc libaio-devel openssl openssl-devel \
    libibverbs librdmacm libibumad libibmad rdma-core-devel \
    openssh-server dnf-plugins-core dnf-utils ant maven bison \
    createrepo tcsh tk tcl pciutils-libs pciutils fuse-libs \
    lsof nfs-utils rpcgen sshpass

RUN yum install -y rsync libev perl-Digest-MD5 perl-DBD-MySQL

RUN wget https://github.com/thkukuk/rpcsvc-proto/releases/download/v1.4/rpcsvc-proto-1.4.tar.gz \
    && tar -zxvf rpcsvc-proto-1.4.tar.gz && rm -rf rpcsvc-proto-1.4.tar.gz && cd rpcsvc-proto-1.4 \
    && ./configure && make && make install && cd -

RUN debuginfo-install -y libibverbs \
    librdmacm libibumad libibmad rdma-core-devel

RUN yum group install -y "Development Tools"

RUN mkdir /tools
WORKDIR /tools
RUN wget --progress=bar:force -O FlameGraph-master.zip https://github.com/brendangregg/FlameGraph/archive/master.zip
RUN wget --progress=bar:force -O fzf-master.zip https://github.com/junegunn/fzf/archive/master.zip
RUN wget --progress=bar:force https://boostorg.jfrog.io/artifactory/main/release/1.73.0/source/boost_1_73_0.tar.gz \
    && tar -zxf boost_1_73_0.tar.gz
RUN wget --progress=bar:force  https://github.com/doxygen/doxygen/releases/download/Release_1_9_2/doxygen-1.9.2.src.tar.gz \
    && tar -zxf doxygen-1.9.2.src.tar.gz && cd doxygen-1.9.2 && mkdir build && cd build \
    && cmake -G "Unix Makefiles" .. && make && cd ../..

RUN wget --progress=bar:force -O /tmp/mysql80-community-release-el8-9.noarch.rpm https://dev.mysql.com/get/mysql80-community-release-el8-9.noarch.rpm && \
    yum install -y /tmp/mysql80-community-release-el8-9.noarch.rpm && \
    rm -rf /tmp/mysql80-community-release-el8-9.noarch.rpm
RUN yum install -y mysql-connector-c++-devel git-clang-format libcap-devel expect --nogpgcheck

RUN wget --progress=bar:force -O /tmp/libasan5-8.2.1-3.bs1.el7.aarch64.rpm http://mirror.centos.org/altarch/7/sclo/aarch64/rh/Packages/l/libasan5-8.2.1-3.bs1.el7.aarch64.rpm && \
    rpm -ivh /tmp/libasan5-8.2.1-3.bs1.el7.aarch64.rpm && rm -rf /tmp/libasan5-8.2.1-3.bs1.el7.aarch64.rpm

RUN yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
RUN sed -i 's/\$releasever/8/g' /etc/yum.repos.d/docker-ce.repo
RUN mkdir /docker-entrypoint-initdb.d
VOLUME /var/lib/mysql
RUN wget --progress=bar:force -O /tmp/docker-ce-19.03.13-3.el8.aarch64.rpm https://download.docker.com/linux/centos/8/aarch64/stable/Packages/docker-ce-cli-19.03.13-3.el8.aarch64.rpm && \
    yum install -y /tmp/docker-ce-19.03.13-3.el8.aarch64.rpm && \
    rm -rf /tmp/docker-ce-19.03.13-3.el8.aarch64.rpm

RUN /usr/bin/ssh-keygen -A
RUN sed -i -e 's/^#Port 22/Port 2200/g' \
    -e 's/^SyslogFacility AUTHPRIV/#SyslogFacility AUTHPRIV/g' \
    -e 's/^#SyslogFacility AUTH/SyslogFacility AUTH/g' \
    -e 's/^UsePAM yes/UsePAM no/g' /etc/ssh/sshd_config

RUN wget --progress=bar:force -P /tools https://go.dev/dl/go1.18.1.linux-arm64.tar.gz \
    && tar -zxvf go1.18.1.linux-arm64.tar.gz -C /usr/local && sed -i '$aexport GO_HOME=/usr/local/go' /etc/profile \
    && sed -i '$a export PATH=$GO_HOME/bin:$PATH' /etc/profile && source /etc/profile && \
    rm -rf go1.18.1.linux-arm64.tar.gz

RUN yum install -y nfs-utils python3-pip
RUN pip install cryptography pyOpenSSL
RUN sed -i '$a export PYTHON3_HOME=/usr/include/python3.6m' /etc/profile

RUN ln -s /usr/bin/gcc /usr/local/bin/gcc && ln -s /usr/bin/g++ /usr/local/bin/g++

RUN touch /opt/bashrc && sed -i '$a ln /dev/sdb /dev/gss-disk1 2>/dev/null' /opt/bashrc
RUN sed -i '$a chmod 777 /dev/gss-disk1' /opt/bashrc
RUN sed -i '$a chmod 666 /var/run/docker.sock' /opt/bashrc

RUN mkdir /cores
RUN mkdir /home/regress

RUN yum install -y cmake openssl-devel libaio libaio-devel automake autoconf \
    bison libtool ncurses-devel libgcrypt-devel libev-devel libcurl-devel zlib-devel \
    libudev-devel \
    zstd vim-common procps-ng-devel && \
    yum clean all

RUN wget https://gitee.com/mirrors/percona-xtrabackup/repository/archive/percona-xtrabackup-8.0.26-18.zip && \
    unzip percona-xtrabackup-8.0.26-18.zip && rm -rf percona-xtrabackup-8.0.26-18.zip && \
    cd percona-xtrabackup-percona-xtrabackup-8.0.26-18 && mkdir build && \
    cd build && cmake -DWITH_BOOST=/tools -DDOWNLOAD_BOOST=OFF -DBUILD_CONFIG=xtrabackup_release -DWITH_MAN_PAGES=OFF .. && \
    make -j$(nproc --all) && make install && rm -rf /home/regress/percona-xtrabackup-percona-xtrabackup-8.0.26-18

RUN yum install -y iptables net-tools nfs-utils libaio-devel iputils iproute \
                   ethtool cpio patch rpm-build python3-unversioned-command autoconf automake \
                   kernel-devel-5.10.0-136.12.0.86.oe2203sp1.aarch64 \
                   fuse-devel pciutils-devel libusbx

RUN wget https://content.mellanox.com/ofed/MLNX_OFED-5.9-0.5.6.0/MLNX_OFED_LINUX-5.9-0.5.6.0-openeuler22.03-aarch64.tgz
RUN tar -zxf MLNX_OFED_LINUX-5.9-0.5.6.0-openeuler22.03-aarch64.tgz && rm -rf MLNX_OFED_LINUX-5.9-0.5.6.0-openeuler22.03-aarch64.tgz
RUN echo -e "y" | MLNX_OFED_LINUX-5.9-0.5.6.0-openeuler22.03-aarch64/mlnxofedinstall --force --add-kernel-support --user-space-only --without-fw-update --without-neo-backend

RUN pip install requests paramiko

WORKDIR /home/regress
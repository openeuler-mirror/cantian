FROM centos:8.2.2004

ARG BUILD=debug

RUN touch /root/.curlrc && sed -i "$a insecure" /root/.curlrc
RUN rm -rf /etc/yum.repos.d/* && curl https://mirrors.huaweicloud.com/repository/conf/CentOS-8-anon.repo > /etc/yum.repos.d/CentOS-Base.repo
RUN yum clean all && echo 'sslverify=False' >> /etc/yum.conf
RUN yum update -y
RUN rm -rf /etc/yum.repos.d/* && curl https://mirrors.huaweicloud.com/repository/conf/CentOS-8-anon.repo > /etc/yum.repos.d/CentOS-Base.repo
RUN yum clean all && echo 'sslverify=False' >> /etc/yum.conf
RUN yum install -y epel-release
RUN yum install -y \
    vim make gcc gcc-c++ gcc-toolset-10 gdb gdb-gdbserver python2 python2-devel \
    python3 python3-devel git net-tools cmake wget \
    tree mlocate psmisc sudo perf gawk perl-open perl \
    kernel-debug kernel-debug-core kernel-debug-devel \
    kernel-debug-modules kernel-debug-modules-extra \
    ndctl ndctl-libs ndctl-devel ncurses ncurses-devel libtirpc-devel \
    jq libpmem libpmem-devel daxio nc libaio-devel openssl openssl-devel \
    libibverbs librdmacm libibumad libibmad rdma-core-devel \
    openssh-server dnf-plugins-core dnf-utils ant maven bison

RUN touch /root/.wgetrc && sed -i "$a check_certificate = off" /root/.wgetrc

# sshpass
RUN wget https://github.com/thkukuk/rpcsvc-proto/releases/download/v1.4/rpcsvc-proto-1.4.tar.gz \
    && tar -zxvf rpcsvc-proto-1.4.tar.gz && cd rpcsvc-proto-1.4 \
    && ./configure && make && make install && cd -

RUN debuginfo-install -y libibverbs \
    librdmacm libibumad libibmad rdma-core-devel \
    libpmem libpmem-devel

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

RUN wget --progress=bar:force -O /tmp/mysql80-community-release-el8-9.noarch.rpm https://dev.mysql.com/get/mysql80-community-release-el8-9.noarch.rpm
RUN yum install -y /tmp/mysql80-community-release-el8-9.noarch.rpm
RUN yum install -y mysql-connector-c++-devel --nogpgcheck
RUN yum install -y git-clang-format
RUN yum install -y libcap-devel
RUN yum install -y expect

RUN wget --progress=bar:force -O /tmp/libasan5-8.2.1-3.el7.x86_64.rpm http://mirror.centos.org/centos/7/sclo/x86_64/rh/Packages/l/libasan5-8.2.1-3.el7.x86_64.rpm
RUN rpm -ivh /tmp/libasan5-8.2.1-3.el7.x86_64.rpm

RUN mkdir /docker-entrypoint-initdb.d
VOLUME /var/lib/mysql
RUN wget --progress=bar:force -O /tmp/docker-ce-cli-19.03.5-3.el7.x86_64.rpm https://download.docker.com/linux/centos/7/x86_64/stable/Packages/docker-ce-cli-19.03.5-3.el7.x86_64.rpm
RUN yum install -y /tmp/docker-ce-cli-19.03.5-3.el7.x86_64.rpm

RUN /usr/bin/ssh-keygen -A
RUN sed -i -e 's/^#Port 22/Port 2200/g' \
    -e 's/^SyslogFacility AUTHPRIV/#SyslogFacility AUTHPRIV/g' \
    -e 's/^#SyslogFacility AUTH/SyslogFacility AUTH/g' \
    -e 's/^UsePAM yes/UsePAM no/g' /etc/ssh/sshd_config

RUN wget --progress=bar:force -P /tools https://mirrors.huaweicloud.com/java/jdk/8u202-b08/jdk-8u202-linux-x64.tar.gz \
    && tar -zxvf jdk-8u202-linux-x64.tar.gz -C /usr/local && sed -i '$aexport JAVA_HOME=/usr/local/jdk1.8.0_202' /etc/profile \
    && sed -i '$aexport PATH=$JAVA_HOME/bin:$PATH' /etc/profile && source /etc/profile

RUN wget --progress=bar:force -P /tools https://go.dev/dl/go1.18.1.linux-amd64.tar.gz \
    && tar -zxvf go1.18.1.linux-amd64.tar.gz -C /usr/local && sed -i '$aexport GO_HOME=/usr/local/go' /etc/profile \
    && sed -i '$a export PATH=$GO_HOME/bin:$PATH' /etc/profile && source /etc/profile

RUN yum install -y nfs-utils
RUN pip3 install --upgrade pip
RUN pip3 install cryptography pyOpenSSL
RUN sed -i '$a export PYTHON3_HOME=/usr/include/python3.6m' /etc/profile

RUN ln -s /usr/bin/gcc /usr/local/bin/gcc && ln -s /usr/bin/g++ /usr/local/bin/g++

RUN touch /opt/bashrc && sed -i '$a ln /dev/sdb /dev/gss-disk1 2>/dev/null' /opt/bashrc
RUN sed -i '$a chmod 777 /dev/gss-disk1' /opt/bashrc
RUN sed -i '$a chmod 666 /var/run/docker.sock' /opt/bashrc

RUN mkdir /cores
RUN mkdir /home/regress
WORKDIR /home/regress

EXPOSE 3306 33060

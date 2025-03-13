FROM centos:8.2.2004 AS buildtag

WORKDIR /tool

RUN yum clean all && touch /root/.curlrc && sed -i "$a insecure" /root/.curlrc && touch /root/.wgetrc && sed -i "$a check_certificate = off" /root/.wgetrc && \
    rm -rf /etc/yum.repos.d/* && curl https://mirrors.huaweicloud.com/repository/conf/CentOS-8-anon.repo > /etc/yum.repos.d/CentOS-Base.repo && \
    echo 'sslverify=False' >> /etc/yum.conf && yum update -y

RUN rm -rf /etc/yum.repos.d/* && curl https://mirrors.huaweicloud.com/repository/conf/CentOS-8-anon.repo > /etc/yum.repos.d/CentOS-Base.repo && yum install -y wget git

RUN git clone https://gitee.com/cantian-repo/dockerbuild.git && \
    cd dockerbuild/third_party && \
    cat boost_1_73_0a* > boost_1_73_0.zip && \
    rm -rf boost_1_73_0a* && \
    mv * /tool && cd - && \
    rm -rf dockerbuild

FROM centos:8.2.2004

ARG BUILD=debug
WORKDIR /tools

COPY --from=buildtag /tool/*.gz /tools/
COPY --from=buildtag /tool/*.zip /tools/
#安装顺序开发工具->编程语言->系统工具->性能分析->安全和权限->库和头文件->容器和集群管理->其他实用工具 \
#    ->内核调试包->特定于系统的库->特定于发行版的软件->不常用的工具->其他
RUN yum clean all && touch /root/.curlrc && sed -i "$a insecure" /root/.curlrc && touch /root/.wgetrc && sed -i "$a check_certificate = off" /root/.wgetrc && \
    rm -rf /etc/yum.repos.d/* && curl https://mirrors.huaweicloud.com/repository/conf/CentOS-8-anon.repo > /etc/yum.repos.d/CentOS-Base.repo && \
    echo 'sslverify=False' >> /etc/yum.conf && mkdir /docker-entrypoint-initdb.d /cores && \
    yum update -y && \
    rm -rf /etc/yum.repos.d/* && curl https://mirrors.huaweicloud.com/repository/conf/CentOS-8-anon.repo > /etc/yum.repos.d/CentOS-Base.repo && \
    tar -zxvf rpcsvc-proto-1.4.tar.gz && \
    tar -zxf doxygen-1.9.2.src.tar.gz && \
    yum install -y vim make gcc gcc-c++ gcc-toolset-10 gdb gdb-gdbserver git cmake libpmem daxio perl-open libcap-devel git-clang-format wget\
    python3 python3-devel perl \
    net-tools iproute iputils nfs-utils unzip openssl ncurses dnf-plugins-core dnf-utils nc openssh-server perf sudo \
    openssl-devel libpmem-devel libaio-devel ncurses-devel libtirpc-devel \
    ndctl ndctl-libs ndctl-devel \
    tree mlocate psmisc gawk jq \
    libibverbs epel-release \
    ant maven bison expect && \
    unzip boost_1_73_0.zip && \
    python3 -m pip install --user --upgrade pip && \
    yum group install -y "Development Tools" && \
    pip3 install cryptography pyOpenSSL && \
    /usr/bin/ssh-keygen -A && \
    debuginfo-install -y libibverbs \
    libpmem libpmem-devel && \
    yum clean all &> /dev/null && \
    cd rpcsvc-proto-1.4 \
    && ./configure && make && make install && cd - && \
    cd doxygen-1.9.2 && mkdir build && cd build \
    && cmake -G "Unix Makefiles" .. && make && cd ../.. && \
    sed -i -e 's/^#Port 22/Port 2200/g' \
    -e 's/^SyslogFacility AUTHPRIV/#SyslogFacility AUTHPRIV/g' \
    -e 's/^#SyslogFacility AUTH/SyslogFacility AUTH/g' \
    -e 's/^UsePAM yes/UsePAM no/g' /etc/ssh/sshd_config && \
    sed -i '$aexport PATH=$JAVA_HOME/bin:$PATH' /etc/profile && \
    sed -i '$a export PYTHON3_HOME=/usr/include/python3.6m' /etc/profile && source /etc/profile && \
    ln -s /usr/bin/gcc /usr/local/bin/gcc && ln -s /usr/bin/g++ /usr/local/bin/g++ && \
    touch /opt/bashrc && sed -i '$a ln /dev/sdb /dev/gss-disk1 2>/dev/null' /opt/bashrc && \
    sed -i '$a chmod 777 /dev/gss-disk1' /opt/bashrc && \
    sed -i '$a chmod 666 /var/run/docker.sock' /opt/bashrc && \
    rm -rf /tools/*.gz /tools/*.zip

VOLUME /var/lib/mysql

WORKDIR /home/regress

EXPOSE 3306 33060

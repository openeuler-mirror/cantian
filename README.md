# Cantian Storage Engine
数据存储加速引擎

# 一、工程说明
- 编程语言：C

- 编译工程：cmake或make，建议使用cmake

- 目录说明：

    -   Cantian：主目录，CMakeLists.txt为主工程入口；
    -   build: 编译构建脚本；
    -   common：管控面脚本；
    -   ct_om：安装部署脚本；
    -   pkg: 源代码目录，按子目录划分模块解耦；

# 二、编译指导<a name="ZH-CN_TOPIC_0000001801512341"></a>




## 2.1 概述<a name="ZH-CN_TOPIC_0000001801631373"></a>

本文档介绍如何对Cantian引擎源码进行编译，生成Cantian引擎软件包。[图1](#fig2092784815585)说明了Cantian引擎的编译流程。
**如需在计算云进行开发者验证调试，请参考第四章**

**图 1**  Cantian引擎编译流程<a name="fig2092784815585"></a>  
![输入图片说明](https://foruda.gitee.com/images/1707301302643678557/8d1658bf_1686238.png "Cantian引擎编译流程.png")
## 2.2 准备编译环境<a name="ZH-CN_TOPIC_0000001754552768"></a>

**硬件要求<a name="section179914360134"></a>**

-   主机数量：1台
-   推荐主机硬件规格：
    -   CPU：4核（64位）
    -   内存：8GB
    -   磁盘空闲空间：100GB

-   ARM架构的主机编译后生成Cantian引擎ARM类型的软件包，X86架构的主机编译后生成Cantian引擎X86类型的软件包

**操作系统要求<a name="section2010693873617"></a>**

Cantian引擎支持的操作系统（Linux 64-bit）如下，建议Cantian引擎的编译操作系统与运行操作系统一致：

-   CentOS 8.2\(x86\_64\)
-   OpenEuler-22.03-LTS\(aarch64\)

**软件要求<a name="section1912447143612"></a>**

Cantian引擎编译过程所依赖的软件如[表1 环境构建依赖](#table169281834113714)所示。

**表 1**  软件依赖

|所需软件|建议版本|说明|
|--|--|--|
|Docker|>=19.03|用于构建、管理、运行Cantian引擎编译镜像和容器。|
|Git|>=2.18.0|用于下载源码。|


## 2.3 版本编译<a name="ZH-CN_TOPIC_0000001754711680"></a>




### 2.3.1 下载源码<a name="ZH-CN_TOPIC_0000001801512345"></a>

本节介绍如何下载Cantian引擎源码以及其他依赖源码。

**前提条件<a name="section17361818184118"></a>**

已在主机正确安装并配置Git软件。

**操作步骤<a name="section16845198174112"></a>**

1.  使用root用户登录主机。
2.  创建并进入源码下载目录。

    此处以将源码下载到目录“/ctdb/cantian\_compile”为例进行说明，您可根据实际环境进行替换。

    ```
    mkdir -p /ctdb/cantian_compile
    cd /ctdb/cantian_compile
    ```

3.  执行以下命令下载Cantian引擎源码。

    ```
    git clone https://gitee.com/openeuler/cantian.git
    ```

1.  执行以下命令下载Cantian-Connector-MySQL源码，用于编译Cantian引擎对接MySQL的插件。

    ```
    git clone https://gitee.com/openeuler/cantian-connector-mysql.git
    ```

1.  进入Cantian-Connector-MySQL源码目录，执行以下命令下载MySQL-8.0.26版本源码，用于编译Cantian引擎对接MySQL的插件。

    ```
    cd cantian-connector-mysql
    wget https://github.com/mysql/mysql-server/archive/refs/tags/mysql-8.0.26.tar.gz --no-check-certificate
    tar -zxf mysql-8.0.26.tar.gz
    ```
### 2.3.2 标题
    mv mysql-server-mysql-8.0.26 mysql-source
    ```
    
    >![输入图片说明](https://foruda.gitee.com/images/1707301851414022105/fc841ea9_1686238.gif "icon-note.gif") **说明：** 
    >Cantian引擎源码和Cantian-Connector-MySQL源码的根目录必须在同级目录下，在该示例中，目录的结构如下：
    >ctdb
    >---- cantian\_compile
    >----------cantian
    >----------cantian-connector-mysql
    >----------------mysql-source

### 2.3.3 准备容器镜像<a name="ZH-CN_TOPIC_0000001817435653"></a>

Cantian引擎仅支持在容器内编译，本节介绍两种准备容器镜像的方法：①通过Cantian-Connector-MySQL源码中的Dockerfile文件自行构建容器镜像；②通过Docker Hub直接获取容器镜像。如果执行编译的主机无法连接网络，则可选择第一种方式，否则两种方式任选其一。

**容器镜像依赖软件介绍<a name="section197590130205"></a>**

如果用户自行制作容器镜像，镜像中需包含[表1](#table169281834113714)中的依赖软件。

**表 1**  容器镜像依赖软件软件

|所需软件|版本|
|--|--|
|CMake|>=3.14.1|
|automake|1.16.1|
|libtool|2.4.6|
|g++|8.5.0|
|libaio-devel|0.3.109-13|
|pkgconfig|0.29.1-3|
|rpm-build|4.14.3|


**前提条件<a name="section17361818184118"></a>**

-   已在主机正确安装并配置docker软件，可参考[Docker官方文档](https://docs.docker.com/engine/)进行安装。
-   已[下载Cantian-Connector-MySQL源码](下载源码.md)。

**使用Dockerfile构建镜像<a name="section11199345189"></a>**

介绍如何使用Dockerfile构建编译容器镜像。

1.  使用root用户登录主机。
2.  执行以下命令进入Dockerfile文件所在目录。

    ```
    cd /code_dir/cantian/docker
    ```

    其中，“_code\_dir_”为源码下载到的目录。

    如，以源码下载到“/ctdb/cantian\_compile”为例，执行以下命令：

    ```
    cd /ctdb/cantian_compile/cantian/docker
    ```

1.  构建容器镜像。
    -   当前主机环境为x86时，执行以下命令：

        ```
        docker build -t cantian_dev:latest -f Dockerfile .
        ```

    -   当前主机环境为arm时，执行以下命令：

        ```
        docker build -t cantian_dev:latest -f Dockerfile_ARM64 .
        ```

2.  构建完成后，执行以下命令查看容器镜像。

    “cantian\_dev“即为构建的容器镜像。

    ```
    docker images
    ```

    回显类似如下：

    ![输入图片说明](https://foruda.gitee.com/images/1707302404781499024/f790cdbe_1686238.png "1705455515494-0.png")

**通过Docker Hub获取镜像<a name="section1585783101812"></a>**

介绍如何通过Docker Hub获取编译容器镜像。

1.  使用root用户登录主机。
2.  从Docker Hub获取编译容器镜像。

    ```
    docker pull ykfnxx/cantian_dev:0.1.0
    ```

1.  设置镜像标签。

    ```
    docker tag ykfnxx/cantian_dev:0.1.0 cantian_dev:latest
    ```

2.  执行以下命令查看容器镜像。

    “cantian\_dev“即为从Docker Hub获取的容器镜像，如图所示。

    ```
    docker images
    ```

    回显类似如下：

    ![输入图片说明](https://foruda.gitee.com/images/1707301524241624886/575c1997_1686238.png "1705455515494.png")

### 2.3.4 编译源码<a name="ZH-CN_TOPIC_0000001754552772"></a>

本节介绍如何在容器环境编译Cantian引擎源码，并生成Cantian引擎软件包。Cantian-Connector作为Cantian引擎运行的必要组件，会在Cantian引擎的自动化编译脚本中一同编译，并打包进Cantian引擎软件包。

**编译脚本介绍<a name="section18900146174715"></a>**

build\_cantian.sh是编译过程中的入口脚本，其集成了软件编译和打包的功能。以sh build\_cantian.sh \[option\]执⾏，\[option\]参数说明如[表1](#table1323046164812)所示。

**表 1**  编译脚本参数说明

|参数选项|功能|
|--|--|
|debug|编译debug版本的软件包，软件包中含有用于调试的符号表文件。|
|release|编译release版本的软件包，软件包中不含有用于调试的符号表文件。|


**前提条件<a name="section17361818184118"></a>**

-   已成功[构建或获取容器镜像](准备容器镜像.md)。
-   已[准备好所有源码](下载源码.md)。

**操作步骤<a name="section7362738114918"></a>**

1.  启动容器。

    Cantian引擎源码提供了容器的启动和初始化脚本container.sh，该脚本可以自动化准备编译Cantian引擎所需的环境设置，推荐使用该脚本启动编译容器。

    1.  使用root用户登录主机。
    2.  执行以下命令进入container.sh所在目录。

        ```
        cd code_dir/cantian/docker
        ```

        其中，“_code\_dir_”为源码下载到的目录。

        如，以源码下载到“/ctdb/cantian\_compile”为例，执行以下命令：

        ```
        cd /ctdb/cantian_compile/cantian/docker
        ```

    3.  执行脚本，启动并进入编译容器。

        ```
        sh container.sh dev
        ```

2.  进入编译脚本目录。

    ```
    cd /home/regress/CantianKernel/build
    ```

1.  执行编译脚本，生成Cantian引擎软件包。

    ```
    sh build_cantian.sh option
    ```

    其中，“_option_”为[表1](#table1323046164812)中的参数选项，指定编译realase或debug版本的软件包。

1.  进入编译目标目录，获取Cantian引擎软件包。

    ```
    cd /tmp/cantian_output
    ```

    回显类似如下表示编译成功：

    ```
    Packing package_name success
    ```

    编译生成的Cantian引擎软件包名如下，请以实际生成的包名为准：

    -   X86：Cantian\__xxx_\_x86\_64\_DEBUG.tgz或Cantian\__xxx_\_x86\_64\_RELEASE.tgz
    -   ARM：Cantian\__xxx_\_aarch64\_DEBUG.tgz或Cantian\_\__xxx_\_aarch64\_RELEASE.tgz

# 三、安装与卸载Cantian引擎<a name="ZH-CN_TOPIC_0000001800412081"></a>




## 3.1 安装前规划<a name="ZH-CN_TOPIC_0000001754837214"></a>

安装Cantian引擎前，请先完成软件和硬件的准备、以及相关的网络和存储规划。



### 3.1.1 组网规划<a name="ZH-CN_TOPIC_0000001779891302"></a>

介绍Cantian引擎规划的原则、硬件的基本配置和软件要求，以及存储设备所需配置的文件系统。

**规划原则<a name="section155871027274"></a>**

规划时，应确保为Cantian引擎规划了如下两个网络平面：

-   Cantian引擎心跳网络：用于部署Cantian引擎的不同数据库服务器之间进行通信。
-   NAS共享网络：进行存储的NAS共享、数据库服务器通过该网络对存储设备进行读写。

**图 1**  逻辑组网图<a name="fig1252163502417"></a>  
![输入图片说明](https://foruda.gitee.com/images/1707301733572311153/567352c2_1686238.png "逻辑组网图.png")

**硬件&软件准备<a name="section1954414863218"></a>**

请在规划时，准备好安装Cantian引擎的硬件基本配置和软件包。

**表 1**  硬件基本配置表

|硬件|数量|备注|
|--|--|--|
|X86服务器/ARM服务器|2|数据库服务器（主机）|
|存储设备|1|-|


对于X86服务器/ARM服务器，推荐使用如下型号或者不低于如下型号性能CPU的服务器：

-   ARM：Kunpeng 920-4826/Kunpeng 920-6426
-   X86：Intel Xeon Gold 6248/Intel Xeon Gold 6348/Intel Xeon Gold 5218/Intel Xeon Gold 6230R

    对于X86服务器，若选择其他型号的CPU，请通过以下命令确认该CPU是否支持constant\_tsc特性，避免因CPU不支持constant\_tsc特性导致数据库服务器的时间精度无法保证。

    ```
    cat /proc/cpuinfo | grep -o constant_tsc | uniq
    ```

    -   若回显包含constant\_tsc字段，则该CPU支持constant\_tsc特性。
    -   若无回显，则该CPU不支持constant\_tsc特性。

**表 2**  软件配置表

|软件|配套版本|
|--|--|
|数据库操作系统|X86：CentOS-8.2.2004-x86_64-dvd1.isoARM：openEuler 2203 sp1|
|数据库软件|参见编译指导编译生成数据库软件。|


对于ARM的“openEuler 2203 sp1”，请登录[OpenEuler](https://www.openeuler.org/zh/download/archive/detail/?version=openEuler%2022.03%20LTS%20SP1)网站，选择“AArch64”架构和“服务器”场景，下载软件包类型为“Offline Standard ISO”的软件包。

>![输入图片说明](https://foruda.gitee.com/images/1707302488160637737/8ec1a8be_1686238.gif "icon-notice.gif") **须知：** 
>-   安装Cantian引擎时，Cantian引擎将安装至路径“/dev/mapper/根目录”（例如：“/dev/mapper/centos-root”），且至少需要20GB空间。在安装数据库操作系统时，请为该路径预留足够的空间（用于安装Cantian引擎以及其他软件），避免因空间不足导致Cantian引擎安装失败。
>-   请确认操作系统上安装的是3.6.0以及之后版本的python。

**文件系统规划<a name="section168254503315"></a>**

安装Cantian引擎时，需要使用存储设备的4个文件系统，请为各个文件系统做好相关的容量规划。

**表 3**  文件系统分配表

|文件系统分类|文件系统名称|容量|个数|功能|
|--|--|--|--|--|
|storage_dbstore_fs|ctdb_dbstore_fs|10TB|1|用于存储Cantian引擎数据的文件系统，容量根据实际业务规划配置。|
|storage_metadata_fs|ctdb_metadata_fs|1TB|1|用于存放MySQL元数据，容量根据实际业务规划配置。|
|storage_share_fs|ctdb_share_fs|2GB|1|用于存放部署Cantian引擎的数据库服务器集群的预留信息，固定2GB大小。|
|storage_archive_fs|ctdb_archive_fs|2TB|1|用于存放归档日志和binlog文件，其中归档日志和binlog文件分别占用50%的空间，建议根据归档日志保留时长及业务量综合评估文件系统大小。|


>![输入图片说明](https://foruda.gitee.com/images/1707301851414022105/fc841ea9_1686238.gif "icon-note.gif") **说明：** 
>此处的文件系统名称和容量仅作为样例进行展示，规划时，请根据实际情况进行设置。

### 3.1.2 规划样例<a name="ZH-CN_TOPIC_0000001788641304"></a>

在有条件的情况下，建议采取交换机冗余连接的组网方式，提升网络的可靠性。同时，设备也支持直接连接的方式进行组网。



#### 3.1.2.1 规划样例（交换机组网）<a name="ZH-CN_TOPIC_0000001780380972"></a>

本节以通过交换机实现冗余连接的组网方式为样例进行介绍，实际规划时请根据需要进行调整。

**组网规划<a name="section1194324019416"></a>**

通过使用双交换机、组成不同环路的方式形成冗余连接，同时使用10GE端口组成Cantian引擎心跳网络和NAS共享网络。

**图 1**  组网规划<a name="fig1252163502417"></a>  
![输入图片说明](https://foruda.gitee.com/images/1707301761837148323/cfe7b10c_1686238.png "组网规划.png")

>![输入图片说明](https://foruda.gitee.com/images/1707301851414022105/fc841ea9_1686238.gif "icon-note.gif") **说明：** 
>通过不同颜色和序号的图标表示不同端口间的线缆连接。例如，Server 01的“eth12”端口和10GE交换机1的“1/0/2”端口使用同一颜色的序号“1”进行了标注，表示组网时，应使用线缆将上述两个端口进行连接。

**硬件准备<a name="section18631529135612"></a>**

组网中使用的硬件设备，应具有足够数目的10GE端口用于完成组网。

**表 1**  硬件配置表

|硬件类别|最低端口数目要求|数量|备注|
|--|--|--|--|
|X86服务器/ARM服务器|6个10GE端口|2|数据库主机（服务器）|
|存储设备|2个10GE端口|1|-|
|业务交换机|9个10GE端口|2|堆叠部署，例如：CE6857交换机|


**服务器地址规划<a name="zh-cn_topic_0000001690293657_zh-cn_topic_0000001519386558_section16225163610514"></a>**

对服务器地址的规划，包含业务网络、Cantian引擎心跳网络和NAS共享网络的地址规划。

>![输入图片说明](https://foruda.gitee.com/images/1707301851414022105/fc841ea9_1686238.gif "icon-note.gif") **说明：** 
>-   业务网络和Cantian引擎心跳网络需要跨接口模块组Bond，使用Bond4模式。
>-   [表2](#table9267104317188)、[表3](#table8643164617188)和[表4](#table331465013188)中“主机”和“物理网口”使用的是[图1](#fig1252163502417)中的设备和端口名。
>-   请对[表2](#table9267104317188)、[表3](#table8643164617188)和[表4](#table331465013188)中分配的不同VLAN的网络进行网络隔离：相同VLAN的网络使用同一网段，不同VLAN的网络不得使用相同的网段。
>-   [表2](#table9267104317188)、[表3](#table8643164617188)和[表4](#table331465013188)的主机、物理网口、绑定网口、VLAN、IP地址和掩码仅为样例进行说明，实际规划时请根据需要进行调整。配置时，请以实际规划为准。

-   业务网络：用作向数据库服务器提供业务，该网络的地址规划如[表2](#table9267104317188)所示。

    **表 2**  业务网络地址规划

|主机|物理网口|绑定网口|VLAN|IP地址|掩码|
|--|--|--|--|--|--|
|server01|eth11eth13|bussiness_bond|10|192.168.10.3|255.255.255.0|
|server02|eth21eth23|bussiness_bond|10|192.168.10.4|255.255.255.0|


-   Cantian引擎心跳网络：用作部署Cantian引擎的数据库服务器间通信，该网络的地址规划如[表3](#table8643164617188)所示。

    **表 3**  Cantian引擎心跳网络地址规划

|主机|物理网口|绑定网口|VLAN|IP地址|掩码|
|--|--|--|--|--|--|
|server01|eth12eth14|cantian_bond|20|192.168.20.2|255.255.255.0|
|server02|eth22eth24|cantian_bond|20|192.168.20.3|255.255.255.0|


-   NAS共享网络：用作共享存储NAS共享，该网络的地址规划如[表4](#table331465013188)所示。

    **表 4**  NAS共享网络地址规划

|主机|物理网口|绑定网口|VLAN|IP地址|掩码|
|--|--|--|--|--|--|
|server01|eth15eth16|storage_bond|77|172.16.77.4|255.255.255.0|
|server01|eth25eth26|storage_bond|77|172.16.77.5|255.255.255.0|


**存储NAS共享网络地址规划<a name="section3947135102914"></a>**

>![输入图片说明](https://foruda.gitee.com/images/1707301851414022105/fc841ea9_1686238.gif "icon-note.gif") **说明：** 
>-   NAS共享网络使用10GE端口，配置接口模块内的绑定和跨接口模块的漂移组。
>-   物理网口名使用组网图中名字，配置时以实际网口名为准。
>-   [表5](#zh-cn_topic_0000001690293657_zh-cn_topic_0000001519386558_table1023015165416)中“物理端口”使用的是[图1](#fig1252163502417)中的端口名。
>-   请对[表5](#zh-cn_topic_0000001690293657_zh-cn_topic_0000001519386558_table1023015165416)中分配的不同VLAN的网络进行网络隔离：相同VLAN的网络使用同一网段，不同VLAN的网络不得使用相同的网段。
>-   此处规划的4个逻辑端口，可分别挂载到绑定网口bond\_nas\_1或bond\_nas\_2上，但同一逻辑端口不能同时挂载到两个绑定网口上。此处以将lgc\_nas\_1和lgc\_nas\_2挂载到bond\_nas\_1、lgc\_nas\_3和lgc\_nas\_4挂载到bond\_nas\_2为例。
>-   [表5](#zh-cn_topic_0000001690293657_zh-cn_topic_0000001519386558_table1023015165416)中的物理端口、绑定网口、逻辑端口、VLAN、IP地址、掩码和DNS侦听仅为样例进行说明，实际规划时请根据需要进行调整。配置时，请以实际规划为准。

**表 5**  存储NAS共享网络地址规划

|物理端口|绑定网口|逻辑端口|VLAN|IP地址|掩码|
|--|--|--|--|--|--|
|eth31|bond_nas_1|lgc_nas_1|77|172.16.77.2|255.255.255.0|
|eth32|bond_nas_1|lgc_nas_2|77|172.16.77.3|255.255.255.0|
|eth33|bond_nas_2|lgc_nas_3|77|172.16.77.4|255.255.255.0|
|eth34|bond_nas_2|lgc_nas_4|77|172.16.77.5|255.255.255.0|


#### 3.1.2.2 规划样例（直连组网）<a name="ZH-CN_TOPIC_0000001785105780"></a>

在未部署交换机的情况下，可通过不同设备间的直接连接进行组网。

**组网规划<a name="section1194324019416"></a>**

在服务器与服务器之间、服务器与存储设备之间，通过连接各个设备的以太端口组成Cantian引擎心跳网络和NAS共享网络。

**图 1**  组网规划<a name="fig1252163502417"></a>  
![输入图片说明](https://foruda.gitee.com/images/1707301785078567079/b344583d_1686238.png "组网规划-1.png")

**硬件准备<a name="section18631529135612"></a>**

组网中使用的硬件设备，应具有足够的端口数目用于完成组网。

**表 1**  硬件配置表

|硬件类别|最低以太端口数目要求|数量|备注|
|--|--|--|--|
|X86服务器/ARM服务器|3|2|数据库主机（服务器）|
|存储设备|2|1|-|


**服务器地址规划<a name="section104681220164116"></a>**

对服务器地址的规划，包含业务网络、Cantian引擎心跳网络和NAS共享网络的地址规划。

>![输入图片说明](https://foruda.gitee.com/images/1707301851414022105/fc841ea9_1686238.gif "icon-note.gif") **说明：** 
>-   [表2](#table9267104317188)、[表3](#table8643164617188)和[表4](#table331465013188)中“主机”和“物理网口”使用的是[图1](#fig1252163502417)中的设备和端口名。
>-   [表2](#table9267104317188)、[表3](#table8643164617188)和[表4](#table331465013188)中“主机”和“物理网口”使用的是[图1](#fig1252163502417)的主机、物理网口、IP地址和掩码仅为样例进行说明，实际规划时请根据需要进行调整。配置时，请以实际规划为准。

-   业务网络：用作向数据库服务器提供业务，该网络的地址规划如[表2](#table9267104317188)所示。

    **表 2**  业务网络地址规划

|主机|物理网口|IP地址|掩码|
|--|--|--|--|
|server01|eth11|192.168.10.3|255.255.255.0|
|server02|eth21|192.168.10.4|255.255.255.0|


-   Cantian引擎心跳网络：用作部署Cantian引擎的数据库服务器间通信，该网络的地址规划如[表3](#table8643164617188)所示。

    **表 3**  Cantian引擎心跳网络地址规划

|主机|物理网口|IP地址|掩码|
|--|--|--|--|
|server01|eth12|192.168.20.2|255.255.255.0|
|server02|eth22|192.168.20.3|255.255.255.0|


-   NAS共享网络：用作共享存储NAS共享，该网络的地址规划如[表4](#table331465013188)所示。

    **表 4**  NAS共享网络地址规划

|主机|物理网口|IP地址|掩码|
|--|--|--|--|
|server01|eth13|172.16.77.4|255.255.255.0|
|server01|eth23|172.16.77.5|255.255.255.0|


**存储NAS共享网络地址规划<a name="section1710120426463"></a>**

>![输入图片说明](https://foruda.gitee.com/images/1707301851414022105/fc841ea9_1686238.gif "icon-note.gif") **说明：** 
>-   [表5](规划样例（交换机组网）.md#zh-cn_topic_0000001690293657_zh-cn_topic_0000001519386558_table1023015165416)中“物理端口”使用的是[图1](#fig1252163502417)中的端口名。
>-   此处规划的逻辑端口，将用于挂载[表3](组网规划.md#zh-cn_topic_0000001690212893_zh-cn_topic_0000001519546530_table86641344117)的4个文件系统。您可以规划4个逻辑端口、每个逻辑端口挂载一个文件系统；也可以只规划1个逻辑端口，同时挂载4个文件系统。此处以规划4个逻辑端口为例进行说明。
>-   [表5](规划样例（交换机组网）.md#zh-cn_topic_0000001690293657_zh-cn_topic_0000001519386558_table1023015165416)中的物理端口、逻辑端口、IP地址、掩码和DNS侦听仅为样例进行说明，实际规划时请根据需要进行调整。配置时，请以实际规划为准。

**表 5**  存储NAS共享网络地址规划

|物理端口|逻辑端口|IP地址|掩码|
|--|--|--|--|
|eth31|lgc_nas_1|172.16.77.2|255.255.255.0|
|eth31|lgc_nas_2|172.16.77.3|255.255.255.0|
|eth31|lgc_nas_3|172.16.77.4|255.255.255.0|
|eth31|lgc_nas_4|172.16.77.5|255.255.255.0|
|eth32|lgc_nas_5|172.16.77.6|255.255.255.0|
|eth32|lgc_nas_6|172.16.77.7|255.255.255.0|
|eth32|lgc_nas_7|172.16.77.8|255.255.255.0|
|eth32|lgc_nas_8|172.16.77.9|255.255.255.0|


## 3.2 安装Cantian引擎<a name="ZH-CN_TOPIC_0000001754996162"></a>

请根据实际的硬件情况和网络规划进行网络配置，并安装Cantian引擎软件。





### 3.2.1 配置10GE交换机<a name="ZH-CN_TOPIC_0000001801796821"></a>

若规划了交换机，请根据规划，将业务网络和Cantian引擎心跳网络、以及NAS共享网络接入10GE交换机，此处以[规划样例（交换机组网）](规划样例（交换机组网）.md)为例、使用CE6857交换机进行配置介绍。

**前提条件<a name="zh-cn_topic_0000001642093132_zh-cn_topic_0000001572428253_zh-cn_topic_0000001571456733_section1319514558493"></a>**

配置前，需确保使用的端口无其他配置，您可以使用**clear configuration interface**命令来一键式清除接口下的配置。

**为与业务网络和Cantian引擎心跳网络连接的交换机端口配置动态LACP模式<a name="zh-cn_topic_0000001642093132_zh-cn_topic_0000001572428253_zh-cn_topic_0000001571456733_section51517816501"></a>**

此处以“10GE 1/0/2”和“10GE 2/0/2”两个端口为例：

配置Trunk21和动态LACP模式，将两个端口的VLAN配置为20并加入Trunk21。完成后，保存配置信息。

```
<SwitchA>system-view 
[~SwitchA]vlan 20 
[*SwitchA]interface Eth-Trunk 21 
[*SwitchA-Eth-Trunk21]port link-type trunk 
[*SwitchA-Eth-Trunk21]port trunk allow-pass vlan 20 
[*SwitchA-Eth-Trunk21]mode lacp-dynamic 
[*SwitchA-Eth-Trunk21]trunkport 10GE 1/0/2 
[*SwitchA-Eth-Trunk21]trunkport 10GE 2/0/2 
[*SwitchA-Eth-Trunk21]commit 
[~SwitchA-Eth-Trunk21]quit 
[~SwitchA]quit 
<SwitchA>save 
Warning: The current configuration will be written to the device. Continue? [Y/N]:y 
Now saving the current configuration to the slot 1 .... 
Info: Save the configuration successfully. 
Now saving the current configuration to the slot 2 ........... 
Info: Save the configuration successfully.
```

>![输入图片说明](https://foruda.gitee.com/images/1707301851414022105/fc841ea9_1686238.gif "icon-note.gif") **说明：** 
>所有规划的要与业务网络和Cantian引擎心跳网络连接的交换机端口，均需进行上述配置并添加规划的VLAN。对端数据库服务器端口的VLAN规划，请参见[表2](规划样例（交换机组网）.md#table9267104317188)和[表3](规划样例（交换机组网）.md#table8643164617188)。

**为与NAS共享网络连接的交换机端口配置静态/动态LACP模式<a name="section1299553311221"></a>**

-   对端为存储设备，配置与存储设备相连的交换机端口的静态LACP模式

    此处以“10GE 1/0/8”和“10GE 2/0/8”两个端口为例：

    配置Trunk30和静态LACP模式，并将Trunk30端口的VLAN配置为77。

    ```
    <SwitchA>system-view 
    [~SwitchA]vlan 77 
    [*SwitchA]interface Eth-Trunk 30 
    [*SwitchA-Eth-Trunk30]port link-type trunk 
    [*SwitchA-Eth-Trunk30]port trunk allow-pass vlan 77 
    [*SwitchA-Eth-Trunk30]mode lacp-static 
    [*SwitchA-Eth-Trunk30]trunkport 10GE 1/0/5 
    [*SwitchA-Eth-Trunk30]trunkport 10GE 2/0/5 
    [*SwitchA-Eth-Trunk30]commit 
    [~SwitchA-Eth-Trunk30]quit 
    [~SwitchA]quit 
    <SwitchA>save 
    Warning: The current configuration will be written to the device. Continue? [Y/N]:y 
    Now saving the current configuration to the slot 1 .... 
    Info: Save the configuration successfully. 
    Now saving the current configuration to the slot 2 ........... 
    Info: Save the configuration successfully.
    ```

    >![输入图片说明](https://foruda.gitee.com/images/1707301851414022105/fc841ea9_1686238.gif "icon-note.gif") **说明：** 
    >所有规划要与存储设备NAS共享网络相连的交换机端口，均需进行上述配置并添加规划的VLAN。对端存储设备端口的VLAN规划，请参见[表5](规划样例（交换机组网）.md#zh-cn_topic_0000001690293657_zh-cn_topic_0000001519386558_table1023015165416)。

-   对端为数据库服务器，配置与数据库服务器相连的交换机端口的动态LACP模式。

    此处以“10GE 1/0/6”和“10GE 2/0/6”两个端口为例：

    配置Trunk31和静态LACP模式，并将Trunk31端口的VLAN配置为77。

    ```
    <SwitchA>system-view 
    [~SwitchA]vlan 77 
    [*SwitchA]interface Eth-Trunk 31 
    [*SwitchA-Eth-Trunk31]port link-type trunk 
    [*SwitchA-Eth-Trunk31]port trunk allow-pass vlan 77 
    [*SwitchA-Eth-Trunk31]mode lacp-dynamic 
    [*SwitchA-Eth-Trunk31]trunkport 10GE 1/0/1 
    [*SwitchA-Eth-Trunk31]trunkport 10GE 2/0/1 
    [*SwitchA-Eth-Trunk31]commit 
    [~SwitchA-Eth-Trunk31]quit 
    [~SwitchA]quit 
    <SwitchA>save 
    Warning: The current configuration will be written to the device. Continue? [Y/N]:y 
    Now saving the current configuration to the slot 1 .... 
    Info: Save the configuration successfully. 
    Now saving the current configuration to the slot 2 ........... 
    Info: Save the configuration successfully.
    ```

    >![输入图片说明](https://foruda.gitee.com/images/1707301851414022105/fc841ea9_1686238.gif "icon-note.gif") **说明：** 
    >所有规划要与数据库服务器NAS共享网络相连的交换机端口，均需进行上述配置并添加规划的VLAN。对端数据库服务器端口的VLAN规划，请参见[表4](规划样例（交换机组网）.md#table331465013188)。

### 3.2.2 配置服务器网络<a name="ZH-CN_TOPIC_0000001832597329"></a>

安装Cantian引擎前，请在数据库服务器上对用于业务网络和Cantian引擎心跳网络、以及NAS共享网络的端口进行配置。



#### 配置服务器网络（交换机组网）<a name="ZH-CN_TOPIC_0000001801875841"></a>

本章节中涉及的交换机、服务器配置，以及使用的VLAN、IP地址等参数的数值均来自[规划样例（交换机组网）](规划样例（交换机组网）.md)中规划的数据，仅作为样例进行展示。实际配置时，请根据实际的硬件配置和网络规划为准。



##### 配置用于NAS共享网络的端口<a name="ZH-CN_TOPIC_0000001801796825"></a>

每台数据库服务器NAS共享网络使用2个10Gb端口，2个端口进行接口模块内组Bond，并采用Bond4模式。

**操作步骤<a name="zh-cn_topic_0000001642093164_zh-cn_topic_0000001572428257_zh-cn_topic_0000001520258314_section983514156578"></a>**

>![输入图片说明](https://foruda.gitee.com/images/1707301851414022105/fc841ea9_1686238.gif "icon-note.gif") **说明：** 
>-   请根据[表4](规划样例（交换机组网）.md#table331465013188)中关于VLAN和IP地址的规划进行配置，此处以服务器“server01”的eth15端口和eth16端口为例进行配置：端口名分别为“eth15”和“eth16”、绑定网口名为“storage\_bond”、端口使用的VLAN为“77”、IP地址为“172.16.77.4”和“172.16.77.5”、子网掩码为“255.255.255.0”。
>-   请重复以下步骤，对另一个服务器上两个用于“NAS共享网络”的端口进行配置。

1.  登录数据库服务器。
2.  依次执行以下命令，创建绑定口。

    ```
    nmcli connection add type bond ifname 绑定网口 mode 802.3ad 
    nmcli connection add type ethernet ifname 端口1 master 绑定网口 
    nmcli connection add type ethernet ifname 端口2 master 绑定网口
    ```

    以绑定网口名为“storage\_bond”的eth15端口和eth16端口为例：

    ```
    [root@host ~]# nmcli connection add type bond ifname storage_bond mode 802.3ad 
    [root@host ~]# nmcli connection add type ethernet ifname eth15 master storage_bond 
    [root@host ~]# nmcli connection add type ethernet ifname eth16 master storage_bond
    ```

3.  修改Bond口配置文件“ifcfg-bond-绑定网口”（例如：ifcfg-bond-storage\_bond），配置文件所在目录/etc/sysconfig/network-scripts/。

    请对如下参数进行修改，其他参数保持不变：

    -   设置“BOOTPROTO”为“none”。
    -   设置“IPV6INIT”为“no”。
    -   设置“IPV6\_AUTOCONF”为“no”。
    -   通过在句首添加“\#”的方式，使“IPV4\_FAILURE\_FATAL=no”、“IPV6\_DEFROUTE=yes”、“IPV6\_FAILURE\_FATAL=no”和“IPV6\_ADDR\_GEN\_MODE=stable-privacy”的内容失效。

    ```
    BONDING_OPTS=mode=802.3ad 
    TYPE=Bond 
    BONDING_MASTER=yes 
    PROXY_METHOD=none 
    BROWSER_ONLY=no 
    BOOTPROTO=none
    DEFROUTE=yes 
    #IPV4_FAILURE_FATAL=no
    IPV6INIT=no
    IPV6_AUTOCONF=no
    #IPV6_DEFROUTE=yes
    #IPV6_FAILURE_FATAL=no
    #IPV6_ADDR_GEN_MODE=stable-privacy
    NAME=storage_bond 
    UUID=fa3ec34f-1180-4d7b-b537-b3be17916d6c 
    DEVICE=storage_bond 
    ONBOOT=yes
    ```

4.  在/etc/sysconfig/network-scripts/目录下，新建VLAN配置文件ifcfg-bond-绑定网口.VLAN，其中，“绑定网口”和“VLAN”为NAS共享网络使用的绑定网口名和VLAN，例如：ifcfg-bond-storage\_bond.77。

    -   设置“TYPE”为“Vlan”。
    -   设置“PHYSDEV”为绑定网口的名字，此处的“PHYSDEV”为“storage\_bond”。
    -   设置“VLAN\_ID”为NAS共享网络使用的VLAN，此处的“VLAN\_ID”为“77”。
    -   设置“BOOTPROTO”为“static”。
    -   设置“IPV4\_FAILURE\_FATAL”为“no”。
    -   设置“NAME”为“绑定网口.VLAN”，此处的“NAME”为“storage\_bond.77”。
    -   设置“DEVICE”为“绑定网口.VLAN”，此处的“DEVICE”为“storage\_bond.77”。
    -   设置“ONBOOT”为“yes”。
    -   设置“VLAN”为“yes”。
    -   设置“IPADDR”为规划的IP地址，此处的“IPADDR”为“172.16.77.4”。
    -   设置“NETMASK”为规划IP地址的子网掩码，此处的“NETMASK”为“255.255.255.0”。

    ```
    TYPE=Vlan
    PHYSDEV=storage_bond
    VLAN_ID=77
    BOOTPROTO=static 
    IPV4_FAILURE_FATAL=no 
    NAME=storage_bond.77 
    DEVICE=storage_bond.77 
    ONBOOT=yes 
    VLAN=yes 
    IPADDR=172.16.77.4 
    NETMASK=255.255.255.0
    ```

5.  依次执行以下命令，重启网络服务。

    ```
    nmcli connection reload 
    nmcli connection up bond-绑定网口 
    nmcli connection up bond-slave-端口1 
    nmcli connection up bond-slave-端口2
    nmcli connection up 绑定网口.VLAN
    ```

    例如：

    ```
    [root@host ~]# nmcli connection reload 
    [root@host ~]# nmcli connection up bond-storage_bond 
    [root@host ~]# nmcli connection up bond-slave-eth15 
    [root@host ~]# nmcli connection up bond-slave-eth16
    [root@host ~]# nmcli connection up storage_bond.77
    ```

    完成重启后，请对存储IP地址进行Ping操作，可以Ping通即配置成功。

    >![输入图片说明](https://foruda.gitee.com/images/1707301851414022105/fc841ea9_1686238.gif "icon-note.gif") **说明：** 
    >以eth15端口和eth16端口为例，[表4](规划样例（交换机组网）.md#table331465013188)中端口的VLAN为77，在对应的[表5](规划样例（交换机组网）.md#zh-cn_topic_0000001690293657_zh-cn_topic_0000001519386558_table1023015165416)中，VLAN为77的“NAS共享网络”IP地址172.16.77.2和172.16.77.3即为进行Ping操作的存储IP地址。

##### 配置用于业务网络和Cantian引擎心跳网络的端口<a name="ZH-CN_TOPIC_0000001754996170"></a>

数据库服务器业务网络和Cantian引擎心跳网络使用10Gb端口，建议在接口模块之间组Bond，并采用Bond4模式。

**操作步骤<a name="zh-cn_topic_0000001690293625_zh-cn_topic_0000001572148265_zh-cn_topic_0000001520257482_section179721130205114"></a>**

>![输入图片说明](https://foruda.gitee.com/images/1707301851414022105/fc841ea9_1686238.gif "icon-note.gif") **说明：** 
>-   请根据[表2](规划样例（交换机组网）.md#table9267104317188)和[表3](规划样例（交换机组网）.md#table8643164617188)中关于VLAN和IP地址的规划进行配置，此处以“业务网络”服务器“server01”的eth11端口和eth13端口为例进行配置：端口名分别为“eth11”和“eth13”、绑定网口名为“bussiness\_bond”、端口使用的VLAN为“10”、IP地址和子网掩码分别为“192.168.10.3”和“255.255.255.0”。
>-   请重复以下步骤，对当前服务器上另一个用于“业务网络”的端口、当前服务器上用于“Cantian引擎心跳网络”的两个端口、以及另一个服务器上用于“业务网络”和“Cantian引擎心跳网络”的各个端口进行配置。

1.  登录数据库服务器。
2.  依次执行以下命令，创建绑定口。

    ```
    nmcli connection add type bond ifname 绑定网口 mode 802.3ad 
    nmcli connection add type ethernet ifname 端口1 master 绑定网口 
    nmcli connection add type ethernet ifname 端口2 master 绑定网口
    ```

    以绑定网口名为“bussiness\_bond”的eth11端口和eth13端口为例：

    ```
    [root@host ~]# nmcli connection add type bond ifname bussiness_bond mode 802.3ad 
    [root@host ~]# nmcli connection add type ethernet ifname eth11 master bussiness_bond 
    [root@host ~]# nmcli connection add type ethernet ifname eth13 master bussiness_bond
    ```

3.  修改Bond口配置文件“ifcfg-bond-绑定网口”（例如：ifcfg-bond-bussiness\_bond），配置文件所在目录/etc/sysconfig/network-scripts/。

    请对如下参数进行修改，其他参数保持不变：

    -   设置“BOOTPROTO”为“none”。
    -   设置“IPV6INIT”为“no”。
    -   设置“IPV6\_AUTOCONF”为“no”。
    -   通过在句首添加“\#”的方式，将“IPV4\_FAILURE\_FATAL=no”、“IPV6\_DEFROUTE=yes”、“IPV6\_FAILURE\_FATAL=no”和“IPV6\_ADDR\_GEN\_MODE=stable-privacy”的内容失效。

    ```
    BONDING_OPTS=mode=802.3ad 
    TYPE=Bond 
    BONDING_MASTER=yes
    PROXY_METHOD=none 
    BROWSER_ONLY=no 
    BOOTPROTO=none 
    DEFROUTE=yes 
    #IPV4_FAILURE_FATAL=no 
    IPV6INIT=no 
    IPV6_AUTOCONF=no 
    #IPV6_DEFROUTE=yes 
    #IPV6_FAILURE_FATAL=no 
    #IPV6_ADDR_GEN_MODE=stable-privacy 
    NAME=bond-bussiness_bond 
    UUID=f4d806b4-66fe-4981-a138-4e0cb1500039 
    DEVICE=bussiness_bond 
    ONBOOT=yes
    ```

4.  在/etc/sysconfig/network-scripts/目录下，新建VLAN配置文ifcfg-bond-绑定网口.VLAN，其中，“绑定网口”和“VLAN”为端口规划的绑定网口名和VLAN，例如：ifcfg-bond-bussiness\_bond.10。

    -   设置“TYPE”为“Vlan”。
    -   设置“PHYSDEV”为绑定网口的名字，此处的“PHYSDEV”为“bussiness\_bond”。
    -   设置“VLAN\_ID”为端口规划的VLAN，此处的“VLAN\_ID”为“10”。
    -   设置“BOOTPROTO”为“static”。
    -   设置“IPV4\_FAILURE\_FATAL”为“no”。
    -   设置“NAME”为“绑定网口.VLAN”，此处的“NAME”为“bussiness\_bond.10”。
    -   设置“DEVICE”为“绑定网口.VLAN”，此处的“DEVICE”为“bussiness\_bond.10”。
    -   设置“ONBOOT”为“yes”。
    -   设置“VLAN”为“yes”。
    -   设置“IPADDR”为规划的IP地址，此处的“IPADDR”为“192.168.10.3”。
    -   设置“NETMASK”为规划IP地址的子网掩码，此处的“NETMASK”为“255.255.255.0”。

    ```
    TYPE=Vlan
    PHYSDEV=bussiness
    VLAN_ID=10
    BOOTPROTO=static 
    IPV4_FAILURE_FATAL=no 
    NAME=bussiness_bond.10 
    DEVICE=bussiness_bond.10 
    ONBOOT=yes 
    VLAN=yes 
    IPADDR=192.168.10.3 
    NETMASK=255.255.255.0
    ```

5.  依次执行以下命令，重启网络服务，对其他配置完成的同平面IP进行Ping，可以Ping通即配置成功。

    ```
    nmcli connection reload 
    nmcli connection up bond-绑定网口 
    nmcli connection up bond-slave-端口1 
    nmcli connection up bond-slave-端口2
    nmcli connection up 绑定网口.VLAN
    ```

    例如：

    ```
    [root@host ~]# nmcli connection reload 
    [root@host ~]# nmcli connection up bond-bussiness_bond 
    [root@host ~]# nmcli connection up bond-slave-eth11 
    [root@host ~]# nmcli connection up bond-slave-eth13
    [root@host ~]# nmcli connection up bussiness_bond.10
    ```

    完成重启后，请对其他配置完成的同平面IP地址进行Ping操作，可以Ping通即配置成功。

    >![输入图片说明](https://foruda.gitee.com/images/1707301851414022105/fc841ea9_1686238.gif "icon-note.gif") **说明：** 
    >以eth11端口和eth13端口为例，[表2](规划样例（交换机组网）.md#table9267104317188)中，上述端口VLAN为10、所在服务器“server01”的IP地址为192.168.10.3，另一服务器“server02”VLAN为10的IP地址为192.168.10.4，其中，192.168.10.4即为进行Ping操作的同平面IP地址。

#### 配置服务器网络（直连组网）<a name="ZH-CN_TOPIC_0000001832218313"></a>



##### 配置用于NAS共享网络的端口<a name="ZH-CN_TOPIC_0000001785538994"></a>

**操作步骤<a name="zh-cn_topic_0000001642093164_zh-cn_topic_0000001572428257_zh-cn_topic_0000001520258314_section983514156578"></a>**

>![输入图片说明](https://foruda.gitee.com/images/1707301851414022105/fc841ea9_1686238.gif "icon-note.gif") **说明：** 
>-   请根据[表4](规划样例（直连组网）.md#table331465013188)中IP地址的规划进行配置，此处以服务器“server01”的eth13端口为例进行配置：端口名为“eth13”、IP地址为“172.16.77.4”、子网掩码为“255.255.255.0”。
>-   请重复以下步骤，对另一个服务器上用于“NAS共享网络”的端口进行配置。

1.  登录数据库服务器。
2.  在/etc/sysconfig/network-scripts/目录下，修改已存在的VLAN配置文件“ifcfg-端口名”，其中，“端口名”为NAS共享网络使用的物理网口名，例如：ifcfg-eth13。

    请对如下参数进行修改：

    -   设置“BOOTPROTO”为“none”。
    -   设置“ONBOOT”为“yes”。
    -   设置“IPADDR”为规划的IP地址，此处的“IPADDR”为“172.16.77.4”。
    -   设置“NETMASK”为规划IP地址的子网掩码，此处的“NETMASK”为“255.255.255.0”。

    其他参数保持不变。

    ```
    TYPE=Ethernet
    PROXY_METHOD=none
    BROWSER_ONLY=no
    BOOTPROTO=none
    DEFROUTE=yes
    IPV6INIT=no
    IPV6_AUTOCONF=no
    NAME=eth13
    UUID=6974c94d-9cb1-4316-b0c7-865bea8f994a
    DEVICE=eth13
    ONBOOT=yes
    IPADDR=172.16.77.4
    NETWORKMASK=255.255.255.0
    ```

3.  依次执行以下命令，重启网络服务。

    ```
    nmcli connection reload 
    nmcli connection up 端口号 
    ```

    例如：

    ```
    [root@host ~]# nmcli connection reload 
    [root@host ~]# nmcli connection up eth13
    ```

    完成重启后，请对存储IP地址进行Ping操作，可以Ping通即配置成功。

    >![输入图片说明](https://foruda.gitee.com/images/1707301851414022105/fc841ea9_1686238.gif "icon-note.gif") **说明：** 
    >以eth13端口为例，根据[图1](规划样例（直连组网）.md#fig1252163502417)的规划，该端口的对端端口为eth31，在对应的[表5](规划样例（直连组网）.md#table161473316461)中，eth31端口的IP地址即为进行Ping操作的存储IP地址。

##### 配置用于业务网络和Cantian引擎心跳网络的端口<a name="ZH-CN_TOPIC_0000001785698650"></a>

**操作步骤<a name="zh-cn_topic_0000001690293625_zh-cn_topic_0000001572148265_zh-cn_topic_0000001520257482_section179721130205114"></a>**

>![输入图片说明](https://foruda.gitee.com/images/1707301851414022105/fc841ea9_1686238.gif "icon-note.gif") **说明：** 
>-   请根据[表2](规划样例（直连组网）.md#table9267104317188)和[表3](规划样例（直连组网）.md#table8643164617188)中IP地址的规划进行配置，此处以“业务网络”服务器“server01”的eth11端口为例进行配置：端口名为“eth11”、IP地址和子网掩码分别为“192.168.10.3”和“255.255.255.0”。
>-   请重复以下步骤，对当前服务器上用于“Cantian引擎心跳网络”的端口、以及另一个服务器上用于“业务网络”和“Cantian引擎心跳网络”的各个端口进行配置。

1.  登录数据库服务器。
2.  在/etc/sysconfig/network-scripts/目录下，修改已存在的VLAN配置文件“ifcfg-端口名”，其中，“端口名”为业务网络或Cantian引擎心跳网络使用的物理网口名，例如：ifcfg-eth11。

    请对如下参数进行修改：

    -   设置“BOOTPROTO”为“none”。
    -   设置“ONBOOT”为“yes”。
    -   设置“IPADDR”为规划的IP地址，此处的“IPADDR”为“192.168.10.3”。
    -   设置“NETMASK”为规划IP地址的子网掩码，此处的“NETMASK”为“255.255.255.0”。

    其他参数保持不变。

    ```
    TYPE=Ethernet
    PROXY_METHOD=none
    BROWSER_ONLY=no
    BOOTPROTO=none
    DEFROUTE=yes
    IPV6INIT=no
    IPV6_AUTOCONF=no
    NAME=eth11
    UUID=6974c94d-9cb1-4316-b0c7-865bea8f994a
    DEVICE=eth11
    ONBOOT=yes
    IPADDR=192.168.10.3
    NETWORKMASK=255.255.255.0
    ```

3.  依次执行以下命令，重启网络服务。

    ```
    nmcli connection reload 
    nmcli connection up 端口号 
    ```

    例如：

    ```
    [root@host ~]# nmcli connection reload 
    [root@host ~]# nmcli connection up eth11
    ```

    完成重启后，请对其他配置完成的同平面IP地址进行Ping操作，可以Ping通即配置成功。

    >![输入图片说明](https://foruda.gitee.com/images/1707301851414022105/fc841ea9_1686238.gif "icon-note.gif") **说明：** 
    >以eth11端口为例，根据[图1](规划样例（直连组网）.md#fig1252163502417)的线缆连接，eth11端口的对端端口为“业务下发设备”的eth01端口，eth01端口的IP地址即为进行Ping操作的同平面IP地址。

### 3.2.3 配置存储网络<a name="ZH-CN_TOPIC_0000001802782129"></a>

在部署Cantian引擎前，您还需在存储设备上进行如下的配置：

-   启用NFSv4.0及NFSv4.1服务。
-   创建[表3](组网规划.md#zh-cn_topic_0000001690212893_zh-cn_topic_0000001519546530_table86641344117)中规划的不同用途的文件系统，并为各个文件系统创建NFS共享。
-   创建用于挂载[表3](组网规划.md#zh-cn_topic_0000001690212893_zh-cn_topic_0000001519546530_table86641344117)中规划的各个文件系统的逻辑端口。

### 3.2.4 部署Cantian引擎<a name="ZH-CN_TOPIC_0000001801875845"></a>

**前提条件<a name="zh-cn_topic_0000001690212877_zh-cn_topic_0000001521308384_zh-cn_topic_0000001571256873_section14896551532"></a>**

-   在Cantian引擎部署到数据库服务器前，请确保各个数据库服务器的时间一致，否则在数据库服务器故障、cms进程故障、网络故障时，时间偏大的数据库服务器会被自动移出集群。
-   已准备好CRT证书和CA证书。
-   服务器上未创建目录“/dev/shm”，或服务器上已存在目录“/dev/shm”且用户具有该目录及文件的drwxrwxrwt权限：
    1.  若存在目录“/dev/shm”，进入该目录并执行以下命令，查看用户是否拥有drwxrwxrwt权限。

        ```
        ll /dev/ | grep shm
        ```

        回显样例如下：

        ```
        [root@node1 shm]# ll
        drwxrwxrwt    2     root  root                               40   Feb  1  15:10   shm
        ```

    2.  若用户没有drwxrwxrwt权限，请执行以下命令修改用户目录权限：

        ```
        chmod 777 /dev/shm
        ```

-   python的依赖库pyopenssl和cryptography已存在：
    1.  执行以下命令，确认python的依赖库pyopenssl和cryptography是否存在。

        ```
        pip show pyopenssl
        pip show cryptography
        ```

        若回显显示“Package\(s\) not found:”，表示对应的依赖库不存在。

        例如，当pyopenssl依赖库不存在，回显如下：

        ```
        [root@node1 shm]# pip show pyopenssl
        WARNING: Package(s) not found: pyopenssl
        ```

    2.  若缺少依赖库pyopenssl或cryptography，请执行以下命令分别进行安装：

        ```
        pip3 install pyopenssl --trusted-host=mirrors.huaweicloud.com -i https://mirrors.huaweicloud.com/repository/pypi/simple/
        pip3 install cryptography --trusted-host=mirrors.huaweicloud.com -i https://mirrors.huaweicloud.com/repository/pypi/simple/
        ```

**操作步骤<a name="zh-cn_topic_0000001690212877_zh-cn_topic_0000001521308384_zh-cn_topic_0000001571256873_section186051491142"></a>**

1.  登录第一台数据库服务器。
2.  <a name="li57931725703"></a>通过执行以下命令，创建新的用户和组，以ctdba:ctdba为例。建议为用于安装Cantian引擎的各个数据库服务器设置相同的用户和组。

    >![输入图片说明](https://foruda.gitee.com/images/1707302488160637737/8ec1a8be_1686238.gif "icon-notice.gif") **须知：** 
    >使用useradd命令时，此处参数的取值必须与MySQL中进程“mysqld”的运行用户id保持一致。此处以5000为例进行说明，具体配置时以实际的运行用户id为准。

    ```
    useradd -m -u 5000 -d /home/ctdba ctdba
    ```

3.  执行以下命令，设置数据库服务器的hostname。

    >![输入图片说明](https://foruda.gitee.com/images/1707302488160637737/8ec1a8be_1686238.gif "icon-notice.gif") **须知：** 
    >为用于安装Cantian引擎的各个数据库服务器设置hostname时，不同数据库服务器的hostname应设置为不同的值，避免因hostname相同导致Cantian引擎安装失败。

    ```
    hostnamectl set-hostname name 
    ```

    其中，“name”为设置的数据库服务器hostname。

4.  <a name="zh-cn_topic_0000001690212877_zh-cn_topic_0000001521308384_li168751833144317"></a>执行以下命令，上传Cantian引擎安装包并解压。

    ```
    mkdir path
    chmod 755 path
    cd path
    tar -zxvf Installation Package
    ```

    其中，“path”为安装包的上传路径，“Installation Package”为[编译指导](编译指导.md)中编译生成的软件包。

    此处以软件包名称为“Cantian\_24.03\_x86\_64\_RELEASE.tgz”、将包放到目录“/ctdb/cantian\_install”为例进行说明。最终的参数配置以[编译指导](编译指导.md)中编译生成的软件包和实际的安装路径为准。

    ```
    [root@host ~]# mkdir /ctdb/cantian_install
    [root@host ~]# chmod 755 /ctdb/cantian_install
    [root@host ~]# cd /ctdb/cantian_install
    [root@host  ]# tar -zxvf Cantian_24.03_x86_64_RELEASE.tgz
    ```

5.  修改配置文件config\_params\_file.json，相关参数如[表1](#zh-cn_topic_0000001690212877_zh-cn_topic_0000001521308384_zh-cn_topic_0000001571256873_table111125312412)所示。

    配置文件的所在路径与[4](#zh-cn_topic_0000001690212877_zh-cn_topic_0000001521308384_li168751833144317)中Cantian引擎安装包的存放路径相关，以安装包的存放路径是“/ctdb/cantian\_install”为例：该文件的所在路径为：/ctdb/cantian\_install/cantian\_connector/action/config\_params\_file.json。

    **表 1**  config\_params\_file.json文件参数说明

|参数名称|参数说明|
|--|--|
|deploy_mode|部署模式：请将部署模式设置为“NAS”。|
|deploy_user|2中创建的数据库配置的“用户:用户组”，例如：“ctdba:ctdba”。|
|node_id|部署Cantian引擎的数据库服务器id，两个数据库服务器分别设置成0和1。请将登录的第一台数据库服务器的node_id设置为0、登录的第二台数据库服务器的node_id设置为1。|
|cms_ip|在规划样例中规划的“Cantian引擎心跳网络”IP地址，即数据库服务器间的通信IP。填写参数时，所有数据库服务器间的通信IP均需填入，比如“192.168.20.2,192.168.20.3”。请先填入node_id为0的数据库服务器IP、再填入node_id为1的数据库服务器IP，上述示例中，192.168.20.2为node_id为0的数据库服务器IP，192.168.20.3为node_id为1的数据库服务器IP。|
|storage_dbstore_fs|Cantian引擎使用的存储文件系统名称。该文件系统应在配置存储网络进行了创建，请填写创建该文件系统时使用的名称。每个文件系统只能部署一个Cantian引擎。完成部署后，请勿修改文件系统的名称、以及NFS共享的名称。|
|storage_share_fs|cms共享数据使用的存储文件系统名称。该文件系统应在配置存储网络进行了创建，请填写创建该文件系统时使用的名称。每个文件系统只能部署一个Cantian引擎。完成部署后，请勿修改文件系统的名称、以及NFS共享的名称。|
|storage_archive_fs|归档使用的存储文件系统名称。该文件系统应在配置存储网络进行了创建，请填写创建该文件系统时使用的名称。每个文件系统只能部署一个Cantian引擎。完成部署后，请勿修改文件系统的名称、以及NFS共享的名称。|
|storage_metadata_fs|用于存放MySQL元数据的文件系统名称。该文件系统应在配置存储网络进行了创建，请填写创建该文件系统时使用的名称。每个文件系统只能部署一个Cantian引擎。完成部署后，请勿修改文件系统的名称、以及NFS共享的名称。|
|mysql_in_container|MySQL是否安装在容器内，“0”表示安装在数据库服务器上，“1”表示安装在容器内。默认值为“0”。|
|share_logic_ip|挂载storage_share_fs文件系统的逻辑端口的IP。该逻辑IP应在配置存储网络进行了设置，请填写设置的逻辑IP值。|
|archive_logic_ip|挂载storage_archive_fs文件系统的逻辑端口的IP。该逻辑IP应在配置存储网络进行了设置，请填写设置的逻辑IP值。|
|metadata_logic_ip|挂载storage_metadata_fs文件系统的逻辑端口的IP。该逻辑IP应在配置存储网络进行了设置，请填写设置的逻辑IP值。|
|storage_logic_ip|挂载storage_dbstore_fs文件系统的逻辑端口的IP。该逻辑IP应在配置存储网络进行了设置，请填写设置的逻辑IP值。|
|db_type|数据库类型，“0”表示性能模式，“1”表示开启归档模式。默认值为“0”。若需要使用Cantian引擎的数据备份功能，请将该参数设置为“1”。|
|mysql_metadata_in_cantian|请将该参数设置为“false”，否则将影响MySQL的对接。|
|MAX_ARCH_FILES_SIZE|单节点归档的最大容量，建议设置为storage_archive_fs文件系统中用于存放归档日志空间的45%。若超过了该最大容量，将按归档日志生成的先后顺序、自动删除部分归档日志。|
|ca_path|存放CA证书的位置，例如："/opt/certificate/ca.crt"。|
|crt_path|存放CRT证书的位置，例如："/opt/certificate/mes.crt"。|
|key_path|存放CRT证书私钥的位置，例如："/opt/certificate/mes.key"。|
|redo_num|单节点的redo文件的数目。|
|redo_size|单节点的redo文件的容量。|


6.  <a name="zh-cn_topic_0000001690212877_zh-cn_topic_0000001521308384_zh-cn_topic_0000001571256873_li1417111015314"></a>执行以下命令，进行Cantian引擎的安装：
    -   若是首次安装Cantian引擎、或上次是通过override方式卸载了Cantian引擎，请执行以下命令进行安装：

        ```
        sh path/cantian_connector/action/appctl.sh install path/cantian_connector/action/config_params_file.json
        ```

        其中，“path”为[4](#zh-cn_topic_0000001690212877_zh-cn_topic_0000001521308384_li168751833144317)中安装包的上传路径，以该路径是“/ctdb/cantian\_install”为例：

        ```
        [root@host ~]# sh /ctdb/cantian_install/cantian_connector/action/appctl.sh install /ctdb/cantian_install/cantian_connector/action/config_params_file.json
        ```

        根据回显的提示，依次输入：

        1.  <a name="zh-cn_topic_0000001690212877_zh-cn_topic_0000001521308384_zh-cn_topic_0000001571256873_li5142123395716"></a>创建数据库系统管理员sys用户的密码。
        2.  确认[6.a](#zh-cn_topic_0000001690212877_zh-cn_topic_0000001521308384_zh-cn_topic_0000001571256873_li5142123395716)中新建的密码。
        3.  CRT证书私钥的密码。

        脚本运行完成后，最后回显“install success”即安装成功。

    -   若上次是通过reserve方式卸载了Cantian引擎，请执行以下命令进行安装：

        ```
        sh path/cantian_connector/action/appctl.sh install reserve
        ```

        其中，“path”为[4](#zh-cn_topic_0000001690212877_zh-cn_topic_0000001521308384_li168751833144317)中安装包的上传路径，以该路径是“/ctdb/cantian\_install”为例：

        ```
        [root@host ~]# sh /ctdb/cantian_install/cantian_connector/action/appctl.sh install reserve
        ```

        脚本运行完成后，最后回显“install success”即安装成功。

7.  登录另一台数据库服务器，重复执行[2](#li57931725703)\~[6](#zh-cn_topic_0000001690212877_zh-cn_topic_0000001521308384_zh-cn_topic_0000001571256873_li1417111015314)，在另一台数据库服务器上安装Cantian引擎。
8.  两台数据库服务器均完成Cantian引擎的安装后，别在两台数据库服务上执行以下命令启动Cantian引擎。

    ```
    sh /opt/cantian/action/appctl.sh start
    ```

    >![输入图片说明](https://foruda.gitee.com/images/1707302488160637737/8ec1a8be_1686238.gif "icon-notice.gif") **须知：** 
    >-   请先在node\_id为0的数据库服务器成功启动Cantian引擎后，再在node\_id为1的数据库服务器启动Cantian引擎。
    >-   用于启动Cantian引擎的命令，与Cantian引擎安装包的上传路径无关。

    您可以通过以下步骤查询相关启动任务是否完成、集群状态是否正常，判断Cantian引擎是否启动成功：

    1.  执行以下命令，查看Cantian引擎的系统定时任务是否完成启动。

        ```
        systemctl status cantian.timer
        ```

        若“Active”的回显内容为“active”，表示系统定时任务启动完成。例如：

        ```
        systemctl status cantian.timer
        [root@host ~]# systemctl status cantian.timer
          cantian.timer - Run every 5s and on boot
          Loaded: loaded (/etc/systemd/system/cantian.timer; enabled; vendor preset: disabled)
          Active: active (waiting) since Mon 2024-02-05 05:45:34 EST; 20h ago
        Trigger: Tue 2024-02-06 02:43:37 EST; 3s left
        ```

    2.  执行以下命令，查看Cantian引擎的日志监控任务是否完成启动。

        ```
        systemctl status cantian_logs_handler.timer
        ```

        若“Active”的回显内容为“active”，表示日志监控任务启动完成。例如：

        ```
        [root@host ~]# systemctl status cantian_logs_handler.timer 
          cantian_logs_handler.timer - Run every 60minutes and on boot
          Loaded: loaded (/etc/systemd/system/cantian_logs_handler.timer; enabled; vendor preset: disabled)
          Active: active (waiting) since Mon 2024-02-05 05:45:35 EST; 20h ago
        Trigger: Tue 2024-02-06 02:45:45 EST; 1min 42s left
        ```

    3.  依次执行以下命令，切换为cantian用户后，查看Cantian引擎的集群状态是否正常。

        ```
        su -s /bin/bash - cantian
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

## 3.3 卸载Cantian引擎<a name="ZH-CN_TOPIC_0000001754837234"></a>

系统支持通过override方式或reserve方式卸载Cantian引擎。卸载时，请在两台数据库服务器上使用相同的方式对Cantian引擎进行卸载。



### 3.3.1 通过override方式卸载Cantian引擎<a name="ZH-CN_TOPIC_0000001801796829"></a>

若无需对数据库服务器的数据进行备份，请通过override方式卸载Cantian引擎。

**注意事项<a name="zh-cn_topic_0000001641933898_zh-cn_topic_0000001583378605_section4654154113292"></a>**

-   卸载Cantian引擎前，请确保上层业务已停止。
-   Cantian引擎卸载后，所有的用户配置、数据库数据将会被清除，请谨慎操作。

**操作步骤<a name="zh-cn_topic_0000001641933898_zh-cn_topic_0000001583378605_section39361939192815"></a>**

1.  登录数据库服务器。
2.  <a name="zh-cn_topic_0000001641933898_zh-cn_topic_0000001583378605_li3936133912813"></a>执行以下命令，停止数据库服务器上运行的Cantian引擎。

    ```
    sh /opt/cantian/action/appctl.sh stop
    ```

3.  登录另一台数据库服务器，重复执行[2](#zh-cn_topic_0000001641933898_zh-cn_topic_0000001583378605_li3936133912813)，停止另一台数据库服务器上运行的Cantian引擎。
4.  依次在两台数据库服务器上执行以下命令，卸载数据库服务器上安装的Cantian引擎。

    ```
    sh /opt/cantian/action/appctl.sh uninstall override
    ```

5.  （可选）若卸载失败，请执行下列命令进行强制卸载。

    ```
    sh /opt/cantian/action/appctl.sh uninstall override force
    ```

    若依然无法卸载，请联系技术工程师。

### 3.3.2 通过reserve方式卸载Cantian引擎<a name="ZH-CN_TOPIC_0000001754996174"></a>

若需对数据库服务器的数据进行备份，请通过reserve方式卸载Cantian引擎。

**操作步骤<a name="zh-cn_topic_0000001690293593_zh-cn_topic_0000001583138609_section187473011390"></a>**

1.  登录数据库服务器。
2.  <a name="zh-cn_topic_0000001690293593_zh-cn_topic_0000001583138609_li138742030173919"></a>执行以下命令，对数据库服务器的数据进行备份。

    ```
    sh /opt/cantian/action/appctl.sh backup
    ```

3.  <a name="zh-cn_topic_0000001690293593_zh-cn_topic_0000001583138609_li14874153016395"></a>执行以下数据，停止数据库服务器上运行的Cantian引擎。

    ```
    sh /opt/cantian/action/appctl.sh stop
    ```

4.  登录另一台数据库服务器，重复执行[2](#zh-cn_topic_0000001690293593_zh-cn_topic_0000001583138609_li138742030173919)和[3](#zh-cn_topic_0000001690293593_zh-cn_topic_0000001583138609_li14874153016395)，停止另一台数据库服务器上运行的Cantian引擎。
5.  依次在两台数据库服务器上执行以下命令，卸载数据库服务器上安装的Cantian引擎。

    ```
    sh /opt/cantian/action/appctl.sh uninstall reserve
    ```

    若无法卸载，请联系技术工程师。

# 四、对接MySQL<a name="ZH-CN_TOPIC_0000001800412089"></a>



## 4.1 安装MySQL<a name="ZH-CN_TOPIC_0000001753452360"></a>

请安装与Cantian引擎匹配的8.0.26版本的MySQL。

>![输入图片说明](https://foruda.gitee.com/images/1707302488160637737/8ec1a8be_1686238.gif "icon-notice.gif") **须知：** 
>请根据[编译源码](编译源码.md)中生成的软件包版本类型（realase或debug版本），安装对应版本类型的MySQL。

## 4.2 加载插件依赖库<a name="ZH-CN_TOPIC_0000001786761450"></a>

Cantian引擎支持通过物理方式和容器方式加载插件依赖库。


### 4.2.1 通过物理方式加载插件依赖库<a name="ZH-CN_TOPIC_0000001808214541"></a>

本章节介绍在数据库服务器上如何通过直接加载或启动MySQL进程的方式加载插件依赖库。

**前提条件<a name="section71229291314"></a>**

-   将如下的文件分别拷贝到插件路径下。

    -   /opt/cantian/mysql/server/plugin/ha\_ctc.so
    -   /opt/cantian/image/cantian\_connector/for\_mysql\_official/mf\_connector\_mount\_dir/cantian\_lib/libctc\_proxy.so
    -   /opt/cantian/image/cantian\_connector/for\_mysql\_official/mf\_connector\_mount\_dir/cantian\_lib/libsecurec.so
    -   /opt/cantian/image/cantian\_connector/for\_mysql\_official/mf\_connector\_mount\_dir/cantian\_lib/libsecurec.a

    拷贝完成后，请确保对上述文件的读写权限、与对插件目录下原有的其他文件的读写权限相同。

-   在数据库服务器的MySQL安装目录下，获取libmysqlclient.so.21文件的所在路径，并将该文件拷贝至插件路径下。若libmysqlclient.so.21不存在，请安装对应操作系统的相关MySQL软件包。

>![输入图片说明](https://foruda.gitee.com/images/1707301851414022105/fc841ea9_1686238.gif "icon-note.gif") **说明：** 
>MySQL的插件路径为“.../mysql/lib/plugin”，完整的插件路径与MySQL的安装路径相关。例如，MySQL安装在“/usr/local/”路径下，则完整的插件路径为“/usr/local/mysql/lib/plugin”

**操作步骤<a name="section105551441133815"></a>**

1.  登录第一台数据库服务器。
2.  <a name="li95222027105913"></a>进入目录“/dev/shm”，执行以下命令，确认用户拥有该目录及文件的rw（读写）权限。

    ```
    ll
    ```

    回显样例如下：

    ```
    [root@node1 shm]# ll
    total 1796964
    -rw-rw---- 1 cantian cantiandba 4003037184 Dec 29 00:53 cantian.0
    -rw-rw---- 1 cantian cantiandba 4003037184 Dec 29 01:14 cantian.1
    -rw-rw---- 1 cantian cantiandba 4003037184 Dec 29 01:14 cantian.2
    -rw-rw---- 1 cantian cantiandba 4003037184 Dec 29 01:10 cantian.3
    -rw-rw---- 1 cantian cantiandba 4003037184 Dec 29 00:40 cantian.4
    -rw-rw---- 1 cantian cantiandba 4003037184 Dec 29 00:37 cantian.5
    -rw-rw---- 1 cantian cantiandba 4003037184 Dec 29 00:43 cantian.6
    -rw-rw---- 1 cantian cantiandba 4003037184 Dec 29 01:09 cantian.7
    -rw-rw---- 1 cantian cantiandba 4003037184 Dec 28 22:45 cantian.8
    -rw-rw---- 1 cantian cantiandba        378 Dec 28 22:39 cantian_shm_config_0.txt
    -rw-rw---- 1 cantian cantiandba        378 Dec 28 22:39 cantian_shm_config_1.txt
    srw-rw---- 1 cantian cantiandba          0 Dec 28 22:39 cantian.shm_unix_sock
    ```

3.  <a name="li142421623195811"></a>加载插件ctc.so的依赖库。

    >![输入图片说明](https://foruda.gitee.com/images/1707302488160637737/8ec1a8be_1686238.gif "icon-notice.gif") **须知：** 
    >执行以下命令前，请确认MySQL配置文件里面配置的用户和组具有读写权限。若没有读写权限，请对配置文件进行修改，并在修改后重启mysqld进程。

    -   方法一：打开MySQL客户端，依次执行以下命令，直接加载插件ctc.so的依赖库。

        ```
        install plugin ctc_ddl_rewriter soname 'ha_ctc.so'
        install plugin CTC soname 'ha_ctc.so'
        ```

    -   方法二：通过启动MySQL进程、加载插件ctc.so的依赖库。
        1.  执行以下命令，初始化MySQL。

            ```
            mysqld_binary_path --defaults-file=configuration_file_path --initialize-insecure --datadir=data_path
            ```

            参数说明：

            -   mysqld\_binary\_path：启动MySQL的二进制文件路径。
            -   configuration\_file\_path：配置文件路径。
            -   data\_path：数据路径。

            例如：

            ```
            /usr/local/mysql/bin/mysqld --defaults-file=/ctdb/cantian_install/mysql-server/scripts/my.cnf --initialize-insecure --datadir=/data/data
            ```

        2.  执行以下命令，启动MySQL。

            ```
            mysqld_binary_path --defaults-file=onfiguration_file_path --datadir=data_path --plugin-dir=mysqld_plugin_path --plugin_load="ctc_ddl_rewriter=ha_ctc.so;ctc=ha_ctc.so;" -- check_proxy_users=ON --mysql_native_password_proxy_users=ON --default-storage-engine=CTC
            ```

            参数说明：

            -   mysqld\_binary\_path：启动MySQL的二进制文件路径。
            -   configuration\_file\_path：配置文件路径。
            -   data\_path：数据路径。
            -   mysqld\_plugin\_path：插件路径。

            例如：

            ```
            /usr/local/mysql/bin/mysqld --defaults-file=/ctdb/cantian_install/mysql-server/scripts/my.cnf --datadir=/data/data --plugin-dir=/usr/local/mysql/lib/plugin --plugin_load="ctc_ddl_rewriter=ha_ctc.so;ctc=ha_ctc.so;" -- check_proxy_users=ON --mysql_native_password_proxy_users=ON --default-storage-engine=CTC
            ```

4.  登录另一台数据库服务器，重复执行[2](#li95222027105913)和[3](#li142421623195811)，为另一台数据库服务器加载插件ha\_ctc.so的依赖库。

# 五、健康巡检<a name="ZH-CN_TOPIC_0000001755835620"></a>

通过脚本对Cantian引擎执行健康巡检，以便了解Cantian引擎各模块的运行状态。

**前提条件<a name="zh-cn_topic_0000001641933798_section1819813364111"></a>**

Cantian引擎已正确安装且正常运行。

**背景信息<a name="zh-cn_topic_0000001641933798_section89072273713"></a>**

-   针对单个节点进行一键巡检或指定巡检项巡检。
-   物理机Cantian引擎巡检和MySQL容器巡检有差异，指令不同。
-   物理机Cantian引擎巡检使用cantian用户执行，MySQL容器内巡检使用root用户执行。
-   一键巡检成功后会生成巡检文件记录巡检结果，默认仅保留最近9个巡检结果文件。
-   容器部署MySQL的场景，支持对Cantian引擎以及MySQL进行巡检。物理机部署MySQL的场景，仅支持对Cantian引擎进行巡检。

**巡检Cantian引擎<a name="zh-cn_topic_0000001641933798_section2502154624517"></a>**

1.  以SSH方式（如PuTTY），依次登录所有Cantian引擎节点。
2.  执行以下命令切换至**cantian**帐号。

    ```
    su -s /bin/bash cantian
    ```

3.  依次在所有Cantian引擎节点执行以下命令进行巡检：
    -   全量巡检：

        ```
        python3 /opt/cantian/action/inspection/inspection_task.py all
        ```

    -   部分巡检：

        ```
        python3 /opt/cantian/action/inspection/inspection_task.py [xxx,xxx,…]
        ```

        >![输入图片说明](https://foruda.gitee.com/images/1707301851414022105/fc841ea9_1686238.gif "icon-note.gif") **说明：** 
        >-   _xxx_表示具体的巡检项，如“cantian\_status”。
        >    巡检项可通过“/opt/cantian/action/inspection/inspection\_config.json“文件查看，如[图1](#zh-cn_topic_0000001641933798_fig18762755183118)所示。巡检项可通过“/opt/cantian/action/inspection/inspection\_config.json“文件查看，如[图1](#zh-cn_topic_0000001641933798_fig18762755183118)所示。
        >-   各巡检项之间以英文逗号隔开，且无空格。

        **图 1**  查看巡检项<a name="zh-cn_topic_0000001641933798_fig18762755183118"></a>  
        ![输入图片说明](https://foruda.gitee.com/images/1707301708579211817/771dd156_1686238.png "查看巡检项.png")

4.  根据回显提示，输入ctsql用户名、密码。

    ![输入图片说明](https://foruda.gitee.com/images/1707301568720998595/442ea8ba_1686238.png "zh-cn_image_0000001641933930.png")

    >![输入图片说明](https://foruda.gitee.com/images/1707301851414022105/fc841ea9_1686238.gif "icon-note.gif") **说明：** 
    >-   执行全量巡检时，需要输入ctsql的用户名及密码。
    >-   执行部分巡检时，如果回显提示输入ctsql的用户名及密码才需要输入。

5.  执行结果，回显类似如下。

    ![输入图片说明](https://foruda.gitee.com/images/1707301593528813341/8279dcf9_1686238.png "zh-cn_image_0000001834699333.png")

6.  查看巡检结果。

    巡检完成后，巡检结果将保存在目录“/opt/cantian/action/inspections\_log”下，以“inspection\_时间戳”命名，并且只保存最近9次的巡检结果文件。

    ![输入图片说明](https://foruda.gitee.com/images/1707301610921579766/7192a086_1686238.png "zh-cn_image_0000001817945905.png")

**巡检MySQL（仅容器部署MySQL场景支持）<a name="zh-cn_topic_0000001641933798_section1762914064619"></a>**

1.  依次进入所有部署MySQL的容器，执行以下巡检命令。
    -   全量巡检：

        ```
        python3 /mf_connector/inspection/inspection_task.py all
        ```

    -   部分巡检：

        ```
        python3 /mf_connector/inspection/inspection_task.py [xxx,xxx,…]
        ```

        >![输入图片说明](https://foruda.gitee.com/images/1707301851414022105/fc841ea9_1686238.gif "icon-note.gif") **说明：** 
        >-   _xxx_表示具体的巡检项，如“mysql\_connection\_check”。
        >    巡检项可通过/mf\_connector/inspection/mysql\_inspection\_config.json文件查看，如[图2](#zh-cn_topic_0000001641933798_fig20421237133419)所示。
        >-   各巡检项之间以逗号隔开，且无空格。

        **图 2**  查看巡检项<a name="zh-cn_topic_0000001641933798_fig20421237133419"></a>  
        ![输入图片说明](https://foruda.gitee.com/images/1707301673675665446/88ca9bb0_1686238.png "查看巡检项-2.png")

2.  查看巡检结果。

    巡检完成后，巡检结果将保存在目录“/mf\_connector/inspection/inspections\_log”下，以“inspection\__时间戳_”命名。并且只保存最近9次的巡检结果文件。

    巡检结果查询如下：

    ![输入图片说明](https://foruda.gitee.com/images/1707301648920644690/22c0aa8b_1686238.png "zh-cn_image_0000001690293749.png")
# 六、Cantian云主机开发编译部署

## 6.1 环境准备

### 6.1.1 下载最新docker镜像

#### x86版本
```shell
docker pull ykfnxx/cantian_dev:0.1.0
docker tag ykfnxx/cantian_dev:0.1.0 cantian_dev:latest
```
#### ARM版本
```shell
docker pull ykfnxx/cantian_dev:0.1.1
docker tag ykfnxx/cantian_dev:0.1.1 cantian_dev:latest
```

### 6.1.2 下载cantian源码
1.执行以下命令下载Cantian引擎源码。
```shell
git clone git@gitee.com:openeuler/cantian.git
```
2.执行以下命令下载Cantian-Connector-MySQL源码，用于编译Cantian引擎对接MySQL的插件。
```shell
git clone git@gitee.com:openeuler/cantian-connector-mysql.git
```
3.执行以下命令,下载MySQL-8.0.26版本源码，用于编译Cantian引擎对接MySQL的插件，并将源码拷贝到cantian-connector-mysql/mysql-source目录下。
```shell
wget --no-check-certificate https://github.com/mysql/mysql-server/archive/refs/tags/mysql-8.0.26.tar.gz
tar -zxf mysql-8.0.26.tar.gz
mv mysql-server-mysql-8.0.26 cantian-connector-mysql/mysql-source
```
4.创建与cantian、cantian-connector-mysql同级的cantian_data目录用于存放相关数据。
```shell
mkdir -p cantian_data
```

### 6.1.3 启动容器

进入cantian目录,启动容器。

+ 单节点
```shell
sh docker/container.sh dev
sh docker/container.sh enterdev
```
+ 双节点
```shell
# 目前只支持双节点，node_id为0, 1
sh docker/container.sh startnode 0
sh docker/container.sh enternode 1
```

[container.sh](https://gitee.com/openeuler/cantian/blob/master/docker/container.sh)按`startnode`和`dev`参数启动时会执行代码拷贝的操作，具体操作参考脚本中`sync_mysql_code`函数

## 6.2 Cantian编译部署

### 6.2.1 cantian编包

以下命令在容器内使用。若为双节点，则只需在其中一个节点执行一次。为方便描述，后续双节点仅需在一个节点的操作默认在node0进行
```shell
cd /home/regress/CantianKernel/build
export local_build=true
# 若此前编译过第三方依赖，可以再加上--no-deps参数，跳过第三方依赖的编译
# debug
sh Makefile.sh package
# release
sh Makefile.sh package-release
```

### 6.2.2 cantian部署

配置core_pattern（在两个节点上配置，用于记录core file）
```shell
echo "/home/core/core-%e-%p-%t" > /proc/sys/kernel/core_pattern
echo 2 > /proc/sys/fs/suid_dumpable
ulimit -c unlimited
```
##### 单节点部署Cantian

```shell
cd /home/regress/CantianKernel/Cantian-DATABASE-CENTOS-64bit
mkdir -p /home/cantiandba/logs
# -Z SESSIONS=1000方便调试，需运行MTR时需要去掉此参数
# 如果需要部署非元数据归一版本，则需要加参数-Z MYSQL_METADATA_IN_CANTIAN=FALSE
python3 install.py -U cantiandba:cantiandba -R /home/cantiandba/install -D /home/cantiandba/data -l /home/cantiandba/logs/install.log -Z _LOG_LEVEL=255 -g withoutroot -d -M cantiand -c -Z _SYS_PASSWORD=Huawei@123 -Z SESSIONS=1000
```
##### 双节点部署Cantian
node0
```shell
cd /home/regress/CantianKernel/Cantian-DATABASE-CENTOS-64bit
mkdir -p /home/cantiandba/logs
python3 install.py -U cantiandba:cantiandba -R /home/cantiandba/install -D /home/cantiandba/data -l /home/cantiandba/logs/install.log -M cantiand_in_cluster -Z _LOG_LEVEL=255 -N 0 -W 192.168.0.1 -g withoutroot -d -c -Z _SYS_PASSWORD=Huawei@123 -Z SESSIONS=1000
```
node1
```shell
cd /home/regress/CantianKernel/Cantian-DATABASE-CENTOS-64bit
mkdir -p /home/cantiandba/logs
python3 install.py -U cantiandba:cantiandba -R /home/cantiandba/install -D /home/cantiandba/data -l /home/cantiandba/logs/install.log -M cantiand_in_cluster -Z _LOG_LEVEL=255 -N 1 -W 192.168.0.1 -g withoutroot -d -c -Z _SYS_PASSWORD=Huawei@123 -Z SESSIONS=1000
```
#### 验证cantian状态是否正常

```shell
su - cantiandba
cms stat
ctsql / as sysdba -q -c 'SELECT NAME, STATUS, OPEN_STATUS FROM DV_DATABASE'
```

### 6.2.3 卸载cantian
**需要使用gaussdba用户执行卸载命令**
如果存在与cantiand相连的mysqld进程，执行以下指令，先停止mysqld进程再停止cantiand:
```shell
/usr/local/mysql/bin/mysql -uroot -e "shutdown;"
```
卸载指令：
```shell
cd /home/cantiandba/install/bin
python3 uninstall.py -U cantiandba -F -D /home/cantiandba/data -g withoutroot -d
```
**如果出现报错，部分目录无法删除，则可以使用root用户手动清理相关目录**
```shell
kill -9 $(pidof mysqld)
kill -9 $(pidof cantiand)
kill -9 $(pidof cms)
rm -rf /home/regress/cantian_data/* /home/regress/install /home/regress/data /home/cantiandba/install/* /data/data/* /home/cantiandba/data
sed -i '/cantiandba/d' /home/cantiandba/.bashrc
```
## 6.3 mysql编译部署
### 6.3.1 mysql编译

#### 6.3.1.1 元数据归一
元数据归一需要应用patch，修改源码
```shell
cd cantian-connector-mysql/mysql-source
patch --ignore-whitespace -p1 < mysql-scripts-meta.patch
patch --ignore-whitespace -p1 < mysql-test-meta.patch
patch --ignore-whitespace -p1 < mysql-source-code-meta.patch
```
编译：
```shell
cd /home/regress/CantianKernel/build
sh Makefile.sh mysql
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/regress/cantian-connector-mysql/bld_debug/library_output_directory
rm -rf /home/regress/mydata/*
```

双节点部署时，如果使用**手动部署**，则两个节点需要分别执行编译。若使用**脚本部署**，只需在一个节点编译即可
特别地，若在node0完成cantian的编译，在node1编译mysql前需要先执行以下命令
```shell
mkdir /home/regress/cantian-connector-mysql/mysql-source/include/protobuf-c
cp /home/regress/CantianKernel/library/protobuf/protobuf-c/protobuf-c.h /home/regress/cantian-connector-mysql/mysql-source/include/protobuf-c
```

#### 6.3.1.2 非归一

双节点部署时，非归一版本只需要在其中一个节点编译mysql即可

```shell
cd /home/regress/CantianKernel/build
sh Makefile.sh mysql
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/regress/cantian-connector-mysql/bld_debug/library_output_directory
```

### 6.3.2 mysql部署

#### 6.3.2.1 元数据归一(手动拉起)

初始化：
双节点仅需在其中一个节点执行初始化命令，且在初始化前，需保证`/home/regress/mydata`下没有文件需先执行

```shell
rm -rf /home/regress/mydata/*
```

```shell
/usr/local/mysql/bin/mysqld --defaults-file=/home/regress/cantian-connector-mysql/scripts/my.cnf --initialize-insecure --datadir=/home/regress/mydata --early-plugin-load="ha_ctc.so" --core-file
```

部署：
双节点在初始化后分别执行部署命令。若在node0完成初始化，则node1需先执行以下命令

```shell
rm -rf /home/regress/mydata/*
mkdir -p /home/regress/mydata/
mkdir -p /home/regress/mydata/mysql
```

部署命令为：
```shell
/usr/local/mysql/bin/mysqld --defaults-file=/home/regress/cantian-connector-mysql/scripts/my.cnf  --datadir=/home/regress/mydata --user=root --early-plugin-load="ha_ctc.so" --core-file
```

#### 6.3.2.2 元数据归一/非归一（脚本）

双节点拉起前需分别执行以下命令

```shell
# node0
cd /home/regress/CantianKernel/build
sh Makefile.sh mysql_package_node0

# node1
cd /home/regress/CantianKernel/build
sh Makefile.sh mysql_package_node1
```

以下为使用`install.py`脚本拉起的命令

```shell
cd /home/regress/CantianKernel/Cantian-DATABASE-CENTOS-64bit
mkdir -p /home/regress/logs
python3 install.py -U cantiandba:cantiandba -l /home/cantiandba/logs/install.log -d -M mysqld -m /home/regress/cantian-connector-mysql/scripts/my.cnf
```

#### 6.3.2.3 拉起检验

```shell
/usr/local/mysql/bin/mysql -uroot
```
##

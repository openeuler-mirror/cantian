# 前言<a name="ZH-CN_TOPIC_0000001989473294"></a>

**概述<a name="section4537382116410"></a>**

若所有业务只运行在Cantian引擎集群中的reformer节点上，Cantian引擎可通过打开DRC资源集中模式的方式提升业务运行的性能。

# 影响与限制<a name="ZH-CN_TOPIC_0000002025991713"></a>

**使用场景<a name="section181283218011"></a>**

-   只适用于所有业务运行在Cantian引擎集群reformer节点的场景。若业务运行在Cantian引擎集群的不同节点上，开启DRC资源集中模式后，reformer节点的性能会有提升，非reformer节点性能可能有下降。
-   请在维护人员指导下使用该功能，请勿独立开启该功能。

**注意事项<a name="section4859815162510"></a>**

-   通过修改参数“DRC\_IN\_REFORMER\_MODE”，可控制DRC资源集中模式的开启和关闭。所有节点完成修改后，重启Cantian引擎，相关的修改才会生效。
-   请确保Cantian引擎集群中所有节点“DRC\_IN\_REFORMER\_MODE”的值一致。若不一致，Cantian引擎重启后，集群中部分节点将无法正常上线。请将各个节点的cantiand.ini文件中该参数修改为相同的值后、再重启Cantian引擎。
-   若Cantian引擎正在进行版本升级操作，请勿修改DRC资源集中模式。

# 修改DRC资源集中模式<a name="ZH-CN_TOPIC_0000002025883445"></a>

**操作步骤<a name="section17412185781811"></a>**

1.  获取Cantian引擎集群中的reformer节点ID。

    >![](public_sys-resources/icon-note.gif) **说明：** 
    >-   Cantian引擎集群支持通过MySQL和ctsql两种方式获取reformer节点ID，但只能通过ctsql方式修改DRC资源集中模式。推荐使用ctsql方式获取reformer节点ID。
    >-   您可以通过重启reformer节点的方式，将reformer节点调整为非reformer节点、非reformer节点调整为reformer节点。

    -   通过MySQL方式获取reformer节点ID。
        1.  登录Cantian引擎集群中的任一节点，执行以下命令，导入cantian\_defs.sql文件。

            ```
            source /opt/cantian/mysql/scripts/cantian_defs.sql
            ```

        2.  执行以下命令，查找Cantian引擎集群中reformer节点的ID。

            ```
            select * from cantian.dv_reform_stats        
            ```

            回显中，“reformer node”所在行的VALUE值，即为reformer节点的ID。例如：

            ```
            mysql> select * from cantian.dv_reform_stats
            STATISTIC#   NAME                        VALUE              INFO    
            ------------ -------------------------- ------------------- --------------------
            0            reform status              6    
            1            reformer node              0     
            2            reform mode                0   
            3            reform role                0
            ```

    -   通过ctsql方式取reformer节点ID。
        1.  登录Cantian引擎集群中的任一节点，切换cantian用户并登录ctsql。
            1.  执行以下命令，切换至cantian用户。

                ```
                su -s /bin/bash - cantian
                ```

            2.  执行以下命令，登录ctsql。

                ```
                ctsql sys@127.0.0.1:1611 -q
                ```

                请根据回显提示信息输入密码，该密码为部署Cantian引擎时创建的数据库系统管理员sys用户的密码。

                ```
                [cantiandba@localhost ~]$ ctsql sys@127.0.0.1:1611 -q
                Please enter password: 
                ********
                connected.
                ```

        2.  执行以下命令，查找Cantian引擎集群中reformer节点的ID。

            ```
            select * from DV_REFORM_STATS        
            ```

            回显中，“reformer node”所在行的VALUE值，即为reformer节点的ID。例如：

            ```
            SQL>select * from DV_REFORM_STATS
            STATISTIC#   NAME                        VALUE              INFO    
            ------------ -------------------------- ------------------- --------------------
            0            reform status              6    
            1            reformer node              0     
            2            reform mode                0   
            3            reform role                0
            ```

2.  查看Cantian引擎集群中各个节点的DRC资源集中模式。

    依次登录Cantian引擎集群中的各个节点，执行以下命令，查询DRC资源集中模式状态。

    ```
    show parameter DRC_IN_REFORMER_MODE
    ```

    回显中，查看RUNTIME\_VALUE的值：

    -   TRUE：DRC资源集中模式已开启。
    -   FASLE：DRC资源集中模式未开启。

    例如：

    ```
    SQL> show parameter DRC_IN_REFORMER_MODE
    NAME                   DATATYPE        VALUE      RUNTIME_VALUE  EFFECTIVE           
    ---------------------- --------------- ---------- -------------- --------
    DRC_IN_REFORMER_MODE   CT_TYPE_BOOLEAN FALSE      FALSE          reboot
    ```

3.  （可选）执行以下命令，查看修改DRC资源集中模式前，各个节点的资源分布情况。

    ```
    select * from DV_DRC_RES_RATIO 
    ```

    例如：

    若当前未开启DRC资源集中模式，在各个节点分别执行该命令后，可以看到reformer节点和非reformer节点基本均匀分配到了系统资源。

    -   reformer节点上的查询结果样例：

        ```
        SQL> select * from DV_DRC_RES_RATIO;
        DRC_RESOURCE         USED         TOTAL        RATIO               
        -------------------- ------------ ------------ --------------------
        PAGE_BUF             53066        4194304      0.01265             
        GLOBAL_LOCK          124          2518316      0.00005             
        LOCAL_LOCK           237          1259158      0.00019             
        LOCAL_TXN            0            3000         0.00000             
        GLOBAL_TXN           0            3000         0.00000             
        LOCK_ITEM            0            6000         0.00000             
        6 rows fetched.
        ```

    -   非reformer节点上的查询结果样例：

        ```
        DRC_RESOURCE         USED         TOTAL        RATIO               
        -------------------- ------------ ------------ --------------------
        PAGE_BUF             56386        4194304      0.01344             
        GLOBAL_LOCK          113          2518316      0.00004             
        LOCAL_LOCK           90           1259158      0.00007             
        LOCAL_TXN            0            3000         0.00000             
        GLOBAL_TXN           0            3000         0.00000             
        LOCK_ITEM            0            6000         0.00000             
        6 rows fetched.
        ```

4.  修改Cantian引擎集群中各个节点的DRC资源集中模式。
    1.  依次登录Cantian引擎集群中的各个节点，执行以下命令，修改DRC资源集中模式。

        ```
        alter system set DRC_IN_REFORMER_MODE=value
        ```

        当“value”设置为TRUE，表示开启DRC资源集中模式；当“value”设置为FALSE，表示关闭DRC资源集中模式。例如：

        ```
        SQL> alter system set DRC_IN_REFORMER_MODE=TRUE;
        Succeed.
        ```

    2.  完成所有节点的DRC资源集中模式修改后，在任一节点上执行以下命令，重启Cantian引擎。

        ```
        cms res -stop db
        cms res -start db
        ```

        例如，在完成集群中最后一个节点的DRC资源集中模配置后，在该节点上重启Cantian引擎。

        ```
        SQL> alter system set DRC_IN_REFORMER_MODE=TRUE;
        Succeed.
        SQL> EXIT
        [cantiandba@localhost ~]$ cms res -stop db
        stop resource succeed.
        [cantiandba@localhost ~]$ cms res -start db
        start resource succeed.
        ```

5.  （可选）执行以下命令，查看修改DRC资源集中模式后，各个节点的资源分布情况。

    ```
    select * from DV_DRC_RES_RATIO 
    ```

    例如：

    若开启了DRC资源集中模式，在各个节点分别执行该命令后，可以看到reformer节点获取到了几乎所有的系统资源。

    -   reformer节点上的查询结果样例：

        ```
        SQL> select * from DV_DRC_RES_RATIO;
        DRC_RESOURCE         USED         TOTAL        RATIO               
        -------------------- ------------ ------------ --------------------
        PAGE_BUF             4706         4194304      0.00112             
        GLOBAL_LOCK          122          2518316      0.00005             
        LOCAL_LOCK           122          1259158      0.00010             
        LOCAL_TXN            0            3000         0.00000             
        GLOBAL_TXN           0            3000         0.00000             
        LOCK_ITEM            0            6000         0.00000             
        6 rows fetched.
        ```

    -   非reformer节点上的查询结果样例：

        ```
        SQL> select * from DV_DRC_RES_RATIO;
        DRC_RESOURCE         USED         TOTAL        RATIO               
        -------------------- ------------ ------------ --------------------
        PAGE_BUF             0            4194304      0.00000             
        GLOBAL_LOCK          0            2518316      0.00000             
        LOCAL_LOCK           90           1259158      0.00007             
        LOCAL_TXN            0            3000         0.00000             
        GLOBAL_TXN           0            3000         0.00000             
        LOCK_ITEM            0            6000         0.00000             
        6 rows fetched.
        ```


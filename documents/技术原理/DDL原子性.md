# 理论基础<a name="ZH-CN_TOPIC_0000002256780237"></a>



## 事务与DDL<a name="ZH-CN_TOPIC_0000002221620650"></a>

事务：是用户定义的一个数据库操作序列，这些操作要么全做，要么全不做，是一个不可分割的工作单位。在关系数据库中，一个事务可以是一条SQL语句，一组SQL语句或者整个程序。

事务的原子性（Atomicity）是事务的一大特性，是指事务包含的操作要么全部执行（成功提交），要么全部不执行（失败回滚），不会出现中间状态。

比如，一组SQL语句包含插入1条数据、更新1条数据并删除一条数据，中间任何一步失败都会导致数据库状态回滚到插入数据前，只有所有操作都成功，事务进行提交后，才认为一个完整事务的执行成功。

DDL: 在数据库操作中，DDL（Data Definition Language）用于定义或修改表结构（如CREATE、ALTER、DROP）。

## MySQL DDL<a name="ZH-CN_TOPIC_0000002256700145"></a>

MySQL 支持多种事务存储引擎，其中最常见的是 InnoDB引擎 和 NDB引擎（也称为 MySQL Cluster），如下表所示，这些引擎支持的原子DDL语句包括：CREATE/ALTER/DROP/TRUNCATE TABLE等。

**表 1**  MySQL引擎

<a name="table738711599505"></a>
<table><thead align="left"><tr id="row13388135915502"><th class="cellrowborder" valign="top" width="24.57245724572457%" id="mcps1.2.4.1.1"><p id="p938875905014"><a name="p938875905014"></a><a name="p938875905014"></a>MySQL引擎</p>
</th>
<th class="cellrowborder" valign="top" width="16.401640164016403%" id="mcps1.2.4.1.2"><p id="p23882595508"><a name="p23882595508"></a><a name="p23882595508"></a>支持事务</p>
</th>
<th class="cellrowborder" valign="top" width="59.025902590259015%" id="mcps1.2.4.1.3"><p id="p1974672618514"><a name="p1974672618514"></a><a name="p1974672618514"></a>说明</p>
</th>
</tr>
</thead>
<tbody><tr id="row12388105925013"><td class="cellrowborder" valign="top" width="24.57245724572457%" headers="mcps1.2.4.1.1 "><p id="p1038815910509"><a name="p1038815910509"></a><a name="p1038815910509"></a>InnoDB</p>
</td>
<td class="cellrowborder" valign="top" width="16.401640164016403%" headers="mcps1.2.4.1.2 "><p id="p19388135975017"><a name="p19388135975017"></a><a name="p19388135975017"></a>是</p>
</td>
<td class="cellrowborder" valign="top" width="59.025902590259015%" headers="mcps1.2.4.1.3 "><p id="p15388359155015"><a name="p15388359155015"></a><a name="p15388359155015"></a>MySQL原生默认存储引擎</p>
</td>
</tr>
<tr id="row93881859115015"><td class="cellrowborder" valign="top" width="24.57245724572457%" headers="mcps1.2.4.1.1 "><p id="p13388359125017"><a name="p13388359125017"></a><a name="p13388359125017"></a>MyISAM</p>
</td>
<td class="cellrowborder" valign="top" width="16.401640164016403%" headers="mcps1.2.4.1.2 "><p id="p0388115975014"><a name="p0388115975014"></a><a name="p0388115975014"></a>否</p>
</td>
<td class="cellrowborder" valign="top" width="59.025902590259015%" headers="mcps1.2.4.1.3 "><p id="p1138875925017"><a name="p1138875925017"></a><a name="p1138875925017"></a>MyISAM存储引擎</p>
</td>
</tr>
<tr id="row638820593506"><td class="cellrowborder" valign="top" width="24.57245724572457%" headers="mcps1.2.4.1.1 "><p id="p103881159205018"><a name="p103881159205018"></a><a name="p103881159205018"></a>MEMORY</p>
</td>
<td class="cellrowborder" valign="top" width="16.401640164016403%" headers="mcps1.2.4.1.2 "><p id="p1547116312542"><a name="p1547116312542"></a><a name="p1547116312542"></a>否</p>
</td>
<td class="cellrowborder" valign="top" width="59.025902590259015%" headers="mcps1.2.4.1.3 "><p id="p1538875910502"><a name="p1538875910502"></a><a name="p1538875910502"></a>用于临时表的存储引擎（基于哈希实现）</p>
</td>
</tr>
<tr id="row183889590505"><td class="cellrowborder" valign="top" width="24.57245724572457%" headers="mcps1.2.4.1.1 "><p id="p20388185915014"><a name="p20388185915014"></a><a name="p20388185915014"></a>PERFORMANCE_SCHEMA</p>
</td>
<td class="cellrowborder" valign="top" width="16.401640164016403%" headers="mcps1.2.4.1.2 "><p id="p17487331543"><a name="p17487331543"></a><a name="p17487331543"></a>否</p>
</td>
<td class="cellrowborder" valign="top" width="59.025902590259015%" headers="mcps1.2.4.1.3 "><p id="p1938816592501"><a name="p1938816592501"></a><a name="p1938816592501"></a>性能统计工具</p>
</td>
</tr>
<tr id="row123881859135019"><td class="cellrowborder" valign="top" width="24.57245724572457%" headers="mcps1.2.4.1.1 "><p id="p15389115965010"><a name="p15389115965010"></a><a name="p15389115965010"></a>BLACKHOLE</p>
</td>
<td class="cellrowborder" valign="top" width="16.401640164016403%" headers="mcps1.2.4.1.2 "><p id="p185001236545"><a name="p185001236545"></a><a name="p185001236545"></a>否</p>
</td>
<td class="cellrowborder" valign="top" width="59.025902590259015%" headers="mcps1.2.4.1.3 "><p id="p1938975911503"><a name="p1938975911503"></a><a name="p1938975911503"></a>BLACKHOLE存储引擎</p>
</td>
</tr>
<tr id="row10389359125010"><td class="cellrowborder" valign="top" width="24.57245724572457%" headers="mcps1.2.4.1.1 "><p id="p103891159115019"><a name="p103891159115019"></a><a name="p103891159115019"></a>CSV</p>
</td>
<td class="cellrowborder" valign="top" width="16.401640164016403%" headers="mcps1.2.4.1.2 "><p id="p1650214310544"><a name="p1650214310544"></a><a name="p1650214310544"></a>否</p>
</td>
<td class="cellrowborder" valign="top" width="59.025902590259015%" headers="mcps1.2.4.1.3 "><p id="p1838915985010"><a name="p1838915985010"></a><a name="p1838915985010"></a>CSV存储引擎</p>
</td>
</tr>
<tr id="row538985995011"><td class="cellrowborder" valign="top" width="24.57245724572457%" headers="mcps1.2.4.1.1 "><p id="p16389125916500"><a name="p16389125916500"></a><a name="p16389125916500"></a>ARCHIVE</p>
</td>
<td class="cellrowborder" valign="top" width="16.401640164016403%" headers="mcps1.2.4.1.2 "><p id="p550319317549"><a name="p550319317549"></a><a name="p550319317549"></a>否</p>
</td>
<td class="cellrowborder" valign="top" width="59.025902590259015%" headers="mcps1.2.4.1.3 "><p id="p6389185915017"><a name="p6389185915017"></a><a name="p6389185915017"></a>ARCHIVE存储引擎</p>
</td>
</tr>
<tr id="row156812161530"><td class="cellrowborder" valign="top" width="24.57245724572457%" headers="mcps1.2.4.1.1 "><p id="p106941615533"><a name="p106941615533"></a><a name="p106941615533"></a>FEDERATED</p>
</td>
<td class="cellrowborder" valign="top" width="16.401640164016403%" headers="mcps1.2.4.1.2 "><p id="p15057315419"><a name="p15057315419"></a><a name="p15057315419"></a>否</p>
</td>
<td class="cellrowborder" valign="top" width="59.025902590259015%" headers="mcps1.2.4.1.3 "><p id="p1170016135315"><a name="p1170016135315"></a><a name="p1170016135315"></a>FEDERATED存储引擎</p>
</td>
</tr>
<tr id="row7983123417531"><td class="cellrowborder" valign="top" width="24.57245724572457%" headers="mcps1.2.4.1.1 "><p id="p149831334125311"><a name="p149831334125311"></a><a name="p149831334125311"></a>MRG_MYISAM</p>
</td>
<td class="cellrowborder" valign="top" width="16.401640164016403%" headers="mcps1.2.4.1.2 "><p id="p95071035544"><a name="p95071035544"></a><a name="p95071035544"></a>否</p>
</td>
<td class="cellrowborder" valign="top" width="59.025902590259015%" headers="mcps1.2.4.1.3 "><p id="p15983103412530"><a name="p15983103412530"></a><a name="p15983103412530"></a>MRG_MYISAM存储引擎</p>
</td>
</tr>
<tr id="row434314475413"><td class="cellrowborder" valign="top" width="24.57245724572457%" headers="mcps1.2.4.1.1 "><p id="p133446416545"><a name="p133446416545"></a><a name="p133446416545"></a>CTC</p>
</td>
<td class="cellrowborder" valign="top" width="16.401640164016403%" headers="mcps1.2.4.1.2 "><p id="p1034474155413"><a name="p1034474155413"></a><a name="p1034474155413"></a>是</p>
</td>
<td class="cellrowborder" valign="top" width="59.025902590259015%" headers="mcps1.2.4.1.3 "><p id="p1634417415413"><a name="p1634417415413"></a><a name="p1634417415413"></a>参天存储引擎</p>
</td>
</tr>
</tbody>
</table>

在MySQL 8.0之前，DDL操作缺乏原子性：若执行过程中发生故障（如宕机），可能残留中间表或元数据不一致。

MySQL 8.0引入原子DDL特性，通过事务日志和数据字典的协同，确保DDL操作要么成功后全部提交，要么失败后完全回滚。

参天存储引擎对接MySQL后，根据MySQL的元数据所在位置，存在两种部署形态：共享系统表元数据和非共享系统表元数据。共享系统表元数据形态下的MySQL元数据存在Cantian侧，非共享系统表元数据形态下的MySQL元数据使用InnoDB引擎，分别存储在不同MySQL服务端的路径下。

对于集群来说（多个MySQL节点），需要保证不同节点间的元数据一致性，通过DDL广播机制来保证（如操作表t1时，所有节点都对t1表加锁，不允许所有节点上其他任何线程对该表做操作）。

对于单个节点来说，无论系统表元数据是否共享，需要保障MySQL和Cantian元数据的一致性，本文主要介绍单节点的DDL原子性实现。

# 参天引擎DDL原子性实现<a name="ZH-CN_TOPIC_0000002221780430"></a>



## 原子DDL执行流程<a name="ZH-CN_TOPIC_0000002256780241"></a>

DDL作为一种SQL语句，同样遵循事务的ACID原则。从保证事务原子性的角度出发，对于单个MySQL实例的DDL操作流程如下：

1.  MySQL加元数据锁：元数据锁根据作用范围分为库、表、存储过程、全局锁等类型，根据操作分为读、写锁等类型，可自行查阅其他详细资料如[Mysql-元数据锁MDL锁简述](https://juejin.cn/post/7395376446586552354)。
2.  MySQL开启事务：注册存储引擎并开启事务。
3.  修改MySQL元数据。
4.  存储引擎执行DDL操作： 如创建/修改/删除指定的库/表。
    1.  加锁：对一个库/表操作时需要禁止其他线程执行写操作，因此在执行DDL之前，需要根据不同的操作加不同的锁。如对库做操作时，需要加user锁；对表做操作时，需要依次加user锁、ddl锁、和表锁等。
    2.  修改DC（Dictionary Cache）：DC是Cantian元数据的缓存，在执行DDL过程中，需要将缓存临时更新成新状态，如表的重命名操作（rename）同时需要修改DC的name。
    3.  修改Cantian元数据：修改Cantian系统表中数据，如创表操作需要在SYS\_TABLES, SYS\_COLUMNS等系统表中插入数据。

5.  执行提交/回滚操作。
    1.  写逻辑日志（仅提交）/恢复修改的DC：如果成功，进入提交逻辑，将MySQL系统表和Cantian系统表的修改落盘。如果执行失败，则无需对逻辑日志进行落盘，而是需要将修改的缓存进行回退，如raname失败则需要将DC中的表名rename回原表名。
    2.  提交/回滚。
    3.  Cantian失效DC：DDL操作提交后，需要将DC缓存失效，在下次对该表进行查询/读写等操作时，加载最新的表结构。
    4.  解锁：在失效缓存后，需要将执行DDL前加的锁全部解锁。
    5.  清理资源。

6.  MySQL解元数据锁。

## DDL原子性实现原理<a name="ZH-CN_TOPIC_0000002221620654"></a>

1.  加解锁。

    ```
    // MDL
    notify_exclusive_mdl
      --> ctc_notify_exclusive_mdl
        --> ctc_notify_pre_event
          --> ctc_lock_table
        --> ctc_notify_post_event
          --> ctc_unlock_table
    notify_alter_table
      --> ctc_notify_alter_table
        --> ctc_notify_exclusive_mdl
    ```

    ```
    ctc_ddl_lock_table
    ctc_ddl_unlock_table
    ```

2.  执行阶段。

    ```
    // register trx
    static void ctc_register_trx(handlerton *hton, THD *thd) {
      trans_register_ha(thd, false, hton, nullptr);
      if (thd_test_options(thd, OPTION_NOT_AUTOCOMMIT | OPTION_BEGIN)) {
        trans_register_ha(thd, true, hton, nullptr);
      }
    }
    
    void register_ha(Transaction_ctx::THD_TRANS *trans, handlerton *ht_arg) {
      if (trans->m_ha_list != this) {
        m_next = trans->m_ha_list;
        trans->m_ha_list = this;
      }
      return;
    }
    ```

    ```
    // ddl operation
    ha_ctc::create // rename_table, delete_table, inplace_alter_table, optimize
      --> ctc_create_table
        --> ctc_ddl_lock_table
        --> ctc_init_ddl_def_node
        --> ctc_ddl_def_list_insert
        --> knl_create_table4mysql
          --> knl_internal_create_table_no_commit
    ```

3.  提交回滚。

    ```
    // commit: success
    ctc_trx_commit
      --> ctc_ddl_commit_log_put
      --> knl_commit4mysql
      --> ctc_ddl_table_after_commit_list
      --> ctc_ddl_unlock_table
      --> ctc_ddl_clear_stmt
    ```

    ```
    // rollback: fail
    ctc_trx_rollback
      --> ctc_ddl_rollback_update_dc
      --> knl_rollback4mysql
      --> ctc_ddl_table_after_rollback
      --> ctc_ddl_unlock_table
      --> ctc_ddl_clear_stmt
    ```

4.  缓存失效。

    ```
    add_to_invalidate
    invalidate_remote_dd
      --> ctc_broadcast_mysql_dd_invalidate
    ```

# 案例分析<a name="ZH-CN_TOPIC_0000002256700149"></a>

1.  create t2 as select \* from t1;

    ```
    ha_ctc::create(t2)
    ha_ctc::rnd_init --> rnd_next --> rnd_end(t1)
    ha_ctc::write_row(t2)
    ```

2.  alter table t1 ..., algorithm = copy;

    ```
    ha_ctc::create(#sql1)
    copy_data
    ha_ctc::rename_table(t1 -> #sql2)
    ha_ctc::rename_table(#sql1 -> t1)
    ha_ctc::delete_table(#sql2)
    ```

3.  create/drop database

    ```
    // create
    knl_create_database4mysql
    knl_create_space4mysql
    knl_create_user4mysql
    ```

    ```
    // drop
    knl_drop_database4mysql
    knl_drop_user4mysql
    knl_drop_space4mysql
    ```


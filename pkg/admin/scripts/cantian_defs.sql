-- cantian user
INSERT IGNORE INTO mysql.user VALUES
('localhost','mysql.cantian','N','N','N','N','N','N','N','N','N','N','N','N','N','N','N','N','N','N','N','N','N','N','N','N','N','N','N','N','N','','','','',0,0,0,0,'caching_sha2_password','\$A\$005\$THISISACOMBINATIONOFINVALIDSALTANDPASSWORDTHATMUSTNEVERBRBEUSED','N',CURRENT_TIMESTAMP,NULL,'Y','N','N',NULL,NULL,NULL,NULL);

INSERT IGNORE INTO mysql.db VALUES
('localhost','cantian','mysql.cantian','N','N','N','N','N','N','N','N','N','N','N','N','N','N','N','N','N','N','Y');

INSERT IGNORE INTO mysql.tables_priv VALUES
('localhost','cantian','mysql.cantian','SYS_TABLES','root@localhost',
CURRENT_TIMESTAMP,'Select','');

INSERT IGNORE INTO mysql.global_grants (USER,HOST,PRIV,WITH_GRANT_OPTION)
VALUES ('mysql.cantian','localhost','SYSTEM_USER','N');

-- prepare
set @ctc_ddl_local_enabled = true;
LOCK INSTANCE FOR BACKUP;

-- cantian system user
CREATE DATABASE IF NOT EXISTS cantian DEFAULT CHARACTER SET utf8mb3 COLLATE utf8_bin;
USE cantian;

-- -- SYS_LOB_ID: SYS_LOBS
-- CREATE TABLE IF NOT EXISTS `cantian`.`sys_lobs`(
--   `USER#`         INTEGER,
--   `TABLE#`        INTEGER,
--   `COLUMN#`       INTEGER,
--   `SPACE#`        INTEGER,
--   `ENTRY`         BIGINT,
--   `ORG_SCN`       BIGINT,
--   `CHG_SCN`       BIGINT,
--   `CHUNK`         INTEGER,
--   `PCTVERSION`    INTEGER,
--   `RETENSION`     INTEGER,
--   `FLAGS`         INTEGER
-- ) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- -- SYS_SHADOW_INDEX_ID: SYS_SHADOW_INDEXES
-- CREATE TABLE IF NOT EXISTS `cantian`.`sys_shadow_indexes`(
--   `USER#`         INTEGER,
--   `TABLE#`        INTEGER,
--   `ID`            INTEGER,
--   `NAME`          VARCHAR(64),
--   `SPACE#`        INTEGER,
--   `SEQUENCE#`     BIGINT,
--   `ENTRY`         BIGINT,
--   `IS_PRIMARY`    INTEGER,
--   `IS_UNIQUE`     INTEGER,
--   `TYPE`          INTEGER,
--   `COLS`          INTEGER,
--   `COL_LIST`      VARCHAR(128),
--   `INITRANS`      INTEGER,
--   `CR_MODE`       INTEGER,
--   `FLAGS`         INTEGER,
--   `PARTED`        INTEGER,
--   `PCTFREE`       INTEGER
-- ) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- -- SYS_SHADOW_INDEXPART_ID: SYS_SHADOW_INDEX_PARTS
-- CREATE TABLE IF NOT EXISTS `cantian`.`sys_shadow_index_parts`(
--   `USER#`         INTEGER,
--   `TABLE#`        INTEGER,
--   `INDEX#`        INTEGER,
--   `PART#`         INTEGER,
--   `NAME`          VARCHAR(64),
--   `HIBOUNDLEN`    INTEGER,
--   `HIBOUNDVAL`    VARCHAR(4000),
--   `SPACE#`        INTEGER,
--   `ORG_SCN`       BIGINT,
--   `ENTRY`         BIGINT,
--   `INITRANS`      INTEGER,
--   `PCTFREE`       INTEGER,
--   `FLAGS`         INTEGER,
--   `BHIBOUNDVAL`   VARBINARY(4000),
--   `PARENT_PART#`  INTEGER
-- ) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- -- SYS_GARBAGE_SEGMENT_ID: SYS_GARBAGE_SEGMENTS
-- CREATE TABLE IF NOT EXISTS `cantian`.`sys_garbage_segments`(
--   `UID`            INTEGER,
--   `OID`            INTEGER,
--   `INDEX_ID`       INTEGER,
--   `COLUMN_ID`      INTEGER,
--   `SPACE`          INTEGER,
--   `ENTRY`          BIGINT,
--   `ORG_SCN`        BIGINT,
--   `SEG_SCN`        BIGINT,
--   `INITRANS`       INTEGER,
--   `PCTFREE`        INTEGER,
--   `OP_TYPE`        INTEGER,
--   `REUSE`          INTEGER,
--   `SERIAL`         BIGINT,
--   `SPARE2`         INTEGER,
--   `SPARE3`         INTEGER
-- ) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- -- SYS_LOGIC_REP_ID: SYS_LOGIC_REPL
-- CREATE TABLE IF NOT EXISTS `cantian`.`sys_logic_repl`(
--   `USER#` 	INTEGER	,
--   `TABLE#`	INTEGER	,
--   `STATUS`	INTEGER	,
--   `INDEX#`	INTEGER,
--   `PARTITION_IDS` TEXT
-- ) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- -- SYS_STORAGE_ID: SYS_STORAGE
-- CREATE TABLE IF NOT EXISTS `cantian`.`sys_storage`(
--   `ORG_SCN`          BIGINT,
--   `INITIAL_PAGES`    INTEGER,
--   `MAX_EXTENTS`      INTEGER
-- ) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- -- SYS_CLUSTER_DDL_TABLE: SYS_CLUSTER_DDL
-- CREATE TABLE IF NOT EXISTS `cantian`.`sys_cluster_ddl`(
--   `SID`            INTEGER,
--   `LSN`            BIGINT,
--   `LOGIC_LOG`      BLOB
-- ) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- cantian sys views
-- 查看当前数据库的数据文件分配情况: DV_DATA_FILES
CREATE TABLE IF NOT EXISTS `cantian`.`dv_data_files`(
  `ID` INTEGER,
  `TABLESPACE_ID` INTEGER,
  `STATUS` VARCHAR(20),
  `TYPE` VARCHAR(20),
  `FILE_NAME` VARCHAR(256),
  `BYTES` BIGINT,
  `AUTO_EXTEND` VARCHAR(20),
  `AUTO_EXTEND_SIZE` BIGINT,
  `MAX_SIZE` BIGINT,
  `HIGH_WATER_MARK` INTEGER,
  `ALLOC_SIZE` BIGINT,
  `COMPRESSION` VARCHAR(20),
  `PUNCHED` VARCHAR(20)
) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- 查看节点信息: NODE_INFO
CREATE TABLE IF NOT EXISTS `cantian`.`node_info`(
  `INST_ID` INTEGER,
  `ADDRESS` VARCHAR(32),
  `INTERCONNECT_PORT` INTEGER,
  `TYPE` VARCHAR(10),
  `CHANNEL_NUM` INTEGER,
  `POOL_SIZE` INTEGER
) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- -- 转换页计数: DV_DTC_CONVERTING_PAGE_CNT
-- CREATE TABLE IF NOT EXISTS `cantian`.`dv_dtc_converting_page_cnt`(
--   `ID` INTEGER,
--   `CONVERTING_PAGE_COUNT` BIGINT,
--   `INST_ID` INTEGER
-- ) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- -- 查看索引合并信息: DV_INDEX_COALESCE
-- CREATE TABLE IF NOT EXISTS `cantian`.`dv_index_coalesce`(
--   `USER_NAME` VARCHAR(64),
--   `TABLE_NAME` VARCHAR(64),
--   `INDEX_NAME` VARCHAR(64),
--   `INDEX_PART_NAME` VARCHAR(64),
--   `INDEX_SUBPART_NAME` VARCHAR(64),
--   `NEED_RECYCLE` VARCHAR(64),
--   `GARBAGE_RATIO` BIGINT,
--   `GARBAGE_SIZE` BIGINT,
--   `EMPTY_RATIO` BIGINT,
--   `EMPTY_SIZE` BIGINT,
--   `FIRST_CHILD_EMPTY_SIZE` BIGINT,
--   `RECYCLE_STAT` VARCHAR(64),
--   `SEGMENT_SIZE` BIGINT,
--   `RECYCLED_SIZE` BIGINT,
--   `RECYCLED_REUSABLE` VARCHAR(64),
--   `FIRST_RECYCLE_SCN` BIGINT,
--   `LAST_RECYCLE_SCN` BIGINT,
--   `OW_DEL_SCN` BIGINT,
--   `OW_RECYCLE_SCN` BIGINT,
--   `DELETE_SIZE` BIGINT,
--   `INSERT_SIZE` BIGINT,
--   `ALLOC_PAGES` BIGINT,
--   `SEGMENT_SCN` BIGINT,
--   `BTREE_LEVEL` BIGINT
-- ) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- -- 查看所有的索引回收: DV_INDEX_RECYCLE
-- CREATE TABLE IF NOT EXISTS `cantian`.`dv_index_recycle`(
--   `UID` INTEGER,
--   `TABLE_ID` INTEGER,
--   `INDEX_ID` INTEGER,
--   `PART_ORG_SCN` BIGINT,
--   `XID` BIGINT,
--   `SCN` BIGINT,
--   `IS_TX_ACTIVE` VARCHAR(64),
--   `MIN_SCN` BIGINT,
--   `CUR_SCN` BIGINT
-- ) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- -- 查看所有的索引重建: DV_INDEX_REBUILD
-- CREATE TABLE IF NOT EXISTS `cantian`.`dv_index_rebuild`(
--   `UID` INTEGER,
--   `TABLE_ID` INTEGER,
--   `ALTER_INDEX_TYPE` VARCHAR(64),
--   `INDEX_NAME` VARCHAR(64),
--   `INDEX_PART_NAME` VARCHAR(64),
--   `STATE` VARCHAR(64),
--   `SCN` BIGINT
-- ) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- 查看所有用户的数据文件信息: DV_TABLESPACES
CREATE TABLE IF NOT EXISTS `cantian`.`dv_tablespaces`(
  `ID` INTEGER,
  `NAME` VARCHAR(64),
  `TEMPORARY` VARCHAR(8),
  `IN_MEMORY` VARCHAR(8),
  `AUTO_PURGE` VARCHAR(8),
  `EXTENT_SIZE` INTEGER,
  `SEGMENT_COUNT` INTEGER,
  `FILE_COUNT` INTEGER,
  `STATUS` VARCHAR(8),
  `AUTO_OFFLINE` VARCHAR(8),
  `EXTENT_MANAGEMENT` VARCHAR(8),
  `EXTENT_ALLOCATION` VARCHAR(8),
  `ENCRYPT` VARCHAR(8),
  `PUNCHED_SIZE` BIGINT
) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- DV_PARAMETERS
CREATE TABLE IF NOT EXISTS `cantian`.`dv_parameters`(
  `NAME` VARCHAR(64),
  `VALUE` VARCHAR(2048),
  `RUNTIME_VALUE` VARCHAR(2048),
  `DEFAULT_VALUE` VARCHAR(2048),
  `ISDEFAULT` VARCHAR(20),
  `MODIFIABLE` VARCHAR(20),
  `DESCRIPTION` VARCHAR(2048),
  `RANGE` VARCHAR(2048),
  `DATATYPE` VARCHAR(20),
  `EFFECTIVE` VARCHAR(20)
) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- 查询系统的基础统计，包括sql执行情况，读写盘时延等: DV_SYS_STATS
 CREATE TABLE IF NOT EXISTS `cantian`.`dv_sys_stats`(
   `STATISTIC#` INTEGER,
   `NAME` VARCHAR(64),
   `CLASS` INTEGER,
   `VALUE` BIGINT
 ) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- 查询会话级等待事件的统计信息：DV_SESSION_EVENTS
CREATE TABLE IF NOT EXISTS `cantian`.`dv_session_events`(
  `SID` INTEGER,
  `EVENT#` INTEGER,
  `EVENT` VARCHAR(64),
  `P1` VARCHAR(64),
  `WAIT_CLASS` VARCHAR(64),
  `TOTAL_WAITS` BIGINT,
  `TIME_WAITED` BIGINT,
  `TIME_WAITED_MIRCO` BIGINT,
  `AVERAGE_WAIT` DOUBLE,
  `AVERAGE_WAIT_MIRCO` BIGINT,
  `TENANT_ID` INTEGER
) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- 查询系统级等待事件的统计信息：DV_SYS_EVENTS
CREATE TABLE IF NOT EXISTS `cantian`.`dv_sys_events`(
  `EVENT#` INTEGER,
  `EVENT` VARCHAR(64),
  `P1` VARCHAR(64),
  `WAIT_CLASS` VARCHAR(64),
  `TOTAL_WAITS` BIGINT,
  `TIME_WAITED` BIGINT,
  `TIME_WAITED_MIRCO` BIGINT,
  `AVERAGE_WAIT` DOUBLE,
  `AVERAGE_WAIT_MIRCO` BIGINT
) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- -- 查询当前资源使用率: DV_DRC_RES_RATIO
-- CREATE TABLE IF NOT EXISTS `cantian`.`dv_drc_res_ratio`(
--   `DRC_RESOURCE` VARCHAR(20),
--   `USED` INTEGER,
--   `TOTAL` INTEGER,
--   `RATIO` VARCHAR(20)
-- ) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- -- 查看所有用户表空间中空闲的区信息: DV_FREE_SPACE
-- CREATE TABLE IF NOT EXISTS `cantian`.`dv_free_space`(
--   `TABLESPACE_NAME` VARCHAR(64),
--   `FILE_ID` INTEGER,
--   `BLOCK_ID` INTEGER,
--   `BYTES` BIGINT,
--   `BLOCKS` BIGINT,
--   `RELATIVE_FNO` INTEGER
-- ) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- DV_BUFFER_POOLS
-- 查询buff pool分配状态
CREATE TABLE IF NOT EXISTS `cantian`.`dv_buffer_pools`(
  `ID` INTEGER,
  `NAME` VARCHAR(64),
  `PAGE_SIZE` INTEGER,
  `CURRENT_SIZE` INTEGER,
  `BUFFERS` INTEGER,
  `FREE` INTEGER
) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- DV_BUFFER_PAGE_STATS
-- 查看各类页面的占用情况
CREATE TABLE IF NOT EXISTS `cantian`.`dv_buffer_page_stats`(
  `POOL_ID` INTEGER,
  `TYPE` VARCHAR(64),
  `CNUM_TOTAL` INTEGER,
  `CNUM_CLEAN` INTEGER,
  `CNUM_DIRTY` INTEGER
) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- -- DV_BUFFER_POOL_STATS
-- CREATE TABLE IF NOT EXISTS `cantian`.`dv_buffer_pool_stats`(
--   `ID` INTEGER,
--   `NAME` VARCHAR(64),
--   `SET_MSIZE` INTEGER,
--   `CNUM_REPL` INTEGER,
--   `CNUM_WRITE` INTEGER,
--   `CNUM_FREE` INTEGER,
--   `CNUM_PINNED` INTEGER,
--   `CNUM_RO` INTEGER,
--   `OLD_LEN` INTEGER,
--   `STATS_LEN` INTEGER,
--   `RECYCLED` INTEGER,
--   `WRITE_LEN` INTEGER,
--   `RECYCLE_GROUP` INTEGER,
--   `COLD_DIRTY_GROUP` INTEGER,
--   `TOTAL_GROUP` INTEGER,
--   `LOCAL_MASTER` INTEGER,
--   `REMOTE_MASTER` INTEGER
-- ) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- -- DV_DRC_BUF_INFO
-- CREATE TABLE IF NOT EXISTS `cantian`.`dv_drc_buf_info`(
--   `IDX` INTEGER UNSIGNED,
--   `FILE_ID` INTEGER UNSIGNED,
--   `PAGE_ID` INTEGER UNSIGNED,
--   `OWNER_ID` INTEGER UNSIGNED,
--   `OWNER_LOCK` INTEGER UNSIGNED,
--   `CONVERTING_INST` INTEGER UNSIGNED,
--   `CONVERTING_CUR_LOCK` VARCHAR(20),
--   `CONVERTING_REQ_LOCK` VARCHAR(20),
--   `CONVERTQ_LEN` INTEGER UNSIGNED,
--   `EDP_MAP` BIGINT,
--   `CONVERTING_REQ_SID` INTEGER UNSIGNED,
--   `CONVERTING_REQ_RSN` INTEGER UNSIGNED,
--   `PART_ID` INTEGER UNSIGNED,
--   `READONLY_COPIES` BIGINT
-- ) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- -- DV_IO_STAT_RECORD
-- CREATE TABLE IF NOT EXISTS `cantian`.`dv_io_stat_record`(
--   `STATISTIC#` INTEGER,
--   `NAME` VARCHAR(64),
--   `START` BIGINT,
--   `BACK_GOOD` BIGINT,
--   `BACK_BAD` BIGINT,
--   `NOT_BACK` BIGINT,
--   `AVG_US` BIGINT,
--   `MAX_US` BIGINT,
--   `MIN_US` BIGINT,
--   `TOTAL_US` BIGINT,
--   `TOTAL_GOOD_US` BIGINT,
--   `AVG_GOOD_US` BIGINT,
--   `TOTAL_BAD_US` BIGINT,
--   `AVG_BAD_US` BIGINT
-- ) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- DV_BUFFER_RECYCLE_STATS
-- 查看BUFFER淘汰状态信息
 CREATE TABLE IF NOT EXISTS `cantian`.`dv_buffer_recycle_stats`(
   `SID` INTEGER,
   `TOTAL` INTEGER,
   `WAITS` INTEGER,
   `AVG_STEP` REAL,
   `SPINS` INTEGER,
   `SLEEPS` INTEGER,
   `FAILS` INTEGER
 ) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- DV_BUFFER_ACCESS_STATS
-- 查看BUFFER cache命中率状态信息
 CREATE TABLE IF NOT EXISTS `cantian`.`dv_buffer_access_stats`(
   `SID` INTEGER,
   `TOTAL_ACCESS` INTEGER,
   `MISS_COUNT` INTEGER,
   `HIT_RATIO` REAL
 ) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- -- DV_DLSLOCKS
-- -- 查看某个锁资源在master上的资源信息
-- CREATE TABLE IF NOT EXISTS `cantian`.`dv_dlslocks`(
--   `IDX` INTEGER,
--   `DRID_TYPE` INTEGER,
--   `DRID_UID` INTEGER,
--   `DRID_ID` INTEGER,
--   `DRID_IDX` INTEGER,
--   `DRID_PART` INTEGER,
--   `DRID_PARENTPART` INTEGER,
--   `MODE` VARCHAR(20),
--   `PART_ID` INTEGER,
--   `GRANTED_MAP` INTEGER,
--   `CONVERTQ_LEN` INTEGER UNSIGNED,
--   `CONVERTING` INTEGER
-- ) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- -- DV_DRC_LOCAL_LOCK_INFO
-- -- 查看某个锁资源在本地的锁缓存信息
-- CREATE TABLE IF NOT EXISTS `cantian`.`dv_drc_local_lock_info`(
--   `IDX` INTEGER,
--   `DRID_TYPE` VARCHAR(20),
--   `DRID_UID` INTEGER,
--   `DRID_ID` INTEGER,
--   `DRID_IDX` INTEGER,
--   `DRID_PART` INTEGER,
--   `DRID_PARENTPART` INTEGER,
--   `IS_OWNER` INTEGER UNSIGNED,
--   `IS_LOCKED` INTEGER UNSIGNED,
--   `COUNT` INTEGER,
--   `LATCH_SHARE_COUNT` INTEGER UNSIGNED,
--   `LATCH_STAT` INTEGER UNSIGNED,
--   `LATCH_SID` INTEGER UNSIGNED
-- ) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- DV_REFORM_STATS
-- 查看reform关键信息视图
CREATE TABLE IF NOT EXISTS `cantian`.`dv_reform_stats`(
  `STATISTIC#` INTEGER,
  `NAME` VARCHAR(64),
  `VALUE` BIGINT,
  `INFO` VARCHAR(1024)
) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- -- DV_REFORM_DETAIL
-- CREATE TABLE IF NOT EXISTS `cantian`.`dv_reform_detail`(
--   `STATISTIC#` INTEGER,
--   `NAME` VARCHAR(64),
--   `START_TIME` VARCHAR(48),
--   `FINISH_TIME` VARCHAR(48),
--   `TIME_COST_US` BIGINT,
--   `STATUS` INTEGER
-- ) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- -- DV_PARAL_REPLAY_STATS
-- -- 查看recovery并发回放时延统计视图
-- CREATE TABLE IF NOT EXISTS `cantian`.`dv_paral_replay_stats`(
--   `SID` INTEGER,
--   `DISK_READ` BIGINT,
--   `DISK_READ_TOTAL_US`BIGINT,
--   `DISK_READ_AVG_US` BIGINT,
--   `SESSION_WORK_US` BIGINT,
--   `SESSION_USED_US` BIGINT,
--   `SESSION_UTIL_RATE` INTEGER,
--   `ADD_BUCKET_SLEEP_US` BIGINT,
--   `SESSION_REPLAY_LOG_GROUP` BIGINT
-- ) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- -- DV_UNDO_SEGMENTS
-- -- UNDO量查询
-- CREATE TABLE IF NOT EXISTS `cantian`.`dv_undo_segments`(
--   `ID` INTEGER,
--   `SEG_ENTRY` BIGINT,
--   `SEG_STATUS`VARCHAR(20),
--   `TXN_PAGES` INTEGER,
--   `TXN_FREE_ITEM_CNT` INTEGER,
--   `TXN_FIRST` INTEGER,
--   `TXN_LAST` INTEGER,
--   `UNDO_PAGES` INTEGER,
--   `UNDO_FIRST` BIGINT,
--   `UNDO_LAST` BIGINT,
--   `FIRST_TIME` DATETIME,
--   `LAST_TIME` DATETIME,
--   `RETENTION_TIME` INTEGER,
--   `OW_SCN` BIGINT,
--   `BEGIN_TIME` DATETIME,
--   `TXN_CNT` INTEGER,
--   `REUSE_XP_PAGES` INTEGER,
--   `REU_UNXP_PAGES` INTEGER,
--   `USE_SPACE_PAGES`INTEGER,
--   `STEAL_XP_PAGES` INTEGER,
--   `STEAL_UNXP_PAGES` INTEGER,
--   `STEALED_XP_PAGES` INTEGER,
--   `STEALED_UNXP_PAGES` INTEGER,
--   `BUF_BUSY_WAITS` BIGINT
-- ) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- DV_SESSIONS
-- 查询当前各个会话执行的sql语句
CREATE TABLE IF NOT EXISTS `cantian`.`dv_sessions`(
  `SID` INTEGER,
  `SPID` VARCHAR(11),
  `SERIAL#` INTEGER,
  `USER#` INTEGER,
  `USERNAME` VARCHAR(64),
  `CURR_SCHEMA` VARCHAR(64),
  `PIPE_TYPE` VARCHAR(20),
  `CLIENT_IP` VARCHAR(64),
  `CLIENT_PORT` VARCHAR(10),
  `CLIENT_UDS_PATH` VARCHAR(108),
  `SERVER_IP` VARCHAR(64),
  `SERVER_PORT`  VARCHAR(10),
  `SERVER_UDS_PATH` VARCHAR(108),
  `SERVER_MODE` VARCHAR(10),
  `OSUSER` VARCHAR(64),
  `MACHINE` VARCHAR(64),
  `PROGRAM` VARCHAR(256),
  `AUTO_COMMIT` BOOLEAN,
  `CLIENT_VERSION`INTEGER,
  `TYPE` VARCHAR(10),
  `LOGON_TIME` DATETIME,
  `STATUS` VARCHAR(10),
  `LOCK_WAIT` VARCHAR(4),
  `WAIT_SID` INTEGER,
  `EXECUTIONS` BIGINT,
  `SIMPLE_QUERIES` BIGINT,
  `DISK_READS` BIGINT,
  `BUFFER_GETS` BIGINT,
  `CR_GETS` BIGINT,
  `CURRENT_SQL` VARCHAR(1024),
  `SQL_EXEC_START` DATETIME,
  `SQL_ID` VARCHAR(11),
  `ATOMIC_OPERS` BIGINT,
  `REDO_BYTES` BIGINT,
  `COMMITS` BIGINT,
  `NOWAIT_COMMITS` BIGINT,
  `XA_COMMITS` BIGINT,
  `ROLLBACKS` BIGINT,
  `XA_ROLLBACKS` BIGINT,
  `LOCAL_TXN_TIMES` BIGINT,
  `XA_TXN_TIMES` BIGINT,
  `PARSES` BIGINT,
  `HARD_PARSES`BIGINT,
  `EVENT#` INTEGER,
  `EVENT` VARCHAR(64),
  `SORTS` BIGINT,
  `PROCESSED_ROWS` BIGINT,
  `IO_WAIT_TIME` BIGINT,
  `CON_WAIT_TIME` BIGINT,
  `CPU_TIME` BIGINT,
  `ELAPSED_TIME` BIGINT,
  `ISOLEVEL` BIGINT,
  `MODULE` VARCHAR(64),
  `VMP_PAGES` BIGINT,
  `LARGE_VMP_PAGES` BIGINT,
  `RES_CONTROL_GROUP` VARCHAR(64),
  `RES_IO_WAIT_TIME` BIGINT,
  `RES_QUEUE_TIME` BIGINT,
  `PRIV_FLAG` INTEGER,
  `QUERY_SCN` BIGINT,
  `STMT_COUNT` INTEGER,
  `MIN_SCN` BIGINT,
  `PREV_SQL_ID` VARCHAR(10),
  `DCS_BUFFER_GETS` BIGINT,
  `DCS_BUFFER_SENDS` BIGINT,
  `DCS_CR_GETS` BIGINT,
  `DCS_CR_SENDS` BIGINT
) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- -- MES_ELAPSED
-- CREATE TABLE IF NOT EXISTS `cantian`.`mes_elapsed`(
--   `INST_ID` INTEGER,
--   `MES_TYPE` CHAR(5),
--   `GROUP_ID` CHAR(4),
--   `DESCRIPTION` CHAR(50),
--   `SEND` CHAR(35),
--   `SEND_IO` CHAR(35),
--   `SEND_ACK` CHAR(35),
--   `RECV` CHAR(35),
--   `GET_BUF` CHAR(35),
--   `READ_MESSAGE` CHAR(35),
--   `PUT_QUEUE` CHAR(35),
--   `GET_QUEUE` CHAR(35),
--   `PROCESS_FUNC` CHAR(35),
--   `BROADCAST` CHAR(35),
--   `BROADCAST_AND_WAIT` CHAR(35),
--   `MULTICAST` CHAR(35),
--   `MULTICAST_AND_WAIT` CHAR(35)
-- ) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- -- MES_STAT
-- -- 查看所有mes状态视图
-- CREATE TABLE IF NOT EXISTS `cantian`.`mes_stat`(
--   `INST_ID` INTEGER,
--   `MES_TYPE` CHAR(5),
--   `DESCRIPTION` CHAR(64),
--   `SEND` BIGINT,
--   `SEND_FAIL` BIGINT,
--   `LOCAL_COUNT` BIGINT,
--   `RECV_PROCESS` BIGINT,
--   `DEALING_COUNT` INTEGER
-- ) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- -- DV_LATCHS
-- CREATE TABLE IF NOT EXISTS `cantian`.`dv_latchs`(
--   `ID` INTEGER,
--   `NAME` CHAR(64),
--   `GETS` INTEGER,
--   `MISSES` INTEGER,
--   `SPIN_GETS` INTEGER,
--   `WAIT_TIME` INTEGER
-- ) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- -- MES_QUEUE
-- CREATE TABLE IF NOT EXISTS `cantian`.`mes_queue`(
--   `INST_ID` INTEGER,
--   `GROUP_ID` CHAR(4),
--   `QUEUE_LENGTH` CHAR(10)
-- ) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- -- MES_TASK_QUEUE
-- CREATE TABLE IF NOT EXISTS `cantian`.`mes_task_queue`(
--   `TASK_INDEX` INTEGER,
--   `QUEUE_LENGTH` INTEGER(10)
-- ) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- -- 提供redo日志文件信息: DV_LOG_FILES
-- CREATE TABLE IF NOT EXISTS `cantian`.`dv_log_files`(
--   `INSTANCE` INTEGER,
--   `ID` INTEGER,
--   `STATUS` VARCHAR(20),
--   `TYPE` VARCHAR(20),
--   `FILE_NAME` VARCHAR(256),
--   `BYTES` BIGINT,
--   `WRITE_POS` BIGINT,
--   `FREE_SIZE` BIGINT,
--   `RESET_ID` INTEGER,
--   `ASN` INTEGER,
--   `BLOCK_SIZE` INTEGER,
--   `CURRENT_POINT` VARCHAR(128),
--   `ARCH_POS` BIGINT
-- ) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- -- 提供当前节点信息（curr_scn、lrp_point、rcy_point、lfn等）： DV_DATABASE
-- CREATE TABLE IF NOT EXISTS `cantian`.`dv_database`(
--   `DBID` INTEGER,
--   `NAME` VARCHAR(32),
--   `STATUS` VARCHAR(20),
--   `OPEN_STATUS` VARCHAR(20),
--   `OPEN_COUNT` INTEGER,
--   `INIT_TIME` DATETIME,
--   `CURRENT_SCN` BIGINT,
--   `RCY_POINT` VARCHAR(20),
--   `LRP_POINT` VARCHAR(20),
--   `CKPT_ID` BIGINT,
--   `LSN` BIGINT,
--   `LFN` BIGINT,
--   `LOG_COUNT` INTEGER,
--   `LOG_FIRST` INTEGER,
--   `LOG_LAST` INTEGER,
--   `LOG_FREE_SIZE` BIGINT,
--   `LOG_MODE` VARCHAR(30),
--   `SPACE_COUNT` INTEGER,
--   `DEVICE_COUNT` INTEGER,
--   `DW_START` INTEGER,
--   `DW_END` INTEGER,
--   `PROTECTION_MODE` VARCHAR(20),
--   `DATABASE_ROLE` VARCHAR(30),
--   `DATABASE_CONDITION` VARCHAR(16),
--   `SWITCHOVER_STATUS` VARCHAR(20),
--   `FAILOVER_STATUS` VARCHAR(20),
--   `ARCHIVELOG_CHANGE` INTEGER,
--   `LREP_POINT` VARCHAR(20),
--   `LREP_MODE` VARCHAR(20),
--   `OPEN_INCONSISTENCY` VARCHAR(20),
--   `CHARACTER_SET` VARCHAR(20),
--   `COMMIT_SCN` BIGINT,
--   `NEED_REPAIR_REASON` VARCHAR(20),
--   `READONLY_REASON` VARCHAR(20),
--   `BIN_SYS_VERSION` INTEGER,
--   `DATA_SYS_VERSION` INTEGER,
--   `RESETLOG` VARCHAR(128),
--   `MIN_SCN` BIGINT,
--   `ARCHIVELOG_SIZE` BIGINT,
--   `DDL_EXEC_STATUS` VARCHAR(40)
-- ) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- 提供内核版本信息: DV_VERSION
CREATE TABLE IF NOT EXISTS `cantian`.`dv_version`(
  `VERSION` VARCHAR(80)
) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- -- DV_CTRL_VERSION
-- CREATE TABLE IF NOT EXISTS `cantian`.`dv_ctrl_version`(
--   `VERSION` VARCHAR(80)
-- ) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- -- 提供事务信息，用于监控事务: DV_ALL_TRANS
-- CREATE TABLE IF NOT EXISTS `cantian`.`dv_all_trans`(
--   `SEG_ID` INTEGER,
--   `SLOT` INTEGER,
--   `XNUM` INTEGER,
--   `SCN` BIGINT,
--   `SID` INTEGER,
--   `STATUS` VARCHAR(64),
--   `UNDO_COUNT` INTEGER,
--   `UNDO_FIRST` INTEGER,
--   `UNDO_LAST` INTEGER,
--   `TXN_PAGEID` INTEGER,
--   `RMID` INTEGER,
--   `REMAINED` VARCHAR(64)
-- ) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- 提供事务信息: DV_TRANSACTIONS
CREATE TABLE IF NOT EXISTS `cantian`.`dv_transactions`(
  `SEG_ID` INTEGER,
  `SLOT` INTEGER,
  `XNUM` INTEGER,
  `SCN` BIGINT,
  `SID` INTEGER,
  `STATUS` VARCHAR(64),
  `UNDO_COUNT` INTEGER,
  `UNDO_FIRST` INTEGER,
  `UNDO_LAST` INTEGER,
  `BEGIN_TIME` DATETIME,
  `TXN_PAGEID` INTEGER,
  `RMID` INTEGER,
  `REMAINED` VARCHAR(64),
  `EXEC_TIME` BIGINT
) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- -- 提供Cantian实例状态: DV_INSTANCE
-- CREATE TABLE IF NOT EXISTS `cantian`.`dv_instance`(
--   `INSTANCE_ID` INTEGER,
--   `INSTANCE_NAME` VARCHAR(20),
--   `STATUS` VARCHAR(20),
--   `KERNEL_SCN` BIGINT,
--   `SHUTDOWN_PHASE` VARCHAR(20),
--   `STARTUP_TIME` DATETIME,
--   `HOST_NAME` VARCHAR(64),
--   `PLATFORM_NAME` VARCHAR(64),
--   `CONNECT_STATUS` VARCHAR(20)
-- ) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- -- 提供当前正在打开的cursor信息: DV_OPEN_CURSORS
-- CREATE TABLE IF NOT EXISTS `cantian`.`dv_open_cursors`(
--   `SESSION_ID` INTEGER,
--   `STMT_ID` INTEGER,
--   `USER_NAME` VARCHAR(64),
--   `SQL_TEXT` VARCHAR(1024),
--   `SQL_TYPE` INTEGER,
--   `SQL_ID` VARCHAR(10),
--   `STATUS` VARCHAR(64),
--   `CURSOR_TYPE` VARCHAR(64),
--   `VM_OPEN_PAGES` BIGINT,
--   `VM_CLOSE_PAGES` BIGINT,
--   `VM_SWAPIN_PAGES` BIGINT,
--   `VM_FREE_PAGES` BIGINT,
--   `QUERY_SCN` BIGINT,
--   `LAST_SQL_ACTIVE_TIME` DATETIME,
--   `VM_ALLOC_PAGES` BIGINT,
--   `VM_MAX_OPEN_PAGES` BIGINT,
--   `VM_SWAPOUT_PAGES` BIGINT,
--   `ELAPSED_TIME` BIGINT,
--   `DISK_READS` BIGINT,
--   `IO_WAIT_TIME` BIGINT,
--   `BUFFER_GETS` BIGINT,
--   `CR_GETS` BIGINT,
--   `CON_WAIT_TIME` BIGINT,
--   `CPU_TIME` BIGINT
-- ) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- -- 提供local temporary table信息: DV_TEMPTABLES
-- CREATE TABLE IF NOT EXISTS `cantian`.`dv_temptables`(
--   `SESSION_ID` INTEGER,
--   `OWNER` VARCHAR(64),
--   `TABLE_NAME` VARCHAR(64),
--   `COLUMNT_COUNT` INTEGER,
--   `INDEX_COUNT` INTEGER,
--   `DATA_PAGES` INTEGER,
--   `INDEX_PAGES` INTEGER
-- ) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- -- 提供全局临时表表状态信息: GLOBAL TEMPORARY TABLE: DV_TEMP_TABLE_STATS
-- CREATE TABLE IF NOT EXISTS `cantian`.`dv_temp_table_stats`(
--   `USER#` INTEGER,
--   `ID` INTEGER,
--   `NAME` VARCHAR(64),
--   `NUM_ROWS` INTEGER,
--   `BLOCKS` INTEGER,
--   `EMPTY_BLOCKS` INTEGER,
--   `AVG_ROW_LEN` BIGINT,
--   `SAMPLESIZE` INTEGER,
--   `ANALYZETIME` TIMESTAMP
-- ) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- -- 提供全局临时表列状态信息: DV_TEMP_COLUMN_STATS
-- CREATE TABLE IF NOT EXISTS `cantian`.`dv_temp_column_stats`(
--   `USER#` INTEGER,
--   `TABLE#` INTEGER,
--   `ID` INTEGER,
--   `NAME` VARCHAR(64),
--   `NUM_DISTINCT` INTEGER,
--   `LOW_VALUE` VARCHAR(64),
--   `HIGH_VALUE` VARCHAR(64),
--   `HISTOGRAM` VARCHAR(64)
-- ) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- -- 提供全局临时表索引状态信息: DV_TEMP_INDEX_STATS
-- CREATE TABLE IF NOT EXISTS `cantian`.`dv_temp_index_stats`(
--   `USER#` INTEGER,
--   `TABLE#` INTEGER,
--   `ID` INTEGER,
--   `NAME` VARCHAR(64),
--   `BLEVEL` INTEGER,
--   `LEVEL_BLOCKS` INTEGER,
--   `DISTINCT_KEYS` INTEGER,
--   `AVG_LEAF_BLOCKS_PER_KEY` DOUBLE,
--   `AVG_DATA_BLOCKS_PER_KEY` DOUBLE,
--   `ANALYZETIME` TIMESTAMP,
--   `EMPTY_LEAF_BLOCKS` INTEGER,
--   `CLUFAC` INTEGER,
--   `COMB_COLS_2_NDV` INTEGER,
--   `COMB_COLS_3_NDV` INTEGER,
--   `COMB_COLS_4_NDV` INTEGER
-- ) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- 记录系统中的直方图头信息: SYS_HISTGRAM_ABSTR
CREATE TABLE IF NOT EXISTS `cantian`.`sys_histgram_abstr`(
  `USER#` INTEGER,
  `TAB#` INTEGER,
  `COL#` INTEGER,
  `BUCKET_NUM` INTEGER,
  `ROW_NUM` INTEGER,
  `NULL_NUM` INTEGER,
  `ANALYZE_TIME` DATETIME,
  `MINVALUE` VARCHAR(4000),
  `MAXVALUE` VARCHAR(4000),
  `DIST_NUM` INTEGER,
  `DENSITY` DOUBLE,
  `SPARE1` BIGINT,
  `SPARE2` BIGINT,
  `SPARE3` BIGINT,
  `SPARE4` BIGINT
) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- 记录系统中表信息：SYS_TABLES
CREATE TABLE IF NOT EXISTS `cantian`.`sys_tables`(
  `USER#` INTEGER, 
  `ID` INTEGER,
  `NAME` VARCHAR(64), 
  `SPACE#` INTEGER,
  `ORG_SCN` BIGINT,
  `CHG_SCN` BIGINT,
  `TYPE` INTEGER,
  `COLS` INTEGER,
  `INDEXES` INTEGER,
  `PARTITIONED` INTEGER,
  `ENTRY` BIGINT,
  `INITRANS` INTEGER, 
  `PCTFREE` INTEGER,
  `CR_MODE` INTEGER,
  `RECYCLED` INTEGER,
  `APPENDONLY` INTEGER,
  `NUM_ROWS` INTEGER,
  `BLOCKS` INTEGER,
  `EMPTY_BLOCKS` INTEGER,
  `AVG_ROW_LEN` BIGINT,
  `SAMPLESIZE` INTEGER,
  `ANALYZETIME` TIMESTAMP(6),
  `SERIAL_START` BIGINT,
  `OPTIONS` VARBINARY(16),
  `OBJ#` INTEGER,
  `VERSION` INTEGER,
  `FLAG` INTEGER
) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- 记录系统中库信息：SYS_USERS
CREATE TABLE IF NOT EXISTS `cantian`.`sys_users`(
  `ID` INTEGER,
  `NAME` VARCHAR(64),
  `PASSWORD` VARBINARY(512),
  `DATA_SPACE#` INTEGER,
  `TEMP_SPACE#` INTEGER,
  `CTIME` DATETIME,
  `PTIME` DATETIME,
  `EXPTIME` DATETIME,
  `LTIME` DATETIME,
  `PROFILE#` INTEGER, 
  `ASTATUS` INTEGER,
  `LCOUNT` INTEGER,
  `OPTIONS` VARBINARY(16),
  `TENANT_ID` INTEGER
) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- 查看所有job信息：SYS_JOBS
CREATE TABLE IF NOT EXISTS `cantian`.`sys_jobs`(
  `JOB` BIGINT,
  `LOWNER` VARCHAR(64),
  `POWNER` VARCHAR(64),
  `COWNER` VARCHAR(64),
  `LAST_DATE` DATETIME,
  `THIS_DATE` DATETIME,
  `NEXT_DATE` DATETIME,
  `TOTAL` INTEGER,
  `INTERVAL#` VARCHAR(200),
  `FAILURES` INTEGER, 
  `BROKEN` INTEGER,
  `WHAT` VARCHAR(4000),
  `CREATE_DATE` DATETIME,
  `INSTANCE` INTEGER
) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- 获取锁的事务信息：DV_LOCKS
CREATE TABLE IF NOT EXISTS `cantian`.`dv_locks`(
  `SID` INTEGER,
  `TYPE` VARCHAR(20),
  `ID1` BIGINT,
  `ID2` BIGINT,
  `LMODE` VARCHAR(20),
  `BLOCK` INTEGER,
  `RMID` INTEGER
) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- end

-- 查询会话的所有等待事件的统计信息: DV_SESSION_EVENTS
CREATE TABLE IF NOT EXISTS `cantian`.`dv_session_events`(
  `SID` INTEGER,
  `EVENT#` INTEGER,
  `EVENT` VARCHAR(64),
  `P1` VARCHAR(64),
  `WAIT_CLASS` VARCHAR(64),
  `TOTAL_WAITS` BIGINT,
  `TIME_WAITED` BIGINT,
  `TIME_WAITED_MIRCO` BIGINT,
  `AVERAGE_WAIT` DOUBLE,
  `AVERAGE_WAIT_MICRO` BIGINT,
  `TENANT_ID` INTEGER
) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- 查看当前数据库的各类事件等待情况: DV_SEGMENT_STATS
CREATE TABLE IF NOT EXISTS `cantian`.`dv_segment_stats`(
  `OWNER` VARCHAR(64),
  `OBJECT_NAME` VARCHAR(64),
  `SUBOBJECT_NAME` VARCHAR(64),
  `TS#` INTEGER,
  `OBJECT_TYPE` VARCHAR(64),
  `STATISTIC_NAME` VARCHAR(64),
  `STATISTIC#` INTEGER,
  `VALUE` INTEGER
) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

-- 查看当前锁资源情况: DV_LOCKS
CREATE TABLE IF NOT EXISTS `cantian`.`dv_locks`(
  `SID` INTEGER,
  `TYPE` VARCHAR(20),
  `ID1` BIGINT,
  `ID2` BIGINT,
  `LMODE` VARCHAR(20),
  `BLOCK` INTEGER,
  `RMID` INTEGER
) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;

UNLOCK INSTANCE;
set @ctc_ddl_local_enabled = NULL;

-- cantian views
-- ADM_DATA_FILES
CREATE OR REPLACE
  DEFINER = 'mysql.cantian'@'localhost'
  SQL SECURITY INVOKER VIEW cantian.cantian_data_files
(
  FILE_NAME,
  FILE_ID,
  TABLESPACE_NAME,
  BYTES,
  BLOCKS,
  STATUS,
  RELATIVE_FNO,
  AUTOEXTENSIBLE,
  MAXBYTES,
  MAXBLOCKS,
  INCREMENT_BY,
  USER_BYTES,
  USER_BLOCKS,
  ONLINE_STATUS
)
AS
  SELECT D.FILE_NAME,D.ID,T.NAME,D.BYTES,CAST((D.BYTES / (CAST(TRIM(TRAILING 'Kk' FROM P.VALUE) as SIGNED) * 1024)) as SIGNED),'VALID',D.ID,(case when D.AUTO_EXTEND='TRUE' then 'YES' else 'NO' end),
  CAST(D.MAX_SIZE as SIGNED),
  CAST((D.MAX_SIZE / (CAST(TRIM(TRAILING 'Kk' FROM P.VALUE) as SIGNED) * 1024)) as SIGNED),
  D.AUTO_EXTEND_SIZE,
  CAST((D.BYTES - 20 * (D.BYTES / (CAST(TRIM(TRAILING 'Kk' FROM P.VALUE) as SIGNED) * 1024))) as SIGNED),
  CAST(((D.BYTES - 20 * (D.BYTES / (CAST(TRIM(TRAILING 'Kk' FROM P.VALUE) as SIGNED) * 1024))) / (CAST(TRIM(TRAILING 'Kk' FROM P.VALUE) as SIGNED) * 1024)) as SIGNED),
  D.STATUS
  FROM cantian.dv_data_files D, cantian.dv_tablespaces T, cantian.dv_parameters P
  WHERE D.TABLESPACE_ID = T.ID AND P.NAME = 'PAGE_SIZE';

-- cantian_log_waits
CREATE OR REPLACE
  DEFINER = 'mysql.cantian'@'localhost'
  SQL SECURITY INVOKER VIEW cantian.cantian_log_waits
(
  cantian_log_waits
)
AS
  SELECT TOTAL_WAITS
  FROM cantian.dv_session_events
  WHERE event = 'log file switch(checkpoint incomplete)';

-- cantian_row_lock_waits
CREATE OR REPLACE
  DEFINER = 'mysql.cantian'@'localhost'
  SQL SECURITY INVOKER VIEW cantian.cantian_row_lock_waits
(
  cantian_row_lock_waits
)
AS
  SELECT SUM(VALUE)
  FROM cantian.dv_segment_stats s
  WHERE s.OBJECT_TYPE = 'TABLE' and s.STATISTIC_NAME = 'ROW LOCK WAITS';

-- cantian_row_lock_current_waits
CREATE OR REPLACE
  DEFINER = 'mysql.cantian'@'localhost'
  SQL SECURITY INVOKER VIEW cantian.cantian_row_lock_current_waits
(
  cantian_row_lock_current_waits
)
AS
  SELECT count(*)
  FROM cantian.dv_sessions s
  WHERE s.LOCK_WAIT = 'Y';

-- cantian_lock_waits
CREATE OR REPLACE
  DEFINER = 'mysql.cantian'@'localhost'
  SQL SECURITY INVOKER VIEW cantian.cantian_lock_waits
(
  session_id,
  lock_watting,
  requesting_trx_rmid,
  requesting_trx_status,
  requesting_trx_begin_time,
  `requesting_trx_exec_time(s)`,
  blocking_wait_sid,
  blocking_trx_rmid,
  blocking_trx_status,
  blocking_trx_begin_time,
  `blocking_trx_exec_time(s)`,
  lock_type,
  lock_page,
  lock_itl
)
AS
  SELECT s.SID,s.LOCK_WAIT,t.RMID,t.STATUS,t.BEGIN_TIME,t.EXEC_TIME/1000000,s.WAIT_SID,twait.RMID,twait.STATUS,twait.BEGIN_TIME,twait.EXEC_TIME/1000000,l.TYPE,l.ID1,l.ID2
  FROM cantian.dv_locks l
  JOIN cantian.dv_transactions t 
  JOIN cantian.dv_transactions twait
  JOIN cantian.dv_sessions s
  JOIN cantian.dv_sessions swait
  WHERE s.LOCK_WAIT = 'Y' AND s.SID = l.SID AND s.SID = t.SID AND s.WAIT_SID = swait.SID AND swait.SID = twait.SID;

-- cantian_trx
CREATE OR REPLACE
  DEFINER = 'mysql.cantian'@'localhost'
  SQL SECURITY INVOKER VIEW cantian.cantian_trx
(
  SEG_ID,
  SLOT,
  XNUM,
  SCN,
  SID,
  STATUS,
  UNDO_COUNT,
  UNDO_FIRST,
  UNDO_LAST,
  BEGIN_TIME,
  TXN_PAGEID,
  TXN_RMID,
  REMAINED,
  EXEC_TIME,
  LOCK_WAIT,
  LOCK_TYPE,
  ID1,
  ID2,
  LMODE,
  BLOCK,
  LOCK_RMID
)
AS
  SELECT t.SEG_ID,t.SLOT,t.XNUM,t.SCN,t.SID,t.STATUS,t.UNDO_COUNT,t.UNDO_FIRST,t.UNDO_LAST,t.BEGIN_TIME,t.TXN_PAGEID,t.RMID,t.REMAINED,t.EXEC_TIME,s.LOCK_WAIT,l.TYPE,l.ID1,l.ID2,l.LMODE,l.BLOCK,l.RMID
  FROM cantian.dv_transactions t
  JOIN cantian.dv_sessions s ON t.SID = s.SID
  JOIN cantian.dv_locks l ON s.SID = l.SID;

-- cantian_locks
CREATE OR REPLACE
  DEFINER = 'mysql.cantian'@'localhost'
  SQL SECURITY INVOKER VIEW cantian.cantian_locks
(
  session_id,
  lock_watting,
  requesting_trx_rmid,
  blocking_wait_sid,
  blocking_trx_rmid,
  lock_type,
  lock_page,
  lock_itl
)
AS
  SELECT s.SID,s.LOCK_WAIT,t.RMID,s.WAIT_SID,twait.RMID,l.TYPE,l.ID1,l.ID2
  FROM cantian.dv_locks l
  JOIN cantian.dv_transactions t 
  JOIN cantian.dv_transactions twait
  JOIN cantian.dv_sessions s
  JOIN cantian.dv_sessions swait
  WHERE s.LOCK_WAIT = 'Y' AND s.SID = l.SID AND s.SID = t.SID AND s.WAIT_SID = swait.SID AND swait.SID = twait.SID 
  UNION ALL
  SELECT s.SID,s.LOCK_WAIT,t.RMID,s.WAIT_SID,null,l.TYPE,l.ID1,l.ID2
  FROM cantian.dv_sessions s
  JOIN cantian.dv_transactions t ON s.SID = t.SID
  JOIN cantian.dv_locks l ON s.SID = l.SID
  WHERE s.LOCK_WAIT = 'N';

-- cantian_io_stats
CREATE OR REPLACE
  DEFINER = 'mysql.cantian'@'localhost'
  SQL SECURITY INVOKER VIEW cantian.cantian_io_stats
(
  `STATISTIC#`,
  NAME,
  CLASS,
  VALUE
)
AS
  SELECT *
  FROM cantian.dv_sys_stats s
  WHERE s.name = 'disk reads' or s.name = 'disk read time' or s.name = 'redo writes' or s.name = 'redo write time' or s.name = 'redo write size' or s.name = 'DBWR disk writes' or s.name = 'DBWR disk write time';

-- cantian_row_lock_time_avg
CREATE OR REPLACE
  DEFINER = 'mysql.cantian'@'localhost'
  SQL SECURITY INVOKER VIEW cantian.cantian_row_lock_time_avg
(
  `VALUE(us)`
)
AS
  SELECT s.VALUE
  FROM cantian.dv_sys_stats s
  WHERE s.NAME = 'pcrh lock row avg time';

-- 超过10s/60s/180s/600s的事务个数：DV_TRANSACTIONS
CREATE OR REPLACE 
  DEFINER = 'mysql.cantian'@'localhost'
  SQL SECURITY INVOKER VIEW cantian_transactions
AS 
  SELECT * 
  FROM `cantian`.`dv_transactions`;
CREATE OR REPLACE 
  DEFINER = 'mysql.cantian'@'localhost'
  SQL SECURITY INVOKER VIEW cantian_transactions_cnt_over10s
AS 
  SELECT COUNT(*) as trx_count 
  FROM `cantian`.`dv_transactions`
  WHERE EXEC_TIME > (10 * 1000000);
CREATE OR REPLACE 
  DEFINER = 'mysql.cantian'@'localhost'
  SQL SECURITY INVOKER VIEW cantian_transactions_cnt_over60s
AS 
  SELECT COUNT(*) as trx_count 
  FROM `cantian`.`dv_transactions`
  WHERE EXEC_TIME > (60 * 1000000);
CREATE OR REPLACE
  DEFINER = 'mysql.cantian'@'localhost'
  SQL SECURITY INVOKER VIEW cantian_transactions_cnt_over180s
AS 
  SELECT COUNT(*) as trx_count 
  FROM `cantian`.`dv_transactions`
  WHERE EXEC_TIME > (180 * 1000000);
CREATE OR REPLACE 
  DEFINER = 'mysql.cantian'@'localhost'
  SQL SECURITY INVOKER VIEW cantian_transactions_cnt_over600s
AS 
  SELECT COUNT(*) as trx_count 
  FROM `cantian`.`dv_transactions`
  WHERE EXEC_TIME > (600 * 1000000);

-- DV_BUFFER_RECYCLE_STATS
CREATE OR REPLACE 
  DEFINER = 'mysql.cantian'@'localhost'
  SQL SECURITY INVOKER VIEW cantian_buffer_pool_wait_free
AS 
  SELECT * 
  FROM `cantian`.`dv_buffer_recycle_stats`;

-- buffer pool命中率：DV_BUFFER_ACCESS_STATS
CREATE OR REPLACE 
  DEFINER = 'mysql.cantian'@'localhost'
  SQL SECURITY INVOKER VIEW cantian_buffer_pool_hit
AS 
  SELECT 1-SUM(MISS_COUNT)/SUM(TOTAL_ACCESS) as cantian_buffer_pool_hit 
  FROM `cantian`.`dv_buffer_access_stats`;

-- fsync data当前等待数频率：DV_SYS_STATS
CREATE OR REPLACE 
  DEFINER = 'mysql.cantian'@'localhost'
  SQL SECURITY INVOKER VIEW cantian_data_pending_fsyncs
AS 
  SELECT VALUE 
  FROM `cantian`.`dv_sys_stats`
  WHERE NAME = 'DBWR disk writes';

-- fsync log当前等待数频率：DV_SYS_STATS
CREATE OR REPLACE 
  DEFINER = 'mysql.cantian'@'localhost'
  SQL SECURITY INVOKER VIEW cantian_os_log_pending_fsyncs
AS 
  SELECT VALUE 
  FROM `cantian`.`dv_sys_stats`
  WHERE NAME = 'redo writes';

-- Redo Log Pending Writes会话级 & 系统级日志写操作被挂起的次数：DV_SESSION_EVENTS & DV_SYS_EVENTS
CREATE OR REPLACE 
  DEFINER = 'mysql.cantian'@'localhost'
  SQL SECURITY INVOKER VIEW cantian_redo_log_pending_writes_session
AS 
  SELECT SID,AVERAGE_WAIT 
  FROM `cantian`.`dv_session_events`
  WHERE EVENT = 'log file sync';
CREATE OR REPLACE 
  DEFINER = 'mysql.cantian'@'localhost'
  SQL SECURITY INVOKER VIEW cantian_redo_log_pending_writes_sys
AS 
  SELECT AVERAGE_WAIT 
  FROM `cantian`.`dv_sys_events`
  WHERE EVENT = 'log file sync';

-- Semaphores会话级 & 系统级等待事件的统计信息：DV_SESSION_EVENTS & DV_SYS_EVENTS
CREATE OR REPLACE 
  DEFINER = 'mysql.cantian'@'localhost'
  SQL SECURITY INVOKER VIEW cantian_semaphores_session
AS 
  SELECT * 
  FROM `cantian`.`dv_session_events`;
CREATE OR REPLACE 
  DEFINER = 'mysql.cantian'@'localhost'
  SQL SECURITY INVOKER VIEW cantian_semaphores_sys
AS 
  SELECT * 
  FROM `cantian`.`dv_sys_events`;

-- 统计信息视图:cantian_histgram_abstr
CREATE OR REPLACE
  DEFINER = 'mysql.cantian'@'localhost'
  SQL SECURITY INVOKER VIEW cantian.cantian_histgram_abstr
(
  `USER#`,
  `USER_NAME`,
  `TAB#`,
  `TABLE_NAME`,
  `COL#`,
  `BUCKET_NUM`,
  `ROW_NUM`,
  `NULL_NUM`,
  `ANALYZE_TIME`,
  `MINVALUE`,
  `MAXVALUE`,
  `DIST_NUM`,
  `DENSITY`,
  `SPARE1`,
  `SPARE2`,
  `SPARE3`,
  `SPARE4`
)
AS
  SELECT h.`USER#`,u.NAME,h.`TAB#`,t.NAME,h.`COL#`,h.BUCKET_NUM,h.ROW_NUM,h.NULL_NUM,h.ANALYZE_TIME,
         h.MINVALUE,h.MAXVALUE,h.DIST_NUM,h.DENSITY,h.SPARE1,h.SPARE2,h.SPARE3,h.SPARE4
  FROM cantian.sys_histgram_abstr h
  JOIN (SELECT ID, NAME FROM cantian.sys_users) u ON h.`USER#` = u.ID
  JOIN (SELECT `USER#`, ID, NAME FROM cantian.sys_tables) t ON h.`USER#` = t.`USER#` AND h.`TAB#` = t.ID;

-- 查看所有job信息:db_jobs
CREATE OR REPLACE
  DEFINER = 'mysql.cantian'@'localhost'
  SQL SECURITY INVOKER VIEW cantian.db_jobs
(
  `JOB`,
  `LOG_USER`,
  `PRIV_USER`,
  `SCHEMA_USER`,
  `LAST_DATE`,
  `LAST_SEC`,
  `THIS_DATE`,
  `THIS_SEC`,
  `NEXT_DATE`,
  `NEXT_SEC`, 
  `BROKEN`,
  `INTERVAL_TIME`,
  `FAILURES`,
  `WHAT`,
  `CREATE_DATE`
)
AS
  SELECT 
    JOB,LOWNER,POWNER,COWNER,LAST_DATE,
    DATE_FORMAT(LAST_DATE, '%H:%i'),
    THIS_DATE, 
    DATE_FORMAT(THIS_DATE, '%H:%i'),
    NEXT_DATE, 
    DATE_FORMAT(NEXT_DATE, '%H:%i'),
    CASE MOD(BROKEN, 2)
        WHEN 1 THEN 'Y'
        WHEN 0 THEN 'N'
        ELSE '?'
    END,
    `INTERVAL#`,FAILURES,WHAT,CREATE_DATE
  FROM cantian.sys_jobs;
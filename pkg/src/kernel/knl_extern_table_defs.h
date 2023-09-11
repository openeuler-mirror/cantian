/* -------------------------------------------------------------------------
 *  This file is part of the Cantian project.
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd.
 *
 * Cantian is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *          http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * -------------------------------------------------------------------------
 *
 * knl_extern_table_defs.h
 *
 *
 * IDENTIFICATION
 * src/kernel/knl_extern_table_defs.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef KNL_EXTERN_TABLE_DEFS_H
#define KNL_EXTERN_TABLE_DEFS_H

#ifdef __cplusplus
extern "C" {
#endif

/*************************************** SYS_HISTGRM *****************************************************************/
#define IX_HIST_003_ID                   0

/* extral system table index column */
#define IX_COL_HIST_003_USER_ID                   0
#define IX_COL_HIST_003_TABLE_ID                  1
#define IX_COL_HIST_003_COL_ID                    2
#define IX_COL_HIST_003_PART_ID                   3
#define IX_COL_HIST_003_ENDPOINT                  4

/******************************************* SYS_HIST_HEAD ***********************************************************/
typedef enum en_sys_histgram_abstr_column {
    SYS_HISTGRAM_ABSTR_COL_USER_ID = 0,
    SYS_HISTGRAM_ABSTR_COL_TABLE_ID = 1,
    SYS_HISTGRAM_ABSTR_COL_ID = 2,
    SYS_HISTGRAM_ABSTR_COL_NUM_BUCKET = 3,
    SYS_HISTGRAM_ABSTR_COL_NUM_ROWS = 4,
    SYS_HISTGRAM_ABSTR_COL_NUM_NULL = 5,
    SYS_HISTGRAM_ABSTR_COL_ANALYZETIME = 6,
    SYS_HISTGRAM_ABSTR_COL_MINVALUE = 7,
    SYS_HISTGRAM_ABSTR_COL_MAXVALUE = 8,
    SYS_HISTGRAM_ABSTR_COL_NUM_DISTINCT = 9,
    SYS_HISTGRAM_ABSTR_COL_DENSITY = 10,
    SYS_HISTGRAM_ABSTR_COL_SPARE1 = 11,       // part id
    SYS_HISTGRAM_ABSTR_COL_SPARE2 = 12,       // subpart id
    SYS_HISTGRAM_ABSTR_COL_SPARE3 = 13,       // sample_size
    SYS_HISTGRAM_ABSTR_COL_SPARE4 = 14,

    SYS_HISTGRAM_ABSTR_COLUMN_COUNT,    // systable column count, must be the last in the struct.
} sys_histgram_abstr_column_t;

#define IX_HIST_HEAD_002_ID              0
#define IX_HIST_HEAD_003_ID              1

/* extral system table index column */
#define IX_COL_HIST_HEAD_002_ANALYZE_TIME         0

#define IX_COL_HIST_HEAD_003_USER_ID              0
#define IX_COL_HIST_HEAD_003_TABLE_ID             1
#define IX_COL_HIST_HEAD_003_COL_ID               2
#define IX_COL_HIST_HEAD_003_SPARE1               3
#define IX_COL_HIST_HEAD_003_SPARE2               4

/*********************************************** SYS_SHADOW_INDEX ****************************************************/
typedef enum en_sys_shadow_index_column {
    SYS_SHADOW_INDEX_COL_USER_ID = 0,
    SYS_SHADOW_INDEX_COL_TABLE_ID = 1,
    SYS_SHADOW_INDEX_COL_ID = 2,
    SYS_SHADOW_INDEX_COL_NAME = 3,
    SYS_SHADOW_INDEX_COL_SPACE_ID = 4,
    SYS_SHADOW_INDEX_COL_SEQUENCE_ID = 5,
    SYS_SHADOW_INDEX_COL_ENTRY = 6,
    SYS_SHADOW_INDEX_COL_IS_PRIMARY = 7,
    SYS_SHADOW_INDEX_COL_IS_UNIQUE = 8,
    SYS_SHADOW_INDEX_COL_TYPE = 9,
    SYS_SHADOW_INDEX_COL_COLS = 10,
    SYS_SHADOW_INDEX_COL_COL_LIST = 11,
    SYS_SHADOW_INDEX_COL_INITRANS = 12,
    SYS_SHADOW_INDEX_COL_CR_MODE = 13,
    SYS_SHADOW_INDEX_COL_FLAGS = 14,
    SYS_SHADOW_INDEX_COL_PARTED = 15,
    SYS_SHADOW_INDEX_COL_PCTFREE = 16,

    SYS_SHADOW_INDEX_COLUMN_COUNT,    // systable column count, must be the last in the struct.
} sys_shadow_index_column_t;

#define IX_SYS_SHADOW_INDEX_001_ID       0

/********************************* SYS_PROFILE ***********************************************************************/
typedef enum en_sys_profile_column {
    SYS_PROFILE_COL_NAME = 0,
    SYS_PROFILE_COL_PROFILE_ID = 1,
    SYS_PROFILE_COL_RESOURCE_ID = 2,
    SYS_PROFILE_COL_THRESHOLD = 3,

    SYS_PROFILE_COLUMN_COUNT,    // systable column count, must be the last in the struct.
} sys_profile_column_t;

#define IX_SYS_PROFILE_001_ID            0

#define IX_COL_SYS_PROFILE_001_PROFILE_ID         0
#define IX_COL_SYS_PROFILE_001_ESOURCE_ID         1

/****************************************** SYS_SHADOW_INDEXPART *****************************************************/
typedef enum en_sys_shadow_indexpart_column {
    SYS_SHADOW_INDEXPART_COL_USER_ID = 0,
    SYS_SHADOW_INDEXPART_COL_TABLE_ID = 1,
    SYS_SHADOW_INDEXPART_COL_INDEX_ID = 2,
    SYS_SHADOW_INDEXPART_COL_PART_ID = 3,
    SYS_SHADOW_INDEXPART_COL_NAME = 4,
    SYS_SHADOW_INDEXPART_COL_HIBOUNDLEN = 5,
    SYS_SHADOW_INDEXPART_COL_HIBOUNDVAL = 6,
    SYS_SHADOW_INDEXPART_COL_SPACE_ID = 7,
    SYS_SHADOW_INDEXPART_COL_ORG_SCN = 8,
    SYS_SHADOW_INDEXPART_COL_ENTRY = 9,
    SYS_SHADOW_INDEXPART_COL_INITRANS = 10,
    SYS_SHADOW_INDEXPART_COL_PCTFREE = 11,
    SYS_SHADOW_INDEXPART_COL_FLAGS = 12,
    SYS_SHADOW_INDEXPART_COL_BHIBOUNDVAL = 13,
    SYS_SHADOW_INDEXPART_COL_SUBPART_CNT = 14,

    SYS_SHADOW_INDEXPART_COLUMN_COUNT,    // systable column count, must be the last in the struct.
} sys_shadow_indexpart_column_t;

#define IX_SYS_SHW_INDEXPART001_ID       0

/* extral system table index column */
#define IX_COL_SYS_SHADOW_INDEX_001_USER_ID       0
#define IX_COL_SYS_SHADOW_INDEX_001_TABLE_ID      1

#define IX_COL_SYS_SHW_INDEXPART001_USER_ID       0
#define IX_COL_SYS_SHW_INDEXPART001_TABLE_ID      1
#define IX_COL_SYS_SHW_INDEXPART001_INDEX_ID      2
#define IX_COL_SYS_SHW_INDEXPART001_PART_ID       3
#define IX_COL_SYS_SHW_INDEXPART001_PARENTPART_ID 4

/************************************ SYS_BACKUP_SET *****************************************************************/
typedef enum en_sys_backup_set_columns {
    SYS_BACKUP_SET_STAGE = 0,
    SYS_BACKUP_SET_STATUS = 1,
    SYS_BACKUP_SET_SCN = 2,
    SYS_BACKUP_SET_COMPLETION_TIME = 3,

    SYS_BACKUP_SET_COLUMN_COUNT,    // systable column count, must be the last in the struct.
} en_sys_backup_set_columns_t;

#define IX_SYS_BACKUPSET_001_ID       0
#define IX_SYS_BACKUPSET_002_ID       1

#define IX_COL_SYS_BACKUPSET_001_RECID       0
#define IX_COL_SYS_BACKUPSET_002_TAG         0

/********************************* SYS_DISTRIBUTE_STRATEGY ***********************************************************/
typedef enum en_sys_distribute_strategy_column {
    DISTRIBUTED_STRATEGY_COL_USER = 0,
    DISTRIBUTED_STRATEGY_COL_TABLE = 1,
    DISTRIBUTED_STRATEGY_COL_DIST_DATA = 2,
    DISTRIBUTED_STRATEGY_COL_BUCKETS = 3,
    DISTRIBUTED_STRATEGY_COL_SLICE_CNT = 4,
    DISTRIBUTED_STRATEGY_COL_FROZEN_STATUS = 5,
    DISTRIBUTED_STRATEGY_COL_DIST_TEXT = 6,
    DISTRIBUTED_STRATEGY_COLUMN_COUNT,    // systable column count, must be the last in the struct.
} sys_distribute_strategy_column_t;

#define IX_COL_SYS_DISTRIBUTE_STRATEGY001_USER    0
#define IX_COL_SYS_DISTRIBUTE_STRATEGY001_TABLE   1

/********************************* SYS_GARBAGE_SEGMENT ***************************************************************/
typedef enum en_sys_garbage_segment_column {
    SYS_GARBAGE_SEGMENT_COL_UID = 0,
    SYS_GARBAGE_SEGMENT_COL_OID = 1,
    SYS_GARBAGE_SEGMENT_COL_INDEX_ID = 2,
    SYS_GARBAGE_SEGMENT_COL_COLUMN_ID = 3,
    SYS_GARBAGE_SEGMENT_COL_SPACE = 4,
    SYS_GARBAGE_SEGMENT_COL_ENTRY = 5,
    SYS_GARBAGE_SEGMENT_COL_ORG_SCN = 6,
    SYS_GARBAGE_SEGMENT_COL_SEG_SCN = 7,
    SYS_GARBAGE_SEGMENT_COL_INITRANS = 8,
    SYS_GARBAGE_SEGMENT_COL_PCTFREE = 9,
    SYS_GARBAGE_SEGMENT_COL_OP_TYPE = 10,
    SYS_GARBAGE_SEGMENT_COL_REUSE = 11,
    SYS_GARBAGE_SEGMENT_COL_SERIAL = 12,
    SYS_GARBAGE_SEGMENT_COL_SPARE2 = 13,
    SYS_GARBAGE_SEGMENT_COL_SPARE3 = 14,

    SYS_GARBAGE_SEGMENT_COLUMN_COUNT,    // systable column count, must be the last in the struct.
} sys_garbage_segment_column_t;

/* system table index slot */
#define IX_SYS_GARBAGE_SEGMENT001_ID     0

/* extral system table index column */
#define IX_COL_SYS_GARBAGE_SEGMENT001_UID            0
#define IX_COL_SYS_GARBAGE_SEGMENT001_OID            1

/********************************* SYS_PARTSTORE *********************************************************************/
typedef enum en_sys_partstore_column {
    SYS_PARTSTORE_COL_USER_ID = 0,
    SYS_PARTSTORE_COL_TABLE_ID = 1,
    SYS_PARTSTORE_COL_INDEX_ID = 2,
    SYS_PARTSTORE_COL_POSITION_ID = 3,
    SYS_PARTSTORE_COL_SPACE_ID = 4,

    SYS_PARTSTORE_COLUMN_COUNT,    // systable column count, must be the last in the struct.
} sys_partstore_column_t;

/* system table index slot */
#define IX_SYS_PARTSTORE001_ID           0

/* extral system table index column */
#define IX_COL_SYS_PARTSTORE001_USER_ID           0
#define IX_COL_SYS_PARTSTORE001_TABLE_ID          1
#define IX_COL_SYS_PARTSTORE001_INDEX_ID          2

/********************************* SYS_USER_HISTORY ******************************************************************/
#define SYSUSER_HISTORY_COLS                      3
#define SYS_USER_HISTORY_USER_ID                  0
#define SYS_USER_HISTORY_PASSOWRD_ID              1
#define SYS_USER_HISTORY_PASSWORD_DATE_ID         2

/* system table index slot */
#define IX_SYS_USER_HISTORY001_ID        0

/* extral system table index column */
#define IX_COL_SYS_USER_HISTORY001_USER_ID        0
#define IX_COL_SYS_USER_HISTORY001_PASSWORD_DATE  1

/********************************* SYS_PROC_ARGS *********************************************************************/
/* system table index slot */
#define IX_PROCARGU_001_ID               0
#define IX_PROCARGU_002_ID               1

/* extral system table index column */
#define IX_COL_PROC_001_NAME                      0
#define IX_COL_PROC_001_USER_ID                   1
#define IX_COL_PROC_001_CLASS                     2

#define IX_COL_PROC_002_TRIG_TABLE                0
#define IX_COL_PROC_002_TRIG_TABLE_USER           1

#define IX_COL_PROC_003_USER_ID                   0
#define IX_COL_PROC_003_OBJ_ID                    1

#define IX_COL_PROC_004_USER_ID                   0
#define IX_COL_PROC_004_LIB_NAME                  1

#define IX_COL_PROCARGU_001_USER_ID               0
#define IX_COL_PROCARGU_001_OBJECT_NAME           1
#define IX_COL_PROCARGU_001_PACKAGE               2
#define IX_COL_PROCARGU_001_SEQUENCE              3
#define IX_COL_PROCARGU_001_OVERLOAD              4

/********************************* SYS_LOGIC_REP *********************************************************************/
/* system table index slot */
#define IX_SYS_LOGICREP_001_ID           0

/* COLUMN ID in LOGIC_REP$ */
#define SYS_LOGIC_REP_COLUMN_ID_USERID       0
#define SYS_LOGIC_REP_COLUMN_ID_TABLEID      1
#define SYS_LOGIC_REP_COLUMN_ID_STATUS       2
#define SYS_LOGIC_REP_COLUMN_ID_INDEXID      3
#define SYS_LOGIC_REP_COLUMN_ID_PARTITIONIDS 4

/* extral system table index column */
#define IX_COL_SYS_LOGICREP_001_USERID            0
#define IX_COL_SYS_LOGICREP_001_TABLEID           1

/********************************* SYS_MON_MODS_ALL ******************************************************************/
#define IX_MODS_001_ID                   0
#define IX_MODS_002_ID                   1
#define IX_MODS_003_ID                   2

#define IX_COL_MODS_001_USER_ID                   0
#define IX_COL_MODS_001_TABLE_ID                  1

#define IX_COL_MODS_002_MODIFY_TIME               0

#define IX_COL_MODS_003_USER_ID                   0
#define IX_COL_MODS_003_TABLE_ID                  1
#define IX_COL_MODS_003_PART_ID                   2

/********************************* SYS_DEPENDENCY ********************************************************************/
/* system table index slot */
#define IX_DEPENDENCY1_ID                0
#define IX_DEPENDENCY2_ID                1

/* extral system table index column */
#define IX_COL_DEPENDENCY1_D_OWNER_ID             0
#define IX_COL_DEPENDENCY1_D_OBJ_ID               1
#define IX_COL_DEPENDENCY1_D_TYPE_ID              2
#define IX_COL_DEPENDENCY1_ORDER_ID               3

/* extral system table index column */
#define IX_COL_DEPENDENCY2_P_OWNER_ID             0
#define IX_COL_DEPENDENCY2_P_OBJ_ID               1
#define IX_COL_DEPENDENCY2_P_TYPE_ID              2

/* columns of dependency$ */
#define SYS_DEPENDENCY_D_OWNER 0
#define SYS_DEPENDENCY_D_OBJ   1
#define SYS_DEPENDENCY_D_TYPE  2
#define SYS_DEPENDENCY_D_SCN   3
#define SYS_DEPENDENCY_ORDER   4
#define SYS_DEPENDENCY_P_OWNER 5
#define SYS_DEPENDENCY_P_OBJ   6
#define SYS_DEPENDENCY_P_TYPE  7
#define SYS_DEPENDENCY_P_SCN   8
#define SYS_DEPENDENCY_D_NAME  9
#define SYS_DEPENDENCY_P_NAME  10

/********************************* SYS_DISTRIBUTE_RULE ***************************************************************/
typedef enum en_sys_distribute_rule_column {
    SYS_DISTRIBUTE_RULE_COL_UID = 0,
    SYS_DISTRIBUTE_RULE_COL_ID = 1,
    SYS_DISTRIBUTE_RULE_COL_DIST_DATA = 2,
    SYS_DISTRIBUTE_RULE_COL_BUCKETS = 3,
    SYS_DISTRIBUTE_RULE_COL_NAME = 4,
    SYS_DISTRIBUTE_RULE_COL_ORG_SCN = 5,
    SYS_DISTRIBUTE_RULE_COL_CHG_SCN = 6,
    SYS_DISTRIBUTE_RULE_COL_COLUMNS = 7,

    SYS_DISTRIBUTE_RULE_COLUMN_COUNT,    // systable column count, must be the last in the struct.
} sys_distribute_rule_column_t;

/* system table index slot */
#define IX_SYS_DISTRIBUTE_STRATEGY001_ID 0

#define IX_SYS_DISTRIBUTE_RULE001_ID     0
#define IX_SYS_DISTRIBUTE_RULE002_ID     1
#define IX_SYS_DISTRIBUTE_RULE003_ID     2

/* extral system table index column */
#define IX_COL_SYS_DISTRIBUTE_RULE001_NAME        0

#define IX_COL_SYS_DISTRIBUTE_RULE002_ID          0
#define IX_COL_SYS_DISTRIBUTE_RULE003_UID         0

/********************************* SYS_LINK **************************************************************************/
/* system table index slot */
#define IX_SYS_LINK001_ID                0

/* extral system table index column */
#define IX_COL_SYS_LINK001_OWNER                  0
#define IX_COL_SYS_LINK001_NAME                   1

/********************************* SYS_TMP_SEG_STAT ******************************************************************/
typedef enum en_tmp_seg_stat_column {
    TMP_SEG_STAT_COL_ORG_SCN = 0,
    TMP_SEG_STAT_COL_UID = 1,
    TMP_SEG_STAT_COL_OID = 2,
    TMP_SEG_STAT_COL_LOGIC_READS = 3,
    TMP_SEG_STAT_COL_PHYSICAL_WRITES = 4,
    TMP_SEG_STAT_COL_PHYSICAL_READS = 5,
    TMP_SEG_STAT_COL_ITL_WAITS = 6,
    TMP_SEG_STAT_COL_BUF_BUSY_WAITS = 7,
    TMP_SEG_STAT_COL_ROW_LOCK_WAITS = 8,

    TMP_SEG_STAT_COLUMN_COUNT,    // systable column count, must be the last in the struct.
} tmp_seg_stat_column_t;

/* system table index slot */
#define IDX_OBJECT_ID                    0

/* extral system table index column */
#define IX_COL_OBJECT_UID                         0
#define IX_COL_OBJECT_OID                         1

/********************************* SYS_JOB  **************************************************************************/
typedef enum en_sys_job_columns {
    SYS_JOB_JOB_ID = 0,
    SYS_JOB_LOWNER = 1,
    SYS_JOB_POWNER = 2,
    SYS_JOB_COWNER = 3,
    SYS_JOB_LAST_DATE = 4,
    SYS_JOB_THIS_DATE = 5,
    SYS_JOB_NEXT_DATE = 6,
    SYS_JOB_TOTAL = 7,
    SYS_JOB_INTERVAL = 8,
    SYS_JOB_FAILURES = 9,
    SYS_JOB_FLAG = 10,
    SYS_JOB_WHAT = 11,
    SYS_JOB_CREATE_DATE = 12,
    SYS_JOB_INSTANCE = 13,
} en_sys_job_columns_t;

/* system table index slot */
#define I_JOB_1_ID                       0

/* extral system table index column */
#define IX_COL_JOB_1_JOB                          0

#define IX_COL_JOB_2_NEXT_DATE                    0

/********************************* SYS_SQL_MAP ***********************************************************************/
typedef enum en_sys_sql_map_column {
    SYS_SQL_MAP_COL_SRC_HASHCODE = 0,
    SYS_SQL_MAP_COL_SRC_TEXT = 1,
    SYS_SQL_MAP_COL_DST_TEXT = 2,
    SYS_SQL_MAP_COL_USER_ID = 3,

    SYS_SQL_MAP_COLUMN_COUNT,    // systable column count, must be the last in the struct.
} sys_sql_map_column_t;

/* system table index slot */
#define IDX_SQL_MAP_001_ID               0
#define IDX_SQL_MAP_002_ID               1

/* extral system table index column */
#define IX_COL_SQL_MAP_001_SRC_HASHCODE           0

#define IX_COL_SQL_MAP_002_SRC_USER_ID            0

/********************************* SYS_DIST_DDL_LOGINFO **************************************************************/
/* system table index slot */
#define IX_DIST_DDL_LOGINFO_001_ID       0

/********************************* SYS_REBALANCE_TASK ****************************************************************/
/* system table index slot */
#define IX_REBALANCE_TASK_001_ID         0

/* extral system table index column */
#define IX_COL_SYS_REBALANCE_ID                   0
#define IX_COL_SYS_REBALANCE_TABLE_ID             1
#define IX_COL_SYS_REBALANCE_TASK_ID              2

/********************************* SYS_RSRC_PLAN *********************************************************************/
typedef enum en_sys_rsrc_plans_column {
    SYS_RSRC_PLAN_COL_ID = 0,
    SYS_RSRC_PLAN_COL_NAME = 1,
    SYS_RSRC_PLAN_COL_RULES = 2,
    SYS_RSRC_PLAN_COL_COMMENT = 3,
    SYS_RSRC_PLAN_COL_TYPE = 4,
    SYS_RSRC_PLAN_COL_COUNT        // systable column count, must be the last in the struct.
} sys_rsrc_plans_column_t;

/* system table index slot */
#define IX_RSRC_PLAN_001_ID              0

/* extral system table index column */
#define IX_COL_SYS_RSRC_PLAN001_NAME              0

/********************************* SYS_RSRC_GROUP ********************************************************************/
typedef enum en_sys_rsrc_groups_column {
    SYS_RSRC_GROUP_COL_ID = 0,
    SYS_RSRC_GROUP_COL_NAME = 1,
    SYS_RSRC_GROUP_COL_COMMENT = 2,

    SYS_RSRC_GROUP_COL_COUNT       // systable column count, must be the last in the struct.
} sys_rsrc_groups_column_t;

/* system table index slot */
#define IX_RSRC_GROUP_001_ID             0

/* extral system table index column */
#define IX_COL_SYS_RSRC_GROUP001_NAME             0

/********************************* SYS_RSRC_GROUP_MAPPING ************************************************************/
typedef enum en_sys_rsrc_group_mapping_column {
    SYS_RSRC_GROUP_MAPPING_COL_ATTRIBUTE = 0,
    SYS_RSRC_GROUP_MAPPING_COL_VALUE = 1,
    SYS_RSRC_GROUP_MAPPING_COL_GROUP = 2,

    SYS_RSRC_GROUP_MAPPING_COL_COUNT // systable column count, must be the last in the struct.
} sys_rsrc_group_mapping_column_t;

/* system table index slot */
#define IX_RSRC_GROUP_MAPPING_001_ID     0

/* extral system table index column */
#define IX_COL_SYS_RSRC_MAPPING001_ATTRIBUTE      0
#define IX_COL_SYS_RSRC_MAPPING001_VALUE          1
/********************************* SYS_DDM ****************************************************************/
typedef enum en_sys_ddm_columns {
    SYS_DDM_UID = 0,
    SYS_DDM_OID = 1,
    SYS_DDM_COLID = 2,
    SYS_DDM_RULE_NAME = 3,
    SYS_DDM_TYPE_NAME = 4,
    SYS_DDM_PARAM = 5,
    SYS_DDM_COUNT // systable column count, must be the last in the struct.
} en_sys_ddm_columns_t;

/* system table index slot */
#define IX_SYS_DDM_001_ID            0
#define IX_SYS_DDM_002_ID            1

/* system table index column */
#define IX_COL_SYS_DDM_001_UID       0
#define IX_COL_SYS_DDM_001_OID       1
#define IX_COL_SYS_DDM_001_COLID     2

#define IX_COL_SYS_DDM_002_UID       0
#define IX_COL_SYS_DDM_002_OID       1
#define IX_COL_SYS_DDM_002_RULENAME  2

/********************************* SYS_RSRC_PLAN_RULE ****************************************************************/
typedef enum en_sys_rsrc_plan_rules_column {
    SYS_RSRC_PLAN_RULE_COL_PLAN = 0,
    SYS_RSRC_PLAN_RULE_COL_GROUP = 1,
    SYS_RSRC_PLAN_RULE_COL_CPU = 2,
    SYS_RSRC_PLAN_RULE_COL_SESSIONS = 3,
    SYS_RSRC_PLAN_RULE_COL_ACTIVE_SESS = 4,
    SYS_RSRC_PLAN_RULE_COL_QUEUE_TIME = 5,
    SYS_RSRC_PLAN_RULE_COL_MAX_EXEC_TIME = 6,
    SYS_RSRC_PLAN_RULE_COL_TEMP_POOL = 7,
    SYS_RSRC_PLAN_RULE_COL_MAX_IOPS = 8,
    SYS_RSRC_PLAN_RULE_COL_MAX_COMMITS = 9,
    SYS_RSRC_PLAN_RULE_COL_COMMENT = 10,

    SYS_RSRC_PLAN_RULE_COL_COUNT // systable column count, must be the last in the struct.
} sys_rsrc_plan_rules_column_t;

/* system table index slot */
#define IX_RSRC_PLAN_RULE_001_ID         0

/* extral system table index column */
#define IX_COL_SYS_RSRC_RULE001_PLAN              0
#define IX_COL_SYS_RSRC_RULE001_GROUP             1

/********************************* SYS_POLICY ************************************************************/
typedef enum en_sys_policies_column {
    SYS_POLICIES_COL_OBJ_SCHEMA_ID = 0,
    SYS_POLICIES_COL_OBJ_NAME = 1,
    SYS_POLICIES_COL_PNAME = 2,
    SYS_POLICIES_COL_PF_SCHEMA = 3,
    SYS_POLICIES_COL_PF_NAME = 4,
    SYS_POLICIES_COL_STMT_TYPE = 5,
    SYS_POLICIES_COL_PTYPE = 6,
    SYS_POLICIES_COL_CHK_OPTION = 7,
    SYS_POLICIES_COL_ENABLE = 8,
    SYS_POLICIES_COL_LONG_PREDICATE = 9,
    SYS_POLICIES_COLUMN_COUNT,
} sys_policies_column_t;

/* system table index slot */
#define IX_SYS_POLICY_001_ID             0

/* extral system table index column */
#define IX_COL_SYS_POLICY_001_OBJ_SCHEMA_ID  0
#define IX_COL_SYS_POLICY_001_OBJ_NAME       1
#define IX_COL_SYS_POLICY_001_PNAME          2

/********************************* SYS_TENANTS ************************************************************/
typedef enum en_sys_tenants_column {
    SYS_TENANTS_COL_ID = 0,
    SYS_TENANTS_COL_NAME = 1,
    SYS_TENANTS_COL_TABLESPACE_ID = 2,
    SYS_TENANTS_COL_TABLESPACES_NUM = 3,
    SYS_TENANTS_COL_TABLESPACES_BITMAP = 4,
    SYS_TENANTS_COL_CTIME = 5,
    SYS_TENANTS_COL_OPTIONS = 6,
    SYS_TENANTS_COLUMN_COUNT,
} sys_tenants_column_t;

/* system table index slot */
#define IX_SYS_TENANTS_001_ID             0
#define IX_SYS_TENANTS_002_ID             1

/* extral system table index column */
#define IX_COL_SYS_TENANTS_001_ID     0
#define IX_COL_SYS_TENANTS_002_NAME   0

/********************************* SYS_TENANT_TABLESPACES ************************************************************/
typedef enum en_sys_tenant_tablespaces_column {
    SYS_TENANT_TABLESPACES_COL_TENANT_ID = 0,
    SYS_TENANT_TABLESPACES_COL_TABLESPACE_ID = 1,
    SYS_TENANT_TABLESPACES_COL_OPTIONS = 2,
    SYS_TENANT_TABLESPACES_COLUMN_COUNT,
} sys_tenant_tablespaces_column_t;

/********************************* SYS_DIRECTORY *********************************************************************/
typedef enum en_sys_directories_column {
    SYS_DIRECTORIES_COL_USER_ID = 0,
    SYS_DIRECTORIES_COL_DIRE_NAME = 1,
    SYS_DIRECTORIES_COL_DIRE_PATH = 2,

    SYS_DIRECTORIES_COLUMN_COUNT,
} sys_directories_column_t;

/* system table index slot */
#define IX_DIRECTORY_001_ID              0

/* extral system table index column */
#define IX_COL_SYS_DIRECTORY_NAME                 0

/********************************* SYS_STORAGE ***********************************************************************/
typedef enum en_sys_storage_column {
    SYS_STORAGE_COL_ORGSCN = 0,
    SYS_STORAGE_COL_INITIAL_PAGES = 1,
    SYS_STORAGE_COL_MAX_PAGES = 2,
    SYS_STORAGE_COLUMN_COUNT,
} sys_storage_column_t;

/* system table index slot */
#define IX_STORAGE_001_ID                0

/* extral system table index column */
#define IX_COL_SYS_STORAGE_ORGSCN                 0

/********************************* SYS_TYPE **************************************************************************/
/* columns of SYS_TYPES */
#define SYS_TYPE_UID                0
#define SYS_TYPE_TYPE_OID           1
#define SYS_TYPE_TYPE_NAME          2
#define SYS_TYPE_TYPE_CODE          3
#define SYS_TYPE_ATTRIBUTES         4
#define SYS_TYPE_METHODS            5
#define SYS_TYPE_PREDEFINED         6
#define SYS_TYPE_INCOMPLETE         7
#define SYS_TYPE_FINAL              8
#define SYS_TYPE_INSTANTIABLE       9
#define SYS_TYPE_SUPERTYPE_UID      10
#define SYS_TYPE_SUPERTYPE_OID      11
#define SYS_TYPE_SUPERTYPE_NAME     12
#define SYS_TYPE_LOCAL_ATTRIBUTES   13
#define SYS_TYPE_LOCAL_METHODS      14
#define SYS_TYPE_ORG_SCN            15
#define SYS_TYPE_CHG_SCN            16

/* system table index slot */
#define IX_TYPE_001_ID                   0
#define IX_TYPE_002_ID                   1

/*********************************SYS_TYPE_ATTR***********************************************************************/
/* system table index slot */
#define IX_TYPE_ATTR_001_ID              0
#define IX_TYPE_ATTR_002_ID              1

/*********************************SYS_TYPE_METHOD*********************************************************************/
/* system table index slot */
#define IX_TYPE_METHOD_001_ID            0
#define IX_TYPE_METHOD_002_ID            1

/*********************************SYS_COLL_TYPE***********************************************************************/
/* system table index slot */
#define IX_COLL_TYPE_001_ID              0
#define IX_COLL_TYPE_002_ID              1

/*********************************SYS_TYPE_VERSION********************************************************************/
/* system table index slot */
#define IX_TYPE_VER_001_ID               0

/*********************************SYS_TYPE_LIBRARY********************************************************************/
/* columns of LIBRARY$ */
typedef enum en_sys_libraries_column {
    SYS_LIBRARY_USER            = 0,
    SYS_LIBRARY_NAME            = 1,
    SYS_LIBRARY_FILE_PATH       = 2,
    SYS_LIBRARY_FLAGS           = 3,
    SYS_LIBRARY_STATUS          = 4,
    SYS_LIBRARY_AGENT_DBLINK    = 5,
    SYS_LIBRARY_LEAF_FILENAME   = 6,
    SYS_LIBRARY_ORG_SCN         = 7,
    SYS_LIBRARY_CHG_SCN         = 8,

    SYS_LIBRARY_COLUMN_COUNT
} sys_libraries_column_t;

/* system table index slot */
#define IDX_LIBRARY_001_ID 0

#define IX_COL_SYS_LIBRARY001_OWNER 0
#define IX_COL_SYS_LIBRARY001_NAME 1

/******************************************* SYS_USER_PRIVS *************************************************************/
typedef enum en_sys_user_privs_column {
    SYS_USER_PRIVS_COL_UID = 0,
    SYS_USER_PRIVS_COL_GRANTOR = 1,
    SYS_USER_PRIVS_COL_GRANTEE = 2,
    SYS_USER_PRIVS_COL_PRIVILEGE = 3,
    SYS_USER_PRIVS_COL_OPTION = 4,

    SYS_USER_PRIVS_COLUMN_COUNT,    // systable column count, must be the last in the struct.
} sys_user_privs_column_t;

#define IX_USER_PRIVS_001_ID          0

/* extral system table index column */
#define IX_COL_SYS_USER_PRIVS_001_UID             0
#define IX_COL_SYS_USER_PRIVS_001_GRANTEE         1
#define IX_COL_SYS_USER_PRIVS_001_RIVILEGE        2

/*********************************** SYS_INSTANCE_INFO *************************************************************/
typedef enum en_sys_instance_info_column {
    SYS_INSTANCE_INFO_COL_NAME = 0,
    SYS_INSTANCE_INFO_COL_VALUE = 1,

    SYS_INSTANCE_INFO_COLUMN_COUNT,    // systable column count, must be the last in the struct.
} sys_instance_info_column_t;

#define IX_SYS_INSTANCE_INFO_001_ID              0
    
    /* system instance info index column */
#define IX_COL_SYS_INSTANCE_INFO_001_NAME        0

/********************************* SYS_COMPRESS ***********************************************************************/
typedef enum en_sys_compress_column {
    SYS_COMPRESS_COL_ORGSCN = 0,
    SYS_COMPRESS_COL_ALGO = 1,
    SYS_COMPRESS_COL_OBJECT_TYPE = 2,
    SYS_COMPRESS_COLUMN_COUNT,
} sys_compress_column_t;

#define IX_SYSCOMPRESS001_ID 0
#define IX_COL_SYSCOMPRESS001_ORGSCN 0

/************************************ SYS_PROMOTE_RECORD *************************************************************/
typedef enum en_sys_promote_record_columns {
    SYS_PROMOTE_RECORD_TIME = 0,
    SYS_PROMOTE_RECORD_TYPE = 1,
    SYS_PROMOTE_RECORD_LOCAL_HOST = 2,
    SYS_PROMOTE_RECORD_PEER_HOST = 3,

    SYS_PROMOTE_RECORD_COLUMN_COUNT,    // systable column count, must be the last in the struct.
} en_sys_promote_record_columns_t;

#define IX_SYS_PROMOTE_RECORD_001_ID        0

#ifdef __cplusplus
}
#endif

#endif

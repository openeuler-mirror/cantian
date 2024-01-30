/* -------------------------------------------------------------------------
 *  This file is part of the Cantian project.
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
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
 * knl_core_table_defs.h
 *
 *
 * IDENTIFICATION
 * src/kernel/knl_core_table_defs.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef KNL_CORE_TABLE_DEFS_H
#define KNL_CORE_TABLE_DEFS_H

#ifdef __cplusplus
extern "C" {
#endif


/**********************************************SYS_TABLE**************************************************************/
typedef enum en_sys_table_column {
    SYS_TABLE_COL_USER_ID = 0,
    SYS_TABLE_COL_ID = 1,
    SYS_TABLE_COL_NAME = 2,
    SYS_TABLE_COL_SPACE_ID = 3,
    SYS_TABLE_COL_ORG_SCN = 4,
    SYS_TABLE_COL_CHG_SCN = 5,
    SYS_TABLE_COL_TYPE = 6,
    SYS_TABLE_COL_COLS = 7,
    SYS_TABLE_COL_INDEXES = 8,
    SYS_TABLE_COL_PARTITIONED = 9,
    SYS_TABLE_COL_ENTRY = 10,
    SYS_TABLE_COL_INITRANS = 11,
    SYS_TABLE_COL_PCTFREE = 12,
    SYS_TABLE_COL_CR_MODE = 13,
    SYS_TABLE_COL_RECYCLED = 14,
    SYS_TABLE_COL_APPENDONLY = 15,
    SYS_TABLE_COL_NUM_ROWS = 16,
    SYS_TABLE_COL_BLOCKS = 17,
    SYS_TABLE_COL_EMPTY_BLOCKS = 18,
    SYS_TABLE_COL_AVG_ROW_LEN = 19,
    SYS_TABLE_COL_SAMPLESIZE = 20,
    SYS_TABLE_COL_ANALYZETIME = 21,
    SYS_TABLE_COL_SERIAL_START = 22,
    SYS_TABLE_COL_OPTIONS = 23,
    SYS_TABLE_COL_OBJID = 24,
    SYS_TABLE_COL_VERSION = 25,
    SYS_TABLE_COL_FLAG = 26,

    SYS_TABLE_COLUMN_COUNT,   // systable column count, must be the last in the struct.
} sys_table_column_t;

/* index of TABLE$ */
#define IX_SYS_TABLE_001_ID              0
#define IX_SYS_TABLE_002_ID              1

#define IX_COL_SYS_TABLE_001_USER_ID     0
#define IX_COL_SYS_TABLE_001_NAME        1

/* core system table index column */
#define IX_COL_SYS_TABLE_002_USER_ID     0
#define IX_COL_SYS_TABLE_002_ID          1

/**********************************************SYS_COLUMN*************************************************************/
typedef enum en_sys_column_column {
    SYS_COLUMN_COL_USER_ID = 0,
    SYS_COLUMN_COL_TABLE_ID = 1,
    SYS_COLUMN_COL_ID = 2,
    SYS_COLUMN_COL_NAME = 3,
    SYS_COLUMN_COL_DATATYPE = 4,
    SYS_COLUMN_COL_BYTES = 5,
    SYS_COLUMN_COL_PRECISION = 6,
    SYS_COLUMN_COL_SCALE = 7,
    SYS_COLUMN_COL_NULLABLE = 8,
    SYS_COLUMN_COL_FLAGS = 9,
    SYS_COLUMN_COL_DEFAULT_TEXT = 10,
    SYS_COLUMN_COL_DEFAULT_DATA = 11,
    SYS_COLUMN_COL_NUM_DISTINCT = 12,
    SYS_COLUMN_COL_LOW_VALUE = 13,
    SYS_COLUMN_COL_HIGH_VALUE = 14,
    SYS_COLUMN_COL_HISTOGRAM = 15,
    SYS_COLUMN_COL_OPTIONS = 16,

    SYS_COLUMN_COLUMN_COUNT,    // systable column count, must be the last in the struct.
} sys_column_column_t;

/* index of COLUMN$ */
#define IX_SYS_COLUMN_001_ID             0

/* core system table index column */
#define IX_COL_SYS_COLUMN_001_USER_ID    0
#define IX_COL_SYS_COLUMN_001_TABLE_ID   1
#define IX_COL_SYS_COLUMN_001_ID         2

/***********************************************SYS_INDEX*************************************************************/
/* COLUMN ID in INDEX$ */
#define SYS_INDEX_COLUMN_ID_USER                    0
#define SYS_INDEX_COLUMN_ID_TABLE                   1
#define SYS_INDEX_COLUMN_ID_ID                      2
#define SYS_INDEX_COLUMN_ID_NAME                    3
#define SYS_INDEX_COLUMN_ID_SPACE                   4
#define SYS_INDEX_COLUMN_ID_SEQUENCE                5
#define SYS_INDEX_COLUMN_ID_ENTRY                   6
#define SYS_INDEX_COLUMN_ID_IS_PRIMARY              7
#define SYS_INDEX_COLUMN_ID_IS_UNIQUE               8
#define SYS_INDEX_COLUMN_ID_TYPE                    9
#define SYS_INDEX_COLUMN_ID_COLS                    10
#define SYS_INDEX_COLUMN_ID_COL_LIST                11
#define SYS_INDEX_COLUMN_ID_INITRANS                12
#define SYS_INDEX_COLUMN_ID_CR_MODE                 13
#define SYS_INDEX_COLUMN_ID_FLAGS                   14
#define SYS_INDEX_COLUMN_ID_PARTITIONED             15
#define SYS_INDEX_COLUMN_ID_PCTFREE                 16
#define SYS_INDEX_COLUMN_ID_BLEVEL                  17
#define SYS_INDEX_COLUMN_ID_LEVEL_BLOCKS            18
#define SYS_INDEX_COLUMN_ID_DISTINCT_KEYS           19
#define SYS_INDEX_COLUMN_ID_AVG_LEAF_BLOCKS_PER_KEY 20
#define SYS_INDEX_COLUMN_ID_AVG_DATA_BLOCKS_PER_KEY 21
#define SYS_INDEX_COLUMN_ID_ANALYZETIME             22
#define SYS_INDEX_COLUMN_ID_EMPTY_LEAF_BLOCKS       23
#define SYS_INDEX_COLUMN_ID_OPTIONS                 24
#define SYS_INDEX_COLUMN_ID_CLUFAC                  25
#define SYS_INDEX_COLUMN_ID_SAMPLESIZE              26
#define SYS_INDEX_COLUMN_ID_OBJ_ID                  27
#define SYS_INDEX_COLUMN_ID_COMB2_NDV               28
#define SYS_INDEX_COLUMN_ID_COMB3_NDV               29
#define SYS_INDEX_COLUMN_ID_COMB4_NDV               30

/* index of INDEX$ */
#define IX_SYS_INDEX_001_ID              0
#define IX_SYS_INDEX_002_ID              1

/* core system table index column */
#define IX_COL_SYS_INDEX_001_USER        0
#define IX_COL_SYS_INDEX_001_TABLE       1
#define IX_COL_SYS_INDEX_001_ID          2

#define IX_COL_SYS_INDEX_002_USER        0
#define IX_COL_SYS_INDEX_002_NAME        1
#define IX_COL_SYS_INDEX_002_TABLE       2


/***************************************************SYS_USER**********************************************************/
typedef enum en_sys_user_column {
    SYS_USER_COL_ID = 0,
    SYS_USER_COL_NAME = 1,
    SYS_USER_COL_PASSWORD = 2,
    SYS_USER_COL_DATA_SPACE_ID = 3,
    SYS_USER_COL_TEMP_SPACE_ID = 4,
    SYS_USER_COL_CTIME = 5,
    SYS_USER_COL_PTIME = 6,
    SYS_USER_COL_EXPTIME = 7,
    SYS_USER_COL_LTIME = 8,
    SYS_USER_COL_PROFILE_ID = 9,
    SYS_USER_COL_ASTATUS = 10,
    SYS_USER_COL_LCOUNT = 11,
    SYS_USER_COL_OPTIONS = 12,
    SYS_USER_COL_TENANT_ID = 13,

    SYS_USER_COLUMN_COUNT,    // systable column count, must be the last in the struct.
} sys_user_column_t;

/* index of user$ */
#define IX_SYS_USER_001_ID               0
#define IX_SYS_USER_002_ID               1

/* core system table index column */
#define IX_COL_SYS_USER_001_ID           0
#define IX_COL_SYS_USER_002_NAME         1

/******************************************SYS_SEQ********************************************************************/
typedef enum en_sys_sequence_column {
    SYS_SEQUENCE_COL_UID = 0,
    SYS_SEQUENCE_COL_ID = 1,
    SYS_SEQUENCE_COL_NAME = 2,
    SYS_SEQUENCE_COL_MINVAL = 3,
    SYS_SEQUENCE_COL_MAXVAL = 4,
    SYS_SEQUENCE_COL_STEP = 5,
    SYS_SEQUENCE_COL_CACHESIZE = 6,
    SYS_SEQUENCE_COL_CYCLE_FLAG = 7,
    SYS_SEQUENCE_COL_ORDER_FLAG = 8,
    SYS_SEQUENCE_COL_ORG_SCN = 9,
    SYS_SEQUENCE_COL_CHG_SCN = 10,
    SYS_SEQUENCE_COL_LAST_NUMBER = 11,
    SYS_SEQUENCE_COL_DIST_DATA = 12,

    SYS_SEQUENCE_COLUMN_COUNT,    // systable column count, must be the last in the struct.
} sys_sequence_column_t;

#define SYS_SEQ001_ID                    0

/* extral system table index column */
#define IX_COL_SYS_SEQ001_UID                     0
#define IX_COL_SYS_SEQ001_NAME                    1

/******************************************** SYS_RB *****************************************************************/
typedef enum en_sys_recyclebin_column {
    SYS_RECYCLEBIN_COL_ID = 0,
    SYS_RECYCLEBIN_COL_NAME = 1,
    SYS_RECYCLEBIN_COL_USR_ID = 2,
    SYS_RECYCLEBIN_COL_ORG_NAME = 3,
    SYS_RECYCLEBIN_COL_PARTITION_NAME = 4,
    SYS_RECYCLEBIN_COL_TYPE_ID = 5,
    SYS_RECYCLEBIN_COL_OPERATION_ID = 6,
    SYS_RECYCLEBIN_COL_SPACE_ID = 7,
    SYS_RECYCLEBIN_COL_ENTRY = 8,
    SYS_RECYCLEBIN_COL_FLAGS = 9,
    SYS_RECYCLEBIN_COL_ORG_SCN = 10,
    SYS_RECYCLEBIN_COL_REC_SCN = 11,
    SYS_RECYCLEBIN_COL_TCHG_SCN = 12,
    SYS_RECYCLEBIN_COL_BASE_ID = 13,
    SYS_RECYCLEBIN_COL_PURGE_ID = 14,

    SYS_RECYCLEBIN_COLUMN_COUNT,    // systable column count, must be the last in the struct.
} sys_recyclebin_column_t;

#define IX_SYS_RB001_ID                  0
#define IX_SYS_RB002_ID                  1
#define IX_SYS_RB003_ID                  2
#define IX_SYS_RB004_ID                  3

#define IX_COL_SYS_RB001_ID                       0

#define IX_COL_SYS_RB002_BASE_ID                  0
#define IX_COL_SYS_RB002_PURGE_ID                 1

#define IX_COL_SYS_RB003_SPACE_ID                 0

#define IX_COL_SYS_RB004_USER_ID                  0

/******************************************SYS_LOB********************************************************************/
typedef enum en_sys_lob_column {
    SYS_LOB_COL_USER_ID = 0,
    SYS_LOB_COL_TABLE_ID = 1,
    SYS_LOB_COL_COLUMN_ID = 2,
    SYS_LOB_COL_SPACE_ID = 3,
    SYS_LOB_COL_ENTRY = 4,
    SYS_LOB_COL_ORG_SCN = 5,
    SYS_LOB_COL_CHG_SCN = 6,
    SYS_LOB_COL_CHUNK = 7,
    SYS_LOB_COL_PCTVERSION = 8,
    SYS_LOB_COL_RETENSION = 9,
    SYS_LOB_COL_FLAGS = 10,

    SYS_LOB_COLUMN_COUNT,    // systable column count, must be the last in the struct.
} sys_lob_column_t;

#define IX_SYS_LOB001_ID                 0

/* extral system table index column */
#define IX_COL_SYS_LOB001_USER_ID                 0
#define IX_COL_SYS_LOB001_TABLE_ID                1
#define IX_COL_SYS_LOB001_COLUMN_ID               2

/****************************************** SYS_CONSDEF **************************************************************/
typedef enum en_sys_consdef_column {
    SYS_CONSDEF_COL_USER_ID = 0,
    SYS_CONSDEF_COL_TABLE_ID = 1,
    SYS_CONSDEF_COL_CONS_NAME = 2,
    SYS_CONSDEF_COL_CONS_TYPE = 3,
    SYS_CONSDEF_COL_COLS = 4,
    SYS_CONSDEF_COL_COL_LIST = 5,
    SYS_CONSDEF_COL_IND_ID = 6,
    SYS_CONSDEF_COL_REF_USER_ID = 7,
    SYS_CONSDEF_COL_REF_TABLE_ID = 8,
    SYS_CONSDEF_COL_REF_CONS = 9,
    SYS_CONSDEF_COL_COND_TEXT = 10,
    SYS_CONSDEF_COL_COND_DATA = 11,
    SYS_CONSDEF_COL_FLAGS = 12,
    SYS_CONSDEF_COL_REFACT = 13,

    SYS_CONSDEF_COLUMN_COUNT,    // systable column count, must be the last in the struct.
} sys_consdef_column_t;

#define IX_SYS_CONSDEF001_ID             0
#define IX_SYS_CONSDEF002_ID             1
#define IX_SYS_CONSDEF003_ID             2

/* extral system table index column */
#define IX_COL_SYS_CONSDEF001_USER_ID             0
#define IX_COL_SYS_CONSDEF001_TABLE_ID            1

#define IX_COL_SYS_CONSDEF002_REF_USER_ID         0
#define IX_COL_SYS_CONSDEF002_REF_TABLE_ID        1

#define IX_COL_SYS_CONSDEF003_REF_USER_ID         0
#define IX_COL_SYS_CONSDEF003_REF_CONS_NAME       1
#define IX_COL_SYS_CONSDEF003_REF_TABLE_ID        2


/***************************************** SYS_VIEW ******************************************************************/
/* columns of VIEW$ */
#define SYS_VIEW_USER        0
#define SYS_VIEW_OBJID       1
#define SYS_VIEW_NAME        2
#define SYS_VIEW_COLS        3
#define SYS_VIEW_FLAG        4
#define SYS_VIEW_ORG_SCN     5
#define SYS_VIEW_CHG_SCN     6
#define SYS_VIEW_TEXT_LENGTH 7
#define SYS_VIEW_TEXT        8
#define SYS_VIEW_SQL_TYPE    9
#define SYS_VIEW_OBJ_ID      10

#define IX_SYS_VIEW001_ID                0
#define IX_SYS_VIEW002_ID                1

/* extral system table index column */
#define IX_COL_SYS_VIEW001_USER                   0
#define IX_COL_SYS_VIEW001_NAME                   1

#define IX_COL_SYS_VIEW002_USER                   0
#define IX_COL_SYS_VIEW002_OBJID                  1

/**************************************** SYS_VIEWCOL ****************************************************************/
typedef enum en_sys_viewcol_column {
    SYS_VIEWCOL_COL_USER_ID = 0,
    SYS_VIEWCOL_COL_VIEW_ID = 1,
    SYS_VIEWCOL_COL_ID = 2,
    SYS_VIEWCOL_COL_NAME = 3,
    SYS_VIEWCOL_COL_DATATYPE = 4,
    SYS_VIEWCOL_COL_BYTES = 5,
    SYS_VIEWCOL_COL_PRECISION = 6,
    SYS_VIEWCOL_COL_SCALE = 7,
    SYS_VIEWCOL_COL_NULLABLE = 8,
    SYS_VIEWCOL_COL_FLAGS = 9,

    SYS_VIEWCOL_COLUMN_COUNT,    // systable column count, must be the last in the struct.
} sys_viewcol_column_t;

#define IX_SYS_VIEWCOL001_ID             0

/* extral system table index column */
#define IX_COL_SYS_VIEWCOL001_USER_ID             0
#define IX_COL_SYS_VIEWCOL001_VIEW_ID             1
#define IX_COL_SYS_VIEWCOL001_ID                  2

/********************************************** SYS_PROC *************************************************************/
/* columns of PROC$ */
#define SYS_PROC_USER_COL            0
#define SYS_PROC_OBJ_ID_COL          1
#define SYS_PROC_NAME_COL            2
#define SYS_PROC_CLASS_COL           3
#define SYS_PROC_TYPE_COL            4
#define SYS_PROC_SOURCE_COL          5
#define SYS_PROC_AGGREGATE_COL       6
#define SYS_PROC_PIPELINED_COL       7
#define SYS_PROC_TRIG_TABLE_USER_COL 8
#define SYS_PROC_TRIG_TABLE_COL      9
#define SYS_PROC_ORG_SCN_COL         10
#define SYS_PROC_CHG_SCN_COL         11
#define SYS_PROC_TRIG_STATUS_COL     12
#define SYS_PROC_STATUS_COL          13
#define SYS_PROC_FLAGS_COL           14
#define SYS_PROC_LIB_NAME_COL        15
#define SYS_PROC_LIB_USER_COL        16


#define IX_PROC_001_ID                   0
#define IX_PROC_002_ID                   1
#define IX_PROC_003_ID                   2
#define IX_PROC_004_ID                   3
#define IX_PROC_003_ID_USER              0
#define IX_PROC_003_ID_OBJ               1

/***************************************** SYS_EXTERNAL **************************************************************/
typedef enum en_sys_external_column {
    SYS_EXTERNAL_COL_TABLE_ID = 0,
    SYS_EXTERNAL_COL_TYPE = 1,
    SYS_EXTERNAL_COL_DIRECTORY = 2,
    SYS_EXTERNAL_COL_LOCATION = 3,
    SYS_EXTERNAL_COL_RECORDS_DEL = 4,
    SYS_EXTERNAL_COL_FIELDS_DEL = 5,
    SYS_EXTERNAL_COL_USER_ID = 6,

    SYS_EXTERNAL_COLUMN_COUNT,    // systable column count, must be the last in the struct.
} sys_external_column_t;

#define IX_EXTERNALTABS_001_ID           0

#define IX_COL_EXTERNALTABS_001_USER_ID           0
#define IX_COL_EXTERNALTABS_001_TABLE_ID          1

/**************************************** SYS_PENDING_TRANS **********************************************************/
typedef enum en_sys_pending_trans_column {
    SYS_PENDING_TRANS_COL_GLOBAL_TRAN_ID = 0,
    SYS_PENDING_TRANS_COL_LOCAL_TRAN_ID = 1,
    SYS_PENDING_TRANS_COL_TLOCK_LOBS = 2,
    SYS_PENDING_TRANS_COL_TLOCK_LOBS_EXT = 3,
    SYS_PENDING_TRANS_COL_FORMAT_ID = 4,
    SYS_PENDING_TRANS_COL_BRANCH_ID = 5,
    SYS_PENDING_TRANS_COL_OWNER = 6,
    SYS_PENDING_TRANS_PREPARE_SCN = 7,
    SYS_PENDING_TRANS_COMMIT_SCN = 8,
    SYS_PENDING_TRANS_COLUMN_COUNT,    // systable column count, must be the last in the struct.
} sys_pending_trans_column_t;

#define IX_PENDINGTRANS_001_ID           0

#define IX_COL_PENDINGTRANS_001_GLOBAL_TRAN_ID    0
#define IX_COL_PENDINGTRANS_001_FORMAT_ID         1
#define IX_COL_PENDINGTRANS_001_BRANCH_ID         2

/*********************************** SYS_SYN *************************************************************************/
/* columns of SYNONYM$ */
#define SYS_SYN_USER         0
#define SYS_SYN_OBJID        1
#define SYS_SYN_ORG_SCN      2
#define SYS_SYN_CHG_SCN      3
#define SYS_SYN_SYNONYM_NAME 4
#define SYS_SYN_TABLE_OWNER  5
#define SYS_SYN_TABLE_NAME   6
#define SYS_SYN_FLAG         7
#define SYS_SYN_TYPE         8

#define IX_SYS_SYNONYM001_ID             0
#define IX_SYS_SYNONYM002_ID             1

/* extral system table index column */
#define IX_COL_SYS_SYNONYM001_USER                0
#define IX_COL_SYS_SYNONYM001_SYNONYM_NAME        1

#define IX_COL_SYS_SYNONYM002_USER                0
#define IX_COL_SYS_SYNONYM002_OBJID               1

/************************************** SYS_COMMENT ******************************************************************/
#define IX_SYS_COMMENT001_ID             0

#define IX_COL_SYS_COMMENT001_USER_ID             0
#define IX_COL_SYS_COMMENT001_TABLE_ID            1
#define IX_COL_SYS_COMMENT001_COLUMN_ID           2

/****************************************** SYS_PRIVS ****************************************************************/
typedef enum en_sys_privs_column {
    SYS_PRIVS_COL_GRANTEE_ID = 0,
    SYS_PRIVS_COL_GRANTEE_TYPE = 1,
    SYS_PRIVS_COL_PRIVILEGE = 2,
    SYS_PRIVS_COL_ADMIN_OPTION = 3,

    SYS_PRIVS_COLUMN_COUNT,    // systable column count, must be the last in the struct.
} sys_privs_column_t;

#define IX_SYS_SYS_PRIVS_001_ID          0

/* extral system table index column */
#define IX_COL_SYS_PRIVS_001_GRANTEE_ID           0
#define IX_COL_SYS_PRIVS_001_GRANTEE_TYPE         1
#define IX_COL_SYS_PRIVS_001_RIVILEGE             2

/***************************************** OBJECT_PRIVS **************************************************************/
typedef enum en_object_privs_column {
    OBJECT_PRIVS_COL_GRANTEE = 0,
    OBJECT_PRIVS_COL_GRANTEE_TYPE = 1,
    OBJECT_PRIVS_COL_OBJECT_OWNER = 2,
    OBJECT_PRIVS_COL_OBJECT_NAME = 3,
    OBJECT_PRIVS_COL_OBJECT_TYPE = 4,
    OBJECT_PRIVS_COL_PRIVILEGE = 5,
    OBJECT_PRIVS_COL_GRANTABLE = 6,
    OBJECT_PRIVS_COL_GRANTOR = 7,

    OBJECT_PRIVS_COLUMN_COUNT,    // systable column count, must be the last in the struct.
} object_privs_column_t;

#define IX_SYS_OBJECT_PRIVS_001_ID       0
#define IX_SYS_OBJECT_PRIVS_002_ID       1
#define IX_SYS_OBJECT_PRIVS_004_ID       2

/* extral system table index column */
#define IX_COL_SYS_OBJECT_PRIVS_001_GRANTEE       0
#define IX_COL_SYS_OBJECT_PRIVS_001_GRANTEE_TYPE  1
#define IX_COL_SYS_OBJECT_PRIVS_001_OBJECT_OWNER  2
#define IX_COL_SYS_OBJECT_PRIVS_001_OBJECT_NAME   3
#define IX_COL_SYS_OBJECT_PRIVS_001_OBJECT_TYPE   4
#define IX_COL_SYS_OBJECT_PRIVS_001_PRIVILEGE     5

#define IX_COL_SYS_OBJECT_PRIVS_002_OBJECT_OWNER  0
#define IX_COL_SYS_OBJECT_PRIVS_002_OBJECT_NAME   1
#define IX_COL_SYS_OBJECT_PRIVS_002_OBJECT_TYPE   2

#define IX_COL_SYS_OBJECT_PRIVS_004_GRANTOR       0
#define IX_COL_SYS_OBJECT_PRIVS_004_OBJECT_OWNER  1
#define IX_COL_SYS_OBJECT_PRIVS_004_OBJECT_NAME   2
#define IX_COL_SYS_OBJECT_PRIVS_004_OBJECT_TYPE   3
#define IX_COL_SYS_OBJECT_PRIVS_004_PRIVILEGE     4

/********************************* SYS_USER_ROLES ********************************************************************/
typedef enum en_sys_user_roles_column {
    SYS_USER_ROLES_COL_GRANTEE_ID = 0,
    SYS_USER_ROLES_COL_GRANTEE_TYPE = 1,
    SYS_USER_ROLES_COL_GRANTED_ROLE_ID = 2,
    SYS_USER_ROLES_COL_ADMIN_OPTION = 3,
    SYS_USER_ROLES_COL_DEFAULT_ROLE = 4,

    SYS_USER_ROLES_COLUMN_COUNT,    // systable column count, must be the last in the struct.
} sys_user_roles_column_t;

#define IX_SYS_USER_ROLES_001_ID         0
#define IX_SYS_USER_ROLES_002_ID         1

/* extral system table index column */
#define IX_COL_SYS_USER_ROLES_001_GRANTEE_ID      0
#define IX_COL_SYS_USER_ROLES_001_GRANTEE_TYPE    1
#define IX_COL_SYS_USER_ROLES_001_GRANTED_ROLE_ID 2

#define IX_COL_SYS_USER_ROLES_002_GRANTED_ROLE_ID 0

/*********************************** SYS_ROLES ***********************************************************************/
typedef enum en_sys_roles_column {
    SYS_ROLES_COL_ID = 0,
    SYS_ROLES_COL_OWNER_UID = 1,
    SYS_ROLES_COL_NAME = 2,
    SYS_ROLES_COL_PASSWORD = 3,

    SYS_ROLES_COLUMN_COUNT,    // systable column count, must be the last in the struct.
} sys_roles_column_t;

#define IX_SYS_ROLES_001_ID              0
#define IX_SYS_ROLES_002_ID              1

/* extral system table index column */
#define IX_COL_SYS_ROLES_001_ID                   0
#define IX_COL_SYS_ROLES_001_NAME                 1

#define IX_COL_SYS_ROLES_002_OWNER_UID            0

/*********************************** SYS_LINKS ***********************************************************************/
typedef enum en_sys_links_column {
    SYS_LINKS_COL_OWNER    = 0,
    SYS_LINKS_COL_NAME     = 1,
    SYS_LINKS_COL_CTIME    = 2,
    SYS_LINKS_COL_NODE_ID  = 3,
    SYS_LINKS_COL_HOST     = 4,
    SYS_LINKS_COL_USERID   = 5,
    SYS_LINKS_COL_PASSWORD = 6,
    SYS_LINKS_COLUMN_COUNT,    // systable column count, must be the last in the struct.
} sys_links_column_t;

#define IX_SYS_LINKS_001_ID              0

/* extral system table index column */
#define IX_COL_SYS_LINKS_001_OWNER       0
#define IX_COL_SYS_LINKS_001_NAME        1

/******************************************* SYS_TRIGGER *********************************************************/
typedef enum en_sys_trigger_column {
    SYS_TRIGGER_COL_OBJ = 0,
    SYS_TRIGGER_COL_TYPE = 1,
    SYS_TRIGGER_COL_EVENT = 2,
    SYS_TRIGGER_COL_OBJECTUID = 3,
    SYS_TRIGGER_COL_BASEOBJECT = 4,
    SYS_TRIGGER_COL_WHENCLAUSE = 5,
    SYS_TRIGGER_COL_ENABLE = 6,
    SYS_TRIGGER_COL_FALGS = 7,
    SYS_TRIGGER_COL_TABNAMELINE = 8,
    SYS_TRIGGER_COL_ACTIONLINENO = 9,
    SYS_TRIGGER_COL_ACTIONCOLNO = 10,
    SYS_TRIGGER_COL_SPARE1 = 11,
    SYS_TRIGGER_COL_SPARE2 = 12,
    SYS_TRIGGER_COL_SPARE3 = 13,
    SYS_TRIGGER_COL_SPARE4 = 14,

    SYS_TRIGGER_COLUMN_COUNT,
} sys_trigger_column_t;

#define IX_SYS_TRIGGER_001_ID                        0
#define IX_SYS_TRIGGER_001_ID_OBJ                    0

#define IX_SYS_TRIGGERS_002_ID                        1
#define IX_SYS_TRIGGERS_002_ID_OBJUID                 0
#define IX_SYS_TRIGGERS_002_ID_BASEOBJ                1
#define IX_SYS_TRIGGER_002_ID_OBJ                     2

#ifdef __cplusplus
}
#endif

#endif

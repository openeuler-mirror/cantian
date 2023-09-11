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
 * knl_sys_part_defs.h
 *
 *
 * IDENTIFICATION
 * src/kernel/knl_sys_part_defs.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef KNL_SYS_PART_DEFS_H
#define KNL_SYS_PART_DEFS_H

#ifdef __cplusplus
extern "C" {
#endif

/************************************** SYS_PARTOBJECT ***************************************************************/
typedef enum en_sys_partobject_column {
    SYS_PARTOBJECT_COL_USER_ID = 0,
    SYS_PARTOBJECT_COL_TABLE_ID = 1,
    SYS_PARTOBJECT_COL_INDEX_ID = 2,
    SYS_PARTOBJECT_COL_PARTTYPE = 3,
    SYS_PARTOBJECT_COL_PARTCNT = 4,
    SYS_PARTOBJECT_COL_PARTKEYS = 5,
    SYS_PARTOBJECT_COL_FLAGS = 6,
    SYS_PARTOBJECT_COL_INTERVAL = 7,
    SYS_PARTOBJECT_COL_BINTERVAL = 8,
    SYS_PARTOBJECT_COL_SUBPARTKEYS = 9,
    SYS_PARTOBJECT_COL_SUBPARTTYPE = 10,
    SYS_PARTOBJECT_COL_IS_SLICE = 11,

    SYS_PARTOBJECT_COLUMN_COUNT,    // systable column count, must be the last in the struct.
} sys_partobject_column_t;

#define IX_SYS_PARTOBJECT001_ID          0

#define IX_COL_SYS_PARTOBJECT001_USER_ID          0
#define IX_COL_SYS_PARTOBJECT001_TABLE_ID         1
#define IX_COL_SYS_PARTOBJECT001_INDEX_ID         2

/****************************************** SYS_PARTCOLUMN ***********************************************************/
typedef enum en_sys_partcolumn_column {
    SYS_PARTCOLUMN_COL_USER_ID = 0,
    SYS_PARTCOLUMN_COL_TABLE_ID = 1,
    SYS_PARTCOLUMN_COL_COLUMN_ID = 2,
    SYS_PARTCOLUMN_COL_POSITION = 3,
    SYS_PARTCOLUMN_COL_DATATYPE = 4,

    SYS_PARTCOLUMN_COLUMN_COUNT,    // systable column count, must be the last in the struct.
} sys_partcolumn_column_t;

#define IX_SYS_PARTCOLUMN001_ID          0

#define IX_COL_SYS_PARTCOLUMN001_USER_ID          0
#define IX_COL_SYS_PARTCOLUMN001_TABLE_ID         1

/******************************************** SYS_TABLEPART **********************************************************/
typedef enum en_sys_tablepart_column {
    SYS_TABLEPART_COL_USER_ID = 0,
    SYS_TABLEPART_COL_TABLE_ID = 1,
    SYS_TABLEPART_COL_PART_ID = 2,
    SYS_TABLEPART_COL_NAME = 3,
    SYS_TABLEPART_COL_HIBOUNDLEN = 4,
    SYS_TABLEPART_COL_HIBOUNDVAL = 5,
    SYS_TABLEPART_COL_SPACE_ID = 6,
    SYS_TABLEPART_COL_ORG_SCN = 7,
    SYS_TABLEPART_COL_ENTRY = 8,
    SYS_TABLEPART_COL_INITRANS = 9,
    SYS_TABLEPART_COL_PCTFREE = 10,
    SYS_TABLEPART_COL_FLAGS = 11,
    SYS_TABLEPART_COL_BHIBOUNDVAL = 12,
    SYS_TABLEPART_COL_ROWCNT = 13,
    SYS_TABLEPART_COL_BLKCNT = 14,
    SYS_TABLEPART_COL_EMPCNT = 15,
    SYS_TABLEPART_COL_AVGRLN = 16,
    SYS_TABLEPART_COL_SAMPLESIZE = 17,
    SYS_TABLEPART_COL_ANALYZETIME = 18,
    SYS_TABLEPART_COL_SUBPART_CNT = 19,

    SYS_TABLEPART_COLUMN_COUNT,    // systable column count, must be the last in the struct.
} sys_tablepart_column_t;

#define IX_SYS_TABLEPART001_ID           0

/* extral system table index column */
#define IX_COL_SYS_TABLEPART001_USER_ID           0
#define IX_COL_SYS_TABLEPART001_TABLE_ID          1
#define IX_COL_SYS_TABLEPART001_PART_ID           2

/******************************************** SYS_INDEXPART **********************************************************/
typedef enum en_sys_indexpart_column {
    SYS_INDEXPART_COL_USER_ID = 0,
    SYS_INDEXPART_COL_TABLE_ID = 1,
    SYS_INDEXPART_COL_INDEX_ID = 2,
    SYS_INDEXPART_COL_PART_ID = 3,
    SYS_INDEXPART_COL_NAME = 4,
    SYS_INDEXPART_COL_HIBOUNDLEN = 5,
    SYS_INDEXPART_COL_HIBOUNDVAL = 6,
    SYS_INDEXPART_COL_SPACE_ID = 7,
    SYS_INDEXPART_COL_ORG_SCN = 8,
    SYS_INDEXPART_COL_ENTRY = 9,
    SYS_INDEXPART_COL_INITRANS = 10,
    SYS_INDEXPART_COL_PCTFREE = 11,
    SYS_INDEXPART_COL_FLAGS = 12,
    SYS_INDEXPART_COL_BHIBOUNDVAL = 13,
    SYS_INDEXPART_COL_BLEVEL = 14,
    SYS_INDEXPART_COL_LEVEL_BLOCKS = 15,
    SYS_INDEXPART_COL_DISTKEY = 16,
    SYS_INDEXPART_COL_LBLKKEY = 17,
    SYS_INDEXPART_COL_DBLKKEY = 18,
    SYS_INDEXPART_COL_ANALYZETIME = 19,
    SYS_INDEXPART_COL_EMPTY_LEAF_BLOCKS = 20,
    SYS_INDEXPART_COL_CLUFAC = 21,
    SYS_INDEXPART_COL_SAMPLESIZE = 22,
    SYS_INDEXPART_COL_COMB_COLS_2_NDV = 23,
    SYS_INDEXPART_COL_COMB_COLS_3_NDV = 24,
    SYS_INDEXPART_COL_COMB_COLS_4_NDV = 25,
    SYS_INDEXPART_COL_SUBPART_CNT = 26,

    SYS_INDEXPART_COLUMN_COUNT,    // systable column count, must be the last in the struct.
} sys_indexpart_column_t;

#define IX_SYS_INDEXPART001_ID           0

/* extral system table index column */
#define IX_COL_SYS_INDEXPART001_USER_ID           0
#define IX_COL_SYS_INDEXPART001_TABLE_ID          1
#define IX_COL_SYS_INDEXPART001_INDEX_ID          2
#define IX_COL_SYS_INDEXPART001_PART_ID           3

/******************************************* SYS_LOBPART *************************************************************/
typedef enum en_sys_lobpart_column {
    SYS_LOBPART_COL_USER_ID = 0,
    SYS_LOBPART_COL_TABLE_ID = 1,
    SYS_LOBPART_COL_COLUMN_ID = 2,
    SYS_LOBPART_COL_PART_ID = 3,
    SYS_LOBPART_COL_SPACE_ID = 4,
    SYS_LOBPART_COL_ORG_SCN = 5,
    SYS_LOBPART_COL_ENTRY = 6,
    SYS_LOBPART_COL_FLAGS = 7,

    SYS_LOBPART_COLUMN_COUNT,    // systable column count, must be the last in the struct.
} sys_lobpart_column_t;

#define IX_SYS_LOBPART001_ID             0

#define IX_COL_SYS_LOBPART001_USER_ID             0
#define IX_COL_SYS_LOBPART001_TABLE_ID            1
#define IX_COL_SYS_LOBPART001_COLUMN_ID           2
#define IX_COL_SYS_LOBPART001_PART_ID             3

/****************************************** SYS_SUBPARTCOLUMN ***********************************************************/
typedef enum en_sys_subpartcolumn_column {
    SYS_SUBPARTCOLUMN_COL_USER_ID = 0,
    SYS_SUBPARTCOLUMN_COL_TABLE_ID = 1,
    SYS_SUBPARTCOLUMN_COL_COLUMN_ID = 2,
    SYS_SUBPARTCOLUMN_COL_POSITION = 3,
    SYS_SUBPARTCOLUMN_COL_DATATYPE = 4,

    SYS_SUBPARTCOLUMN_COLUMN_COUNT,    // systable column count, must be the last in the struct.
} sys_subpartcolumn_column_t;

#define IX_SYS_SUBPARTCOLUMN001_ID          0

#define IX_COL_SYS_SUBPARTCOLUMN001_USER_ID          0
#define IX_COL_SYS_SUBPARTCOLUMN001_TABLE_ID         1

/******************************************** SYS_TABLESUBPART ******************************************************/
typedef enum en_sys_tablesubpart_column {
    SYS_TABLESUBPART_COL_USER_ID = 0,
    SYS_TABLESUBPART_COL_TABLE_ID = 1,
    SYS_TABLESUBPART_COL_SUB_PART_ID = 2,
    SYS_TABLESUBPART_COL_NAME = 3,
    SYS_TABLESUBPART_COL_HIBOUNDLEN = 4,
    SYS_TABLESUBPART_COL_HIBOUNDVAL = 5,
    SYS_TABLESUBPART_COL_SPACE_ID = 6,
    SYS_TABLESUBPART_COL_ORG_SCN = 7,
    SYS_TABLESUBPART_COL_ENTRY = 8,
    SYS_TABLESUBPART_COL_INITRANS = 9,
    SYS_TABLESUBPART_COL_PCTFREE = 10,
    SYS_TABLESUBPART_COL_FLAGS = 11,
    SYS_TABLESUBPART_COL_BHIBOUNDVAL = 12,
    SYS_TABLESUBPART_COL_ROWCNT = 13,
    SYS_TABLESUBPART_COL_BLKCNT = 14,
    SYS_TABLESUBPART_COL_EMPCNT = 15,
    SYS_TABLESUBPART_COL_AVGRLN = 16,
    SYS_TABLESUBPART_COL_SAMPLESIZE = 17,
    SYS_TABLESUBPART_COL_ANALYZETIME = 18,
    SYS_TABLESUBPART_COL_PARENT_PART_ID = 19,

    SYS_TABLESUBPART_COLUMN_COUNT,    // systable column count, must be the last in the struct.
} sys_tablesubpart_column_t;
    
#define IX_SYS_TABLESUBPART001_ID           0
#define IX_SYS_TABLESUBPART002_ID           1
    
/* extral system table index column */
#define IX_COL_SYS_TABLESUBPART001_USER_ID           0
#define IX_COL_SYS_TABLESUBPART001_TABLE_ID          1
#define IX_COL_SYS_TABLESUBPART001_PARENT_PART_ID    2
#define IX_COL_SYS_TABLESUBPART001_SUB_PART_ID       3

#define IX_COL_SYS_TABLESUBPART002_USER_ID           0
#define IX_COL_SYS_TABLESUBPART002_TABLE_ID          1
#define IX_COL_SYS_TABLESUBPART002_NAME              2

/******************************************** SYS_INDEXSUBPART *******************************************************/
typedef enum en_sys_indexsubpart_column {
    SYS_INDEXSUBPART_COL_USER_ID = 0,
    SYS_INDEXSUBPART_COL_TABLE_ID = 1,
    SYS_INDEXSUBPART_COL_INDEX_ID = 2,
    SYS_INDEXSUBPART_COL_SUB_PART_ID = 3,
    SYS_INDEXSUBPART_COL_NAME = 4,
    SYS_INDEXSUBPART_COL_HIBOUNDLEN = 5,
    SYS_INDEXSUBPART_COL_HIBOUNDVAL = 6,
    SYS_INDEXSUBPART_COL_SPACE_ID = 7,
    SYS_INDEXSUBPART_COL_ORG_SCN = 8,
    SYS_INDEXSUBPART_COL_ENTRY = 9,
    SYS_INDEXSUBPART_COL_INITRANS = 10,
    SYS_INDEXSUBPART_COL_PCTFREE = 11,
    SYS_INDEXSUBPART_COL_FLAGS = 12,
    SYS_INDEXSUBPART_COL_BHIBOUNDVAL = 13,
    SYS_INDEXSUBPART_COL_BLEVEL = 14,
    SYS_INDEXSUBPART_COL_LEVEL_BLOCKS = 15,
    SYS_INDEXSUBPART_COL_DISTKEY = 16,
    SYS_INDEXSUBPART_COL_LBLKKEY = 17,
    SYS_INDEXSUBPART_COL_DBLKKEY = 18,
    SYS_INDEXSUBPART_COL_ANALYZETIME = 19,
    SYS_INDEXSUBPART_COL_EMPTY_LEAF_BLOCKS = 20,
    SYS_INDEXSUBPART_COL_CLUFAC = 21,
    SYS_INDEXSUBPART_COL_SAMPLESIZE = 22,
    SYS_INDEXSUBPART_COL_COM_COLS_2_NDV = 23,
    SYS_INDEXSUBPART_COL_COM_COLS_3_NDV = 24,
    SYS_INDEXSUBPART_COL_COM_COLS_4_NDV = 25,
    SYS_INDEXSUBPART_COL_PPART_ID = 26,

    SYS_INDEXSUBPART_COLUMN_COUNT,    // systable column count, must be the last in the struct.
} sys_indexsubpart_column_t;
        
#define IX_SYS_INDEXSUBPART001_ID           0
        
/* subpart index system table index column */
#define IX_COL_SYS_INDEXSUBPART001_USER_ID           0
#define IX_COL_SYS_INDEXSUBPART001_TABLE_ID          1
#define IX_COL_SYS_INDEXSUBPART001_INDEX_ID          2
#define IX_COL_SYS_INDEXSUBPART001_PARENT_PART_ID    3
#define IX_COL_SYS_INDEXSUBPART001_SUB_PART_ID       4

/******************************************* SYS_LOBSUBPART *********************************************************/
typedef enum en_sys_lobsubpart_column {
    SYS_LOBSUBPART_COL_USER_ID = 0,
    SYS_LOBSUBPART_COL_TABLE_ID = 1,
    SYS_LOBSUBPART_COL_COLUMN_ID = 2,
    SYS_LOBSUBPART_COL_PART_ID = 3,
    SYS_LOBSUBPART_COL_SPACE_ID = 4,
    SYS_LOBSUBPART_COL_ORG_SCN = 5,
    SYS_LOBSUBPART_COL_ENTRY = 6,
    SYS_LOBSUBPART_COL_FLAGS = 7,
    SYS_LOBSUBPART_COL_PARENT_PART_ID = 8,

    SYS_LOBSUBPART_COLUMN_COUNT,    // systable column count, must be the last in the struct.
} sys_lobsubpart_column_t;
    
#define IX_SYS_LOBSUBPART001_ID             0
    
#define IX_COL_SYS_LOBSUBPART001_USER_ID             0
#define IX_COL_SYS_LOBSUBPART001_TABLE_ID            1
#define IX_COL_SYS_LOBSUBPART001_PARENT_PART_ID      2
#define IX_COL_SYS_LOBSUBPART001_COLUMN_ID           3
#define IX_COL_SYS_LOBSUBPART001_SUB_PART_ID         4

#ifdef __cplusplus
}
#endif

#endif

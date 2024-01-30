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
 * knl_lrepl_meta.h
 *
 *
 * IDENTIFICATION
 * src/kernel/replication/knl_lrepl_meta.h
 *
 * -------------------------------------------------------------------------
 */
 
#ifndef KNL_LREPL_META_H
#define KNL_LREPL_META_H

#ifdef __cplusplus
extern "C" {
#endif

#define TABLEMETA_DIFF_TABLE_NAME "SYS_TABLEMETA_DIFF"
#define COLUMNMETA_HIS_TABLE_NAME "SYS_COLUMNMETA_HIS"
#define COLUMNMETA_HIS_DEFAULT_TEXT_MAX 1024

/* columns of SYS.SYS_TABLEMETA_DIFF */
typedef enum en_tablemeta_diff_column {
    SYS_TABLEMETA_DIFF_COL_ORG_SCN = 0,     // org_scn of table
    SYS_TABLEMETA_DIFF_COL_USER_NAME = 1,   // user name
    SYS_TABLEMETA_DIFF_COL_TABLE_NAME = 2,  // table name
    SYS_TABLEMETA_DIFF_COL_USER_ID = 3,     // user id
    SYS_TABLEMETA_DIFF_COL_TABLE_ID = 4,    // table id
    SYS_TABLEMETA_DIFF_COL_OBJECT_ID = 5,   // object id
    SYS_TABLEMETA_DIFF_COL_VERSION = 6,     // metadata version, for one table it starts from 0 and continuous
    SYS_TABLEMETA_DIFF_COL_DDL_TYPE = 7,    // DDL operation type that causes metadata changes
    SYS_TABLEMETA_DIFF_COL_CHG_SCN = 8,     // expiration time of the current metadata version
    SYS_TABLEMETA_DIFF_COL_INVALID_SCN = 9, // invalid scn used to delete unused row
    SYS_TABLEMETA_DIFF_COL_OPTIONS = 10,    // prepare for future use
    SYS_TABLEMETA_DIFF_COLUMN_COUNT,
} tablemeta_diff_column_t;

#define IX_TABLEMETA_DIFF001_ID 0
#define IX_COL_TABLEMETA_DIFF001_ID 0
#define IX_COL_TABLEMETA_DIFF001_VERSION 1
#define IX_COL_TABLEMETA_DIFF001_CHG_SCN 2

#define IX_TABLEMETA_DIFF002_ID 1
#define IX_COL_TABLEMETA_HIS002_USER_ID 0
#define IX_COL_TABLEMETA_HIS002_TABLE_ID 1

#define IX_TABLEMETA_DIFF003_ID 2
#define IX_COL_TABLEMETA_DIFF003_ID 0
#define IX_COL_TABLEMETA_DIFF003_VERSION 1
#define IX_COL_TABLEMETA_DIFF003_CHG_SCN 2
#define IX_COL_TABLEMETA_DIFF003_INVALID_SCN 3

/* columns of sys.SYS_COLUMNMETA_HIS */
typedef enum en_columnmeta_his_column {
    SYS_COLUMNMETA_HIS_COL_ORG_SCN = 0,      // org_scn of table
    SYS_COLUMNMETA_HIS_COL_VERSION = 1,      // metadata version
    SYS_COLUMNMETA_HIS_COL_USER_ID = 2,      // user id
    SYS_COLUMNMETA_HIS_COL_TABLE_ID = 3,     // table id
    SYS_COLUMNMETA_HIS_COL_OBJECT_ID = 4,    // object id
    SYS_COLUMNMETA_HIS_COL_COLUMN_ID = 5,    // column id
    SYS_COLUMNMETA_HIS_COL_COLUMN_NAME = 6,  // column name
    SYS_COLUMNMETA_HIS_COL_PRIMARY = 7,      // is primary key
    SYS_COLUMNMETA_HIS_COL_CHANGED = 8,      // column metadata is changed in this version
    SYS_COLUMNMETA_HIS_COL_TYPE = 9,
    SYS_COLUMNMETA_HIS_COL_BYTES = 10,
    SYS_COLUMNMETA_HIS_COL_PRECISION = 11,
    SYS_COLUMNMETA_HIS_COL_SCALE = 12,
    SYS_COLUMNMETA_HIS_COL_NULLABLE = 13,
    SYS_COLUMNMETA_HIS_COL_FLAGS = 14,
    SYS_COLUMNMETA_HIS_COL_DEFAULT_TEXT = 15,
    SYS_COLUMNMETA_HIS_COL_OPTIONS = 16,
    SYS_COLUMNMETA_HIS_COLUMN_COUNT,
} columnmeta_his_column_t;

#define IX_COLUMNMETA_HIS001_ID 0
#define IX_COL_COLUMNMETA_HIS001_ORG_SCN 0
#define IX_COL_COLUMNMETA_HIS001_VERSION 1
#define IX_COL_COLUMNMETA_HIS001_COLUMN_ID 2

#define IX_COLUMNMETA_HIS002_ID 1
#define IX_COL_COLUMNMETA_HIS001_USER_ID 0
#define IX_COL_COLUMNMETA_HIS001_TABLE_ID 1

typedef struct st_tablemeta_diff_info {
    uint32 uid;
    uint32 tid;
    uint32 obj_id;
    knl_scn_t org_scn;
    uint64 version;
    char user_name[CT_NAME_BUFFER_SIZE];
    char name[CT_NAME_BUFFER_SIZE];
    altable_action_t ddl_type;
    knl_scn_t chg_scn;
    knl_scn_t invalid_scn;
} tablemeta_diff_info_t;

typedef struct st_columnmeta_his_info {
    knl_scn_t org_scn;
    uint64 version;
    uint32 user_id;
    uint32 table_id;
    uint32 object_id;
    uint32 column_id;
    char column_name[CT_NAME_BUFFER_SIZE];
    bool32 primary;
    bool32 changed;
    uint32 datatype;
    uint32 size;
    int32 precision;
    int32 scale;
    bool32 nullable;
    uint32 flags;
    bool32 has_default;
    char default_text[COLUMNMETA_HIS_DEFAULT_TEXT_MAX];
    uint16 collate_id;
    uint8 mysql_ori_datatype;
    uint8 mysql_unsigned;
} columnmeta_his_info_t;

typedef struct st_lrepl_meta_mtrl_context_t {
    mtrl_context_t mtrl_ctx;
    uint32 seg_id;
} lrepl_meta_mtrl_context_t;

typedef struct st_lrepl_columnmeta_his_match_cond {
    knl_cursor_t *cursor;
    bool32 invisible;
} lrepl_columnmeta_his_match_cond_t;

status_t knl_meta_record(knl_session_t *session, knl_altable_def_t *def, knl_dictionary_t *dc, knl_scn_t scn);
status_t knl_meta_record_when_copy(knl_session_t *session, knl_dictionary_t *old_dc,
                                   knl_dictionary_t *new_dc, knl_scn_t scn, bool32 is_rename_cross_db);
status_t knl_meta_delete(knl_session_t *session, knl_scn_t scn);
#ifdef __cplusplus
}
#endif
 
#endif
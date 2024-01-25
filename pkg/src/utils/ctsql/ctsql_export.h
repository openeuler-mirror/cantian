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
 * ctsql_export.h
 *
 *
 * IDENTIFICATION
 * src/utils/ctsql/ctsql_export.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CTSQL_EXP_H
#define CTSQL_EXP_H

#include "ctsql.h"
#include "cm_types.h"
#include "ctsql_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
    1. EXP_CACHE_ALL_TABLE unit include : exp_cache_unit_t array
       EXP_CACHE_ALL_TABLE unit may include below unit types:
            EXP_CACHE_CREATE_TABLE, EXP_CACHE_TABLE_NAME,
            EXP_CACHE_SUB_FILE_NAME, EXP_CACHE_COLUMN_INFO,
            EXP_CACHE_TABLE_INDEX
    2. EXP_CACHE_CREATE_TABLE unit include : create table SQL
    3. EXP_CACHE_SUB_FILE_NAME unit include : sub file name array
    4. EXP_CACHE_COLUMN_INFO unit include : exp_cache_column_info_t array
    5. EXP_CACHE_VIEW unit include : exp_cache_unit_t array
       EXP_CACHE_VIEW unit may include below unit types:
            EXP_CACHE_VIEW_NAME, EXP_CACHE_VIEW_COLUMNS,
            EXP_CACHE_VIEW_SRC
*/
typedef enum {
    // for 'table' type
    EXP_CACHE_ALL_TABLE,
    EXP_CACHE_CREATE_TABLE,
    EXP_CACHE_TABLE_NAME,
    EXP_CACHE_SUB_FILE_NAME,
    EXP_CACHE_COLUMN_INFO,
    EXP_CACHE_TABLE_INDEX,
    // for 'view' type
    EXP_CACHE_VIEW,
    EXP_CACHE_VIEW_NAME,
    EXP_CACHE_VIEW_COLUMNS,
    EXP_CACHE_VIEW_SRC,
    // for 'procedure, function, trigger' type
    EXP_CACHE_OBJ,
    EXP_CACHE_OBJ_TYPE,
    EXP_CACHE_OBJ_NAME,
    EXP_CACHE_OBJ_SRC
} exp_cache_unit_type_t;

typedef enum {
    EXP_DESC_HELP = 0,
    EXP_DESC_USAGE = 1,
    EXP_DESC_OPTION = 2,
    EXP_DESC_HYPHEN_H = 3,
    EXP_DESC_VERSION = 4,
    EXP_DESC_HYPHEN_V = 5,
    EXP_DESC_UNUSED = CT_INVALID_ID32
} exp_desc_type_t;

typedef struct {
    char name[CT_MAX_NAME_LEN + 4]; // align by 4 bytes
    uint16 type;
    uint16 size;
    uchar is_array;
    uchar unused[3];
} exp_cache_column_info_t;

typedef struct {
    exp_cache_unit_type_t type;
    text_t content;
    uint32 max_size;
} exp_cache_unit_t;

typedef struct {
    uint32 idx;
    exp_cache_unit_type_t type;
} exp_cache_iterator_t;

typedef struct {
    uint32 unit_idx;
    uint32 unit_offset;
} exp_subfile_iterator_t;

/* root unit, create table, table name, column info, subfile name, table index  */
#define EXP_MAX_UNIT_CNT_PER_TABLE 14
#define EXP_MAX_TABLE_CACHE_EXT_CNT 20
#define EXP_MAX_UNIT_CNT_PER_VIEW 4
#define EXP_MAX_UNIT_CNT_PER_OBJ 4
#define EXP_MAX_SUBFILE_NAME_LEN (CT_MAX_NAME_LEN + 1)
#define EXP_ESCAPE_CHAR_LEN 2
#define EXP_QUOTA_LEN 2

/* table export info cached in 'exp_table_cache_t', then flush to file */
typedef struct {
    fixed_memory_pool_t fixed_mem_pool; // table's sql(create table , create index) sql buffer pool
    exp_cache_unit_t root_unit;
    exp_cache_unit_t *curr_unit;
    union {
        uint64 record_cnt; // used for cache table records number
    };
} exp_cache_t;

#define CACHE_UNIT_REMAIN_SIZE(cache_unit) ((cache_unit)->max_size - (cache_unit)->content.len)
#define EXP_CACHE_REMAIN_SIZE(exp_cache) CACHE_UNIT_REMAIN_SIZE((exp_cache)->curr_unit)
#define EXP_CACHE_UNIT_CNT(exp_cache) ((exp_cache)->root_unit.content.len / sizeof(exp_cache_unit_t))
#define EXP_CACHE_UNIT_I(exp_cache, i) (exp_cache_unit_t*)((exp_cache)->root_unit.content.str + \
    sizeof(exp_cache_unit_t) * (i))

/* exp-cache interface */
status_t init_exp_cache(exp_cache_t* exp_cache, uint32 unit_cnt, exp_cache_unit_type_t root_type);
status_t exp_start_cache_unit(exp_cache_t* exp_cache, exp_cache_unit_type_t type);
status_t exp_extend_cache_unit(exp_cache_t* exp_cache);
status_t alloc_exp_cache_unit(exp_cache_t* exp_cache, exp_cache_unit_type_t type, exp_cache_unit_t** unit);
status_t get_exp_cache_unit(exp_cache_t* exp_cache, exp_cache_unit_type_t type, exp_cache_unit_t** unit);
void reset_exp_cache(exp_cache_t* exp_cache);
void uninit_exp_cache(exp_cache_t* exp_cache);

bool8 exp_cache_init_iterator(exp_cache_t *exp_cache, exp_cache_unit_type_t type, exp_cache_iterator_t *iter);
bool8 exp_cache_next_iterator(exp_cache_t *exp_cache, exp_cache_iterator_t *iter);
exp_cache_unit_t* exp_cache_get_iterator(exp_cache_t *exp_cache, exp_cache_iterator_t *iter);

bool8 exp_subfile_init_iterator(exp_cache_t *exp_cache, exp_subfile_iterator_t *iter);
bool8 exp_subfile_next_iterator(exp_cache_t *exp_cache, exp_subfile_iterator_t *iter);
char* exp_subfile_get_iterator(exp_cache_t *exp_cache, exp_subfile_iterator_t *iter);

/* exp-cache-unit interface */
status_t alloc_column_cache_info(exp_cache_t* exp_cache, exp_cache_column_info_t** column_info);
status_t alloc_column_subfile_info(exp_cache_t* exp_cache, char** subfile);
status_t exp_cache_append_str(exp_cache_t* exp_cache, const char* str);
status_t exp_cache_append_str_quote(exp_cache_t* exp_cache, const char* str);
status_t exp_cache_append_text(exp_cache_t* exp_cache, const text_t* text);
status_t exp_cache_append_escape_str(exp_cache_t* exp_cache, const char* str, char escape);
status_t cache_unit_append_str(exp_cache_unit_t* unit, const char* str);
status_t cache_unit_append_str_quote(exp_cache_unit_t* unit, const char* str);
status_t cache_unit_append_text(exp_cache_unit_t* unit, const text_t* text);
status_t cache_unit_append_escape_str(exp_cache_unit_t* unit, const char* str, char escape);
status_t cache_unit_append_escape_text(exp_cache_unit_t* unit, const text_t* text, char escape);

/* exp-cache flush interface for bin/txt mode */
status_t exp_cache_unit_write_file(exp_cache_t* exp_cache, exp_cache_unit_type_t type);
status_t table_cache_write_file(exp_cache_t* table_cache);
status_t table_cache_write_txt_tab_meta(exp_cache_t* table_cache);
status_t table_cache_write_txt_tab_index_meta(exp_cache_t* table_cache);
status_t view_cache_write_file(exp_cache_t* view_cache);
status_t obj_cache_write_file(exp_cache_t* obj_cache);

status_t par_exp_create_dn_connectdb(ctsql_conn_info_t *dn_conn_info, bool32 is_get_pwd);
status_t exp_clean_pwd_info(ctsql_conn_info_t *dn_conn_info);

/* export */
status_t ctsql_get_saved_pswd(char *password, uint32 len);
void ctsql_get_saved_user(char *user, uint32 len);
status_t ctsql_export(text_t *cmd_text, uint8 show_parse_info);

#ifdef __cplusplus
}
#endif

#endif
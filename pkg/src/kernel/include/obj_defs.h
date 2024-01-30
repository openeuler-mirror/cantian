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
 * obj_defs.h
 *
 *
 * IDENTIFICATION
 * src/kernel/include/obj_defs.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_OBJ_DEFS_H__
#define __KNL_OBJ_DEFS_H__

#include "dml_defs.h"
#include "knl_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_knl_lobstor_def {
    text_t col_name;
    bool32 in_row;
    text_t space;
    text_t seg_name;
} knl_lobstor_def_t;

// lob API
uint32 knl_lob_size(knl_handle_t locator);
char *knl_inline_lob_data(knl_handle_t locator);
bool32 knl_lob_is_inline(knl_handle_t locator);
status_t knl_read_lob(knl_handle_t se, knl_handle_t loc, uint32 offset_input, void *buf, uint32 size,
                      uint32 *read_size, page_id_t *page_id);
status_t knl_write_lob(knl_handle_t se, knl_cursor_t *cursor, char *locator, knl_column_t *column,
                       bool32 force_outline, void *data);
status_t knl_row_put_lob(knl_handle_t session, knl_cursor_t *cursor, knl_column_t *column,
                         void *data, knl_handle_t ra);
status_t knl_row_move_lob(knl_handle_t session, knl_cursor_t *cursor, knl_column_t *column,
                          knl_handle_t src_locator, knl_handle_t ra);

#define SYNONYM_IS_NULL    0x00000000
#define SYNONYM_IS_REPLACE 0x00000001
#define SYNONYM_IS_PUBLIC  0x00000002

typedef struct st_knl_synonym_def {
    text_t owner;
    text_t name;
    text_t table_owner;
    text_t table_name;
    bool32 is_knl_syn;
    uint32 flags;
    uint32 ref_uid;               //  user id of ref object
    uint32 ref_oid;               //  object id of ref object
    knl_dict_type_t ref_dc_type;  //  dc type of ref object
    knl_scn_t ref_org_scn;        //  org scn of ref object
    knl_scn_t ref_chg_scn;        //  chg scn of ref object
} knl_synonym_def_t;

typedef enum e_object_type {
    OBJ_TYPE_TABLE = 0,
    OBJ_TYPE_VIEW = 1,
    OBJ_TYPE_SEQUENCE = 2,
    OBJ_TYPE_PROCEDURE = 3,

    OBJ_TYPE_SYNONYM = 7,

    OBJ_TYPE_FUNCTION = 8,
    OBJ_TYPE_TRIGGER = 9,
    OBJ_TYPE_INDEX = 10,
    OBJ_TYPE_LOB = 11,
    OBJ_TYPE_TABLE_PART = 12,
    OBJ_TYPE_INDEX_PART = 13,
    OBJ_TYPE_LOB_PART = 14,
    OBJ_TYPE_PL_SYNONYM = 15,
    OBJ_TYPE_PACKAGE_SPEC = 16,
    OBJ_TYPE_PACKAGE_BODY = 17,
    OBJ_TYPE_DIRECTORY = 18,
    OBJ_TYPE_TYPE_SPEC = 19,
    OBJ_TYPE_TYPE_BODY = 20,
    OBJ_TYPE_LIBRARY = 21,
    OBJ_TYPE_SHADOW_INDEX = 22,
    OBJ_TYPE_SHADOW_INDEX_PART = 23,
    OBJ_TYPE_GARBAGE_SEGMENT = 24,
    OBJ_TYPE_USER = 25,
    OBJ_TYPE_TABLE_SUBPART = 26,
    OBJ_TYPE_INDEX_SUBPART = 27,
    OBJ_TYPE_LOB_SUBPART = 28,
    OBJ_TYPE_SHADOW_INDEX_SUBPART = 29,
    OBJ_TYPE_SYS_PACKAGE = 30,
    OBJ_TYPE_INVALID = CT_INVALID_ID32,
} object_type_t;

typedef struct st_obj_info {
    object_type_t tid; /* type Id for object */
    uint32 uid;        /* owner user id */
    uint64 oid;        /* ID of the object */
} obj_info_t;

#define PL_TYPE_TO_OBJ_TYPE_CHAR(type) \
    (((type) == 'P') ? OBJ_TYPE_PROCEDURE : (((type) == 'F') ? OBJ_TYPE_FUNCTION : OBJ_TYPE_TRIGGER))

#define IS_PL_SYN(type) \
    ((type) == OBJ_TYPE_FUNCTION || (type) == OBJ_TYPE_PROCEDURE || (type) == OBJ_TYPE_PACKAGE_SPEC || \
     (type) == OBJ_TYPE_TYPE_SPEC || (type) == OBJ_TYPE_SYS_PACKAGE)

typedef struct st_synonym_t {
    uint32 uid;                             // user id
    uint32 id;                              // synonym id
    knl_scn_t org_scn;                      // original scn
    knl_scn_t chg_scn;                      // scn when changed by DDL(alter)
    char name[CT_NAME_BUFFER_SIZE];         // synonym name
    char table_owner[CT_NAME_BUFFER_SIZE];  // table owner
    char table_name[CT_NAME_BUFFER_SIZE];   // table name
    uint32 flags;                           // synonym tatus:valid(1), invalid(0), unknown(2)
    object_type_t type;                     //  type of real object
} knl_synonym_t;


status_t knl_create_synonym(knl_handle_t session, knl_handle_t stmt, knl_synonym_def_t *def);
status_t knl_drop_synonym(knl_handle_t session, knl_handle_t stmt, knl_drop_def_t *def);
status_t knl_pl_create_synonym(knl_handle_t knl_session, knl_synonym_def_t *def, const int64 syn_id);
status_t knl_delete_syssyn_by_name(knl_handle_t knl_session, uint32 uid, const char *syn_name);
status_t knl_check_and_load_synonym(knl_handle_t knl_session, text_t *user, text_t *name, knl_synonym_t *result,
    bool32 *exists);

// definition of sequence
typedef struct st_knl_sequence_def {
    text_t user;
    text_t name;
    int64 start;
    int64 step;
    int64 min_value;
    int64 max_value;
    int64 cache;
    bool32 is_cycle;
    bool32 nocache;
    bool32 nominval;
    bool32 nomaxval;
    bool32 is_order;
#ifdef Z_SHARDING
    galist_t distribute_groups;
    binary_t dist_data;
#endif
    union {
        struct {
            bool32 is_minval_set : 1;
            bool32 is_maxval_set : 1;
            bool32 is_step_set : 1;
            bool32 is_cache_set : 1;
            bool32 is_start_set : 1;
            bool32 is_cycle_set : 1;
            bool32 is_order_set : 1;
            bool32 is_nocache_set : 1;
            bool32 is_nominval_set : 1;
            bool32 is_nomaxval_set : 1;
            bool32 is_groupid_set : 1;
            bool32 unused : 21;
        };
        bool32 is_option_set;
    };
} knl_sequence_def_t;

static inline object_type_t knl_get_object_type(knl_dict_type_t type)
{
    switch (type) {
        case DICT_TYPE_TABLE:
        case DICT_TYPE_TEMP_TABLE_TRANS:
        case DICT_TYPE_TEMP_TABLE_SESSION:
        case DICT_TYPE_TABLE_NOLOGGING:
        case DICT_TYPE_TABLE_EXTERNAL:
            return OBJ_TYPE_TABLE;

        case DICT_TYPE_SEQUENCE:
            return OBJ_TYPE_SEQUENCE;

        case DICT_TYPE_VIEW:
        case DICT_TYPE_DYNAMIC_VIEW:
        case DICT_TYPE_GLOBAL_DYNAMIC_VIEW:
            return OBJ_TYPE_VIEW;

        case DICT_TYPE_SYNONYM:
            return OBJ_TYPE_SYNONYM;

        default:
            return OBJ_TYPE_INVALID;
    }
}

status_t knl_create_sequence(knl_handle_t session, knl_handle_t stmt, knl_sequence_def_t *def);
status_t knl_alter_sequence(knl_handle_t session, knl_handle_t stmt, knl_sequence_def_t *def);
status_t knl_drop_sequence(knl_handle_t session, knl_handle_t stmt, knl_drop_def_t *def);
status_t knl_get_sequence_id(knl_handle_t session, text_t *user, text_t *name, uint32 *id);

status_t knl_seq_nextval(knl_handle_t session, text_t *user, text_t *name, int64 *nextval);
status_t knl_get_nextval_for_cn(knl_handle_t session, text_t *user, text_t *name, int64 *value);
status_t knl_seq_currval(knl_handle_t session, text_t *user, text_t *name, int64 *nextval);
status_t knl_seq_multi_val(knl_handle_t session, knl_sequence_def_t *def,
    uint32 group_order, uint32 group_cnt, uint32 count);

status_t knl_get_seq_dist_data(knl_handle_t session, text_t *user, text_t *name, binary_t **dist_data);
status_t knl_set_cn_seq_currval(knl_handle_t session, text_t *user, text_t *name, int64 nextval);
status_t knl_alter_seq_nextval(knl_handle_t session, knl_sequence_def_t *def, int64 value);
status_t knl_get_seq_def(knl_handle_t session, text_t *user, text_t *name, knl_sequence_def_t *def);

status_t knl_reconstruct_lob_row(knl_handle_t session, knl_handle_t entity, knl_cursor_t *cursor, uint32 *scan_id,
    uint32 col_id);
status_t knl_reconstruct_lob_update_info(knl_handle_t session, knl_dictionary_t *dc, knl_cursor_t *cursor,
    uint32 col_id);

#ifdef __cplusplus
}
#endif

#endif
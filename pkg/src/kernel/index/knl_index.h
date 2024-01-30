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
 * knl_index.h
 *
 *
 * IDENTIFICATION
 * src/kernel/index/knl_index.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_INDEX_H__
#define __KNL_INDEX_H__

#include "cm_defs.h"
#include "knl_common.h"
#include "knl_interface.h"
#include "knl_session.h"
#include "knl_page.h"
#include "knl_lock.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CT_SHADOW_INDEX_ID     (CT_MAX_TABLE_INDEXES + 1)
#define INDEX_DESC(index)      (&((index_t *)(index))->desc)
#define CT_MAX_RECYCLE_INDEXES 1024
#define INDEX_RECY_CLOCK 2
#define INDEX_NEED_RECY_RATIO(se) ((se)->kernel->attr.idx_recycle_percent * 1.0 / CT_PERCENT)
#define INDEX_NEED_REBUILD_RATION 0.5
#define INDEX_NEED_REBUILD_SIZE SIZE_G(1)

#define MAX_SORT_THREADS 12
#define MIN_SORT_THREADS 2
#define INDEX_IS_UNSTABLE(index, is_splitting) (((index)->desc.primary || (index)->desc.unique) && !(is_splitting))

typedef enum en_dep_scan_mode {
    DEP_SCAN_TABLE_FULL = 0,
    DEP_SCAN_INDEX_ONLY = 1,
    DEP_SCAN_MIX = 2,
} dep_scan_mode_t;

typedef struct st_cons_dep {
    uint16 *cols;
    uint8 *col_map;
    struct st_cons_dep *next;
    volatile bool32 loaded;
    spinlock_t lock;
    knl_refactor_t refactor;
    knl_constraint_state_t cons_state;
    uint16 uid;
    uint32 oid;
    uint8 col_count;
    uint8 idx_slot;
    uint8 ix_match_cols;
    uint8 align;
    dep_scan_mode_t scan_mode;
    knl_scn_t chg_scn;
} cons_dep_t;

typedef struct st_dep_condition {
    char *data[CT_MAX_INDEX_COLUMNS];
    uint16 lens[CT_MAX_INDEX_COLUMNS];
    knl_cursor_t *child_cursor;
    cons_dep_t *dep;
} dep_condition_t;

typedef struct st_cons_dep_set {
    cons_dep_t *first;
    cons_dep_t *last;
    uint32 count;
} cons_dep_set_t;

/* index access method structure */
typedef struct st_index_accessor {
    knl_cursor_operator_t do_fetch;
    knl_cursor_operator_t do_insert;
    knl_cursor_operator_t do_delete;
} idx_accessor_t;

typedef struct st_index {
    knl_index_desc_t desc;
    cons_dep_set_t dep_set;  // which constraints depends on this table
    struct st_dc_entity *entity;
    union {
        btree_t btree;     // index entity
        void *temp_btree;  // temp index entity
    };
    struct st_part_index *part_index;  // partitioned index
    idx_accessor_t *acsor;           // index access method
} index_t;

#define INDEX_PROFILE(index)           (&(index)->desc.profile)
#define IS_UNIQUE_PRIMARY_INDEX(index) ((index)->desc.primary || (index)->desc.unique)
#define IS_PART_INDEX(index)           (((index_t *)(index))->desc.parted)
#define INDEX_GET_PART(index, part_no) PART_GET_ENTITY(((index_t *)(index))->part_index, part_no)
#define CT_MAX_ROOT_LEVEL  (CT_MAX_BTREE_LEVEL - 1)
#define BTREE_NEED_CMP_ROWID(cursor, index) (!IS_UNIQUE_PRIMARY_INDEX(index) || (cursor)->index_paral)
#define COLUMN_IS_REAL(c)  ((c)->datatype == CT_TYPE_REAL)
#define BTREE_LOCATE_NEXT_KEY(search_info, cursor) ((search_info)->is_dsc_scan \
    || (cursor)->asc_relocate_next_key)

typedef struct st_index_set {
    index_t *items[CT_MAX_TABLE_INDEXES];
    uint32 count;
    uint32 total_count;
} index_set_t;

typedef struct st_index_recycle_item {
    xid_t xid;
    knl_scn_t scn;
    knl_scn_t part_org_scn;
    uint32 table_id;
    uint32 part_no;
    uint32 uid;
    uint32 index_id;
    bool32 is_tx_active;
    uint32 next;
} index_recycle_item_t;

typedef struct st_index_recycle_ctx {
    spinlock_t lock;
    bool32 is_working;
    id_list_t idx_list;
    id_list_t free_list;
    thread_t thread;
    index_recycle_item_t items[CT_MAX_RECYCLE_INDEXES];
} index_recycle_ctx_t;

typedef struct st_index_page_item {
    uint32 next;
    bool32 is_invalid;
    knl_scn_t cache_scn;
    char page[0];
} index_page_item_t;

typedef struct st_index_cache_ctx {
    spinlock_t lock;
    uint32 capacity;
    uint32 hwm;
    id_list_t free_items;
    id_list_t expired_items;
    index_page_item_t *items;
} index_cache_ctx_t;

typedef struct st_index_area {
    index_recycle_ctx_t recycle_ctx;
    index_cache_ctx_t cache_ctx;
} index_area_t;

typedef struct st_btree_mt_context {
    mtrl_context_t mtrl_ctx;
    mtrl_context_t mtrl_ctx_paral;
    bool32 initialized;
    uint32 seg_id;
    bool32 is_parallel;
    bool32 nologging;
    uint64 rows;
    char *page_buf;
} btree_mt_context_t;

typedef struct st_btree_path_t {
    rowid_t path[CT_MAX_BTREE_LEVEL];
    uint64 leaf_lsn;
    knl_part_locate_t part_loc;
    bool8 get_sibling;
    char *sibling_key;
    bool8 is_rebuild;
    bool8 is_empty_newnode;
} btree_path_info_t;

typedef struct st_idx_range_info {
    page_id_t l_page[CT_MAX_BTREE_LEVEL];
    page_id_t r_page[CT_MAX_BTREE_LEVEL];
    uint32 l_slot[CT_MAX_BTREE_LEVEL];
    uint32 r_slot[CT_MAX_BTREE_LEVEL];
    uint32 keys;
    uint32 level;
}idx_range_info_t;

typedef enum en_index_build_mode {
    REBUILD_INDEX_ONLINE = 0,
    REBUILD_INDEX = 1,
    CREATE_INDEX_ONLINE = 2,
    REBUILD_INDEX_PARALLEL = 3,
}index_build_mode_t;

typedef struct st_auto_rebuild_item {
    uint32 uid;
    uint32 oid;
    alter_index_type_t type;
    arebuild_index_state_t state;
    knl_scn_t scn; // creation segment scn or last busy resource generate time
    char name[CT_NAME_BUFFER_SIZE]; // index name
    char part_name[CT_NAME_BUFFER_SIZE]; // index part name
    knl_scn_t org_scn;
    uint32 next;
} auto_rebuild_item_t;

typedef struct st_auto_rebuild_ctx {
    spinlock_t lock;
    bool32 working;
    id_list_t idx_list;
    id_list_t free_list;
    thread_t thread;
    auto_rebuild_item_t items[CT_MAX_RECYCLE_INDEXES];
} auto_rebuild_ctx_t;

extern idx_accessor_t g_btree_acsor;
extern idx_accessor_t g_pcr_btree_acsor;
extern idx_accessor_t g_temp_btree_acsor;
extern idx_accessor_t g_invalid_index_acsor;

typedef void (*idx_put_key_data_t)(char *key_buf, ct_type_t type, const char *data, uint16 len, uint16 id);
typedef status_t (*idx_batch_insert)(knl_handle_t session, knl_cursor_t *cursor);
status_t knl_make_key(knl_handle_t session, knl_cursor_t *cursor, index_t *index, char *key_buf);
status_t knl_make_update_key(knl_handle_t session, knl_cursor_t *cursor, index_t *index, char *key_buf,
                             knl_update_info_t *ui, uint16 *map);
void idx_decode_row(knl_session_t *session, knl_cursor_t *cursor, uint16 *offsets, uint16 *lens, uint16 *size);
status_t idx_generate_dupkey_error(knl_session_t *session, index_t *index, const char *key);
status_t idx_construct(btree_mt_context_t *ctx);

void idx_recycle_proc(thread_t *thread);
void idx_recycle_close(knl_session_t *session);
void idx_binary_search(index_t *index, char *curr_page, knl_scan_key_t *scan_key, btree_path_info_t *path_info,
                       bool32 cmp_rowid, bool32 *is_same);
status_t idx_get_paral_schedule(knl_session_t *session, btree_t *btree, knl_scn_t org_scn,
                                knl_idx_paral_info_t paral_info, knl_index_paral_range_t *sub_ranges);
void idx_enter_next_range(knl_session_t *session, page_id_t page_id, uint32 slot, uint32 step, uint32 *border);
void idx_reverse_key_data(char *data, ct_type_t type, uint16 len);
uint16 idx_get_col_size(ct_type_t type, uint16 len, bool32 is_pcr);

void auto_rebuild_init(knl_session_t *session);
void auto_rebuild_add_index(knl_session_t *session, index_t *index, knl_part_locate_t part_loc);
void auto_rebuild_release_item(knl_session_t *session, uint32 id_input);
void auto_rebuild_close(knl_session_t *session);
void idx_auto_rebuild_proc(thread_t *thread);
#ifdef __cplusplus
}
#endif

#endif

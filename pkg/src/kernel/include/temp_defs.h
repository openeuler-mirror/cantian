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
 * temp_defs.h
 *
 *
 * IDENTIFICATION
 * src/kernel/include/temp_defs.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_TEMP_DEFS_H__
#define __KNL_TEMP_DEFS_H__

#include "knl_defs.h"
#include "stats_defs.h"
#include "dml_defs.h"

#ifdef __cplusplus
extern "C" {
#endif
  
#define TEMP_SAFE_ROWS 1000000

typedef struct st_cbo_stats_table cbo_stats_table_t;

typedef struct st_temp_btree_segment {
    knl_scn_t org_scn;
    uint32 index_segid;
    uint32 root_vmid;
    uint32 level;
} temp_btree_segment_t;

typedef struct st_stats_table_mon {
    bool32 is_change;      // table is change or not
    uint32 inserts;        // insert
    uint32 updates;        // updates
    uint32 deletes;        // deletes
    uint32 drop_segments;  // partition truncates
    date_t timestamp;
} stats_table_mon_t;

typedef struct st_knl_temp_cache {
    knl_dict_type_t table_type;
    knl_scn_t org_scn;
    knl_scn_t seg_scn;
    knl_scn_t chg_scn;
    knl_scn_t mem_chg_scn;  // table->chg_scn when alloc memory
    uint64 serial;
    uint32 user_id;
    uint32 table_id;
    uint32 table_segid;
    uint32 index_segid;
    uint32 lob_segid;
    uint32 rmid;
    uint32 hold_rmid;    // the rm that hold the temp table
    uint32 rows;  // cbo estimated card for temp table
    stats_table_mon_t table_smon;
    temp_btree_segment_t index_root[CT_MAX_TABLE_INDEXES];
    cbo_stats_table_t *cbo_stats;
    memory_context_t *memory;
    bool32 stat_exists;
    uint32 stats_version;
} knl_temp_cache_t;

static inline uint32 CBO_TEMP_SAFE_ROWS(knl_handle_t temp_cache)
{
    knl_temp_cache_t *cache = (knl_temp_cache_t *)temp_cache;

    return cache->rows > TEMP_SAFE_ROWS ? TEMP_SAFE_ROWS : cache->rows;
}

void knl_free_temp_cache_memory(knl_temp_cache_t *temp_table);
knl_handle_t knl_get_temp_cache(knl_handle_t session, uint32 uid, uint32 oid);
status_t knl_put_temp_cache(knl_handle_t session, knl_handle_t dc_entity);
void knl_free_temp_vm(knl_handle_t session, knl_handle_t temp_table);
bool32 knl_is_temp_table_empty(knl_handle_t session, uint32 uid, uint32 oid);

status_t knl_open_external_cursor(knl_handle_t session, knl_cursor_t *cursor, knl_dictionary_t *dc);
void knl_close_temp_tables(knl_handle_t session, knl_dict_type_t type);
status_t knl_open_temp_cursor(knl_handle_t session, knl_cursor_t *cursor, knl_dictionary_t *dc);
status_t knl_init_temp_dc(knl_handle_t session);
void knl_release_temp_dc(knl_handle_t session);
status_t knl_create_ltt(knl_handle_t session, knl_table_def_t *def, bool32 *is_existed);
status_t knl_drop_ltt(knl_handle_t session, knl_drop_def_t *def);
status_t knl_create_ltt_index(knl_handle_t session, knl_index_def_t *def);
status_t knl_drop_ltt_index(knl_handle_t session, knl_drop_def_t *def);
status_t knl_ensure_temp_cache(knl_handle_t session, knl_handle_t dc_entity, knl_temp_cache_t **temp_table_ret);
status_t knl_ensure_temp_index(knl_handle_t session, knl_cursor_t *cursor,
    knl_dictionary_t *dc, knl_temp_cache_t *temp_table);
status_t knl_alloc_swap_extent(knl_handle_t se, page_id_t *extent);
void knl_release_swap_extent(knl_handle_t se, page_id_t extent);
status_t knl_read_swap_data(knl_handle_t se, page_id_t extent, uint32 cipher_len, char *data, uint32 size);
status_t knl_write_swap_data(knl_handle_t se, page_id_t extent, const char *data, uint32 p_size, uint32 *cipher_len);
uint32 knl_get_swap_extents(knl_handle_t se);

#ifdef __cplusplus
}
#endif

#endif

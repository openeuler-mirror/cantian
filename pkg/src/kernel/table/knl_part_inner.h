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
 * knl_part_inner.h
 *
 *
 * IDENTIFICATION
 * src/kernel/table/knl_part_inner.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef _KNL_PART_INNER_H_
#define _KNL_PART_INNER_H_

#include "cm_defs.h"
#include "cm_partkey.h"
#include "cm_latch.h"
#include "knl_common.h"
#include "knl_interface.h"
#include "knl_session.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_split_redistribute {
    knl_session_t *session;
    knl_cursor_t *cursor_delete;
    uint32 left_pno;
    part_table_t *part_table;
} split_redistribute_t;

status_t db_write_sys_tablepart(knl_session_t *session, knl_cursor_t *cursor, knl_table_desc_t *table_desc,
    knl_table_part_desc_t *desc);
status_t db_write_sys_indexpart(knl_session_t *session, knl_cursor_t *cursor, knl_index_part_desc_t *desc);
status_t part_write_sys_lobpart(knl_session_t *session, knl_cursor_t *cursor, knl_lob_part_desc_t *desc);
bool32 check_part_encrypt_allowed(knl_session_t *session, bool32 is_encrypt_table, uint32 space_id);
int32 part_compare_range_key(knl_part_column_desc_t *desc, part_decode_key_t *cmp_key, part_decode_key_t *range_key);
uint32 part_hash_value_combination(uint32 idx, unsigned int hashValue, variant_t *value, bool32 *is_type_ok,
    uint32 version);
void part_generate_index_part_desc(knl_session_t *session, knl_handle_t knl_index, knl_table_part_desc_t *part_desc,
                                   knl_index_part_desc_t *desc);
status_t part_write_shadowindex_part(knl_session_t *session, knl_dictionary_t *dc,
    index_part_t *index_part, bool32 create_segment);
void part_init_lob_part_desc(knl_session_t *session, knl_handle_t knl_desc, uint32 part_id, uint32 space_id,
    knl_lob_part_desc_t *desc);
status_t part_redis_move_part(knl_session_t *session, knl_cursor_t *cursor_delete, knl_dictionary_t *dc,
    knl_cursor_t *cursor_insert, bool32 is_parent);
status_t db_drop_part(knl_session_t *session, knl_dictionary_t *dc, table_part_t *table_part,
    bool32 add_or_coalesce);
uint32 part_locate_list_key(part_table_t *part_table, part_decode_key_t *decoder);
status_t part_lob_get_space_id(knl_session_t *session, lob_t *lob, knl_part_def_t *def,
    uint32 *space_id);
status_t part_init_table_part_desc(knl_session_t *session, table_t *table, knl_part_def_t *def,
    uint32 part_id, knl_table_part_desc_t *desc, bool32 not_ready);
void part_get_hash_key_variant(ct_type_t datatype, text_t *value, variant_t *variant_value, uint32 version);
uint32 part_generate_part_id(table_t *table, uint32 number);
status_t part_check_interval_valid(part_key_t *interval_key);
status_t part_write_sys_shadowindex_part(knl_session_t *session, knl_index_part_desc_t *desc);
uint32 part_locate_interval_key(part_table_t *part_table, part_decode_key_t *transition_decoder,
    part_decode_key_t *decoder);
status_t db_add_index_parts(knl_session_t *session, knl_dictionary_t *dc, table_t *table,
    knl_table_part_desc_t *part_desc);
int32 part_compare_range_key(knl_part_column_desc_t *desc, part_decode_key_t *cmp_key, part_decode_key_t *range_key);
status_t part_redis_get_subpartno(knl_session_t *session, knl_dictionary_t *dc, knl_cursor_t *cursor_delete,
    knl_cursor_t *cursor_insert);
status_t db_write_sys_tablesubpart(knl_session_t *session, knl_cursor_t *cursor, knl_table_part_desc_t *subpart_desc);
status_t subpart_lob_get_space_id(knl_session_t *session, lob_t *lob, knl_part_def_t *def, uint32 *space_id);
status_t subpart_write_syslob(knl_session_t *session, knl_lob_part_desc_t *desc);
status_t db_write_sys_indsubpart(knl_session_t *session, knl_cursor_t *cursor, knl_index_part_desc_t *desc);
status_t subpart_generate_part_key(row_head_t *row, uint16 *offsets, uint16 *lens, part_table_t *part_table,
    part_key_t *key);
uint32 subpart_generate_partid(part_table_t *part_table, table_part_t *compart, uint32 number);
status_t subpart_init_table_part_desc(knl_session_t *session, knl_table_part_desc_t *comdesc,
    knl_part_def_t *def, uint32 subpart_id, knl_table_part_desc_t *desc);
status_t db_update_subtabpart_count(knl_session_t *session, uint32 uid, uint32 tid, uint32 compart_id, bool32 is_add);
status_t db_add_index_subpart(knl_session_t *session, table_t *table, knl_table_part_desc_t *tab_desc);
status_t db_update_subidxpart_count(knl_session_t *session, knl_index_desc_t *desc, uint32 compart_id,
    bool32 is_add);
status_t part_clean_garbage_partition(knl_session_t *session, knl_dictionary_t *dc);
status_t subpart_clean_garbage_partition(knl_session_t *session, knl_dictionary_t *dc);
status_t db_update_part_name(knl_session_t *session, table_part_t *table_part, text_t *new_name);
status_t db_update_part_id(knl_session_t *session, knl_dictionary_t *dc, table_part_t *table_part, uint32 new_partid);
status_t subpart_delete_sub_idx_part(knl_session_t *session, knl_dictionary_t *dc, uint32 compart_no,
    uint32 subpart_no, bool32 reuse_storage);
status_t db_upd_idx_part_ids(knl_session_t *session, knl_cursor_t *cursor, table_part_t *table_part,
    knl_dictionary_t *dc, uint32 new_partid);

#ifdef __cplusplus
}
#endif

#endif


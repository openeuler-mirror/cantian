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
 * dc_part.h
 *
 *
 * IDENTIFICATION
 * src/kernel/catalog/dc_part.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DC_PART_H__
#define __DC_PART_H__

#include "knl_context.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t dc_get_table_part_desc(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity,
    uint32 partkeys, knl_table_part_desc_t *desc, bool32 is_reserved);
uint32 dc_cal_part_name_hash(text_t *name);
uint32 dc_cal_list_value_hash(const text_t *values, uint32 count);
status_t dc_decode_part_key_group(knl_session_t *session, dc_entity_t *entity, uint32 partkeys,
    part_key_t *key, part_decode_key_t **groups, uint32 *groupcnt);
uint32 dc_get_hash_bucket_count(uint32 pcnt);
uint32 dc_generate_interval_part_id(uint32 part_lno, uint32 transition_no);
status_t dc_load_interval_part(knl_session_t *session, knl_dictionary_t *dc, uint32 part_no);
status_t dc_alloc_index_part(knl_session_t *session, dc_entity_t *entity, part_index_t *part_index, uint32 id);
status_t dc_alloc_lob_part(knl_session_t *session, dc_entity_t *entity, part_lob_t *part_lob, uint32 id);
status_t dc_alloc_table_part(knl_session_t *session, dc_entity_t *entity, part_table_t *part_table, uint32 id);
status_t dc_load_table_part_segment(knl_session_t *session, knl_handle_t dc_entity, table_part_t *table_part);
status_t dc_load_index_part_segment(knl_session_t *session, knl_handle_t dc_entity, index_part_t *part);
void db_create_interval_update_desc(table_t *table, uint32 part_cnt);
void dc_load_all_part_segments(knl_session_t *session, knl_handle_t dc_entity);
void dc_part_convert_column_desc(knl_cursor_t *cursor, knl_part_column_desc_t *desc);
void dc_partno_sort(part_table_t *part_table);
void dc_partno_swap(uint32 *a, uint32 *b);
status_t part_convert_index_part_desc(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity,
    uint32 partkeys, knl_index_part_desc_t *desc);
void dc_load_lob_part_segment(knl_session_t *session, dc_entity_t *entity, lob_part_t *part, lob_t *lob);
void dc_set_index_part_valid(index_t *index, knl_index_part_desc_t desc);
status_t db_reserve_interval_dc_memory(knl_session_t *session, knl_dictionary_t *dc, uint32 part_no);

#ifdef __cplusplus
}
#endif

#endif

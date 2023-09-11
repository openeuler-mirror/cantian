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
 * dc_tbl.h
 *
 *
 * IDENTIFICATION
 * src/kernel/catalog/dc_tbl.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_DC_TBL_H__
#define __KNL_DC_TBL_H__

#include "knl_dc.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t dc_load_systables(knl_session_t *session, dc_context_t *ctx);
status_t dc_load_table(knl_session_t *session, knl_cursor_t *cursor, dc_user_t *user, uint32 oid,
                       dc_entity_t *entity);
status_t dc_load_columns(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity);
status_t dc_load_ddm(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity);
status_t dc_load_trigger_by_table_id(knl_session_t *session, uint32 obj_uid, uint64 base_obj,
                                     trig_set_t *trig_set);
status_t dc_load_indexes(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity);
status_t dc_load_lobs(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity);
status_t dc_load_cons(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity);
status_t dc_load_policies(knl_session_t *session, knl_cursor_t *cursor, dc_user_t *user,
    uint32 oid, dc_entity_t *entity);
status_t dc_load_view(knl_session_t *session, knl_cursor_t *cursor, dc_user_t *user, text_t *name,
                      dc_entity_t *entity);
status_t dc_load_entity(knl_session_t *session, dc_user_t *user, uint32 oid, dc_entry_t *entry);
status_t dc_load_view_entity(knl_session_t *session, dc_user_t *user, uint32 oid, dc_entity_t *entity);
status_t dc_load_table_entity(knl_session_t *session, dc_user_t *user, uint32 oid, dc_entity_t *entity);
status_t dc_load_distribute_rule(knl_session_t *session, dc_context_t *ctx);
status_t dc_open_table_or_view(knl_session_t *session, dc_user_t *user, dc_entry_t *entry, knl_dictionary_t *dc);
status_t dc_open_table_directly(knl_session_t *session, uint32 uid, uint32 oid, knl_dictionary_t *dc);
status_t dc_init_table_entries(knl_session_t *session, dc_context_t *ctx, uint32 uid);
status_t dc_init_view_entries(knl_session_t *session, dc_context_t *ctx, uint32 uid);
status_t dc_init_synonym_entries(knl_session_t *session, dc_context_t *ctx, uint32 uid);
status_t dc_create_synonym_entry(knl_session_t *session, dc_user_t *user, knl_synonym_t *synonym);
status_t dc_convert_distribute_rule_desc(knl_cursor_t *cursor, knl_table_desc_t *rule, dc_entity_t *entity,
    knl_session_t *session);
void dc_convert_column_list(uint32 col_count, text_t *column_list, uint16 *cols);
void dc_segment_recycle(dc_context_t *ctx, dc_entity_t *entity);
void dc_fk_indexable(knl_session_t *session, table_t *table, cons_dep_t *dep);
void estimate_row_len(table_t *table, knl_column_t *column);
void dc_release_segment_dls(knl_session_t *session, dc_entity_t *entity);
void drc_recycle_dls_res(knl_session_t *session, drid_t *lock_id);
#ifdef __cplusplus
}
#endif

#endif
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
 * dc_subpart.h
 *
 *
 * IDENTIFICATION
 * src/kernel/catalog/dc_subpart.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DC_SUBPART_H__
#define __DC_SUBPART_H__

#include "knl_context.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t dc_load_subpart_columns(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity);
status_t dc_alloc_subpart_table(knl_session_t *session, dc_entity_t *entity, part_table_t *part_table);
status_t dc_alloc_subpart_index(knl_session_t *session, dc_entity_t *entity, part_index_t *part_index);
status_t dc_alloc_table_subparts(knl_session_t *session, dc_entity_t *entity, table_part_t *compart);
status_t dc_load_table_subparts(knl_session_t *session, dc_entity_t *entity, knl_cursor_t *cursor);
table_part_t *dc_get_table_subpart(part_table_t* part_table, uint64 org_scn);
status_t dc_alloc_index_subparts(knl_session_t *session, dc_entity_t *entity, index_part_t *compart);
status_t dc_load_index_subparts(knl_session_t *session, knl_cursor_t *cursor, index_t *index);
status_t dc_load_shwidx_subparts(knl_session_t *session, knl_cursor_t *cursor, index_t *index);
status_t dc_load_lob_subparts(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity, lob_t *lob);
status_t dc_alloc_lob_subparts(knl_session_t *session, dc_entity_t *entity, lob_part_t *compart);
status_t dc_alloc_index_subpart(knl_session_t *session, dc_entity_t *entity, index_t *index, uint32 id);
status_t dc_alloc_lob_subpart(knl_session_t *session, dc_entity_t *entity, lob_t *lob, uint32 id);
status_t dc_alloc_table_subpart(knl_session_t *session, dc_entity_t *entity, uint32 id);
status_t dc_load_interval_index_subpart(knl_session_t *session, knl_cursor_t *cursor, index_t *index,
    index_part_t *compart_index, bool32 is_shadow);
status_t dc_load_interval_lob_subpart(knl_session_t *session, knl_dictionary_t *dc, knl_cursor_t *cursor,
    lob_t *lob, lob_part_t *compart_lob);
status_t dc_load_interval_table_subpart(knl_session_t *session, knl_dictionary_t *dc, knl_cursor_t *cursor,
    table_part_t *compart_tab);

#ifdef __cplusplus
}
#endif

#endif


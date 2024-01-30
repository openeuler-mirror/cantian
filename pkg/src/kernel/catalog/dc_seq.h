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
 * dc_seq.h
 *
 *
 * IDENTIFICATION
 * src/kernel/catalog/dc_seq.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_DC_SEQ_H__
#define __KNL_DC_SEQ_H__

#include "knl_dc.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline sequence_entry_t *dc_get_seq_entry(dc_user_t *user, uint32 id)
{
    sequence_entry_t *entry = NULL;
    sequence_group_t *group;

    group = user->sequence_set.groups[id / DC_GROUP_SIZE];
    if (group != NULL) {
        entry = group->entries[id % DC_GROUP_SIZE];
    }

    return entry;
}

#define DC_GET_SEQ_ENTRY                dc_get_seq_entry

status_t dc_alloc_seq_entry(knl_session_t *session, sequence_desc_t *desc);
void dc_sequence_drop(knl_session_t *session, sequence_entry_t *entry);
status_t dc_init_sequence_set(knl_session_t *session, dc_user_t *user);
void dc_convert_seq_desc(knl_cursor_t *cursor, sequence_desc_t *desc);
void dc_insert_into_seqindex(dc_user_t *user, sequence_entry_t *entry);
bool32 dc_seq_find(knl_session_t *session, dc_user_t *user, text_t *obj_name, knl_dictionary_t *dc);
status_t dc_create_sequence_entry(knl_session_t *session, dc_user_t *user, uint32 oid, sequence_entry_t **entry);

#ifdef __cplusplus
}
#endif

#endif
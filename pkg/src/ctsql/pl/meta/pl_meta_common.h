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
 * pl_meta_common.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/meta/pl_meta_common.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __PL_META_COMMON_H__
#define __PL_META_COMMON_H__

#include "pl_dc_util.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_pl_drop_def pl_drop_def_t;
struct st_pl_drop_def {
    var_udo_t obj;
    uint32 type;
    uint32 option;
};

status_t pl_load_sys_proc_desc(knl_session_t *session, pl_desc_t *desc);
status_t pl_fetch_obj_by_uid(knl_session_t *session, uint32 uid, pl_desc_t *desc, bool32 *found);
status_t pl_delete_sysproc_by_trig(knl_session_t *session, text_t *tab_user, text_t *tab_name, uint64 target_oid,
    uint32 *uid, bool32 *exists);
status_t pl_load_sysproc_source(knl_session_t *session, pl_desc_t *desc, pl_source_pages_t *source_page, text_t *source,
    bool32 *new_page);
status_t pl_delete_dependency(knl_session_t *session, object_address_t *obj_addr);
status_t pl_insert_dependency_list(knl_session_t *session, object_address_t *obj_addr, galist_t *ref_list);
status_t pl_update_depender_status(knl_session_t *session, object_address_t *obj_addr);
status_t pl_write_sys_proc(knl_session_t *knl_session, pl_desc_t *desc, pl_entity_t *entity);
status_t pl_delete_sys_proc(knl_session_t *session, uint64 oid, uint32 uid);
status_t pl_update_sys_proc_source(knl_session_t *session, pl_desc_t *desc, pl_entity_t *entity);
status_t pl_update_language(knl_session_t *session, pl_desc_t *desc, pl_entity_t *entity);
status_t pl_update_sysproc_status(knl_session_t *session, pl_desc_t *desc);
status_t pl_check_update_sysproc(knl_session_t *session, pl_desc_t *desc);

status_t pl_get_desc_objaddr(object_address_t *obj_addr, pl_desc_t *desc);
status_t pl_delete_obj_priv(knl_session_t *session, pl_entry_t *entry, object_type_t type);

#ifdef __cplusplus
}
#endif

#endif
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
 * pl_package.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/meta/pl_package.c
 *
 * -------------------------------------------------------------------------
 */
#include "pl_package.h"
#include "pl_meta_common.h"

#ifdef Z_SHARDING
status_t shd_pre_execute_ddl(sql_stmt_t *stmt, bool32 multi_ddl, bool32 need_encrypt);
status_t shd_trigger_check_for_rebalance(sql_stmt_t *stmt, text_t *user, text_t *tab);
#endif

status_t pl_load_entity_update_pack_def(knl_session_t *session, void *desc_in, void *entity_in)
{
    pl_desc_t *desc = (pl_desc_t *)desc_in;
    pl_entity_t *entity = (pl_entity_t *)entity_in;
    object_address_t obj_addr;
    pl_entry_t *entry = entity->entry;

    CT_RETURN_IFERR(pl_get_desc_objaddr(&obj_addr, desc));
    CT_RETURN_IFERR(pl_update_sysproc_status(session, desc));
    CT_RETURN_IFERR(pl_delete_sys_argument(session, &entry->desc));
    CT_RETURN_IFERR(pl_delete_dependency(session, &obj_addr));

    if (desc->status == OBJ_STATUS_VALID) {
        CT_RETURN_IFERR(pl_insert_package_proc_args(session, desc, entity));
        CT_RETURN_IFERR(pl_insert_dependency_list(session, &obj_addr, &entity->ref_list));
    }

    if (entry->desc.status == OBJ_STATUS_VALID && desc->status != OBJ_STATUS_VALID) {
        CT_RETURN_IFERR(pl_update_depender_status(session, &obj_addr));
    }

    return CT_SUCCESS;
}

status_t pl_load_entity_update_pack_body(knl_session_t *session, void *desc_in, void *entity_in)
{
    pl_desc_t *desc = (pl_desc_t *)desc_in;
    pl_entity_t *entity = (pl_entity_t *)entity_in;
    object_address_t obj_addr;

    CT_RETURN_IFERR(pl_get_desc_objaddr(&obj_addr, desc));
    CT_RETURN_IFERR(pl_update_sysproc_status(session, desc));
    CT_RETURN_IFERR(pl_delete_dependency(session, &obj_addr));

    if (desc->status == OBJ_STATUS_VALID) {
        CT_RETURN_IFERR(pl_insert_dependency_list(session, &obj_addr, &entity->ref_list));
    }

    return CT_SUCCESS;
}

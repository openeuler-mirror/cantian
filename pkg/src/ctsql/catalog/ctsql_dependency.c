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
 * ctsql_dependency.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/catalog/ctsql_dependency.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_dependency.h"
#include "cm_bilist.h"
#include "cm_rbtree.h"
#include "srv_instance.h"
#include "dml_executor.h"
#include "dml_parser.h"
#include "pl_meta_common.h"

const obj_status_table_t g_tab_obj_status = {
    .tab_id = SYS_TABLE_ID,
    .ind_id = 1,
    .status_col_id = SYS_TABLE_COL_FLAG,
    .oid_size = sizeof(uint32)
};
const obj_status_table_t g_view_obj_status = {
    .tab_id = SYS_VIEW_ID,
    .ind_id = 1,
    .status_col_id = SYS_VIEW_FLAG,
    .oid_size = sizeof(uint32)
};
const obj_status_table_t g_syn_obj_status = {
    .tab_id = SYS_SYN_ID,
    .ind_id = 1,
    .status_col_id = SYS_SYN_FLAG,
    .oid_size = sizeof(uint32)
};
const obj_status_table_t g_plm_obj_status = {
    .tab_id = SYS_PROC_ID,
    .ind_id = 2,
    .status_col_id = SYS_PROC_STATUS_COL,
    .oid_size = sizeof(int64)
};
/*
 * sql_append_references
 * append the src info to dest info list
 */
status_t sql_append_references(galist_t *dest, const sql_context_t *sql_ctx)
{
    uint32 i;
    object_address_t *ref = NULL;
    if (dest == NULL || sql_ctx == NULL || sql_ctx->ref_objects == NULL) {
        return CT_SUCCESS;
    }

    for (i = 0; i < sql_ctx->ref_objects->count; i++) {
        ref = (object_address_t *)cm_galist_get(sql_ctx->ref_objects, i);
        if (!sql_check_ref_exists(dest, ref)) {
            CT_RETURN_IFERR(cm_galist_copy_append(dest, sizeof(object_address_t), ref));
        }
    }
    return CT_SUCCESS;
}

status_t sql_get_object_status_core(knl_session_t *session, obj_info_t *obj, bool32 *is_found,
    object_status_t *obj_status, obj_status_table_t *sys_tab)
{
    knl_cursor_t *cursor = NULL;
    *is_found = CT_FALSE;
    CM_SAVE_STACK(session->stack);
    if (sql_push_knl_cursor(session, &cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }
    knl_set_session_scn(session, CT_INVALID_ID64);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, sys_tab->tab_id, sys_tab->ind_id);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&obj->uid,
        sizeof(uint32), 0);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&obj->oid,
        sys_tab->oid_size, 1);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (!cursor->eof) {
        *obj_status = *(uint32 *)CURSOR_COLUMN_DATA(cursor, sys_tab->status_col_id);
        *is_found = CT_TRUE;
    }
    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

status_t sql_get_object_status(knl_session_t *session, obj_info_t *obj, bool32 *is_found, object_status_t *obj_status)
{
    obj_status_table_t sys_table;
    switch (obj->tid) {
        case OBJ_TYPE_PROCEDURE:
        case OBJ_TYPE_FUNCTION:
        case OBJ_TYPE_TRIGGER:
        case OBJ_TYPE_PACKAGE_SPEC:
        case OBJ_TYPE_PACKAGE_BODY:
        case OBJ_TYPE_TYPE_SPEC:
        case OBJ_TYPE_TYPE_BODY:
            sys_table = g_plm_obj_status;
            break;

        case OBJ_TYPE_PL_SYNONYM:
        case OBJ_TYPE_SYNONYM:
            sys_table = g_syn_obj_status;
            break;

        case OBJ_TYPE_VIEW:
            sys_table = g_view_obj_status;
            break;
        case OBJ_TYPE_TABLE:
        case OBJ_TYPE_TABLE_PART:
            sys_table = g_tab_obj_status;
            break;

        default:
            return CT_SUCCESS;
    }

    return sql_get_object_status_core(session, obj, is_found, obj_status, &sys_table);
}

bool32 sql_check_ref_exists(galist_t *ref_objects, object_address_t *ref_obj)
{
    object_address_t *obj = NULL;
    uint32 i;

    if (ref_objects == NULL) {
        return CT_FALSE;
    }

    for (i = 0; i < ref_objects->count; i++) {
        obj = (object_address_t *)cm_galist_get(ref_objects, i);
        if (obj->uid == ref_obj->uid && obj->oid == ref_obj->oid && obj->tid == ref_obj->tid) {
            return CT_TRUE;
        }
    }

    return CT_FALSE;
}

status_t sql_append_reference_knl_dc(galist_t *dest, knl_dictionary_t *dc)
{
    object_address_t ref;
    dc_entry_t *dc_entry = NULL;
    dc_entity_t *entity = NULL;
    if (dc->is_sysnonym) {
        dc_entry = (dc_entry_t *)dc->syn_handle;
        ref.tid = OBJ_TYPE_SYNONYM;
        ref.oid = dc_entry->id;
        ref.uid = dc_entry->uid;
        ref.scn = dc->chg_scn;
        MEMS_RETURN_IFERR(strcpy_s(ref.name, CT_NAME_BUFFER_SIZE, dc_entry->name));
    } else {
        ref.tid = knl_get_object_type(dc->type);
        ref.oid = dc->oid;
        ref.uid = dc->uid;
        ref.scn = dc->chg_scn;
        entity = (dc_entity_t *)dc->handle;
        MEMS_RETURN_IFERR(strcpy_s(ref.name, CT_NAME_BUFFER_SIZE, entity->entry->name));
    }
    if (!sql_check_ref_exists(dest, &ref)) {
        return cm_galist_copy_append(dest, sizeof(object_address_t), &ref);
    }
    return CT_SUCCESS;
}

status_t sql_apend_dependency_table(sql_stmt_t *stmt, sql_table_t *sql_table)
{
    knl_dictionary_t *dc = &sql_table->entry->dc;
    if (stmt->context->ref_objects == NULL) { // only DML context will init
        return CT_SUCCESS;
    }
    return sql_append_reference_knl_dc(stmt->context->ref_objects, dc);
}

static status_t sql_update_pl_status(knl_session_t *session, const obj_info_t *obj, object_status_t obj_status)
{
    pl_entry_info_t entry_info;
    pl_desc_t desc;
    desc.uid = obj->uid;
    desc.oid = obj->oid;
    desc.type = pl_get_obj_type(obj->tid);
    desc.status = obj_status;

    pl_find_entry_by_oid(desc.oid, desc.type, &entry_info);
    if (entry_info.entry != NULL) {
        pl_update_entry_status(entry_info.entry, obj_status);
        pl_entity_invalidate_by_entry(entry_info.entry);
    }

    if (pl_check_update_sysproc(session, &desc) != CT_SUCCESS) {
        knl_rollback(session, NULL);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t sql_update_syn_status(knl_session_t *session, const obj_info_t *obj, object_status_t obj_status)
{
    row_assist_t ra;
    knl_update_info_t *ui = NULL;
    knl_cursor_t *cursor = NULL;
    status_t status;
    uint32 syn_oid = (uint32)obj->oid;

    CM_SAVE_STACK(session->stack);

    if (sql_push_knl_cursor(session, &cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    knl_set_session_scn(session, CT_INVALID_ID64);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_SYN_ID, 1);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&obj->uid,
        sizeof(uint32), 0);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&syn_oid,
        sizeof(uint32), 1);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        CT_THROW_ERROR(ERR_OBJECT_ID_NOT_EXIST, "synonym", syn_oid);
        return CT_ERROR;
    }

    if (cursor->eof) {
        status = CT_SUCCESS;
    } else {
        ui = &cursor->update_info;
        row_init(&ra, ui->data, CT_MAX_ROW_SIZE, 1);
        if (row_put_int32(&ra, obj_status) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
        ui->count = 1;
        ui->columns[0] = SYS_SYN_FLAG;
        cm_decode_row(ui->data, ui->offsets, ui->lens, NULL);

        status = knl_internal_update(session, cursor);
        if (status != CT_SUCCESS) {
            knl_rollback(session, NULL);
        }
    }

    CM_RESTORE_STACK(session->stack);
    return status;
}

static status_t sql_update_view_status(knl_session_t *session, const obj_info_t *obj, object_status_t obj_status)
{
    row_assist_t ra;
    knl_update_info_t *ui = NULL;
    knl_cursor_t *cursor = NULL;
    char *ptr = NULL;
    char name[CT_NAME_BUFFER_SIZE];
    uint32 length = 0;
    status_t status;
    knl_dictionary_t dc;
    knl_dict_type_t obj_type;
    text_t owner_name, object_name;
    uint32 view_oid = (uint32)obj->oid;

    CM_SAVE_STACK(session->stack);
    if (sql_push_knl_cursor(session, &cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (knl_get_user_name((knl_handle_t *)session, obj->uid, &owner_name) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    knl_set_session_scn(session, CT_INVALID_ID64);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_VIEW_ID, 1);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&obj->uid,
        sizeof(uint32), 0);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&view_oid,
        sizeof(uint32), 1);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        return CT_SUCCESS;
    } else {
        ptr = CURSOR_COLUMN_DATA(cursor, SYS_VIEW_NAME);
        length = CURSOR_COLUMN_SIZE(cursor, SYS_VIEW_NAME);
        if (length < CT_NAME_BUFFER_SIZE) {
            errno_t errcode = memcpy_s(name, CT_NAME_BUFFER_SIZE, ptr, length);
            if (errcode != EOK) {
                CM_RESTORE_STACK(session->stack);
                CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
                return CT_ERROR;
            }
            name[length] = '\0';
        } else {
            CT_THROW_ERROR(ERR_NAME_TOO_LONG, "object", length, CT_NAME_BUFFER_SIZE);
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }

        ui = &cursor->update_info;
        row_init(&ra, ui->data, CT_MAX_ROW_SIZE, 1);
        if (row_put_int32(&ra, obj_status) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
        ui->count = 1;
        ui->columns[0] = SYS_VIEW_FLAG;
        cm_decode_row(ui->data, ui->offsets, ui->lens, NULL);

        status = knl_internal_update(session, cursor);
        if (status != CT_SUCCESS) {
            knl_rollback(session, NULL);
        }
    }

    /* free the current entry and dc */
    if (status == CT_SUCCESS && obj_status != OBJ_STATUS_VALID) {
        object_name.str = name;
        object_name.len = length;
        if (!dc_object_exists((knl_session_t *)session, &owner_name, &object_name, &obj_type)) {
            CM_RESTORE_STACK(session->stack);
            return CT_SUCCESS;
        }
        if (dc_open(session, &owner_name, &object_name, &dc) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
        if (SYNONYM_EXIST(&dc) || dc.type != DICT_TYPE_VIEW) {
            CT_THROW_ERROR(ERR_USER_OBJECT_NOT_EXISTS, "view", T2S(&owner_name), T2S_EX(&object_name));
            dc_close(&dc);
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }

        dc_invalidate(session, DC_ENTITY(&dc));
        dc_close(&dc);
    }

    CM_RESTORE_STACK(session->stack);
    return status;
}

/*
* sql_update_object_status

* This function is used to update the object status.
* If the object status is updated to invalid or unknown, the knl_dictionary entry will be invalid
*/
status_t sql_update_object_status(knl_session_t *session, const obj_info_t *obj, object_status_t obj_status)
{
    status_t status = CT_SUCCESS;

    if (obj == NULL) {
        CT_THROW_ERROR(ERR_OBJECT_NOT_EXISTS, "updated", "object");
        return CT_ERROR;
    }

    /* procedure,function, trigger */
    switch (obj->tid) {
        case OBJ_TYPE_PROCEDURE:
        case OBJ_TYPE_FUNCTION:
        case OBJ_TYPE_TRIGGER:
        case OBJ_TYPE_PACKAGE_SPEC:
        case OBJ_TYPE_PACKAGE_BODY:
        case OBJ_TYPE_TYPE_SPEC:
        case OBJ_TYPE_TYPE_BODY:
            status = sql_update_pl_status(session, obj, obj_status);
            break;

        case OBJ_TYPE_PL_SYNONYM:
        case OBJ_TYPE_SYNONYM:
            status = sql_update_syn_status(session, obj, obj_status);
            break;

        case OBJ_TYPE_VIEW:
            status = sql_update_view_status(session, obj, obj_status);
            break;

        default:
            break;
    }

    return status;
}


#define OPEN_DEPS_CURSOR(session, cursor, obj)                                                                         \
    do {                                                                                                               \
        knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_DEPENDENCY_ID, IX_DEPENDENCY2_ID);              \
        knl_init_index_scan(cursor, CT_TRUE);                                                                          \
        knl_set_scan_key(INDEX_DESC((cursor)->index), &(cursor)->scan_range.l_key, CT_TYPE_INTEGER,                    \
            (void *)&(obj).uid, sizeof(uint32), IX_COL_DEPENDENCY2_P_OWNER_ID);                                        \
        knl_set_scan_key(INDEX_DESC((cursor)->index), &(cursor)->scan_range.l_key, CT_TYPE_BIGINT, (void *)&(obj).oid, \
            sizeof(int64), IX_COL_DEPENDENCY2_P_OBJ_ID);                                                               \
        knl_set_scan_key(INDEX_DESC((cursor)->index), &(cursor)->scan_range.l_key, CT_TYPE_INTEGER,                    \
            (void *)&(obj).tid, sizeof(uint32), IX_COL_DEPENDENCY2_P_TYPE_ID);                                         \
    } while (0)

#define DEPS_CURSOR_GET_OBJ(cursor, obj)                                              \
    do {                                                                              \
        (obj)->uid = *(uint32 *)CURSOR_COLUMN_DATA((cursor), SYS_DEPENDENCY_D_OWNER); \
        (obj)->oid = *(int64 *)CURSOR_COLUMN_DATA((cursor), SYS_DEPENDENCY_D_OBJ);    \
        (obj)->tid = *(uint32 *)CURSOR_COLUMN_DATA((cursor), SYS_DEPENDENCY_D_TYPE);  \
    } while (0);


static status_t sql_dep_check_upgrade(knl_session_t *session, bool32 *is_upgrade)
{
    dc_entry_t *entry = NULL;
    dc_user_t *sys_user = NULL;

    /* check dependency$ has loaded or not */
    if (DB_IS_UPGRADE(session)) {
        CT_RETURN_IFERR(dc_open_user_by_id(session, DB_SYS_USER_ID, &sys_user));
        entry = DC_GET_ENTRY(sys_user, SYS_DEPENDENCY_ID);
        if (entry == NULL || entry->entity == NULL) {
            *is_upgrade = CT_TRUE;
            return CT_SUCCESS;
        }
    }
    *is_upgrade = CT_FALSE;
    return CT_SUCCESS;
}


typedef struct st_obj_node_t {
    rb_node_t rb_node; // must be first
    bilist_node_t list_node;
    obj_info_t obj_addr;
} obj_node_t;


static status_t sql_update_deps_status(knl_session_t *session, rb_tree_t *dep_tree)
{
    rb_node_t *node = NULL;
    obj_node_t *obj_node = NULL;

    RB_TREE_SCAN(dep_tree, node)
    {
        obj_node = RBTREE_NODE_OF(obj_node_t, node, rb_node);
        if (!knl_chk_user_status((knl_handle_t *)session, obj_node->obj_addr.uid)) {
            continue;
        }
        if (sql_update_object_status(session, &obj_node->obj_addr, OBJ_STATUS_UNKONWN) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}


void sql_dep_free_func(void *ptr)
{
    BUDDY_FREE_PTR(ptr);
}

int sql_dep_cmp_func(rb_node_t *left, rb_node_t *right)
{
    obj_info_t obj_left = ((obj_node_t *)left)->obj_addr;
    obj_info_t obj_right = ((obj_node_t *)right)->obj_addr;

    if (obj_left.uid > obj_right.uid) {
        return 1;
    } else if (obj_left.uid < obj_right.uid) {
        return -1;
    }

    if (obj_left.tid > obj_right.tid) {
        return 1;
    } else if (obj_left.tid < obj_right.tid) {
        return -1;
    }

    if (obj_left.oid > obj_right.oid) {
        return 1;
    } else if (obj_left.oid < obj_right.oid) {
        return -1;
    }

    return 0;
}


#define SQL_DEP_FREE(rb_tree, session)                   \
    do {                                                 \
        cm_rbtree_free_tree(rb_tree, sql_dep_free_func); \
        CM_RESTORE_STACK((session)->stack);              \
    } while (0)

#define IS_SAME_OBJ(obj1, obj2) ((obj1).uid == (obj2).uid && (obj1).oid == (obj2).oid && (obj1).tid == (obj2).tid)


status_t sql_dep_trace_obj(knl_session_t *session, knl_cursor_t *cursor, rb_tree_t *dep_tree, bilist_t *trace_list,
    obj_info_t first_node)
{
    obj_info_t obj_buf;
    obj_node_t key_node;
    object_status_t obj_status;
    rb_node_t *res_node = NULL;
    obj_node_t *new_node = NULL;
    bool32 is_found = CT_FALSE;

    do {
        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (cursor->eof) {
            break;
        }
        DEPS_CURSOR_GET_OBJ(cursor, &obj_buf);

        if (!knl_chk_user_status((knl_handle_t *)session, obj_buf.uid)) {
            continue;
        }

        if (IS_SAME_OBJ(obj_buf, first_node)) {
            continue;
        }

        key_node.obj_addr = obj_buf;
        res_node = cm_rbtree_search_node(dep_tree, &(key_node.rb_node));
        if (res_node != NULL) {
            continue;
        }

        if (sql_get_object_status(session, &obj_buf, &is_found, &obj_status) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (!is_found || obj_status != OBJ_STATUS_VALID) {
            continue;
        }

        new_node = (obj_node_t *)galloc(buddy_mem_pool, sizeof(obj_node_t));
        if (new_node == NULL) {
            CT_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(obj_node_t), "dependency");
            return CT_ERROR;
        }

        new_node->obj_addr = obj_buf;

        if (cm_rbtree_insert_node(dep_tree, &new_node->rb_node) != CT_SUCCESS) {
            BUDDY_FREE_PTR(new_node);
            return CT_ERROR;
        }
        cm_bilist_add_tail(&new_node->list_node, trace_list);
    } while (CT_TRUE);
    return CT_SUCCESS;
}

/*
 * sql_update_depender_status
 *
 * This function is used to update the status of depender objects to unknown.
 */
status_t sql_update_depender_status(knl_handle_t sess, obj_info_t *obj)
{
    status_t status;
    obj_info_t obj_addr;
    rb_tree_t dep_tree;
    bilist_t trace_list;
    knl_cursor_t *cursor = NULL;
    obj_node_t *obj_node = NULL;
    obj_node_t *first_node = NULL;
    bilist_node_t *node = NULL;
    bool32 is_upgrade = CT_FALSE;
    knl_session_t *session = (knl_session_t *)sess;

    CT_RETURN_IFERR(sql_dep_check_upgrade(session, &is_upgrade));
    if (is_upgrade) {
        return CT_SUCCESS;
    }

    CM_SAVE_STACK(session->stack);
    cm_bilist_init(&trace_list);
    cm_rbtree_init(&dep_tree, sql_dep_cmp_func);

    if (sql_push_knl_cursor(session, &cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }

    first_node = (obj_node_t *)galloc(buddy_mem_pool, sizeof(obj_node_t));
    if (first_node == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(obj_node_t), "dependency");
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }
    first_node->obj_addr = *obj;
    cm_bilist_add_tail(&first_node->list_node, &trace_list);

    while (!cm_bilist_empty(&trace_list)) {
        node = cm_bilist_remove_tail(&trace_list);
        obj_node = BILIST_NODE_OF(obj_node_t, node, list_node);
        obj_addr = obj_node->obj_addr;
        OPEN_DEPS_CURSOR(session, cursor, obj_addr);

        if (sql_dep_trace_obj(session, cursor, &dep_tree, &trace_list, *obj) != CT_SUCCESS) {
            BUDDY_FREE_PTR(first_node);
            SQL_DEP_FREE(&dep_tree, session);
            return CT_ERROR;
        }
        knl_close_cursor(session, cursor);
    }

    status = sql_update_deps_status(session, &dep_tree);
    BUDDY_FREE_PTR(first_node);
    SQL_DEP_FREE(&dep_tree, session);
    return status;
}

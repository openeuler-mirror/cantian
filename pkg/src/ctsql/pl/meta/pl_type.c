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
 * pl_type.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/meta/pl_type.c
 *
 * -------------------------------------------------------------------------
 */
#include "pl_type.h"
#include "srv_instance.h"
#include "pl_meta_common.h"

#ifdef Z_SHARDING
status_t shd_pre_execute_ddl(sql_stmt_t *stmt, bool32 multi_ddl, bool32 need_encrypt);
status_t shd_trigger_check_for_rebalance(sql_stmt_t *stmt, text_t *user, text_t *tab);
#endif

status_t pl_check_type_dependency(sql_stmt_t *stmt, obj_info_t *obj_addr, bool32 *in_table, bool32 *in_other_type)
{
    knl_session_t *session = &stmt->session->knl_session;
    knl_cursor_t *cursor = NULL;
    dc_user_t *sys_user = NULL;
    dc_entry_t *entry = NULL;
    bool32 sub_in_table = CT_FALSE;
    bool32 sub_in_other_type = CT_FALSE;
    obj_info_t sub_obj_addr;

    *in_table = CT_FALSE;
    *in_other_type = CT_FALSE;

    /* check SYS_DEPENDENCIES has loaded or not */
    if (DB_IS_UPGRADE(session)) {
        CT_RETURN_IFERR(dc_open_user_by_id(session, DB_SYS_USER_ID, &sys_user));
        entry = DC_GET_ENTRY(sys_user, SYS_DEPENDENCY_ID);
        if (entry == NULL || entry->entity == NULL) {
            return CT_SUCCESS;
        }
    }

    CM_SAVE_STACK(session->stack);

    if (sql_push_knl_cursor(session, &cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_DEPENDENCY_ID, IX_DEPENDENCY2_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&obj_addr->uid,
        sizeof(uint32), 0);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_BIGINT, (void *)&obj_addr->oid,
        sizeof(int64), 1);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&obj_addr->tid,
        sizeof(int32), 2);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    while (!cursor->eof) {
        sub_obj_addr.uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_DEPENDENCY_D_OWNER);
        sub_obj_addr.oid = *(uint64 *)CURSOR_COLUMN_DATA(cursor, SYS_DEPENDENCY_D_OBJ);
        sub_obj_addr.tid = *(int32 *)CURSOR_COLUMN_DATA(cursor, SYS_DEPENDENCY_D_TYPE);
        if (sub_obj_addr.tid == OBJ_TYPE_TABLE) {
            *in_table = CT_TRUE;
            CM_RESTORE_STACK(session->stack);
            return CT_SUCCESS;
        } else if (sub_obj_addr.tid == OBJ_TYPE_TYPE_SPEC) {
            *in_other_type = CT_TRUE;
            if (pl_check_type_dependency(stmt, &sub_obj_addr, &sub_in_table, &sub_in_other_type) != CT_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return CT_ERROR;
            }
            if (sub_in_table) {
                *in_table = CT_TRUE;
                CM_RESTORE_STACK(session->stack);
                return CT_SUCCESS;
            }
        }

        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);

    return CT_SUCCESS;
}


status_t pl_get_type_name(sql_stmt_t *stmt, expr_tree_t *arg, var_udo_t *obj)
{
    func_word_t *func = &arg->root->word.func;
    obj->pack = CM_NULL_TEXT;
    obj->pack_sensitive = CT_FALSE;
    obj->name_sensitive = (IS_CASE_INSENSITIVE) ? CT_TRUE : CT_FALSE;
    if (func->args.len > 0) {
        text_t user;
        user.str = func->name.str;
        user.len = func->name.len;
        CT_RETURN_IFERR(sql_copy_prefix_tenant(stmt, &user, &obj->user, sql_copy_text));
        obj->name = func->args.value;
        if (obj->name_sensitive) {
            cm_str_upper(obj->name.str);
        }
        obj->user_explicit = CT_TRUE;
    } else {
        obj->user.str = stmt->session->curr_schema;
        obj->user.len = (uint32)strlen(stmt->session->curr_schema);
        obj->name = func->name.value;
        obj->user_explicit = CT_FALSE;
    }

    return CT_SUCCESS;
}

static inline char *plm_get_type_code_str(plv_type_t type)
{
    switch (type) {
        case PLV_OBJECT:
            return "OBJECT";
        case PLV_COLLECTION:
        default:
            return "COLLECTION";
    }
}


status_t pl_init_sys_types(knl_session_t *knl_session, void *desc_in)
{
    row_assist_t ra;
    knl_cursor_t *cursor = NULL;
    status_t status = CT_ERROR;
    uint32 column_count;
    pl_desc_t *desc = (pl_desc_t *)desc_in;

    CM_SAVE_STACK(knl_session->stack);

    do {
        CT_BREAK_IF_ERROR(sql_push_knl_cursor(knl_session, &cursor));

        knl_set_session_scn(knl_session, CT_INVALID_ID64);
        knl_open_sys_cursor(knl_session, cursor, CURSOR_ACTION_INSERT, SYS_TYPE_ID, CT_INVALID_ID32);
        column_count = knl_get_column_count(cursor->dc_entity);

        row_init(&ra, cursor->buf, g_instance->kernel.attr.max_row_size, column_count);

        CT_BREAK_IF_ERROR(row_put_int32(&ra, desc->uid));                       // UID
        CT_BREAK_IF_ERROR(row_put_int64(&ra, desc->oid));                       // TYPE_OID
        CT_BREAK_IF_ERROR(row_put_str(&ra, desc->name));                        // TYPE_NAME
        CT_BREAK_IF_ERROR(row_put_str(&ra, plm_get_type_code_str(PLV_OBJECT))); // TYPE_CODE
        CT_BREAK_IF_ERROR(row_put_int32(&ra, 0));                               // ATTRIBUTES
        CT_BREAK_IF_ERROR(row_put_int32(&ra, 0));                               // METHODS
        CT_BREAK_IF_ERROR(row_put_int32(&ra, 0));                               // PREDEFINED
        CT_BREAK_IF_ERROR(row_put_int32(&ra, 1));                               // INCOMPLETE
        CT_BREAK_IF_ERROR(row_put_int32(&ra, 1));                               // FINAL
        CT_BREAK_IF_ERROR(row_put_int32(&ra, 1));                               // INSTANTIABLE
        CT_BREAK_IF_ERROR(row_put_null(&ra));                                   // SUPERTYPE_UID
        CT_BREAK_IF_ERROR(row_put_null(&ra));                                   // SUPERTYPE_OID
        CT_BREAK_IF_ERROR(row_put_null(&ra));                                   // SUPERTYPE_NAME
        CT_BREAK_IF_ERROR(row_put_null(&ra));                                   // LOCAL_ATTRIBUTES
        CT_BREAK_IF_ERROR(row_put_null(&ra));                                   // LOCAL_METHODS
        CT_BREAK_IF_ERROR(row_put_int64(&ra, desc->org_scn));                   // ORG_SCN
        CT_BREAK_IF_ERROR(row_put_int64(&ra, desc->chg_scn));                   // CHG_SCN

        CT_BREAK_IF_ERROR(knl_internal_insert(knl_session, cursor));

        status = CT_SUCCESS;
    } while (0);

    CM_RESTORE_STACK(knl_session->stack);

    return status;
}

status_t pl_write_sys_types(knl_session_t *knl_session, type_spec_t *type_spec, void *desc_in)
{
    row_assist_t ra;
    knl_cursor_t *cursor = NULL;
    status_t status = CT_ERROR;
    uint32 column_count;
    pl_desc_t *desc = (pl_desc_t *)desc_in;
    udt_desc_t *udt_desc = &type_spec->desc;
    type_spec_t *super_type = type_spec->super_type;

    CM_SAVE_STACK(knl_session->stack);

    do {
        CT_BREAK_IF_ERROR(sql_push_knl_cursor(knl_session, &cursor));

        knl_set_session_scn(knl_session, CT_INVALID_ID64);
        knl_open_sys_cursor(knl_session, cursor, CURSOR_ACTION_INSERT, SYS_TYPE_ID, CT_INVALID_ID32);
        column_count = knl_get_column_count(cursor->dc_entity);

        row_init(&ra, cursor->buf, g_instance->kernel.attr.max_row_size, column_count);

        CT_BREAK_IF_ERROR(row_put_int32(&ra, desc->uid));                                // UID
        CT_BREAK_IF_ERROR(row_put_int64(&ra, desc->oid));                                // TYPE_OID
        CT_BREAK_IF_ERROR(row_put_str(&ra, desc->name));                                 // TYPE_NAME
        CT_BREAK_IF_ERROR(row_put_str(&ra, plm_get_type_code_str(udt_desc->type_code))); // TYPE_CODE
        CT_BREAK_IF_ERROR(row_put_int32(&ra, udt_desc->attributes));                     // ATTRIBUTES
        CT_BREAK_IF_ERROR(row_put_int32(&ra, udt_desc->methods));                        // METHODS
        CT_BREAK_IF_ERROR(row_put_int32(&ra, 0));                                        // PREDEFINED
        CT_BREAK_IF_ERROR(row_put_int32(&ra, 0));                                        // INCOMPLETE

        if (PL_IS_FINAL(udt_desc->inherit_flag)) {
            CT_BREAK_IF_ERROR(row_put_int32(&ra, 1)); // FINAL
        } else {
            CT_BREAK_IF_ERROR(row_put_int32(&ra, 0)); // FINAL
        }

        if (PL_IS_INSTANTIABLE(udt_desc->inherit_flag)) {
            CT_BREAK_IF_ERROR(row_put_int32(&ra, 1)); // INSTANTIABLE
        } else {
            CT_BREAK_IF_ERROR(row_put_int32(&ra, 0)); // INSTANTIABLE
        }

        if (super_type != NULL) {
            udt_desc_t super_desc = super_type->desc;
            CT_BREAK_IF_ERROR(row_put_int32(&ra, super_type->desc.uid));                         // SUPERTYPE_UID
            CT_BREAK_IF_ERROR(row_put_int64(&ra, super_type->desc.oid));                         // SUPERTYPE_OID
            CT_BREAK_IF_ERROR(row_put_str(&ra, super_type->desc.name));                          // SUPERTYPE_NAME
            CT_BREAK_IF_ERROR(row_put_int32(&ra, udt_desc->attributes - super_desc.attributes)); // LOCAL_ATTRIBUTES
            CT_BREAK_IF_ERROR(row_put_int32(&ra, udt_desc->methods - super_desc.methods));       // LOCAL_METHODS
        } else {
            CT_BREAK_IF_ERROR(row_put_null(&ra));                        // SUPERTYPE_UID
            CT_BREAK_IF_ERROR(row_put_null(&ra));                        // SUPERTYPE_OID
            CT_BREAK_IF_ERROR(row_put_null(&ra));                        // SUPERTYPE_NAME
            CT_BREAK_IF_ERROR(row_put_int32(&ra, udt_desc->attributes)); // LOCAL_ATTRIBUTES
            CT_BREAK_IF_ERROR(row_put_int32(&ra, udt_desc->methods));    // LOCAL_METHODS
        }

        CT_BREAK_IF_ERROR(row_put_int64(&ra, desc->org_scn)); // ORG_SCN
        CT_BREAK_IF_ERROR(row_put_int64(&ra, desc->chg_scn)); // CHG_SCN

        CT_BREAK_IF_ERROR(knl_internal_insert(knl_session, cursor));

        status = CT_SUCCESS;
    } while (0);

    CM_RESTORE_STACK(knl_session->stack);
    return status;
}

status_t pl_delete_sys_types(knl_session_t *session, uint32 uid, uint64 oid)
{
    knl_cursor_t *cursor = NULL;
    status_t status = CT_ERROR;

    knl_set_session_scn(session, CT_INVALID_ID64);

    CM_SAVE_STACK(session->stack);

    do {
        CT_BREAK_IF_ERROR(sql_push_knl_cursor(session, &cursor));

        knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_TYPE_ID, IX_TYPE_001_ID);
        knl_init_index_scan(cursor, CT_TRUE);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &uid, sizeof(int32), 0);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_BIGINT, &oid, sizeof(int64), 1);

        CT_BREAK_IF_ERROR(knl_fetch(session, cursor));

        while (!cursor->eof) {
            CT_BREAK_IF_ERROR(knl_internal_delete(session, cursor));

            CT_BREAK_IF_ERROR(knl_fetch(session, cursor));
        }
        if (cursor->eof) {
            status = CT_SUCCESS;
        }
    } while (0);

    CM_RESTORE_STACK(session->stack);

    return status;
}

static status_t pl_type_attrs_row_prepare(pl_desc_t *desc, plv_object_attr_t *attr, bool32 is_inherit, row_assist_t *ra)
{
    char buf[CT_NAME_BUFFER_SIZE];
    CT_RETURN_IFERR(row_put_int32(ra, (int32)desc->uid));          // UID
    CT_RETURN_IFERR(row_put_int64(ra, desc->oid));                 // TYPE_OID
    CT_RETURN_IFERR(row_put_str(ra, desc->name));                  // TYPE_NAME
    CT_RETURN_IFERR(row_put_text(ra, &attr->name));                // ATTR_NAME
    CT_RETURN_IFERR(row_put_int32(ra, (int32)attr->field_id + 1)); // ATTR_NO
    CT_RETURN_IFERR(row_put_null(ra));                             // ATTR_TYPE_MOD

    if (attr->type != UDT_SCALAR) {
        void *attr_root = (attr->type == UDT_OBJECT) ? UDT_GET_TYPE_DEF_OBJECT(attr->udt_field)->root :
                                                       UDT_GET_TYPE_DEF_COLLECTION(attr->udt_field)->root;
        pl_entry_t *attr_entry = ((pl_entity_t *)attr_root)->entry;
        CT_RETURN_IFERR(row_put_int32(ra, attr_entry->desc.uid)); // ATTR_TYPE_UID
        CT_RETURN_IFERR(row_put_str(ra, attr_entry->desc.name));  // ATTR_TYPE_NAME
        CT_RETURN_IFERR(row_put_null(ra));                        // ATTR_TYPE
        CT_RETURN_IFERR(row_put_null(ra));                        // LENGTH
        CT_RETURN_IFERR(row_put_null(ra));                        // PRECISION
        CT_RETURN_IFERR(row_put_null(ra));                        // SCALE
        CT_RETURN_IFERR(row_put_null(ra));                        // CHAR_SET
    } else {
        CT_RETURN_IFERR(row_put_null(ra)); // ATTR_TYPE_UID
        ct_type_t datatype = attr->scalar_field->type_mode.datatype;
        CT_RETURN_IFERR(cm_text2str(get_datatype_name(datatype), buf, CT_NAME_BUFFER_SIZE));
        CT_RETURN_IFERR(row_put_str(ra, buf)); // ATTR_TYPE_NAME
        CT_RETURN_IFERR(row_put_null(ra));     // ATTR_TYPE
        if (CT_IS_VARLEN_TYPE(datatype)) {
            CT_RETURN_IFERR(row_put_int32(ra, (int32)attr->scalar_field->type_mode.size)); // LENGTH
            CT_RETURN_IFERR(row_put_null(ra));                                             // PRECISION
            CT_RETURN_IFERR(row_put_null(ra));                                             // SCALE
        } else if (CT_IS_NUMERIC_TYPE(datatype) || CT_IS_DATETIME_TYPE(datatype)) {
            CT_RETURN_IFERR(row_put_null(ra));                                                  // LENGTH
            CT_RETURN_IFERR(row_put_int32(ra, (int32)attr->scalar_field->type_mode.precision)); // PRECISION
            CT_RETURN_IFERR(row_put_int32(ra, (int32)attr->scalar_field->type_mode.scale));     // SCALE
        } else {
            CT_RETURN_IFERR(row_put_null(ra)); // PRECISION
            CT_RETURN_IFERR(row_put_null(ra)); // SCALE
            CT_RETURN_IFERR(row_put_null(ra)); // CHAR_SET
        }
        if (CT_IS_STRING_TYPE(datatype)) {
            CT_RETURN_IFERR(row_put_int32(ra, (int32)attr->scalar_field->type_mode.charset)); // CHAR_SET
        } else {
            CT_RETURN_IFERR(row_put_null(ra)); // CHAR_SET
        }
    }

    CT_RETURN_IFERR(row_put_int32(ra, (int32)is_inherit)); // INHERITED
    return CT_SUCCESS;
}


status_t pl_write_sys_type_attrs(knl_session_t *knl_session, type_spec_t *type, void *desc_in)
{
    row_assist_t ra;
    knl_cursor_t *cursor = NULL;
    uint32 column_count;
    pl_desc_t *desc = (pl_desc_t *)desc_in;
    plv_object_t *object = &type->decl->typdef.object;
    bool32 is_inherit;
    type_spec_t *super_type = type->super_type;
    int32 super_attrs_count = (super_type == NULL) ? 0 : super_type->desc.attributes;

    CM_SAVE_STACK(knl_session->stack);

    if (sql_push_knl_cursor(knl_session, &cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(knl_session->stack);
        return CT_ERROR;
    }

    knl_set_session_scn(knl_session, CT_INVALID_ID64);
    knl_open_sys_cursor(knl_session, cursor, CURSOR_ACTION_INSERT, SYS_TYPE_ATTR_ID, CT_INVALID_ID32);

    for (uint16 i = 0; i < object->count; i++) {
        plv_object_attr_t *attr = udt_seek_obj_field_byid(object, i);
        column_count = knl_get_column_count(cursor->dc_entity);
        row_init(&ra, cursor->buf, g_instance->kernel.attr.max_row_size, column_count);
        is_inherit = (attr->field_id < super_attrs_count) ? CT_TRUE : CT_FALSE;
        if (pl_type_attrs_row_prepare(desc, attr, is_inherit, &ra) != CT_SUCCESS) {
            CM_RESTORE_STACK(knl_session->stack);
            return CT_ERROR;
        }
        if (knl_internal_insert(knl_session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(knl_session->stack);
            return CT_ERROR;
        }
    }

    CM_RESTORE_STACK(knl_session->stack);
    return CT_SUCCESS;
}


status_t pl_delete_sys_type_attrs(knl_session_t *session, uint32 uid, uint64 oid)
{
    knl_cursor_t *cursor = NULL;
    status_t status = CT_ERROR;

    knl_set_session_scn(session, CT_INVALID_ID64);

    CM_SAVE_STACK(session->stack);

    do {
        CT_BREAK_IF_ERROR(sql_push_knl_cursor(session, &cursor));

        knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_TYPE_ATTR_ID, IX_TYPE_ATTR_001_ID);
        knl_init_index_scan(cursor, CT_FALSE);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &uid, sizeof(int32), 0);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_BIGINT, &oid, sizeof(int64), 1);
        knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, 2);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, &uid, sizeof(int32), 0);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_BIGINT, &oid, sizeof(int64), 1);
        knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, 2);

        CT_BREAK_IF_ERROR(knl_fetch(session, cursor));

        while (!cursor->eof) {
            CT_BREAK_IF_ERROR(knl_internal_delete(session, cursor));

            CT_BREAK_IF_ERROR(knl_fetch(session, cursor));
        }
        if (cursor->eof) {
            status = CT_SUCCESS;
        }
    } while (0);

    CM_RESTORE_STACK(session->stack);

    return status;
}

status_t pl_delete_sys_type_methods(knl_session_t *session, uint32 uid, uint64 oid)
{
    knl_cursor_t *cursor = NULL;
    status_t status = CT_ERROR;

    knl_set_session_scn(session, CT_INVALID_ID64);

    CM_SAVE_STACK(session->stack);

    do {
        CT_BREAK_IF_ERROR(sql_push_knl_cursor(session, &cursor));

        knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_TYPE_METHOD_ID, IX_TYPE_METHOD_001_ID);
        knl_init_index_scan(cursor, CT_FALSE);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &uid, sizeof(int32), 0);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_BIGINT, &oid, sizeof(int64), 1);
        knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, 2);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, &uid, sizeof(int32), 0);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_BIGINT, &oid, sizeof(int64), 1);
        knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, 2);

        CT_BREAK_IF_ERROR(knl_fetch(session, cursor));

        while (!cursor->eof) {
            CT_BREAK_IF_ERROR(knl_internal_delete(session, cursor));

            CT_BREAK_IF_ERROR(knl_fetch(session, cursor));
        }
        if (cursor->eof) {
            status = CT_SUCCESS;
        }
    } while (0);

    CM_RESTORE_STACK(session->stack);

    return status;
}


status_t pl_coll_types_row_prepare_scalar(row_assist_t *ra, plv_collection_t *coll_meta)
{
    ct_type_t datatype = coll_meta->type_mode.datatype;
    const char *datetype_name = get_datatype_name_str(datatype);
    CT_RETURN_IFERR(row_put_null(ra));               // ELEM_TYPE_UID
    CT_RETURN_IFERR(row_put_str(ra, datetype_name)); // ELEM_TYPE_NAME
    if (CT_IS_VARLEN_TYPE(datatype)) {
        CT_RETURN_IFERR(row_put_int32(ra, (int32)coll_meta->type_mode.size)); // LENGTH
        CT_RETURN_IFERR(row_put_null(ra));                                    // PRECISION
        CT_RETURN_IFERR(row_put_null(ra));                                    // SCALE
    } else if (CT_IS_NUMERIC_TYPE(datatype) || CT_IS_DATETIME_TYPE(datatype)) {
        CT_RETURN_IFERR(row_put_null(ra));                                         // LENGTH
        CT_RETURN_IFERR(row_put_int32(ra, (int32)coll_meta->type_mode.precision)); // PRECISION
        CT_RETURN_IFERR(row_put_int32(ra, (int32)coll_meta->type_mode.scale));     // SCALE
    } else {
        CT_RETURN_IFERR(row_put_null(ra)); // PRECISION
        CT_RETURN_IFERR(row_put_null(ra)); // SCALE
        CT_RETURN_IFERR(row_put_null(ra)); // CHAR_SET
    }

    if (CT_IS_STRING_TYPE(datatype)) {
        CT_RETURN_IFERR(row_put_int32(ra, (int32)coll_meta->type_mode.charset)); // CHAR_SET
    } else {
        CT_RETURN_IFERR(row_put_null(ra)); // CHAR_SET
    }
    return CT_SUCCESS;
}

static inline char *plm_get_coll_type_str(collection_type_t type)
{
    switch (type) {
        case UDT_VARRAY:
            return "VARYING ARRAY";
        case UDT_NESTED_TABLE:
        default:
            return "TABLE";
    }
}

status_t pl_coll_types_row_prepare(plv_collection_t *coll_meta, pl_desc_t *desc, row_assist_t *ra)
{
    CT_RETURN_IFERR(row_put_int32(ra, (int32)desc->uid));                     // UID
    CT_RETURN_IFERR(row_put_int64(ra, desc->oid));                            // TYPE_OID
    CT_RETURN_IFERR(row_put_str(ra, desc->name));                             // TYPE_NAME
    CT_RETURN_IFERR(row_put_str(ra, plm_get_coll_type_str(coll_meta->type))); // COLL_TYPE
    if (coll_meta->type == UDT_VARRAY) {
        CT_RETURN_IFERR(row_put_int32(ra, (int32)coll_meta->limit)); // UPPER_BOUND
    } else {
        CT_RETURN_IFERR(row_put_null(ra)); // UPPER_BOUND
    }

    CT_RETURN_IFERR(row_put_null(ra)); // ELEM_TYPE_MOD
    if (coll_meta->attr_type != UDT_SCALAR) {
        if (coll_meta->attr_type == UDT_OBJECT ||
            (coll_meta->attr_type == UDT_COLLECTION && coll_meta->elmt_type->typdef.collection.is_global)) {
            void *attr_root = (coll_meta->attr_type == UDT_OBJECT) ? coll_meta->elmt_type->typdef.object.root :
                                                                     coll_meta->elmt_type->typdef.collection.root;
            pl_entry_t *attr_entry = ((pl_entity_t *)attr_root)->entry;
            CT_RETURN_IFERR(row_put_int32(ra, attr_entry->desc.uid)); // ELEM_TYPE_UID
            CT_RETURN_IFERR(row_put_str(ra, attr_entry->desc.name));  // ELEM_TYPE_NAME
        } else {
            CT_RETURN_IFERR(row_put_null(ra)); // ELEM_TYPE_UID
            CT_RETURN_IFERR(row_put_null(ra)); // ELEM_TYPE_NAME
        }
        CT_RETURN_IFERR(row_put_null(ra)); // LENGTH
        CT_RETURN_IFERR(row_put_null(ra)); // PRECISION
        CT_RETURN_IFERR(row_put_null(ra)); // SCALE
        CT_RETURN_IFERR(row_put_null(ra)); // CHAR_SET
    } else {
        CT_RETURN_IFERR(pl_coll_types_row_prepare_scalar(ra, coll_meta));
    }
    CT_RETURN_IFERR(row_put_null(ra));     // ELEM_STORAGE
    CT_RETURN_IFERR(row_put_int32(ra, 1)); // NULLS_STORED

    return CT_SUCCESS;
}


status_t pl_write_sys_coll_types(knl_session_t *knl_session, type_spec_t *type, void *desc_in)
{
    row_assist_t ra;
    knl_cursor_t *cursor = NULL;
    uint32 column_count;
    pl_desc_t *desc = (pl_desc_t *)desc_in;
    plv_collection_t *colletion = &type->decl->typdef.collection;
    CM_SAVE_STACK(knl_session->stack);

    if (sql_push_knl_cursor(knl_session, &cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(knl_session->stack);
        return CT_ERROR;
    }

    knl_set_session_scn(knl_session, CT_INVALID_ID64);

    knl_open_sys_cursor(knl_session, cursor, CURSOR_ACTION_INSERT, SYS_COLL_TYPE_ID, CT_INVALID_ID32);
    column_count = knl_get_column_count(cursor->dc_entity);
    row_init(&ra, cursor->buf, g_instance->kernel.attr.max_row_size, column_count);

    if (pl_coll_types_row_prepare(colletion, desc, &ra) != CT_SUCCESS) {
        CM_RESTORE_STACK(knl_session->stack);
        return CT_ERROR;
    }
    if (knl_internal_insert(knl_session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(knl_session->stack);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(knl_session->stack);
    return CT_SUCCESS;
}


status_t pl_delete_sys_coll_types(knl_session_t *session, uint32 uid, uint64 oid)
{
    knl_cursor_t *cursor = NULL;
    status_t status = CT_ERROR;

    knl_set_session_scn(session, CT_INVALID_ID64);

    CM_SAVE_STACK(session->stack);

    do {
        CT_BREAK_IF_ERROR(sql_push_knl_cursor(session, &cursor));

        knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_COLL_TYPE_ID, IX_COLL_TYPE_001_ID);
        knl_init_index_scan(cursor, CT_FALSE);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &uid, sizeof(int32), 0);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_BIGINT, &oid, sizeof(int64), 1);
        knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, 2);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, &uid, sizeof(int32), 0);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_BIGINT, &oid, sizeof(int64), 1);
        knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, 2);

        CT_BREAK_IF_ERROR(knl_fetch(session, cursor));

        while (!cursor->eof) {
            CT_BREAK_IF_ERROR(knl_internal_delete(session, cursor));

            CT_BREAK_IF_ERROR(knl_fetch(session, cursor));
        }
        if (cursor->eof) {
            status = CT_SUCCESS;
        }
    } while (0);

    CM_RESTORE_STACK(session->stack);

    return status;
}

status_t pl_load_entity_update_udt_table(knl_session_t *session, void *desc_in, void *entity_in)
{
    pl_desc_t *desc = (pl_desc_t *)desc_in;
    pl_entity_t *entity = (pl_entity_t *)entity_in;
    object_address_t obj_addr;
    pl_entry_t *entry = entity->entry;
    type_spec_t *type_spec = entity->type_spec;
    type_spec_t *type = entity->type_spec;

    CT_RETURN_IFERR(pl_get_desc_objaddr(&obj_addr, desc));
    CT_RETURN_IFERR(pl_update_sysproc_status(session, desc));
    CT_RETURN_IFERR(pl_delete_sys_types(session, desc->uid, desc->oid));
    CT_RETURN_IFERR(pl_delete_sys_type_attrs(session, desc->uid, desc->oid));
    CT_RETURN_IFERR(pl_delete_sys_type_methods(session, desc->uid, desc->oid));
    CT_RETURN_IFERR(pl_delete_sys_coll_types(session, desc->uid, desc->oid));
    CT_RETURN_IFERR(pl_delete_dependency(session, &obj_addr));

    if (desc->status == OBJ_STATUS_VALID) {
        CT_RETURN_IFERR(pl_write_sys_types(session, type_spec, desc));
        if (type->decl->typdef.type == PLV_COLLECTION) {
            CT_RETURN_IFERR(pl_write_sys_coll_types(session, type_spec, desc));
        } else {
            CT_RETURN_IFERR(pl_write_sys_type_attrs(session, type_spec, desc));
        }
        CT_RETURN_IFERR(pl_insert_dependency_list(session, &obj_addr, &entity->ref_list));
    } else {
        CT_RETURN_IFERR(pl_init_sys_types(session, desc));
    }

    if (entry->desc.status == OBJ_STATUS_VALID && desc->status != OBJ_STATUS_VALID) {
        CT_RETURN_IFERR(pl_update_depender_status(session, &obj_addr));
    }

    return CT_SUCCESS;
}

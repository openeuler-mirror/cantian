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
 * ctsql_privilege.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_privilege.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_privilege.h"
#include "srv_instance.h"
#include "pl_library.h"
#include "pl_meta_common.h"
#include "dtc_dls.h"
#ifdef __cplusplus
extern "C" {
#endif

static status_t sql_check_pl_privs_core(sql_stmt_t *stmt, pl_entity_t *entity, text_t *checked_user);

uint32 sql_get_any_priv_id(sql_stmt_t *stmt)
{
    switch (stmt->context->type) {
        case CTSQL_TYPE_CREATE_TABLE:
            return CREATE_ANY_TABLE;
        case CTSQL_TYPE_CREATE_INDEX:
            return CREATE_ANY_INDEX;
        case CTSQL_TYPE_CREATE_SEQUENCE:
            return CREATE_ANY_SEQUENCE;
        case CTSQL_TYPE_CREATE_VIEW:
            return CREATE_ANY_VIEW;
        case CTSQL_TYPE_CREATE_SYNONYM:
            return CREATE_ANY_SYNONYM;
        case CTSQL_TYPE_CREATE_PROC:
            return CREATE_ANY_PROCEDURE;
        case CTSQL_TYPE_CREATE_TRIG:
            return CREATE_ANY_TRIGGER;

        case CTSQL_TYPE_DROP_TABLE:
        case CTSQL_TYPE_TRUNCATE_TABLE:
            return DROP_ANY_TABLE;
        case CTSQL_TYPE_DROP_INDEX:
            return DROP_ANY_INDEX;
        case CTSQL_TYPE_DROP_SEQUENCE:
            return DROP_ANY_SEQUENCE;
        case CTSQL_TYPE_DROP_VIEW:
            return DROP_ANY_VIEW;
        case CTSQL_TYPE_DROP_SYNONYM:
            return DROP_ANY_SYNONYM;
        case CTSQL_TYPE_DROP_TRIG:
            return DROP_ANY_TRIGGER;
        case CTSQL_TYPE_DROP_PROC:
            return DROP_ANY_PROCEDURE;
        case CTSQL_TYPE_DROP_LIBRARY:
            return DROP_ANY_LIBRARY;

        case CTSQL_TYPE_LOCK_TABLE:
            return LOCK_ANY_TABLE;

        case CTSQL_TYPE_ALTER_TABLE:
            return ALTER_ANY_TABLE;
        case CTSQL_TYPE_ALTER_INDEX:
            return ALTER_ANY_INDEX;
        case CTSQL_TYPE_ALTER_SEQUENCE:
            return ALTER_ANY_SEQUENCE;

        case CTSQL_TYPE_SELECT:
            return SELECT_ANY_TABLE;

        case CTSQL_TYPE_INSERT:
        case CTSQL_TYPE_REPLACE:
            return INSERT_ANY_TABLE;

        case CTSQL_TYPE_UPDATE:
            return UPDATE_ANY_TABLE;

        case CTSQL_TYPE_DELETE:
            return DELETE_ANY_TABLE;

        case CTSQL_TYPE_COMMENT:
            return COMMENT_ANY_TABLE;

        case CTSQL_TYPE_ANALYSE_TABLE:
            return ANALYZE_ANY;

        case CTSQL_TYPE_MERGE:
            return INSERT_ANY_TABLE;

        case CTSQL_TYPE_GRANT:
            return GRANT_ANY_OBJECT_PRIVILEGE;

        case CTSQL_TYPE_REVOKE:
            return GRANT_ANY_OBJECT_PRIVILEGE;

        /* READ ANY TABLE */
        /* EXECUTE ANY PROCEDURE */
        default:
            return CT_SYS_PRIVS_COUNT;
    }
}

status_t sql_check_inherit_priv(sql_stmt_t *stmt, text_t *obj_user)
{
    knl_session_t *knl_session = &stmt->session->knl_session;
    text_t curr_user;

    if (stmt->session->switched_schema) {
        cm_str2text(stmt->session->curr_schema, &curr_user);
    } else {
        curr_user = stmt->session->curr_user;
    }

    if (cm_text_equal_ins(&curr_user, obj_user) || knl_session->kernel->attr.enable_auto_inherit) {
        return CT_SUCCESS;
    }

    /* check inherit any privilege */
    if (knl_check_sys_priv_by_name(knl_session, obj_user, INHERIT_ANY_PRIVILEGES)) {
        return CT_SUCCESS;
    }

    /* check inherit privilege */
    if (knl_check_user_priv_by_name(knl_session, &curr_user, obj_user, CT_PRIV_INHERIT_PRIVILEGES)) {
        return CT_SUCCESS;
    }

    CT_LOG_DEBUG_ERR("Inherit privileges on user %s has not granted to %s", T2S(&curr_user), T2S_EX(obj_user));
    CT_THROW_ERROR(ERR_NO_INHERIT_PRIV);
    return CT_ERROR;
}

static status_t sql_check_pl_priv_core(sql_stmt_t *stmt, text_t *obj_owner, text_t *obj_name, text_t *curr_user,
    object_type_t obj_type, uint32 any_priv_id)
{
    knl_session_t *knl_session = &stmt->session->knl_session;

    /* is owner ? */
    if (cm_text_equal_ins(curr_user, obj_owner)) {
        return CT_SUCCESS;
    }

    /* has execute privilege or public has execute privilege ? */
    if (knl_check_obj_priv_by_name(knl_session, curr_user, obj_owner, obj_name, obj_type, CT_PRIV_EXECUTE)) {
        return CT_SUCCESS;
    }

    /* has execute any privilege ? */
    if (!cm_text_str_equal(obj_owner, SYS_USER_NAME) &&
        knl_check_sys_priv_by_name(knl_session, curr_user, any_priv_id)) {
        return CT_SUCCESS;
    }

    CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
    return CT_ERROR;
}

status_t sql_check_proc_priv_core(sql_stmt_t *stmt, text_t *obj_owner, text_t *obj_name, text_t *curr_user)
{
    object_type_t type = OBJ_TYPE_PROCEDURE;
    uint32 priv_id = EXECUTE_ANY_PROCEDURE;

    if (sql_check_pl_priv_core(stmt, obj_owner, obj_name, curr_user, type, priv_id) != CT_SUCCESS) {
        CT_LOG_DEBUG_ERR("user %s has no privilege for procedure/function %s", T2S(curr_user), T2S_EX(obj_name));
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_check_library_priv_core(sql_stmt_t *stmt, text_t *obj_owner, text_t *obj_name, text_t *curr_user)
{
    object_type_t type = OBJ_TYPE_LIBRARY;
    uint32 priv_id = EXECUTE_ANY_LIBRARY;

    if (sql_check_pl_priv_core(stmt, obj_owner, obj_name, curr_user, type, priv_id) != CT_SUCCESS) {
        CT_LOG_DEBUG_ERR("user %s has no privilege for library %s", T2S(curr_user), T2S_EX(obj_name));
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_check_type_priv_core(sql_stmt_t *stmt, text_t *obj_owner, text_t *obj_name, text_t *curr_user)
{
    object_type_t type = OBJ_TYPE_PROCEDURE;
    uint32 priv_id = EXECUTE_ANY_TYPE;

    if (sql_check_pl_priv_core(stmt, obj_owner, obj_name, curr_user, type, priv_id) != CT_SUCCESS) {
        CT_LOG_DEBUG_ERR("user %s has no privilege for type %s", T2S(curr_user), T2S_EX(obj_name));
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_check_seq_priv(sql_stmt_t *stmt, text_t *user, text_t *seqname)
{
    text_t *curr_user = &stmt->session->curr_user;
    knl_session_t *session = &stmt->session->knl_session;

    /* is owner ? */
    if (cm_text_equal(user, curr_user)) {
        return CT_SUCCESS;
    }

    /* has select any system privilege ? */
    if (knl_check_sys_priv_by_uid(session, session->uid, SELECT_ANY_SEQUENCE)) {
        return CT_SUCCESS;
    }

    /* has select object privilege ? */
    if (knl_check_obj_priv_by_name(session, curr_user, user, seqname, OBJ_TYPE_SEQUENCE, CT_PRIV_SELECT)) {
        return CT_SUCCESS;
    }

    return CT_ERROR;
}

status_t sql_check_table_priv_by_name(sql_stmt_t *stmt, text_t *curr_user, text_t *owner, text_t *obj_name,
    uint32 priv_id)
{
    text_t owner_name;
    text_t table_name;
    knl_dictionary_t dc;
    object_type_t obj_type;
    knl_session_t *knl = &stmt->session->knl_session;

    if (knl_open_dc(knl, owner, obj_name, &dc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc.is_sysnonym) {
        knl_get_link_name(&dc, &owner_name, &table_name);
    } else {
        owner_name = *owner;
        table_name = *obj_name;
    }

    if (cm_text_equal(curr_user, &owner_name)) {
        knl_close_dc(&dc);
        return CT_SUCCESS;
    }

    obj_type = knl_get_object_type(dc.type);
    if (knl_check_obj_priv_by_name(&stmt->session->knl_session, curr_user, &owner_name, &table_name, obj_type, priv_id)) {
        knl_close_dc(&dc);
        return CT_SUCCESS;
    }

    knl_close_dc(&dc);
    return CT_ERROR;
}

static bool32 sql_check_trigger_if_exists(sql_stmt_t *stmt, pl_entry_t *entry)
{
    pl_entry_t *temp_entry = NULL;

    if (stmt->trigger_list == NULL) {
        return CT_FALSE;
    }

    for (uint32 i = 0; i < stmt->trigger_list->count; i++) {
        temp_entry = (pl_entry_t *)cm_galist_get(stmt->trigger_list, i);
        if (temp_entry->desc.oid == entry->desc.oid) {
            return CT_TRUE;
        }
    }

    return CT_FALSE;
}

static status_t sql_record_trigger_entry(sql_stmt_t *stmt, pl_entry_t *entry)
{
    if (stmt->trigger_list == NULL) {
        sql_init_trigger_list(stmt);
    }
    return cm_galist_insert(stmt->trigger_list, entry);
}

status_t sql_check_trigger_priv(sql_stmt_t *stmt, void *entity_in)
{
    knl_session_t *session = KNL_SESSION(stmt);
    pl_entity_t *entity = (pl_entity_t *)entity_in;
    pl_entry_t *entry = entity->entry;
    dc_user_t *dc_user = NULL;
    text_t checked_user;

    if (sql_check_trigger_if_exists(stmt, entry)) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(sql_check_inherit_priv(stmt, &entity->def.user));
    CT_RETURN_IFERR(dc_open_user_by_id(session, session->uid, &dc_user));
    cm_str2text(dc_user->desc.name, &checked_user);

    CT_RETURN_IFERR(sql_check_pl_privs_core(stmt, entity, &checked_user));
    return sql_record_trigger_entry(stmt, entry);
}

static status_t sql_check_table_priv(sql_stmt_t *stmt, sql_table_t *table, uint32 priv_id, text_t *checked_user)
{
    text_t owner_name;
    text_t table_name;
    object_type_t obj_type;

    if (table->entry == NULL) {
        return CT_ERROR;
    }

    if (table->entry->dc.is_sysnonym) {
        knl_get_link_name(&table->entry->dc, &owner_name, &table_name);
        if ((owner_name.len == 0) || (table_name.len == 0)) {
            return CT_ERROR;
        }
    } else {
        owner_name = table->user.value;
        table_name = table->name.value;
    }

    if (cm_text_equal(checked_user, &owner_name)) {
        return CT_SUCCESS;
    }

    obj_type = knl_get_object_type(table->entry->dc.type);
    if (knl_check_obj_priv_by_name(&stmt->session->knl_session, checked_user, &owner_name, &table_name, obj_type,
        priv_id)) {
        return CT_SUCCESS;
    }

    return CT_ERROR;
}

status_t sql_check_single_select_priv(sql_stmt_t *stmt, sql_select_t *select, text_t *checked_user);

status_t sql_check_user_select_priv(knl_session_t *session, text_t *checked_user, text_t *owner, text_t *obj_name,
    object_type_t obj_type, bool32 for_update)
{
    if (cm_text_equal(checked_user, owner)) {
        return CT_SUCCESS;
    }

    if (knl_check_obj_priv_by_name(session, checked_user, owner, obj_name, obj_type, CT_PRIV_SELECT)) {
        return CT_SUCCESS;
    }

    if (!for_update) {
        if (knl_check_obj_priv_by_name(session, checked_user, owner, obj_name, obj_type, CT_PRIV_READ)) {
            return CT_SUCCESS;
        }
    }

    return CT_ERROR;
}

status_t sql_has_select_any_priv(sql_stmt_t *stmt, sql_query_t *query, text_t *checked_user)
{
    knl_session_t *session = &stmt->session->knl_session;

    /* checked user has select/read any table privilege */
    if (cm_text_equal_ins(checked_user, &stmt->session->curr_user)) {
        if (knl_check_sys_priv_by_uid(session, stmt->session->knl_session.uid, SELECT_ANY_TABLE)) {
            return CT_SUCCESS;
        }

        if (!query->for_update) {
            if (knl_check_sys_priv_by_uid(session, stmt->session->knl_session.uid, READ_ANY_TABLE)) {
                return CT_SUCCESS;
            }
        }
    } else {
        if (knl_check_sys_priv_by_name(session, checked_user, SELECT_ANY_TABLE)) {
            return CT_SUCCESS;
        }

        if (!query->for_update) {
            if (knl_check_sys_priv_by_name(session, checked_user, READ_ANY_TABLE)) {
                return CT_SUCCESS;
            }
        }
    }

    return CT_ERROR;
}

static status_t sql_check_ssa_priv(sql_stmt_t *stmt, sql_array_t *ssa, text_t *checked_user)
{
    for (uint32 i = 0; i < ssa->count; i++) {
        sql_select_t *select_ctx = (sql_select_t *)sql_array_get(ssa, i);
        CT_RETURN_IFERR(sql_check_single_select_priv(stmt, select_ctx, checked_user));
    }
    return CT_SUCCESS;
}

static inline void reset_has_any_priv(text_t *sys_user_name, text_t *owner_name, text_t *checked_user,
    bool32 dba_curr_user, bool32 has_any_dictionary, bool32 *has_any_priv)
{
    if (!dba_curr_user && (cm_compare_text(checked_user, sys_user_name) != 0) &&
        (cm_compare_text(owner_name, sys_user_name) == 0)) {
        if (((g_instance->attr.access_dc_enable == CT_TRUE) && *has_any_priv) || (has_any_dictionary == CT_TRUE)) {
            *has_any_priv = CT_TRUE;
        } else {
            *has_any_priv = CT_FALSE;
        }
    }
}

/*
Synonym privileges are the same as the privileges for the target object.
Granting a privilege on a synonym is equivalent to granting the privilege on
the base object. Similarly, granting a privilege on a base object is equivalent to
granting the privilege on all synonyms for the object. If you grant to a user a
privilege on a synonym, then the user can use either the synonym name or the
base object name in the SQL statement that exercises the privilege.
*/
status_t sql_check_query_priv(sql_stmt_t *stmt, sql_query_t *query, text_t *checked_user)
{
    text_t owner_name;
    text_t table_name;
    object_type_t obj_type;
    sql_table_t *table = NULL;
    knl_session_t *session = &stmt->session->knl_session;
    text_t sys_user_name = {
        .str = SYS_USER_NAME,
        .len = SYS_USER_NAME_LEN
    };
    text_t role = { DBA_ROLE, 3 };
    bool32 has_any_dictionary = knl_check_sys_priv_by_name(session, checked_user, SELECT_ANY_DICTIONARY);
    bool32 has_any_priv = (sql_has_select_any_priv(stmt, query, checked_user) == CT_SUCCESS) ? CT_TRUE : CT_FALSE;
    bool32 dba_curr_user = knl_grant_role_with_option(&stmt->session->knl_session, checked_user, &role, CT_FALSE);

    for (uint32 i = 0; i < query->tables.count; i++) {
        table = (sql_table_t *)sql_array_get(&query->tables, i);
        if ((table->type == SUBSELECT_AS_TABLE && table->subslct_tab_usage == SUBSELECT_4_NORMAL_JOIN) ||
            table->type == WITH_AS_TABLE) {
            CT_RETURN_IFERR(sql_check_single_select_priv(stmt, table->select_ctx, checked_user));
            continue;
        }

        if (table->entry == NULL) {
            continue;
        }

        if (IS_DBLINK_TABLE(table)) {
            continue;
        }

        if (table->entry->dc.is_sysnonym) {
            knl_get_link_name(&table->entry->dc, &owner_name, &table_name);
            if ((owner_name.len == 0) || (table_name.len == 0)) {
                return CT_ERROR;
            }
        } else {
            owner_name = table->user.value;
            table_name = table->name.value;
        }
        reset_has_any_priv(&sys_user_name, &owner_name, checked_user, dba_curr_user, has_any_dictionary, &has_any_priv);
        obj_type = knl_get_object_type(table->entry->dc.type);
        if (!has_any_priv) {
            CT_RETURN_IFERR(
                sql_check_user_select_priv(session, checked_user, &owner_name, &table_name, obj_type, query->for_update));
        }
        /* the view owner must have the READ or SELECT privilege on the base tables */
        if (table->type == VIEW_AS_TABLE) {
            CT_RETURN_IFERR(sql_check_single_select_priv(stmt, table->select_ctx, &owner_name));
        }
    }
    if (query->ssa.count > 0) {
        CT_RETURN_IFERR(sql_check_ssa_priv(stmt, &query->ssa, checked_user));
    }

    return CT_SUCCESS;
}

status_t sql_check_select_node_priv(sql_stmt_t *stmt, select_node_t *node, text_t *checked_user)
{
    CT_RETURN_IFERR(sql_stack_safe(stmt));
    CT_RETSUC_IFTRUE(node == NULL);

    switch (node->type) {
        case SELECT_NODE_QUERY:
            return sql_check_query_priv(stmt, node->query, checked_user);

        case SELECT_NODE_UNION:
        case SELECT_NODE_UNION_ALL:
        case SELECT_NODE_MINUS:
        case SELECT_NODE_INTERSECT:
        case SELECT_NODE_INTERSECT_ALL:
        case SELECT_NODE_EXCEPT_ALL:
        case SELECT_NODE_EXCEPT:
            CT_RETURN_IFERR(sql_check_select_node_priv(stmt, node->left, checked_user));
            CT_RETURN_IFERR(sql_check_select_node_priv(stmt, node->right, checked_user));
            return CT_SUCCESS;

        default:
            break;
    }

    return CT_ERROR;
}

static status_t sql_check_single_pl_dc_priv(sql_stmt_t *stmt, pl_dc_t *pl_dc, text_t *checked_user)
{
    text_t obj_owner;
    text_t obj_name;
    dc_user_t *dc_user = NULL;

    // There is no need to check privilege, because there is a non-recursive pl_dc at previous level
    if (pl_dc->is_recursive) {
        return CT_SUCCESS;
    }

    if (pl_dc->type == PL_SYS_PACKAGE) {
        cm_str2text(SYS_USER_NAME, &obj_owner);
        cm_str2text(pl_dc->entry->desc.name, &obj_name);
        return sql_check_proc_priv_core(stmt, &obj_owner, &obj_name, checked_user);
    }

    CT_RETURN_IFERR(dc_open_user_by_id(KNL_SESSION(stmt), pl_dc->uid, &dc_user));
    cm_str2text(dc_user->desc.name, &obj_owner);
    cm_str2text(pl_dc->entry->desc.name, &obj_name);

    if (pl_dc->type == PL_TYPE_SPEC) {
        CT_RETURN_IFERR(sql_check_type_priv_core(stmt, &obj_owner, &obj_name, checked_user));
    } else {
        CT_RETURN_IFERR(sql_check_proc_priv_core(stmt, &obj_owner, &obj_name, checked_user));
    }

    return sql_check_pl_privs_core(stmt, pl_dc->entity, checked_user);
}

status_t sql_check_ple_dc_priv(sql_stmt_t *stmt, void *pl_dc_in)
{
    pl_dc_t *pl_dc = (pl_dc_t *)pl_dc_in;
    knl_session_t *knl_session = KNL_SESSION(stmt);
    dc_user_t *dc_user = NULL;
    text_t user_name;

    if (dc_open_user_by_id(knl_session, knl_session->uid, &dc_user) != CT_SUCCESS) {
        return CT_ERROR;
    }

    cm_str2text(dc_user->desc.name, &user_name);
    if (sql_check_single_pl_dc_priv(stmt, pl_dc, &user_name) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_check_pl_dc_lst_priv(sql_stmt_t *stmt, galist_t *pl_dc_lst, text_t *checked_user)
{
    if (pl_dc_lst == NULL) {
        return CT_SUCCESS;
    }

    // skip priv check if context is in plsql object compile, because has checked in pl_dc_open
    if (stmt->pl_compiler != NULL) {
        return CT_SUCCESS;
    }

    for (uint32 i = 0; i < pl_dc_lst->count; i++) {
        pl_dc_t *pl_dc = (pl_dc_t *)cm_galist_get(pl_dc_lst, i);
        if (sql_check_single_pl_dc_priv(stmt, pl_dc, checked_user) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t sql_check_single_select_priv(sql_stmt_t *stmt, sql_select_t *select, text_t *checked_user)
{
    CT_RETVALUE_IFTRUE(select == NULL, CT_ERROR);
    CT_RETURN_IFERR(sql_check_select_node_priv(stmt, select->root, checked_user));
    CT_RETURN_IFERR(sql_check_pl_dc_lst_priv(stmt, select->pl_dc_lst, checked_user));
    return CT_SUCCESS;
}

static status_t sql_check_select_priv(sql_stmt_t *stmt, text_t *checked_user)
{
    sql_select_t *select_ctx = NULL;

        select_ctx = (sql_select_t *)stmt->context->entry;

    CT_RETVALUE_IFTRUE(select_ctx == NULL, CT_ERROR);
    return sql_check_single_select_priv(stmt, select_ctx, checked_user);
}

static status_t sql_check_update_priv(sql_stmt_t *stmt, text_t *checked_user)
{
    uint32 loop;
    upd_object_t *upd_obj = NULL;
    text_t table_user;
    sql_update_t *update_ctx = (sql_update_t *)stmt->context->entry;
    knl_session_t *session = &stmt->session->knl_session;

    CT_RETVALUE_IFTRUE(update_ctx == NULL, CT_ERROR);

    bool32 have_any_priv = knl_check_sys_priv_by_name(session, checked_user, UPDATE_ANY_TABLE);
    for (loop = 0; loop < update_ctx->objects->count; ++loop) {
        upd_obj = (upd_object_t *)cm_galist_get(update_ctx->objects, loop);
        if (sql_check_table_priv(stmt, upd_obj->table, CT_PRIV_UPDATE, checked_user) != CT_SUCCESS) {
            if (have_any_priv) {
                table_user.str = upd_obj->table->user.str;
                table_user.len = upd_obj->table->user.len;
                // other user can't modify (create drop alter...)  sys's obj
                if ((cm_text_str_equal(&table_user, "SYS")) && (!cm_text_equal(checked_user, &table_user))) {
                    break;
                }
            } else {
                break;
            }
        }
    }
    if (update_ctx->query->ssa.count > 0) {
        CT_RETURN_IFERR(sql_check_ssa_priv(stmt, &update_ctx->query->ssa, checked_user));
    }

    CT_RETURN_IFERR(sql_check_pl_dc_lst_priv(stmt, update_ctx->pl_dc_lst, checked_user));

    if (loop == update_ctx->objects->count) {
        return CT_SUCCESS;
    }
    return CT_ERROR;
}

static status_t sql_check_insert_priv(sql_stmt_t *stmt, text_t *checked_user)
{
    sql_table_t *table = NULL;
    sql_insert_t *insert_ctx = (sql_insert_t *)stmt->context->entry;

    CT_RETVALUE_IFTRUE(insert_ctx == NULL, CT_ERROR);

    table = insert_ctx->table;
    if (sql_check_table_priv(stmt, table, CT_PRIV_INSERT, checked_user) != CT_SUCCESS) {
        if (knl_check_sys_priv_by_name(&stmt->session->knl_session, checked_user, INSERT_ANY_TABLE)) {
            text_t table_user = { table->user.str, table->user.len };
            // other user can't modify (create drop alter...)  sys's obj
            if ((cm_text_str_equal(&table_user, "SYS")) && (!cm_text_equal(checked_user, &table_user))) {
                return CT_ERROR;
            }
        } else {
            return CT_ERROR;
        }
    }
    if (insert_ctx->select_ctx != NULL) {
        CT_RETURN_IFERR(sql_check_single_select_priv(stmt, insert_ctx->select_ctx, checked_user));
    }

    CT_RETURN_IFERR(sql_check_pl_dc_lst_priv(stmt, insert_ctx->pl_dc_lst, checked_user));

    return CT_SUCCESS;
}

static status_t sql_check_delete_priv(sql_stmt_t *stmt, text_t *checked_user)
{
    uint32 loop;
    del_object_t *del_obj = NULL;
    sql_delete_t *delete_ctx = (sql_delete_t *)stmt->context->entry;
    text_t table_user;

    CT_RETVALUE_IFTRUE(delete_ctx == NULL, CT_ERROR);
    bool32 have_any_priv = knl_check_sys_priv_by_name(&stmt->session->knl_session, checked_user, DELETE_ANY_TABLE);
    for (loop = 0; loop < delete_ctx->objects->count; ++loop) {
        del_obj = (del_object_t *)cm_galist_get(delete_ctx->objects, loop);
        if (sql_check_table_priv(stmt, del_obj->table, CT_PRIV_DELETE, checked_user) != CT_SUCCESS) {
            if (have_any_priv) {
                table_user.str = del_obj->table->user.str;
                table_user.len = del_obj->table->user.len;
                // other user can't modify (create drop alter...)  sys's obj
                if ((cm_text_str_equal(&table_user, "SYS")) && (!cm_text_equal(checked_user, &table_user))) {
                    break;
                }
            } else {
                break;
            }
        }
    }
    if (delete_ctx->query->ssa.count > 0) {
        CT_RETURN_IFERR(sql_check_ssa_priv(stmt, &delete_ctx->query->ssa, checked_user));
    }

    CT_RETURN_IFERR(sql_check_pl_dc_lst_priv(stmt, delete_ctx->pl_dc_lst, checked_user));

    if (loop == delete_ctx->objects->count) {
        return CT_SUCCESS;
    }
    return CT_ERROR;
}

static status_t sql_check_replace_priv(sql_stmt_t *stmt, text_t *checked_user)
{
    sql_table_t *table = NULL;
    sql_insert_t *insert_ctx = &((sql_replace_t *)stmt->context->entry)->insert_ctx;

    CT_RETVALUE_IFTRUE(insert_ctx == NULL, CT_ERROR);

    table = insert_ctx->table;
    if (sql_check_table_priv(stmt, table, CT_PRIV_INSERT, checked_user) != CT_SUCCESS) {
        if (knl_check_sys_priv_by_name(&stmt->session->knl_session, checked_user, INSERT_ANY_TABLE)) {
            text_t table_user = { table->user.str, table->user.len };
            // other user can't modify (create drop alter...)  sys's obj
            if ((cm_text_str_equal(&table_user, "SYS")) && (!cm_text_equal(checked_user, &table_user))) {
                return CT_ERROR;
            }
        } else {
            return CT_ERROR;
        }
    }
    if (insert_ctx->select_ctx != NULL) {
        if (sql_check_single_select_priv(stmt, insert_ctx->select_ctx, checked_user) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (sql_check_table_priv(stmt, table, CT_PRIV_DELETE, checked_user) != CT_SUCCESS) {
        if (knl_check_sys_priv_by_name(&stmt->session->knl_session, checked_user, DELETE_ANY_TABLE)) {
            text_t table_user = { table->user.str, table->user.len };
            // other user can't modify (create drop alter...)  sys's obj
            if ((cm_text_str_equal(&table_user, "SYS")) && (!cm_text_equal(checked_user, &table_user))) {
                return CT_ERROR;
            }
        } else {
            return CT_ERROR;
        }
    }

    return sql_check_pl_dc_lst_priv(stmt, insert_ctx->pl_dc_lst, checked_user);
}

static status_t sql_check_merge_target_table(sql_stmt_t *stmt, sql_merge_t *merge_ctx, sql_table_t *table,
    text_t *checked_user)
{
    knl_session_t *session = &stmt->session->knl_session;

    if (merge_ctx->insert_ctx != NULL) {
        if (sql_check_table_priv(stmt, table, CT_PRIV_INSERT, checked_user) != CT_SUCCESS &&
            !knl_check_sys_priv_by_name(session, checked_user, INSERT_ANY_TABLE)) {
            return CT_ERROR;
        }

        if (merge_ctx->insert_ctx->select_ctx != NULL) {
            if (sql_check_single_select_priv(stmt, merge_ctx->insert_ctx->select_ctx, checked_user) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
    }

    if (merge_ctx->update_ctx != NULL) {
        if (sql_check_table_priv(stmt, table, CT_PRIV_UPDATE, checked_user) != CT_SUCCESS &&
            !knl_check_sys_priv_by_name(session, checked_user, UPDATE_ANY_TABLE)) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t sql_check_merge_src_table(sql_stmt_t *stmt, sql_table_t *table, text_t *checked_user)
{
    text_t owner_name;
    text_t table_name;
    knl_session_t *session = &stmt->session->knl_session;

    if (table->type == NORMAL_TABLE) {
        if (sql_check_table_priv(stmt, table, CT_PRIV_SELECT, checked_user) == CT_SUCCESS ||
            sql_check_table_priv(stmt, table, CT_PRIV_READ, checked_user) == CT_SUCCESS ||
            knl_check_sys_priv_by_name(session, checked_user, SELECT_ANY_TABLE) ||
            knl_check_sys_priv_by_name(session, checked_user, READ_ANY_TABLE)) {
            return CT_SUCCESS;
        }

        return CT_ERROR;
    } else if (table->type == VIEW_AS_TABLE) {
        /* current user should has the select/read privilege of the table/view */
        if (sql_check_table_priv(stmt, table, CT_PRIV_SELECT, checked_user) != CT_SUCCESS &&
            sql_check_table_priv(stmt, table, CT_PRIV_READ, checked_user) != CT_SUCCESS &&
            !knl_check_sys_priv_by_name(session, checked_user, SELECT_ANY_TABLE) &&
            !knl_check_sys_priv_by_name(session, checked_user, READ_ANY_TABLE)) {
            return CT_ERROR;
        }

        if (table->entry->dc.is_sysnonym) {
            knl_get_link_name(&table->entry->dc, &owner_name, &table_name);
            if ((owner_name.len == 0) || (table_name.len == 0)) {
                return CT_ERROR;
            }
        } else {
            owner_name = table->user.value;
            table_name = table->name.value;
        }
        return sql_check_single_select_priv(stmt, table->select_ctx, &owner_name);
    } else if (table->type == SUBSELECT_AS_TABLE || table->type == WITH_AS_TABLE) {
        return sql_check_single_select_priv(stmt, table->select_ctx, checked_user);
    } else {
        return CT_ERROR;
    }
}

/* You must have the INSERT(ANY TABLE) and UPDATE(ANY TABLE) object privileges on the target table and the
READ or SELECT object privilege on the source table. To specify the DELETE clause of the
merge_update_clause, you must also have the DELETE object privilege on the target
table. */
static status_t sql_check_merge_priv(sql_stmt_t *stmt, text_t *checked_user)
{
    uint32 i;
    sql_table_t *table = NULL;
    sql_merge_t *merge_ctx = (sql_merge_t *)stmt->context->entry;

    CT_RETVALUE_IFTRUE(merge_ctx == NULL, CT_ERROR);

    /* check the target table privilege */
    table = (sql_table_t *)sql_array_get(&merge_ctx->query->tables, 0);
    CT_RETURN_IFERR(sql_check_merge_target_table(stmt, merge_ctx, table, checked_user));

    /* check the source table privilege */
    for (i = 1; i < merge_ctx->query->tables.count; i++) {
        table = (sql_table_t *)sql_array_get(&merge_ctx->query->tables, i);
        CT_RETURN_IFERR(sql_check_merge_src_table(stmt, table, checked_user));
    }

    return sql_check_pl_dc_lst_priv(stmt, merge_ctx->pl_dc_lst, checked_user);
}

status_t sql_check_alter_user_priv(sql_stmt_t *stmt, sys_privs_id base_privid, sys_privs_id any_privid)
{
    uint32 mask;
    text_t *username = &stmt->session->curr_user;
    text_t role = { DBA_ROLE, 3 };
    text_t name;
    knl_user_def_t *def = (knl_user_def_t *)stmt->context->entry;

    if (!cm_text_str_equal_ins(username, "SYS") && cm_str_equal_ins(def->name, "SYS")) {
        return CT_ERROR;
    }

    cm_str2text(def->name, &name);
    bool32 dba_curr_user = knl_grant_role_with_option(&stmt->session->knl_session, username, &role, CT_FALSE);
    bool32 dba_alter_user = knl_grant_role_with_option(&stmt->session->knl_session, &name, &role, CT_FALSE);
    if (!dba_curr_user && dba_alter_user) {
        return CT_ERROR;
    }

    /* the current user and sys can change his own pwd without ALTER_USER privilege */
    mask = def->mask;
    if (CT_BIT_TEST(mask, CT_GET_MASK(ALTER_USER_FIELD_PASSWORD))) {
        if (CT_BIT_RESET(mask, CT_GET_MASK(ALTER_USER_FIELD_PASSWORD)) == 0 &&
            cm_text_str_equal(username, def->name)) {
            return CT_SUCCESS;
        }
    }

    if (knl_check_sys_priv_by_uid(&stmt->session->knl_session, stmt->session->knl_session.uid, any_privid)) {
        return CT_SUCCESS;
    }

    return CT_ERROR;
}

static status_t sql_check_alter_trig_priv(sql_stmt_t *stmt, sys_privs_id base_privid, sys_privs_id any_privid)
{
    text_t *curr_user = &stmt->session->curr_user;
    knl_alttrig_def_t *def = (knl_alttrig_def_t *)stmt->context->entry;

    if (cm_text_equal(curr_user, &def->user)) {
        return CT_SUCCESS;
    }

    if (knl_check_sys_priv_by_uid(&stmt->session->knl_session, stmt->session->knl_session.uid, any_privid)) {
        if ((cm_text_str_equal(&def->user, "SYS")) &&
            (!cm_text_equal(curr_user, &def->user))) { // other user can't modify (create drop alter...)  sys's obj
            CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
            return CT_ERROR;
        }
        return CT_SUCCESS;
    }

    return CT_ERROR;
}

status_t sql_check_priv(sql_stmt_t *stmt, text_t *curr_user, text_t *object_user, sys_privs_id base_privid,
    sys_privs_id any_privid)
{
    knl_session_t *session = &stmt->session->knl_session;

    /* object belongs to self ? */
    if (cm_text_equal(curr_user, object_user)) {
        if ((uint32)base_privid == CT_INVALID_ID32) {
            return CT_SUCCESS;
        } else if (knl_check_sys_priv_by_uid(session, session->uid, base_privid)) {
            return CT_SUCCESS;
        }
    }

    if (knl_check_sys_priv_by_uid(session, session->uid, any_privid)) {
        if ((cm_text_str_equal(object_user, "SYS")) &&
            (!cm_text_equal(curr_user, object_user))) { // other user can't modify (create drop alter...)  sys's obj
            return CT_ERROR;
        }
        return CT_SUCCESS;
    }

    return CT_ERROR;
}

status_t sql_check_create_table_priv(sql_stmt_t *stmt, sys_privs_id base_privid, sys_privs_id any_privid)
{
    uint32 i;
    knl_constraint_def_t *cons_def = NULL;
    knl_reference_def_t *ref = NULL;
    knl_table_def_t *table_def = (knl_table_def_t *)stmt->context->entry;
    text_t *curr_user = &stmt->session->curr_user;

    CT_RETVALUE_IFTRUE(table_def == NULL, CT_ERROR);

    /* has CREATE TABLE or CREATE ANY TABLE privilege ? */
    CT_RETURN_IFERR(sql_check_priv(stmt, curr_user, &table_def->schema, base_privid, any_privid));

    /* user U1 creates table T2 in schema S2 owned by user U2, and table T2 references table T3 in schema S3 owned
       by user U3.  privileges required:
       user U1 : CREATE ANY TABLE
       USER U2 : REFERENCES object privileges on table C
    */
    for (i = 0; i < table_def->constraints.count; i++) {
        cons_def = (knl_constraint_def_t *)cm_galist_get(&table_def->constraints, i);
        if (cons_def->type != CONS_TYPE_REFERENCE) {
            /* primary & unique index is in the same schema with the table,
               no need additional privileges */
            continue;
        }

        ref = &cons_def->ref;
        if (cm_text_equal_ins(&table_def->schema, &ref->ref_user)) {
            continue;
        }
        if (sql_check_table_priv_by_name(stmt, &table_def->schema, &ref->ref_user, &ref->ref_table, CT_PRIV_REFERENCES) !=
            CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (stmt->context->supplement != NULL) {
        return sql_check_single_select_priv(stmt, (sql_select_t *)stmt->context->supplement, curr_user);
    }

    return CT_SUCCESS;
}

/*
To create an index in your own schema, one of the following conditions must be true:
1. The table or cluster to be indexed must be in your own schema.
2. You must have the INDEX object privilege on the table to be indexed.
3. You must have the CREATE ANY INDEX system privilege.
To create an index in another schema, you must have the CREATE ANY INDEX system privilege.
*/
status_t sql_check_create_index_priv(sql_stmt_t *stmt, sys_privs_id base_privid, sys_privs_id any_privid)
{
    text_t *curr_user = &stmt->session->curr_user;
    knl_index_def_t *def = (knl_index_def_t *)stmt->context->entry;

    CT_RETVALUE_IFTRUE(def == NULL, CT_ERROR);

    if (sql_check_priv(stmt, curr_user, &def->user, base_privid, any_privid) == CT_SUCCESS) {
        return CT_SUCCESS;
    }

    return sql_check_table_priv_by_name(stmt, curr_user, &def->user, &def->table, CT_PRIV_INDEX);
}

status_t sql_check_create_seq_priv(sql_stmt_t *stmt, sys_privs_id base_privid, sys_privs_id any_privid)
{
    text_t *curr_user = &stmt->session->curr_user;
    knl_sequence_def_t *def = (knl_sequence_def_t *)stmt->context->entry;

    CT_RETVALUE_IFTRUE(def == NULL, CT_ERROR);

    return sql_check_priv(stmt, curr_user, &def->user, base_privid, any_privid);
}
/*
To create a view in your own schema, you must have the CREATE VIEW system privilege.
To create a view in another user's schema, you must have the CREATE ANY VIEW system privilege.
The owner of the schema containing the view must have the privileges necessary to
either select (READ or SELECT privilege), insert, update, or delete rows from all the
tables or views on which the view is based.
*/
status_t sql_check_create_view_priv(sql_stmt_t *stmt, sys_privs_id base_privid, sys_privs_id any_privid)
{
    text_t *curr_user = &stmt->session->curr_user;
    knl_view_def_t *def = (knl_view_def_t *)stmt->context->entry;

    CT_RETVALUE_IFTRUE(def == NULL, CT_ERROR);

    /* check CREATE VIEW or CREATE ANY VIEW system privilege */
    CT_RETURN_IFERR(sql_check_priv(stmt, curr_user, &def->user, base_privid, any_privid));

    /* check if the user has privileges of the base objects */
    return sql_check_single_select_priv(stmt, (sql_select_t *)(def->select), &def->user);
}

/*
To create a private synonym in your own schema, you must have the CREATE SYNONYM system privilege.
To create a private synonym in another user's schema, you must have the CREATE ANY SYNONYM system privilege.
To create a PUBLIC synonym, you must have the CREATE PUBLIC SYNONYM system privilege.
*/
status_t sql_check_create_sysn_priv(sql_stmt_t *stmt, sys_privs_id base_privid, sys_privs_id any_privid)
{
    text_t *curr_user = &stmt->session->curr_user;
    knl_synonym_def_t *def = (knl_synonym_def_t *)stmt->context->entry;

    if (def->flags & SYNONYM_IS_PUBLIC) {
        if (knl_check_sys_priv_by_uid(&stmt->session->knl_session, stmt->session->knl_session.uid,
            CREATE_PUBLIC_SYNONYM)) {
            return CT_SUCCESS;
        } else {
            return CT_ERROR;
        }
    }

    return sql_check_priv(stmt, curr_user, &def->owner, base_privid, any_privid);
}

status_t sql_check_create_library_priv(sql_stmt_t *stmt, sys_privs_id base_privid, sys_privs_id any_privid)
{
    text_t *curr_user = &stmt->session->curr_user;
    pl_library_def_t *library_def = (pl_library_def_t *)stmt->context->entry;

    CT_RETVALUE_IFTRUE(library_def == NULL, CT_ERROR);

    /* check CREATE LIBRARY or CREATE ANY LIBRARY system privilege */
    return sql_check_priv(stmt, curr_user, &library_def->owner, base_privid, any_privid);
}

status_t sql_check_drop_library_priv(sql_stmt_t *stmt, sys_privs_id base_privid, sys_privs_id any_privid)
{
    text_t *curr_user = &stmt->session->curr_user;
    knl_drop_def_t *def = (knl_drop_def_t *)stmt->context->entry;
    knl_session_t *session = &stmt->session->knl_session;

    if (cm_compare_text_str_ins(&def->owner, T2S(curr_user)) == 0) {
        return CT_SUCCESS;
    }

    if (knl_check_sys_priv_by_uid(session, session->uid, DROP_ANY_LIBRARY)) {
        if ((cm_text_str_equal(&def->owner, "SYS")) &&
            (!cm_text_equal(curr_user, &def->owner))) { // other user can't modify (create drop alter...)  sys's obj
            CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
            return CT_ERROR;
        }
        return CT_SUCCESS;
    }
    CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
    return CT_ERROR;
}

// prevent user in non-root tenant from operation for space,tenant,etc... make sure base_privid is valid
status_t sql_check_sys_priv_for_tenant(sql_stmt_t *stmt, sys_privs_id base_privid, sys_privs_id any_privid)
{
    if (sql_check_user_tenant(&stmt->session->knl_session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (knl_check_sys_priv_by_uid(&stmt->session->knl_session, stmt->session->knl_session.uid, base_privid)) {
        return CT_SUCCESS;
    }

    return CT_ERROR;
}

status_t sql_check_create_dir_priv(sql_stmt_t *stmt, sys_privs_id base_privid, sys_privs_id any_privid)
{
    if (knl_check_dir_priv_by_uid(&stmt->session->knl_session, stmt->session->knl_session.uid, CREATE_ANY_DIRECTORY)) {
        return CT_SUCCESS;
    }

    return CT_ERROR;
}

status_t sql_check_drop_dir_priv(sql_stmt_t *stmt, sys_privs_id base_privid, sys_privs_id any_privid)
{
    if (knl_check_dir_priv_by_uid(&stmt->session->knl_session, stmt->session->knl_session.uid, DROP_ANY_DIRECTORY)) {
        return CT_SUCCESS;
    }

    return CT_ERROR;
}

status_t sql_check_drop_tab_priv(sql_stmt_t *stmt, sys_privs_id base_privid, sys_privs_id any_privid)
{
    text_t owner;
    text_t obj_name;
    knl_dictionary_t dc;
    text_t *curr_user = &stmt->session->curr_user;
    knl_drop_def_t *def = (knl_drop_def_t *)stmt->context->entry;

    CT_RETVALUE_IFTRUE(def == NULL, CT_ERROR);

    /* check if the object is synonym */
    if (CT_SUCCESS == knl_open_dc(&stmt->session->knl_session, &def->owner, &def->name, &dc)) {
        if (dc.is_sysnonym) {
            knl_get_link_name(&dc, &owner, &obj_name);
        } else {
            owner = def->owner;
            obj_name = def->name;
        }

        knl_close_dc(&dc);
        return sql_check_priv(stmt, curr_user, &owner, base_privid, any_privid);
    } else {
        /* here NOT return ERROR in order to report the proper error information */
        cm_reset_error();
        return CT_SUCCESS;
    }
}

status_t sql_check_drop_priv(sql_stmt_t *stmt, sys_privs_id base_privid, sys_privs_id any_privid)
{
    text_t *curr_user = &stmt->session->curr_user;
    knl_drop_def_t *def = (knl_drop_def_t *)stmt->context->entry;

    CT_RETVALUE_IFTRUE(def == NULL, CT_ERROR);
    return sql_check_priv(stmt, curr_user, &def->owner, base_privid, any_privid);
}

/*
To drop a private synonym, either the synonym must be in your own schema or you
must have the DROP ANY SYNONYM system privilege.
To drop a PUBLIC synonym, you must have the DROP PUBLIC SYNONYM system privilege.
*/
status_t sql_check_drop_sysn_priv(sql_stmt_t *stmt, sys_privs_id base_privid, sys_privs_id any_privid)
{
    text_t *curr_user = &stmt->session->curr_user;
    knl_drop_def_t *def = (knl_drop_def_t *)stmt->context->entry;
    knl_session_t *session = &stmt->session->knl_session;

    if (cm_compare_text_str_ins(&def->owner, "PUBLIC") == 0) {
        if (knl_check_sys_priv_by_uid(session, session->uid, DROP_PUBLIC_SYNONYM)) {
            return CT_SUCCESS;
        } else {
            return CT_ERROR;
        }
    }

    if (cm_compare_text_str_ins(&def->owner, T2S(curr_user)) == 0) {
        return CT_SUCCESS;
    }

    if (knl_check_sys_priv_by_uid(session, session->uid, DROP_ANY_SYNONYM)) {
        if ((cm_text_str_equal(&def->owner, "SYS")) &&
            (!cm_text_equal(curr_user, &def->owner))) { // other user can't modify (create drop alter...)  sys's obj
            CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
            return CT_ERROR;
        }
        return CT_SUCCESS;
    }

    return CT_ERROR;
}

status_t sql_check_drop_role_priv(sql_stmt_t *stmt, sys_privs_id base_privid, sys_privs_id any_privid)
{
    text_t *curr_user = &stmt->session->curr_user;
    knl_drop_def_t *def = (knl_drop_def_t *)stmt->context->entry;
    knl_session_t *session = &stmt->session->knl_session;
    text_t sys_user_name = {
        .str = SYS_USER_NAME,
        .len = SYS_USER_NAME_LEN
    };
    uint32 rid;
    dc_role_t *role = NULL;
    dc_context_t *ctx = &session->kernel->dc_ctx;

    if (!cm_text_equal_ins(curr_user, &sys_user_name)) {
        dls_spin_lock(session, &ctx->paral_lock, NULL);
        if (dc_get_role_id(session, &def->name, &rid)) {
            role = ctx->roles[rid];
            if (role->desc.owner_uid == DB_SYS_USER_ID) {
                dls_spin_unlock(session, &ctx->paral_lock);
                return CT_ERROR;
            }
        }
        dls_spin_unlock(session, &ctx->paral_lock);
    }

    if (knl_check_sys_priv_by_uid(session, session->uid, any_privid)) {
        return CT_SUCCESS;
    }

    if (knl_grant_role_with_option(session, curr_user, &def->name, CT_TRUE)) {
        return CT_SUCCESS;
    }

    return CT_ERROR;
}
/*
The table or view must be in your own schema, or you must have the LOCK ANY TABLE
system privilege, or you must have any object privilege (except the READ object
privilege) on the table or view.
*/
status_t sql_check_lock_table_priv(sql_stmt_t *stmt, sys_privs_id base_privid, sys_privs_id any_privid)
{
    uint32 i;
    text_t *curr_user = &stmt->session->curr_user;
    knl_session_t *session = &stmt->session->knl_session;
    lock_tables_def_t *tables_def = (lock_tables_def_t *)stmt->context->entry;
    lock_table_t *table = NULL;
    bool32 have_any_priv = knl_check_sys_priv_by_uid(session, session->uid, any_privid);
    for (i = 0; i < tables_def->tables.count; i++) {
        table = (lock_table_t *)cm_galist_get(&tables_def->tables, i);
        if (cm_text_equal(curr_user, &table->schema)) {
            continue;
        } else { /* check if the user has object privileges of the table/view */
            if (have_any_priv) {
                // other user can't modify (create drop alter...)  sys's obj
                if ((cm_text_str_equal(&table->schema, "SYS")) && (!cm_text_equal(curr_user, &table->schema))) {
                    return CT_ERROR;
                }
                continue;
            } else {
                return CT_ERROR;
            }
        }
    }

    return CT_SUCCESS;
}

status_t sql_check_truncate_priv(sql_stmt_t *stmt, sys_privs_id base_privid, sys_privs_id any_privid)
{
    text_t owner;
    text_t obj_name;
    knl_dictionary_t dc;
    text_t *curr_user = &stmt->session->curr_user;
    knl_trunc_def_t *def = (knl_trunc_def_t *)stmt->context->entry;

    CT_RETVALUE_IFTRUE(def == NULL, CT_ERROR);

    /* check if the object is synonym */
    if (CT_SUCCESS == knl_open_dc(&stmt->session->knl_session, &def->owner, &def->name, &dc)) {
        if (dc.is_sysnonym) {
            knl_get_link_name(&dc, &owner, &obj_name);
        } else {
            owner = def->owner;
            obj_name = def->name;
        }

        knl_close_dc(&dc);
        return sql_check_priv(stmt, curr_user, &owner, base_privid, any_privid);
    } else {
        /* here NOT return ERROR in order to report the proper error information */
        cm_reset_error();
        return CT_SUCCESS;
    }
}

status_t sql_check_flashback_priv(sql_stmt_t *stmt, sys_privs_id base_privid, sys_privs_id any_privid)
{
    text_t *curr_user = &stmt->session->curr_user;
    knl_flashback_def_t *def = (knl_flashback_def_t *)stmt->context->entry;

    CT_RETVALUE_IFTRUE(def == NULL, CT_ERROR);

    return sql_check_priv(stmt, curr_user, &def->owner, base_privid, any_privid);
}

/*
The database object must reside in your own schema or you must have the DROP ANY ...
system privilege for the type of object to be purged
*/
status_t sql_check_purge_type_priv(knl_session_t *knl_session, text_t *curr_user, bool32 own, uint32 priv_id)
{
    if (own) {
        return CT_SUCCESS;
    } else {
        if (knl_check_sys_priv_by_uid(knl_session, knl_session->uid, priv_id)) {
            return CT_SUCCESS;
        }
    }

    return CT_ERROR;
}

status_t sql_check_purge_priv(sql_stmt_t *stmt, sys_privs_id base_privid, sys_privs_id any_privid)
{
    bool32 own;
    text_t *user = &stmt->session->curr_user;
    knl_purge_def_t *purge_def = (knl_purge_def_t *)stmt->context->entry;
    knl_session_t *knl_session = &stmt->session->knl_session;

    own = cm_text_equal(user, &purge_def->owner);

    switch (purge_def->type) {
        case PURGE_TABLE:
        case PURGE_TABLE_OBJECT:
        case PURGE_PART:
        case PURGE_PART_OBJECT: {
            return sql_check_purge_type_priv(knl_session, user, own, DROP_ANY_TABLE);
        }

        case PURGE_INDEX:
        case PURGE_INDEX_OBJECT: {
            return sql_check_purge_type_priv(knl_session, user, own, DROP_ANY_INDEX);
        }

        case PURGE_RECYCLEBIN: {
            return sql_check_purge_type_priv(knl_session, user, CT_FALSE, PURGE_DBA_RECYCLEBIN);
        }

        case PURGE_TABLESPACE: {
            return sql_check_purge_type_priv(knl_session, user, CT_FALSE, DROP_TABLESPACE);
        }

        default:
            break;
    }

    return CT_ERROR;
}

bool32 sql_check_objpriv(knl_handle_t session, text_t *curr_user, knl_priv_def_t *priv, sql_priv_check_t *priv_check)
{
    knl_session_t *knl_session = (knl_session_t *)session;
    text_t sys_user = {
        .str = "SYS",
        .len = 3
    };
    /* owner has all privileges of the objects, can grant to others */
    if (cm_text_equal(curr_user, priv_check->objowner)) {
        return CT_TRUE;
    }
    if (priv->priv_type != PRIV_TYPE_ALL_PRIV) {
        /* check if the current user has the object privilege with grant option */
        if (knl_check_obj_priv_with_option(session, curr_user, priv_check->objowner, priv_check->objname,
            priv_check->objtype, priv->priv_id)) {
            return CT_TRUE;
        }
    } else {
        if (knl_check_allobjprivs_with_option(session, curr_user, priv_check->objowner, priv_check->objname,
            priv_check->objtype)) {
            return CT_TRUE;
        }
    }
    if (cm_text_equal(&sys_user, priv_check->objowner)) {
        return CT_FALSE;
    }
    if (knl_check_sys_priv_by_uid(session, knl_session->uid, GRANT_ANY_OBJECT_PRIVILEGE)) {
        return CT_TRUE;
    }
    return CT_FALSE;
}

bool32 sql_check_obj_user_priv(knl_handle_t session, text_t *curr_user, knl_priv_def_t *priv,
    sql_priv_check_t *priv_check)
{
    knl_session_t *knl_session = (knl_session_t *)session;
    text_t sys_user = {
        .str = "SYS",
        .len = 3
    };

    if (cm_text_equal(curr_user, priv_check->objname)) {
        return CT_TRUE;
    }

    if (cm_text_equal(&sys_user, priv_check->objname)) {
        return CT_FALSE;
    }

    if (knl_check_sys_priv_by_uid(session, knl_session->uid, GRANT_ANY_OBJECT_PRIVILEGE)) {
        return CT_TRUE;
    }
    return CT_FALSE;
}

static bool32 sql_has_grant_revoke_priv(sql_stmt_t *stmt, knl_priv_def_t *priv, sql_priv_check_t *priv_check)
{
    text_t *curr_user = &stmt->session->curr_user;
    knl_session_t *session = &stmt->session->knl_session;

    if (priv->priv_type == PRIV_TYPE_SYS_PRIV) {
        if (knl_check_sys_priv_by_uid(session, session->uid, GRANT_ANY_PRIVILEGE) ||
            knl_sys_priv_with_option(session, curr_user, priv->priv_id)) {
            return CT_TRUE;
        }
    } else if (priv->priv_type == PRIV_TYPE_ROLE) {
        /* grant role with admin option or create the role */
        /* grant role with admin option or create the role */
        if (knl_grant_role_with_option(session, curr_user, &priv->priv_name, CT_TRUE)) {
            return CT_TRUE;
        }
        if (knl_check_sys_priv_by_uid(session, session->uid, GRANT_ANY_ROLE)) {
            if (priv->priv_id < SYS_ROLE_ID_COUNT) {
                return knl_check_sys_priv_by_uid(session, session->uid, GRANT_ANY_PRIVILEGE);
            }
            return CT_TRUE;
        }
    } else if (priv->priv_type == PRIV_TYPE_OBJ_PRIV) {
        return sql_check_objpriv(session, curr_user, priv, priv_check);
    } else if (priv->priv_type == PRIV_TYPE_ALL_PRIV) {
        if (priv_check->priv_type == PRIV_TYPE_SYS_PRIV) {
            if (knl_check_sys_priv_by_uid(session, session->uid, GRANT_ANY_PRIVILEGE)) {
                return CT_TRUE;
            }
        } else {
            return sql_check_objpriv(session, curr_user, priv, priv_check);
        }
    } else if (priv->priv_type == PRIV_TYPE_USER_PRIV) {
        return sql_check_obj_user_priv(session, curr_user, priv, priv_check);
    }

    return CT_FALSE;
}

status_t sql_check_grant_revoke_priv(sql_stmt_t *stmt, sql_priv_check_t *priv_check)
{
    uint32 i;
    knl_priv_def_t *priv = NULL;

    for (i = 0; i < priv_check->priv_list->count; i++) {
        priv = (knl_priv_def_t *)cm_galist_get(priv_check->priv_list, i);
        if (!sql_has_grant_revoke_priv(stmt, priv, priv_check)) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

/*
To grant a system privilege, one of the following conditions must be met:
1. You must have been granted the GRANT ANY PRIVILEGE system privilege.
2. You must have been granted the system privilege with the ADMIN OPTION.

To grant a role to a user or another role, one of the following conditions must be met:
1. you must have been directly granted the role with the ADMIN OPTION
2. you must have been granted the GRANT ANY ROLE system privilege
3. you must have created the role.

To grant an object privilege on a user, by specifying the ON USER clause of the on_object_clause:
1. you must be the user on whom the privilege is granted
2. you must have been granted the object privilege on that user with the WITH GRANT OPTION
3. you must have been granted the GRANT ANY OBJECT PRIVILEGE system privilege.
*/
status_t sql_check_grant_priv(sql_stmt_t *stmt, sys_privs_id base_privid, sys_privs_id any_privid)
{
    knl_grant_def_t *grant_def = (knl_grant_def_t *)stmt->context->entry;
    sql_priv_check_t priv_check;

    CT_RETVALUE_IFTRUE(grant_def == NULL, CT_ERROR);
    priv_check.objowner = &grant_def->schema;
    priv_check.objname = &grant_def->objname;
    priv_check.priv_list = &grant_def->privs;
    priv_check.objtype = grant_def->objtype;
    priv_check.priv_type = grant_def->priv_type;

    return sql_check_grant_revoke_priv(stmt, &priv_check);
}

/*
To revoke a system privilege, one of the following conditions must be met:
1. you must have been granted the privilege with the ADMIN OPTION
2. You can revoke any privilege if you have the GRANT ANY PRIVILEGE system privilege

To revoke a role from a user or another role, one of the following conditions must be met:
1. you must have been directly granted the role with the ADMIN OPTION
2. you must have created the role
3. You can revoke any role if you have the GRANT ANY ROLE system privilege.

revoke object privileges
*/
status_t sql_check_revoke_priv(sql_stmt_t *stmt, sys_privs_id base_privid, sys_privs_id any_privid)
{
    knl_revoke_def_t *revoke_def = (knl_revoke_def_t *)stmt->context->entry;
    sql_priv_check_t priv_check;

    CT_RETVALUE_IFTRUE(revoke_def == NULL, CT_ERROR);
    priv_check.objowner = &revoke_def->schema;
    priv_check.objname = &revoke_def->objname;
    priv_check.priv_list = &revoke_def->privs;
    priv_check.objtype = revoke_def->objtype;
    priv_check.priv_type = revoke_def->priv_type;

    return sql_check_grant_revoke_priv(stmt, &priv_check);
}

status_t sql_check_alter_table_priv(sql_stmt_t *stmt, sys_privs_id base_privid, sys_privs_id any_privid)
{
    text_t owner, obj_name;
    text_t *curr_user = &stmt->session->curr_user;
    knl_dictionary_t dc;
    knl_altable_def_t *def = (knl_altable_def_t *)stmt->context->entry;
    knl_constraint_def_t *cons = NULL;
    text_t sys_user_name = {
        .str = SYS_USER_NAME,
        .len = SYS_USER_NAME_LEN
    };
    CT_RETVALUE_IFTRUE(def == NULL, CT_ERROR);
    if (CT_SUCCESS == knl_open_dc(&stmt->session->knl_session, &def->user, &def->name, &dc)) {
        if (dc.is_sysnonym) {
            knl_get_link_name(&dc, &owner, &obj_name);
        } else {
            owner = def->user;
            obj_name = def->name;
        }
        knl_close_dc(&dc);
    } else {
        // If the SQL check privilege function reports an error,
        // it will report insufficient permission.
        // The error code of the object does not exist is reported at the execution stage.
        // Otherwise, there will be inaccurate error information
        cm_reset_error();
        return CT_SUCCESS;
    }

    if (sql_check_priv(stmt, curr_user, &owner, base_privid, any_privid) != CT_SUCCESS &&
        sql_check_table_priv_by_name(stmt, curr_user, &owner, &obj_name, CT_PRIV_ALTER) != CT_SUCCESS) {
        return CT_ERROR;
    }

    /* if you are not the owner of the table, you need the DROP ANY TABLE privilege in order to drop
       or truncate partition */
    if (ALTABLE_DROP_PARTITION == def->action || ALTABLE_TRUNCATE_PARTITION == def->action) {
        if (!cm_text_equal(curr_user, &owner)) {
            if (!knl_check_sys_priv_by_uid(&stmt->session->knl_session, stmt->session->knl_session.uid,
                DROP_ANY_TABLE)) {
                return CT_ERROR;
            }
        }
    }

    if (ALTABLE_ADD_CONSTRAINT == def->action || ALTABLE_MODIFY_CONSTRAINT == def->action ||
        ALTABLE_RENAME_CONSTRAINT == def->action) {
        cons = &def->cons_def.new_cons;
        if (cons->type != CONS_TYPE_REFERENCE) {
            return CT_SUCCESS;
        }
        /* check table owner's reference privilege on the ref-table */
        if (cm_text_equal(&owner, &cons->ref.ref_user) || cm_text_equal(&owner, &sys_user_name)) {
            return CT_SUCCESS;
        }

        if (!knl_check_obj_priv_by_name(&stmt->session->knl_session, &owner, &cons->ref.ref_user, &cons->ref.ref_table,
            OBJ_TYPE_TABLE, CT_PRIV_REFERENCES)) {
            CT_LOG_DEBUG_ERR("%s has no references privilege on table %s", T2S(&owner), T2S_EX(&cons->ref.ref_table));
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t sql_check_alter_seq_priv(sql_stmt_t *stmt, sys_privs_id base_privid, sys_privs_id any_privid)
{
    text_t *curr_user = &stmt->session->curr_user;
    knl_session_t *se = &stmt->session->knl_session;
    knl_sequence_def_t *def = (knl_sequence_def_t *)stmt->context->entry;

    CT_RETVALUE_IFTRUE(def == NULL, CT_ERROR);
    if (sql_check_priv(stmt, curr_user, &def->user, base_privid, any_privid) == CT_SUCCESS) {
        return CT_SUCCESS;
    }
    if (cm_text_equal(curr_user, &def->user)) {
        return CT_SUCCESS;
    }
    if (knl_check_obj_priv_by_name(se, curr_user, &def->user, &def->name, OBJ_TYPE_SEQUENCE, CT_PRIV_ALTER)) {
        return CT_SUCCESS;
    }

    return CT_ERROR;
}

status_t sql_check_alter_index_priv(sql_stmt_t *stmt, sys_privs_id base_privid, sys_privs_id any_privid)
{
    text_t *curr_user = &stmt->session->curr_user;
    knl_alindex_def_t *def = (knl_alindex_def_t *)stmt->context->entry;

    CT_RETVALUE_IFTRUE(def == NULL, CT_ERROR);

    return sql_check_priv(stmt, curr_user, &def->user, base_privid, any_privid);
}

status_t sql_check_comment_priv(sql_stmt_t *stmt, sys_privs_id base_privid, sys_privs_id any_privid)
{
    text_t *curr_user = &stmt->session->curr_user;
    knl_comment_def_t *def = (knl_comment_def_t *)stmt->context->entry;

    CT_RETVALUE_IFTRUE(def == NULL, CT_ERROR);

    return sql_check_priv(stmt, curr_user, &def->owner, base_privid, any_privid);
}

/*
privileges required
S1: user A create a trigger T in schema A based on table C (in schema A) : CREATE TRIGGER
S2: user A create a trigger T in schema A based on table C (in schema B) : CREATE ANY TRIGGER
S3: user A create a trigger T in schema B based on table C (in schema A) : CREATE ANY TRIGGER
S4: user A create a trigger T in schema B based on table C (in schema B) : CREATE ANY TRIGGER
*/
status_t sql_check_create_trig_priv(sql_stmt_t *stmt, text_t *obj_owner, text_t *table_user)
{
    text_t *curr_user = &stmt->session->curr_user;
    knl_session_t *session = &stmt->session->knl_session;
    uint32 oper_uid = session->uid;

    if (cm_text_equal_ins(curr_user, obj_owner)) {
        /* Table C in current user's schema ? */
        if (cm_text_equal_ins(curr_user, table_user)) {
            if (knl_check_sys_priv_by_uid(session, oper_uid, CREATE_TRIGGER)) {
                return CT_SUCCESS;
            }
        }
    }

    if (!knl_check_sys_priv_by_uid(session, oper_uid, CREATE_ANY_TRIGGER)) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_check_pl_create_priv(sql_stmt_t *stmt, sys_privs_id base_privid, sys_privs_id any_privid)
{
    pl_entity_t *pl_ctx = (pl_entity_t *)stmt->pl_context;
    text_t *curr_user = &stmt->session->curr_user;
    text_t *obj_owner = &pl_ctx->def.user;

    return sql_check_priv(stmt, curr_user, obj_owner, base_privid, any_privid);
}

status_t sql_check_exec_type_priv(sql_stmt_t *stmt, text_t *obj_owner, text_t *obj_name)
{
    text_t curr_user;
    knl_session_t *session = &stmt->session->knl_session;

    cm_str2text(stmt->session->curr_schema, &curr_user);

    if (cm_text_equal_ins(&curr_user, obj_owner)) {
        return CT_SUCCESS;
    }

    /* has procedure's execute privilege ? */
    if (knl_check_obj_priv_by_name(session, &curr_user, obj_owner, obj_name, OBJ_TYPE_PROCEDURE, CT_PRIV_EXECUTE)) {
        return CT_SUCCESS;
    }

    /* or has execute any procedure privilege ? */
    if (knl_check_sys_priv_by_uid(session, stmt->session->curr_schema_id, EXECUTE_ANY_TYPE)) {
        if ((cm_text_str_equal(obj_owner, "SYS")) &&
            (!cm_text_equal(&curr_user, obj_owner))) { // other user can't modify (create drop alter...)  sys's obj
            CT_LOG_DEBUG_ERR("user %s has no privilege for procedure/function %s", T2S(&curr_user), T2S_EX(obj_name));
            CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
            return CT_ERROR;
        }
        return CT_SUCCESS;
    }

    CT_LOG_DEBUG_ERR("user %s has no privilege for procedure/function %s", T2S(&curr_user), T2S_EX(obj_name));
    CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
    return CT_ERROR;
}

status_t sql_check_pl_drop_priv_core(knl_session_t *session, text_t *obj_owner, text_t *curr_user, uint32 priv_id)
{
    if (knl_check_sys_priv_by_uid(session, session->uid, priv_id)) {
        // other user can't modify (create drop alter...)  sys's obj
        if ((cm_text_str_equal(obj_owner, "SYS")) && (!cm_text_equal(curr_user, obj_owner))) {
            CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
            return CT_ERROR;
        }
        return CT_SUCCESS;
    } else {
        CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
        return CT_ERROR;
    }
}

status_t sql_check_pl_drop_priv(sql_stmt_t *stmt, sys_privs_id base_privid, sys_privs_id any_privid)
{
    pl_drop_def_t *drop_def = (pl_drop_def_t *)stmt->context->entry;
    text_t *user = &stmt->session->curr_user;
    text_t *obj_owner = &drop_def->obj.user;

    return sql_check_priv(stmt, user, obj_owner, base_privid, any_privid);
}

status_t sql_privs_no_check(sql_stmt_t *stmt, sys_privs_id base_privid, sys_privs_id any_privid)
{
    return CT_SUCCESS;
}

status_t sql_check_backup_priv(sql_stmt_t *stmt, sys_privs_id base_privid, sys_privs_id any_privid)
{
    knl_session_t *session = &stmt->session->knl_session;

    if (sql_check_user_tenant(session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (knl_check_sys_priv_by_uid(session, session->uid, SYSDBA)) {
        return CT_SUCCESS;
    }

    if (knl_check_sys_priv_by_uid(session, session->uid, SYSBACKUP)) {
        return CT_SUCCESS;
    }

    return CT_ERROR;
}

status_t sql_check_analyse_priv(sql_stmt_t *stmt, sys_privs_id base_privid, sys_privs_id any_privid)
{
    knl_analyze_tab_def_t *def = (knl_analyze_tab_def_t *)stmt->context->entry;
    CT_RETVALUE_IFTRUE(def == NULL, CT_ERROR);

    if (!sql_check_stats_priv(stmt->session, &def->owner)) {
        CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_check_analyze_index_priv(sql_stmt_t *stmt, sys_privs_id base_privid, sys_privs_id any_privid)
{
    knl_analyze_index_def_t *def = (knl_analyze_index_def_t *)stmt->context->entry;
    CT_RETVALUE_IFTRUE(def == NULL, CT_ERROR);

    if (!sql_check_stats_priv(stmt->session, &def->owner)) {
        CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_check_sql_map_priv(sql_stmt_t *stmt, sys_privs_id base_privid, sys_privs_id any_privid)
{
    text_t schema;
    cm_str2text(stmt->session->curr_schema, &schema);
    return sql_check_priv(stmt, &stmt->session->curr_user, &schema, base_privid, any_privid);
}

static status_t sql_check_dml_privs_core(sql_stmt_t *stmt)
{
    text_t checked_user;

    // in pl compile, should always check table/view privs
    if (stmt->pl_compiler == NULL) {
        if (!stmt->context->has_pl_objects && stmt->context->obj_belong_self &&
            cm_text_str_equal(&stmt->session->curr_user, stmt->session->curr_schema)) {
            return CT_SUCCESS;
        }
        checked_user = stmt->session->curr_user;
    } else {
        if (stmt->session->switched_schema) {
            cm_str2text(stmt->session->curr_schema, &checked_user);
        } else {
            checked_user = stmt->session->curr_user;
        }
    }

    switch (stmt->context->type) {
        case CTSQL_TYPE_SELECT:
            return sql_check_select_priv(stmt, &checked_user);

        case CTSQL_TYPE_INSERT:
            return sql_check_insert_priv(stmt, &checked_user);

        case CTSQL_TYPE_UPDATE:
            return sql_check_update_priv(stmt, &checked_user);

        case CTSQL_TYPE_DELETE:
            return sql_check_delete_priv(stmt, &checked_user);

        case CTSQL_TYPE_MERGE:
            return sql_check_merge_priv(stmt, &checked_user);

        case CTSQL_TYPE_REPLACE:
            return sql_check_replace_priv(stmt, &checked_user);

        default:
            return CT_ERROR;
    }
}

status_t sql_check_dml_privs(sql_stmt_t *stmt, bool32 need_lock_ctrl)
{
    sql_context_t *context = stmt->context;

    if (context->ctrl.cleaned) {
        CM_ASSERT(context->ctrl.valid == CT_FALSE);
        return CT_SUCCESS; // skip cleaned sql_context,it will be re-parsed later
    }

    if (!need_lock_ctrl) {
        return sql_check_dml_privs_core(stmt);
    }

    sql_inc_ctx_ref(stmt, context);
    if (context->ctrl.cleaned) {
        sql_dec_ctx_ref(stmt, context);
        CM_ASSERT(context->ctrl.valid == CT_FALSE);
        return CT_SUCCESS; // skip cleaned sql_context,it will be re-parsed later
    }

    status_t status = sql_check_dml_privs_core(stmt);
    sql_dec_ctx_ref(stmt, context);
    return status;
}

static bool32 sql_context_is_dml(sql_context_t *context)
{
    if (context->type == CTSQL_TYPE_SELECT || context->type == CTSQL_TYPE_INSERT || context->type == CTSQL_TYPE_UPDATE ||
        context->type == CTSQL_TYPE_DELETE || context->type == CTSQL_TYPE_MERGE || context->type == CTSQL_TYPE_REPLACE) {
        return CT_TRUE;
    }

    return CT_FALSE;
}

static status_t sql_check_pl_privs_core(sql_stmt_t *stmt, pl_entity_t *entity, text_t *checked_user)
{
    sql_context_t *context = NULL;
    sql_stmt_t *sub_stmt = NULL;
    status_t ret = CT_SUCCESS;
    sql_stmt_t *save_curr_stmt = stmt->session->current_stmt;
    if (entity == NULL) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(sql_stack_safe(stmt));

    if (sql_check_pl_dc_lst_priv(stmt, &entity->dc_lst, checked_user) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_push(stmt, sizeof(sql_stmt_t), (void **)&sub_stmt) != CT_SUCCESS) {
        return CT_ERROR;
    }
    sql_init_stmt(stmt->session, sub_stmt, stmt->id);
    sub_stmt->is_sub_stmt = CT_TRUE;
    sub_stmt->parent_stmt = stmt;
    SET_STMT_PL_CONTEXT(sub_stmt, NULL);
    sub_stmt->session->current_stmt = sub_stmt;

    for (uint32 i = 0; i < entity->sqls.count; i++) {
        context = (sql_context_t *)cm_galist_get(&entity->sqls, i);
        CM_ASSERT(sql_context_is_dml(context));
        sub_stmt->context = context;
        if (sql_check_dml_privs(sub_stmt, CT_TRUE) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
            ret = CT_ERROR;
            break;
        }
    }
    stmt->session->current_stmt = save_curr_stmt;
    sql_release_lob_info(sub_stmt);
    sql_release_resource(sub_stmt, CT_TRUE);
    CTSQL_POP(stmt);
    return ret;
}

static status_t sql_check_pl_privs(sql_stmt_t *stmt)
{
    text_t checked_user = stmt->session->curr_user;

    return sql_check_pl_privs_core(stmt, stmt->pl_context, &checked_user);
}

// for g_priv_tab_def
static status_t sql_check_sys_priv(sql_stmt_t *stmt, sys_privs_id base_privid, sys_privs_id any_privid)
{
    knl_session_t *session = KNL_SESSION(stmt);

    CM_ASSERT(base_privid != CT_INVALID_ID32);
    if (knl_check_sys_priv_by_uid(session, session->uid, base_privid)) {
        return CT_SUCCESS;
    }

    return CT_ERROR;
}

static priv_tab_def g_priv_tab_def[] = {
    [CTSQL_TYPE_CREATE_DATABASE] = { CREATE_DATABASE, CT_INVALID_ID32, sql_check_sys_priv_for_tenant },
    [CTSQL_TYPE_CREATE_CLUSTERED_DATABASE] = { CREATE_DATABASE, CT_INVALID_ID32, sql_check_sys_priv_for_tenant },
    [CTSQL_TYPE_CREATE_USER] = { CREATE_USER, CT_INVALID_ID32, sql_check_sys_priv },
    [CTSQL_TYPE_CREATE_ROLE] = { CREATE_ROLE, CT_INVALID_ID32, sql_check_sys_priv },
    [CTSQL_TYPE_CREATE_TABLESPACE] = { CREATE_TABLESPACE, CT_INVALID_ID32, sql_check_sys_priv_for_tenant },
    [CTSQL_TYPE_CREATE_NODE] = { CREATE_NODE, CT_INVALID_ID32, sql_check_sys_priv },
    [CTSQL_TYPE_CREATE_PROFILE] = { CREATE_PROFILE, CT_INVALID_ID32, sql_check_sys_priv_for_tenant },
    [CTSQL_TYPE_CREATE_CTRLFILE] = { CREATE_CTRLFILE, CT_INVALID_ID32, sql_check_sys_priv },
    [CTSQL_TYPE_DROP_TABLESPACE] = { DROP_TABLESPACE, CT_INVALID_ID32, sql_check_sys_priv_for_tenant },
    [CTSQL_TYPE_DROP_USER] = { DROP_USER, CT_INVALID_ID32, sql_check_sys_priv },
    [CTSQL_TYPE_DROP_NODE] = { DROP_NODE, CT_INVALID_ID32, sql_check_sys_priv },
    [CTSQL_TYPE_DROP_PROFILE] = { DROP_PROFILE, CT_INVALID_ID32, sql_check_profile_priv },
    [CTSQL_TYPE_ALTER_TABLESPACE] = { ALTER_TABLESPACE, CT_INVALID_ID32, sql_check_sys_priv_for_tenant },
    [CTSQL_TYPE_ALTER_SYSTEM] = { ALTER_SYSTEM, CT_INVALID_ID32, sql_check_sys_priv_for_tenant },
    [CTSQL_TYPE_ALTER_DATABASE] = { ALTER_DATABASE, CT_INVALID_ID32, sql_check_sys_priv_for_tenant },
    [CTSQL_TYPE_ALTER_PROFILE] = { ALTER_PROFILE, CT_INVALID_ID32, sql_check_profile_priv },
    [CTSQL_TYPE_ALTER_NODE] = { ALTER_NODE, CT_INVALID_ID32, sql_check_sys_priv },
    [CTSQL_TYPE_ALTER_USER] = { CT_INVALID_ID32, ALTER_USER, sql_check_alter_user_priv },
    [CTSQL_TYPE_ALTER_TRIGGER] = { CT_INVALID_ID32, ALTER_ANY_TRIGGER, sql_check_alter_trig_priv },
    [CTSQL_TYPE_CREATE_DATABASE_LINK] = { CREATE_DATABASE_LINK, CT_INVALID_ID32, sql_check_sys_priv_for_tenant },
    [CTSQL_TYPE_DROP_DATABASE_LINK] = { DROP_DATABASE_LINK, CT_INVALID_ID32, sql_check_sys_priv_for_tenant },
    [CTSQL_TYPE_ALTER_DATABASE_LINK] = { ALTER_DATABASE_LINK, CT_INVALID_ID32, sql_check_sys_priv_for_tenant },
    [CTSQL_TYPE_CREATE_TABLE] = { CREATE_TABLE, CREATE_ANY_TABLE, sql_check_create_table_priv },
    [CTSQL_TYPE_CREATE_INDEX] = { CT_INVALID_ID32, CREATE_ANY_INDEX, sql_check_create_index_priv },
    [CTSQL_TYPE_CREATE_INDEXES] = { CT_INVALID_ID32, CREATE_ANY_INDEX, sql_check_create_index_priv },
    [CTSQL_TYPE_CREATE_SEQUENCE] = { CREATE_SEQUENCE, CREATE_ANY_SEQUENCE, sql_check_create_seq_priv },
    [CTSQL_TYPE_CREATE_VIEW] = { CREATE_VIEW, CREATE_ANY_VIEW, sql_check_create_view_priv },
    [CTSQL_TYPE_CREATE_SYNONYM] = { CREATE_SYNONYM, CREATE_ANY_SYNONYM, sql_check_create_sysn_priv },
    [CTSQL_TYPE_CREATE_DIRECTORY] = { CT_INVALID_ID32, CREATE_ANY_DIRECTORY, sql_check_create_dir_priv },
    [CTSQL_TYPE_DROP_TABLE] = { CT_INVALID_ID32, DROP_ANY_TABLE, sql_check_drop_tab_priv },
    [CTSQL_TYPE_DROP_INDEX] = { CT_INVALID_ID32, DROP_ANY_INDEX, sql_check_drop_priv },
    [CTSQL_TYPE_DROP_SEQUENCE] = { CT_INVALID_ID32, DROP_ANY_SEQUENCE, sql_check_drop_priv },
    [CTSQL_TYPE_DROP_VIEW] = { CT_INVALID_ID32, DROP_ANY_VIEW, sql_check_drop_tab_priv },
    [CTSQL_TYPE_DROP_SYNONYM] = { CT_INVALID_ID32, DROP_ANY_SYNONYM, sql_check_drop_sysn_priv },
    [CTSQL_TYPE_DROP_ROLE] = { CT_INVALID_ID32, DROP_ANY_ROLE, sql_check_drop_role_priv },
    [CTSQL_TYPE_DROP_DIRECTORY] = { CT_INVALID_ID32, DROP_ANY_DIRECTORY, sql_check_drop_dir_priv },
    [CTSQL_TYPE_DROP_LIBRARY] = { CT_INVALID_ID32, DROP_ANY_LIBRARY, sql_check_drop_library_priv },
    [CTSQL_TYPE_LOCK_TABLE] = { CT_INVALID_ID32, LOCK_ANY_TABLE, sql_check_lock_table_priv },
    [CTSQL_TYPE_TRUNCATE_TABLE] = { CT_INVALID_ID32, DROP_ANY_TABLE, sql_check_truncate_priv },
    [CTSQL_TYPE_FLASHBACK_TABLE] = { CT_INVALID_ID32, FLASHBACK_ANY_TABLE, sql_check_flashback_priv },
    [CTSQL_TYPE_PURGE] = { CT_INVALID_ID32, CT_INVALID_ID32, sql_check_purge_priv },
    [CTSQL_TYPE_GRANT] = { CT_INVALID_ID32, GRANT_ANY_PRIVILEGE, sql_check_grant_priv },
    [CTSQL_TYPE_REVOKE] = { CT_INVALID_ID32, CT_INVALID_ID32, sql_check_revoke_priv },
    [CTSQL_TYPE_ALTER_TABLE] = { CREATE_TABLE, ALTER_ANY_TABLE, sql_check_alter_table_priv },
    [CTSQL_TYPE_ALTER_SEQUENCE] = { CREATE_SEQUENCE, ALTER_ANY_SEQUENCE, sql_check_alter_seq_priv },
    [CTSQL_TYPE_ALTER_INDEX] = { CT_INVALID_ID32, ALTER_ANY_INDEX, sql_check_alter_index_priv },
    [CTSQL_TYPE_COMMENT] = { CT_INVALID_ID32, COMMENT_ANY_TABLE, sql_check_comment_priv },
    [CTSQL_TYPE_CREATE_LIBRARY] = { CREATE_LIBRARY, CREATE_ANY_LIBRARY, sql_check_create_library_priv },
    [CTSQL_TYPE_BEGIN] = { CT_INVALID_ID32, CT_INVALID_ID32, sql_privs_no_check },
    [CTSQL_TYPE_COMMIT] = { CT_INVALID_ID32, CT_INVALID_ID32, sql_privs_no_check },
    [CTSQL_TYPE_COMMIT_PHASE1] = { CT_INVALID_ID32, CT_INVALID_ID32, sql_privs_no_check },
    [CTSQL_TYPE_COMMIT_PHASE2] = { CT_INVALID_ID32, CT_INVALID_ID32, sql_privs_no_check },
    [CTSQL_TYPE_ROLLBACK_PHASE2] = { CT_INVALID_ID32, CT_INVALID_ID32, sql_privs_no_check },
    [CTSQL_TYPE_ROLLBACK] = { CT_INVALID_ID32, CT_INVALID_ID32, sql_privs_no_check },
    [CTSQL_TYPE_ROLLBACK_TO] = { CT_INVALID_ID32, CT_INVALID_ID32, sql_privs_no_check },
    [CTSQL_TYPE_SAVEPOINT] = { CT_INVALID_ID32, CT_INVALID_ID32, sql_privs_no_check },
    [CTSQL_TYPE_RELEASE_SAVEPOINT] = { CT_INVALID_ID32, CT_INVALID_ID32, sql_privs_no_check },
#ifdef DB_DEBUG_VERSION
    [CTSQL_TYPE_SYNCPOINT] = { CT_INVALID_ID32, CT_INVALID_ID32, sql_privs_no_check },
#endif /* DB_DEBUG_VERSION */
    [CTSQL_TYPE_SET_TRANS] = { CT_INVALID_ID32, CT_INVALID_ID32, sql_privs_no_check },
    [CTSQL_TYPE_BACKUP] = { CT_INVALID_ID32, CT_INVALID_ID32, sql_check_backup_priv },
    [CTSQL_TYPE_ANALYSE_TABLE] = { CT_INVALID_ID32, ANALYZE_ANY, sql_check_analyse_priv },
    [CTSQL_TYPE_ANALYZE_INDEX] = { CT_INVALID_ID32, ANALYZE_ANY, sql_check_analyze_index_priv },
    [CTSQL_TYPE_RESTORE] = { SYSDBA, CT_INVALID_ID32, sql_check_sys_priv_for_tenant },
    [CTSQL_TYPE_RECOVER] = { SYSDBA, CT_INVALID_ID32, sql_check_sys_priv_for_tenant },
    [CTSQL_TYPE_SHUTDOWN] = { SYSDBA, CT_INVALID_ID32, sql_check_sys_priv_for_tenant },
    [CTSQL_TYPE_BUILD] = { SYSDBA, CT_INVALID_ID32, sql_check_sys_priv_for_tenant },
    [CTSQL_TYPE_VALIDATE] = { SYSDBA, CT_INVALID_ID32, sql_check_sys_priv_for_tenant },
    [CTSQL_TYPE_DAAC] = { SYSDBA, CT_INVALID_ID32, sql_check_sys_priv_for_tenant },
    [CTSQL_TYPE_ANONYMOUS_BLOCK] = { CT_INVALID_ID32, CT_INVALID_ID32, sql_privs_no_check },
    [CTSQL_TYPE_CREATE_PROC] = { CREATE_PROCEDURE, CREATE_ANY_PROCEDURE, sql_check_pl_create_priv },
    [CTSQL_TYPE_CREATE_FUNC] = { CREATE_PROCEDURE, CREATE_ANY_PROCEDURE, sql_check_pl_create_priv },
    [CTSQL_TYPE_CREATE_TRIG] = { CREATE_TRIGGER, CREATE_ANY_TRIGGER, sql_check_pl_create_priv },
    [CTSQL_TYPE_CREATE_PACK_SPEC] = { CREATE_PROCEDURE, CREATE_ANY_PROCEDURE, sql_check_pl_create_priv },
    [CTSQL_TYPE_CREATE_PACK_BODY] = { CREATE_PROCEDURE, CREATE_ANY_PROCEDURE, sql_check_pl_create_priv },
    [CTSQL_TYPE_CREATE_TYPE_SPEC] = { CREATE_TYPE, CREATE_ANY_TYPE, sql_check_pl_create_priv },
    [CTSQL_TYPE_CREATE_TYPE_BODY] = { CREATE_TYPE, CREATE_ANY_TYPE, sql_check_pl_create_priv },
    [CTSQL_TYPE_DROP_PROC] = { CT_INVALID_ID32, DROP_ANY_PROCEDURE, sql_check_pl_drop_priv },
    [CTSQL_TYPE_DROP_FUNC] = { CT_INVALID_ID32, DROP_ANY_PROCEDURE, sql_check_pl_drop_priv },
    [CTSQL_TYPE_DROP_TRIG] = { CT_INVALID_ID32, DROP_ANY_TRIGGER, sql_check_pl_drop_priv },
    [CTSQL_TYPE_DROP_PACK_SPEC] = { CT_INVALID_ID32, DROP_ANY_PROCEDURE, sql_check_pl_drop_priv },
    [CTSQL_TYPE_DROP_PACK_BODY] = { CT_INVALID_ID32, DROP_ANY_PROCEDURE, sql_check_pl_drop_priv },
    [CTSQL_TYPE_DROP_TYPE_SPEC] = { CT_INVALID_ID32, DROP_ANY_TYPE, sql_check_pl_drop_priv },
    [CTSQL_TYPE_DROP_TYPE_BODY] = { CT_INVALID_ID32, DROP_ANY_TYPE, sql_check_pl_drop_priv },
    [CTSQL_TYPE_ALTER_SESSION] = { CT_INVALID_ID32, CT_INVALID_ID32, sql_privs_no_check },
    [CTSQL_TYPE_ALTER_SQL_MAP] = { CT_INVALID_ID32, CREATE_ANY_SQL_MAP, sql_check_sql_map_priv },
    [CTSQL_TYPE_DROP_SQL_MAP] = { CT_INVALID_ID32, DROP_ANY_SQL_MAP, sql_check_sql_map_priv },
    [CTSQL_TYPE_CREATE_TENANT] = { CREATE_TENANT, CT_INVALID_ID32, sql_check_sys_priv_for_tenant },
    [CTSQL_TYPE_ALTER_TENANT] = { ALTER_TENANT, CT_INVALID_ID32, sql_check_sys_priv_for_tenant },
    [CTSQL_TYPE_DROP_TENANT] = { DROP_TENANT, CT_INVALID_ID32, sql_check_sys_priv_for_tenant },
    [CTSQL_TYPE_INHERIT_PRIVILEGES] = { CT_INVALID_ID32, INHERIT_ANY_PRIVILEGES, sql_privs_no_check },
};

static status_t sql_check_other_privs(sql_stmt_t *stmt)
{
    sql_type_t type = stmt->context->type;
    priv_tab_def priv_def = g_priv_tab_def[type];

    CM_ASSERT(priv_def.proc != NULL);
    if (priv_def.proc == NULL) {
        return CT_ERROR;
    }

    if (priv_def.proc(stmt, priv_def.base_privid, priv_def.any_privid) != CT_SUCCESS) {
        cm_reset_error();
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_check_privilege(sql_stmt_t *stmt, bool32 need_lock_ctrl)
{
    /* no need to check SELECT privilege when execute add/enable check constraint sql */
    if (stmt->chk_priv == CT_FALSE) {
        return CT_SUCCESS;
    }
    /* when ctrl has been locked, then checking privilege is not need to modify ctrl->exec_ccount */
    if (stmt->lang_type == LANG_DML || stmt->lang_type == LANG_EXPLAIN) {
        return sql_check_dml_privs(stmt, need_lock_ctrl);
    }
    if (stmt->lang_type == LANG_PL) {
        return sql_check_pl_privs(stmt);
    }
    return sql_check_other_privs(stmt);
}

/*
 * check current user is dba or not
 */
bool32 sql_user_is_dba(session_t *session)
{
    text_t role = { DBA_ROLE, 3 };

    if (cm_text_str_equal_ins(&session->curr_user, "SYS")) {
        return CT_TRUE;
    }

    return knl_grant_role_with_option(&session->knl_session, &session->curr_user, &role, CT_FALSE);
}

/* check current user is dba or equal to object schema */
bool32 sql_check_schema_priv(session_t *session, text_t *obj_schema)
{
    if (cm_text_equal_ins(&session->curr_user, obj_schema)) {
        return CT_TRUE;
    }

    return sql_user_is_dba(session);
}

bool32 sql_check_stats_priv(session_t *session, text_t *obj_schema)
{
    if (sql_check_schema_priv(session, obj_schema)) {
        return CT_TRUE;
    }

    /* check sys priv */
    if (!cm_text_str_equal_ins(obj_schema, "SYS")) {
        return knl_check_sys_priv_by_uid(&session->knl_session, session->knl_session.uid, ANALYZE_ANY);
    } else {
        return CT_FALSE;
    }
}

bool32 sql_check_policy_exempt(session_t *session)
{
    if (cm_text_str_equal_ins(&session->curr_user, SYS_USER_NAME)) {
        return CT_TRUE;
    }

    return knl_check_sys_priv_by_uid(&session->knl_session, session->knl_session.uid, EXEMPT_ACCESS_POLICY);
}

status_t sql_check_xa_priv(knl_session_t *session, xa_xid_t *xa_xid)
{
    knl_xa_xid_t knl_xa_xid;
    dc_user_t *cur_user = NULL;
    dc_user_t *rm_user = NULL;
    uint16 rmid;
    knl_rm_t *rm = NULL;
    rm_pool_t *rm_pool = &g_instance->rm_pool;

    // sys has the privilege of any transactions
    if (session->uid == 0) {
        return CT_SUCCESS;
    }
    if (knl_convert_xa_xid(xa_xid, &knl_xa_xid) != CT_SUCCESS) {
        return CT_ERROR;
    }
    rmid = srv_get_xa_xid(&knl_xa_xid);
    if (rmid == CT_INVALID_ID16) {
        return CT_SUCCESS;
    }
    rm = rm_pool->rms[rmid];
    // other users do not have the privilege of sys transaction
    if (rm->uid == 0) {
        CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
        return CT_ERROR;
    }
    if (rm->uid == CT_INVALID_ID32) {
        CT_THROW_ERROR(ERR_XA_INVALID_XID, "XID not started");
        return CT_ERROR;
    }
    if (rm->uid == session->uid) {
        return CT_SUCCESS;
    }
    if (dc_open_user_by_id(session, session->uid, &cur_user) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (dc_open_user_by_id(session, rm->uid, &rm_user) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (cur_user->desc.tenant_id != rm_user->desc.tenant_id && cur_user->desc.tenant_id != 0) {
        CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
        return CT_ERROR;
    }
    if (!knl_check_sys_priv_by_uid(session, session->uid, FORCE_ANY_TRANSACTION)) {
        CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_check_profile_priv(sql_stmt_t *stmt, sys_privs_id base_privid, sys_privs_id any_privid)
{
    knl_session_t *knl_session = &stmt->session->knl_session;

    if (sql_check_user_tenant(knl_session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!knl_check_sys_priv_by_uid(knl_session, knl_session->uid, base_privid)) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

// return SUCCESS while user belong to TENANT$ROOT
status_t sql_check_user_tenant(knl_session_t *session)
{
    dc_user_t *user = NULL;

    if (dc_open_user_by_id(session, session->uid, &user) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (user->desc.tenant_id != SYS_TENANTROOT_ID) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ", only support for users in TENANT$ROOT");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_check_dump_priv(sql_stmt_t *stmt, knl_alter_sys_def_t *def)
{
    text_t sys_user = { "SYS", 3 };
    if (cm_text_equal_ins(&stmt->session->curr_user, &sys_user)) {
        return CT_SUCCESS;
    }

    if (cm_text_equal_ins(&def->dump_info.user_name, &stmt->session->curr_user)) {
        return CT_SUCCESS;
    }

    if (cm_text_equal_ins(&def->dump_info.user_name, &sys_user)) {
        CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
        return CT_ERROR;
    }

    text_t role = { DBA_ROLE, 3 };
    if (knl_grant_role_with_option(&stmt->session->knl_session, &stmt->session->curr_user, &role, CT_FALSE)) {
        return CT_SUCCESS;
    }

    CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
    return CT_ERROR;
}

#ifdef __cplusplus
}
#endif

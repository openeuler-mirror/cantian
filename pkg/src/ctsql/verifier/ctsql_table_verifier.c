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
 * ctsql_table_verifier.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/verifier/ctsql_table_verifier.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_table_verifier.h"
#include "dml_parser.h"
#include "cond_parser.h"
#include "srv_instance.h"
#include "ctsql_table_func.h"
#include "ctsql_dependency.h"
#include "ctsql_privilege.h"
#include "ctsql_json_table.h"
#include "cm_error.h"

#ifdef __cplusplus
extern "C" {
#endif


char *sql_get_dml_type(trig_dml_type_t dml_type)
{
    switch (dml_type) {
        case TRIG_EVENT_INSERT:
            return "INSERT";
        case TRIG_EVENT_UPDATE:
            return "UPDATE";
        case TRIG_EVENT_DELETE:
            return "DELETE";
        default:
            CM_ASSERT(0);
            return NULL;
    }
}

status_t sql_verify_view_insteadof_trig(sql_stmt_t *stmt, sql_table_t *table, trig_dml_type_t dml_type)
{
    knl_dictionary_t *dc = &table->entry->dc;
    dc_entity_t *dc_entity = NULL;
    bool32 is_found = CT_FALSE;
    trig_set_t *trig_set = NULL;
    trig_item_t *item = NULL;

    if (table->type != VIEW_AS_TABLE) {
        return CT_SUCCESS;
    }

    dc_entity = DC_ENTITY(dc);
    trig_set = &dc_entity->trig_set;
    if (trig_set->trig_count == 0) {
        CT_SRC_THROW_ERROR_EX(table->name.loc, ERR_SQL_SYNTAX_ERROR,
            "view operation %s must based on instead of "
            "trigger but current view has no trigger",
            sql_get_dml_type(dml_type));
        return CT_ERROR;
    }

    for (uint32 i = 0; i < trig_set->trig_count; ++i) {
        item = &trig_set->items[i];

        if (!item->trig_enable) {
            continue;
        }

        if ((uint32)item->trig_type == TRIG_INSTEAD_OF && (item->trig_event & (uint8)dml_type)) {
            is_found = CT_TRUE;
            break;
        }
    }

    if (!is_found) {
        CT_SRC_THROW_ERROR_EX(table->name.loc, ERR_SQL_SYNTAX_ERROR,
            "view operation %s must based on instead of "
            "tigger but %s.%s not have instead of trigger correspondings",
            sql_get_dml_type(dml_type), T2S(&table->user.value), T2S_EX(&table->name.value));
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

bool32 sql_search_table_name(sql_table_t *query_table, text_t *user, text_t *alias)
{
    if (user->len > 0 && !cm_text_equal(&query_table->user.value, user)) {
        return CT_FALSE;
    }

    if (query_table->alias.value.len > 0 && !query_table->alias.implicit) {
        return cm_text_equal(&query_table->alias.value, alias);
    }

    return cm_text_equal(&query_table->name.value, alias);
}

static status_t sql_search_table_in_table(sql_table_t *src_table, text_t *user, text_t *alias, sql_table_t **table,
    bool32 *is_found)
{
    if (sql_search_table_name(src_table, user, alias)) {
        *table = src_table;
        *is_found = CT_TRUE;
    }
    return CT_SUCCESS;
}

static status_t sql_search_table_in_table_list(sql_array_t *tables, expr_node_t *node, text_t *user, text_t *alias,
    sql_table_t **table, bool32 *is_found)
{
    for (uint32 i = 0; i < tables->count; i++) {
        sql_table_t *tmp_table = (sql_table_t *)sql_array_get(tables, i);

        if (sql_search_table_name(tmp_table, user, alias)) {
            if (*is_found) {
                CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "column ambiguously defined");
                return CT_ERROR;
            }
            *is_found = CT_TRUE;
            *table = tmp_table;
        }
    }
    return CT_SUCCESS;
}

status_t sql_search_table_local(sql_verifier_t *verif, expr_node_t *node, text_t *user, text_t *alias,
    sql_table_t **table, bool32 *is_found)
{
    if (verif->tables == NULL) { // for non select
        if (verif->table == NULL) {
            CT_SRC_THROW_ERROR_EX(node->loc, ERR_SQL_SYNTAX_ERROR, "invalid table alias '%s'", T2S(alias));
            return CT_ERROR;
        }
        CT_RETURN_IFERR(sql_search_table_in_table(verif->table, user, alias, table, is_found));
    } else {
        CT_RETURN_IFERR(sql_search_table_in_table_list(verif->tables, node, user, alias, table, is_found));
    }

    if (*is_found) {
        if (verif->join_tab_id == CT_INVALID_ID32) {
            verif->join_tab_id = (*table)->id;
        } else if (verif->join_tab_id != (*table)->id) {
            verif->same_join_tab = CT_FALSE;
        }
    }

    return CT_SUCCESS;
}

static inline status_t sql_create_parent_ref(sql_stmt_t *stmt, galist_t *parent_refs, uint32 tab, expr_node_t *node)
{
    parent_ref_t *parent_ref = NULL;

    CT_RETURN_IFERR(cm_galist_new(parent_refs, sizeof(parent_ref_t), (void **)&parent_ref));
    parent_ref->tab = tab;
    CT_RETURN_IFERR(sql_create_list(stmt, &parent_ref->ref_columns));
    CT_RETURN_IFERR(cm_galist_insert(parent_ref->ref_columns, node));
    node->parent_ref = CT_TRUE;
    return CT_SUCCESS;
}

status_t sql_add_parent_refs(sql_stmt_t *stmt, galist_t *parent_refs, uint32 tab, expr_node_t *node)
{
    parent_ref_t *parent_ref = NULL;

    if (node->parent_ref) {
        return CT_SUCCESS;
    }
    for (uint32 i = 0; i < parent_refs->count; i++) {
        parent_ref = (parent_ref_t *)cm_galist_get(parent_refs, i);
        if (parent_ref->tab == tab) {
            CT_RETURN_IFERR(cm_galist_insert(parent_ref->ref_columns, node));
            node->parent_ref = CT_TRUE;
            return CT_SUCCESS;
        }
    }
    return sql_create_parent_ref(stmt, parent_refs, tab, node);
}

void sql_del_parent_refs(galist_t *parent_refs, uint32 tab, expr_node_t *node)
{
    parent_ref_t *parent_ref = NULL;
    expr_node_t *exist_node = NULL;
    galist_t *ref_cols = NULL;

    for (uint32 i = 0; i < parent_refs->count; i++) {
        parent_ref = (parent_ref_t *)cm_galist_get(parent_refs, i);
        if (parent_ref->tab != tab) {
            continue;
        }
        ref_cols = parent_ref->ref_columns;
        for (uint32 j = 0; j < ref_cols->count; ++j) {
            exist_node = (expr_node_t *)cm_galist_get(ref_cols, j);
            if (exist_node == node) {
                cm_galist_delete(ref_cols, j);
                exist_node->parent_ref = CT_FALSE;
                if (ref_cols->count == 0) {
                    cm_galist_delete(parent_refs, i);
                }
                return; // one expr_node can be added only once
            }
        }
    }
}

status_t sql_search_table_parent(sql_verifier_t *verif, expr_node_t *node, text_t *user, text_t *alias,
    sql_table_t **table, uint32 *level, bool32 *is_found)
{
    sql_select_t *prev_ctx = verif->select_ctx;
    sql_verifier_t *parent_verf = verif->parent;

    if (prev_ctx == NULL) {
        return CT_SUCCESS;
    }

    verif->same_join_tab = CT_FALSE;
    verif->incl_flags |= SQL_INCL_PRNT_OR_ANCSTR;

    sql_query_t *parent = prev_ctx->parent;

    while (parent_verf != NULL && parent != NULL) {
        (*level)++;
        if (parent_verf->tables != NULL) {
            CT_RETURN_IFERR(sql_search_table_in_table_list(parent_verf->tables, node, user, alias, table, is_found));
        }
        if (*is_found || parent->owner == NULL) {
            if (*is_found) {
                CT_RETURN_IFERR(sql_add_parent_refs(verif->stmt, prev_ctx->parent_refs, (*table)->id, node));
            }
            break;
        }
        prev_ctx = parent->owner;
        parent = prev_ctx->parent;
        parent_verf = parent_verf->parent;
    }
    sql_set_ancestor_level(verif->select_ctx, *level);
    return CT_SUCCESS;
}

status_t sql_search_table(sql_verifier_t *verif, expr_node_t *node, text_t *user, text_t *alias, sql_table_t **table,
    uint32 *level)
{
    bool32 is_found = CT_FALSE;

    CT_RETURN_IFERR(sql_search_table_local(verif, node, user, alias, table, &is_found));
    if (is_found) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(sql_search_table_parent(verif, node, user, alias, table, level, &is_found));
    if (!is_found) {
        CT_SRC_THROW_ERROR_EX(node->loc, ERR_SQL_SYNTAX_ERROR, "invalid table alias '%s'", T2S(alias));
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_table_cache_query_field_impl(sql_stmt_t *stmt, sql_table_t *table, query_field_t *src_query_fld,
    bool8 is_cond_col)
{
    query_field_t *query_field = NULL;
    query_field_t *new_field = NULL;
    bilist_node_t *node = cm_bilist_head(&table->query_fields);

    for (; node != NULL; node = BINODE_NEXT(node)) {
        query_field = BILIST_NODE_OF(query_field_t, node, bilist_node);
        if (src_query_fld->col_id < query_field->col_id) {
            break;
        }
        if (src_query_fld->col_id == query_field->col_id) {
            if (is_cond_col) {
                query_field->is_cond_col = is_cond_col;
            }
            query_field->ref_count++;
            return CT_SUCCESS;
        }
    }
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(query_field_t), (void **)&new_field));
    new_field->col_id = src_query_fld->col_id;
    new_field->datatype = src_query_fld->datatype;
    new_field->is_array = src_query_fld->is_array;
    new_field->start = src_query_fld->start;
    new_field->end = src_query_fld->end;
    new_field->is_cond_col = is_cond_col;
    new_field->ref_count = 1;

    if (node == NULL) {
        cm_bilist_add_tail(&new_field->bilist_node, &table->query_fields);
    } else {
        cm_bilist_add_prev(&new_field->bilist_node, node, &table->query_fields);
    }
    return CT_SUCCESS;
}

status_t sql_table_cache_query_field(sql_stmt_t *stmt, sql_table_t *table, query_field_t *src_query_fld)
{
    return sql_table_cache_query_field_impl(stmt, table, src_query_fld, CT_FALSE);
}

status_t sql_table_cache_cond_query_field(sql_stmt_t *stmt, sql_table_t *table, query_field_t *src_query_fld)
{
    return sql_table_cache_query_field_impl(stmt, table, src_query_fld, CT_TRUE);
}

void get_view_user(sql_verifier_t *verif, sql_table_t *table, text_t *owner)
{
    if (table->type == VIEW_AS_TABLE) {
        if (table->entry->dc.is_sysnonym && table->entry->dc.syn_handle) {
            dc_entry_t *entry = (dc_entry_t *)table->entry->dc.syn_handle;
            synonym_link_t *synonym_link = entry->appendix->synonym_link;
            cm_str2text(synonym_link->user, owner);
        } else {
            *owner = table->user.value;
        }
    } else {
        owner->str = NULL;
        owner->len = 0;
    }
}

static status_t sql_generate_unnamed_pivot_table_name(sql_stmt_t *stmt, sql_table_t *table)
{
    if (table->select_ctx->first_query->pivot_items == NULL) {
        return CT_SUCCESS;
    }
    if (table->select_ctx->first_query->pivot_items->type == PIVOT_TYPE) {
        CT_RETURN_IFERR(sql_generate_unnamed_table_name(stmt, table, TAB_TYPE_PIVOT));
    } else {
        CT_RETURN_IFERR(sql_generate_unnamed_table_name(stmt, table, TAB_TYPE_UNPIVOT));
    }
    return CT_SUCCESS;
}

static status_t sql_verify_subselect_table(sql_verifier_t *verif, sql_query_t *query, sql_table_t *table)
{
    text_t view_owner;
    saved_schema_t saved_schema;

    if (table->type == WITH_AS_TABLE) {
        CT_RETURN_IFERR(sql_create_project_columns(verif->stmt, table));
        return CT_SUCCESS;
    }

    if (table->type == SUBSELECT_AS_TABLE || table->type == VIEW_AS_TABLE) {
        table->select_ctx->parent = query;
    }

    // for plsql objects in view
    get_view_user(verif, table, &view_owner);
    CT_RETURN_IFERR(sql_switch_schema_by_name(verif->stmt, &view_owner, &saved_schema));
    status_t status = sql_verify_sub_select(verif->stmt, table->select_ctx, verif);
    sql_restore_schema(verif->stmt, &saved_schema);
    CT_RETURN_IFERR(status);

    CT_RETURN_IFERR(sql_create_project_columns(verif->stmt, table));
    if (table->type == SUBSELECT_AS_TABLE && table->alias.len == 0) {
        CT_RETURN_IFERR(sql_generate_unnamed_pivot_table_name(verif->stmt, table));
    }
    return CT_SUCCESS;
}

static status_t sql_verify_specify_part_info(sql_verifier_t *verif, sql_table_t *table)
{
    uint32 excl_flags;
    expr_tree_t *expr = NULL;

    if (table->part_info.type == SPECIFY_PART_NONE) {
        return CT_SUCCESS;
    }

    if (table->type != NORMAL_TABLE || !knl_is_part_table(table->entry->dc.handle)) {
        CT_SRC_THROW_ERROR_EX(table->name.loc, ERR_SQL_SYNTAX_ERROR, "%s is not a partition table", T2S(&table->name));
        return CT_ERROR;
    }

    if (table->part_info.type == SPECIFY_PART_VALUE) {
        uint32 count = table->part_info.values->count;
        uint32 partkey_count = knl_part_key_count(table->entry->dc.handle);

        if (table->part_info.is_subpart) {
            if (!knl_is_compart_table(table->entry->dc.handle)) {
                CT_SRC_THROW_ERROR_EX(table->name.loc, ERR_SQL_SYNTAX_ERROR, "%s is not a composite partition table",
                    T2S(&table->name));
                return CT_ERROR;
            }

            partkey_count += knl_subpart_key_count(table->entry->dc.handle);
        }

        if (count != partkey_count) {
            CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "value count not equal to the number of partitioning columns");
            return CT_ERROR;
        }

        excl_flags = verif->excl_flags;
        verif->excl_flags = SQL_EXCL_AGGR | SQL_EXCL_SEQUENCE | SQL_EXCL_STAR | SQL_EXCL_PRIOR;

        for (uint32 i = 0; i < count; i++) {
            expr = (expr_tree_t *)cm_galist_get(table->part_info.values, i);
            CT_RETURN_IFERR(sql_verify_expr(verif, expr));
        }
        verif->excl_flags = excl_flags;
    }
    return CT_SUCCESS;
}

static status_t sql_switch_tenant_by_uid(sql_stmt_t *stmt, uint32 switch_uid, saved_tenant_t *tenant)
{
    dc_user_t *dc_user = NULL;
    dc_tenant_t *dc_tenant = NULL;

    tenant->id = CT_INVALID_ID32;
    if (dc_open_user_by_id(KNL_SESSION(stmt), switch_uid, &dc_user) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc_user->desc.tenant_id == stmt->session->curr_tenant_id) {
        return CT_SUCCESS;
    }

    if (dc_open_tenant_by_id(KNL_SESSION(stmt), dc_user->desc.tenant_id, &dc_tenant) != CT_SUCCESS) {
        return CT_ERROR;
    }

    MEMS_RETURN_IFERR(
        strncpy_s(tenant->name, CT_TENANT_BUFFER_SIZE, stmt->session->curr_tenant, strlen(stmt->session->curr_tenant)));
    tenant->id = stmt->session->curr_tenant_id;

    MEMS_RETURN_IFERR(strncpy_s(stmt->session->curr_tenant, CT_TENANT_BUFFER_SIZE, dc_tenant->desc.name,
        strlen(dc_tenant->desc.name)));
    stmt->session->curr_tenant_id = dc_tenant->desc.id;

    return CT_SUCCESS;
}

static void sql_restore_tenant(sql_stmt_t *stmt, saved_tenant_t *tenant)
{
    if (tenant->id == CT_INVALID_ID32) {
        return;
    }

    dc_close_tenant(KNL_SESSION(stmt), stmt->session->curr_tenant_id);
    errno_t errcode = strncpy_s(stmt->session->curr_tenant, CT_TENANT_BUFFER_SIZE, tenant->name, strlen(tenant->name));
    MEMS_RETVOID_IFERR(errcode);

    stmt->session->curr_tenant_id = tenant->id;
    return;
}

status_t sql_create_query_view(sql_stmt_t *stmt, sql_table_t *query_table)
{
    text_t sub_sql;
    uint32 large_page_id = CT_INVALID_ID32;
    knl_session_t *knl_session = &stmt->session->knl_session;
    knl_dictionary_t *dc = &query_table->entry->dc;

    query_table->type = VIEW_AS_TABLE;
    saved_schema_t schema;
    saved_tenant_t tenant;

    status_t status = knl_get_view_sub_sql(knl_session, dc, &sub_sql, &large_page_id);
    CT_RETURN_IFERR(status);
    do {
        status = sql_switch_schema_by_uid(stmt, dc->uid, &schema);
        CT_BREAK_IF_ERROR(status);
        status = sql_switch_tenant_by_uid(stmt, dc->uid, &tenant);
        if (status != CT_SUCCESS) {
            sql_restore_schema(stmt, &schema);
            break;
        }
        status = sql_parse_view_subselect(stmt, &sub_sql, &query_table->select_ctx, &query_table->user.loc);
        sql_restore_tenant(stmt, &tenant);
        sql_restore_schema(stmt, &schema);
    } while (0);

    if (large_page_id != CT_INVALID_ID32) {
        mpool_free_page(knl_session->kernel->attr.large_pool, large_page_id);
    }

    return status;
}

status_t sql_init_normal_query_table(sql_stmt_t *stmt, sql_table_t *sql_table, sql_query_t *parent_query)
{
    if (sql_create_project_columns(stmt, sql_table) != CT_SUCCESS) {
        return CT_ERROR;
    }
    CT_RETURN_IFERR(sql_apend_dependency_table(stmt, sql_table));
    if (sql_table->entry->dc.type == DICT_TYPE_VIEW) {
        SAVE_AND_RESET_NODE_STACK(stmt);
        CT_RETURN_IFERR(sql_create_query_view(stmt, sql_table));
        sql_table->select_ctx->parent = parent_query;
        SQL_RESTORE_NODE_STACK(stmt);
    }
    return CT_SUCCESS;
}

bool32 sql_table_belong_self(sql_stmt_t *stmt, knl_dictionary_t *dc)
{
    uint32 uid = stmt->session->knl_session.uid;
    text_t *curr_user = &stmt->session->curr_user;

    if (stmt->pl_compiler != NULL || stmt->pl_exec != NULL) {
        return CT_FALSE;
    }
    if (cm_compare_text_str_ins(&stmt->session->curr_user, stmt->session->curr_schema) != 0) {
        return CT_FALSE;
    }
    if (SYNONYM_EXIST(dc)) {
        text_t link_user;
        text_t link_name;
        knl_get_link_name(dc, &link_user, &link_name);

        if (!cm_text_equal_ins(&link_user, curr_user)) {
            return CT_FALSE;
        }
    } else {
        if (uid != dc->uid) {
            return CT_FALSE;
        }
    }
    return CT_TRUE;
}

bool32 sql_check_any_priv(sql_stmt_t *stmt, text_t *obj_user, uint32 any_priv_id)
{
    knl_session_t *knl_se = &stmt->session->knl_session;
    bool32 has_any_privs = CT_FALSE;
    bool32 has_any_dictionary = CT_FALSE;

    if ((knl_se->uid == 0) || (cm_compare_text(&stmt->session->curr_user, obj_user) == 0)) {
        return CT_TRUE;
    }
    has_any_privs = knl_check_sys_priv_by_name(knl_se, &stmt->session->curr_user, any_priv_id);
    has_any_dictionary = knl_check_sys_priv_by_name(knl_se, &stmt->session->curr_user, SELECT_ANY_DICTIONARY);
    if (cm_text_str_equal_ins(obj_user, SYS_USER_NAME)) {
        if ((any_priv_id == SELECT_ANY_TABLE) &&
            (has_any_dictionary || (has_any_privs && g_instance->attr.access_dc_enable))) {
            return CT_TRUE;
        } else {
            return CT_FALSE;
        }
    } else {
        return has_any_privs;
    }
}

void sql_check_user_priv(sql_stmt_t *stmt, text_t *obj_user)
{
    const char *msg = NULL;
    int32 code;
    uint32 priv_id = sql_get_any_priv_id(stmt);
    if (priv_id == CT_SYS_PRIVS_COUNT) {
        return;
    }
    cm_get_error(&code, &msg, NULL);
    if ((ERR_SEQ_NOT_EXIST == code) && (priv_id == SELECT_ANY_TABLE)) {
        priv_id = SELECT_ANY_SEQUENCE;
    }

    if (((ERR_TABLE_OR_VIEW_NOT_EXIST == code) || (ERR_DISTRIBUTE_RULE_NOT_EXIST == code) ||
        (ERR_INDEX_NOT_EXIST == code) || (ERR_USER_OBJECT_NOT_EXISTS == code) || (ERR_SEQ_NOT_EXIST == code) ||
        (ERR_USER_NOT_EXIST == code)) &&
        (sql_check_any_priv(stmt, obj_user, priv_id) == CT_FALSE)) {
        cm_reset_error();
        CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
    }
}

static bool32 is_policy_exists(sql_stmt_t *stmt, knl_dictionary_t *dc)
{
    dc_entity_t *dc_entity = DC_ENTITY(dc);
    table_t *knl_table = &dc_entity->table;

    for (uint32 i = 0; i < knl_table->policy_set.plcy_count; i++) {
        policy_def_t *table_policy = knl_table->policy_set.policies[i];
        if (table_policy->enable == CT_TRUE && stmt->session->curr_schema_id != DB_SYS_USER_ID &&
            !cm_text_equal_ins(&stmt->session->curr_user, &table_policy->function_owner)) {
            return CT_TRUE;
        }
    }

    return CT_FALSE;
}

static status_t sql_get_table_dc(sql_stmt_t *stmt, sql_table_t *sql_table)
{
    knl_handle_t knl_session = &stmt->session->knl_session;
    knl_dictionary_t dc;

    knl_set_session_scn(knl_session, CT_INVALID_ID64);

    if (sql_table->dblink.len == 0) {
        if (knl_open_dc_with_public(knl_session, &sql_table->user.value, sql_table->user.implicit,
            &sql_table->name.value, &dc) != CT_SUCCESS) {
            cm_set_error_loc(sql_table->user.loc);
            sql_check_user_priv(stmt, &sql_table->user.value);
            return CT_ERROR;
        }
    } else {
        CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "select wtih @dblink on DBLINK table");
        return CT_ERROR;
    }

    sql_table->entry->dc = dc;
    return CT_SUCCESS;
}

status_t sql_init_table_dc(sql_stmt_t *stmt, sql_table_t *sql_table)
{
    // normal table no need to reload entry except dblink table
    if (sql_table->entry->dc.type != DICT_TYPE_UNKNOWN && sql_table->dblink.len == 0) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(sql_get_table_dc(stmt, sql_table));

    knl_dictionary_t *dc = &sql_table->entry->dc;

    if (stmt->context->obj_belong_self == CT_TRUE && is_policy_exists(stmt, dc)) {
        stmt->context->obj_belong_self = CT_FALSE;
    }
    if (stmt->context->obj_belong_self == CT_TRUE && !sql_table_belong_self(stmt, dc)) {
        stmt->context->obj_belong_self = CT_FALSE;
    }

    return CT_SUCCESS;
}

status_t sql_init_normal_table_dc(sql_stmt_t *stmt, sql_table_t *sql_table, sql_query_t *parent_query)
{
    if (sql_table->type == SUBSELECT_AS_TABLE || sql_table->type == WITH_AS_TABLE || sql_table->type == FUNC_AS_TABLE ||
        sql_table->type == JSON_TABLE) {
        return CT_SUCCESS;
    }
    CT_RETURN_IFERR(sql_init_table_dc(stmt, sql_table));
    CT_RETURN_IFERR(sql_init_normal_query_table(stmt, sql_table, parent_query));
    return CT_SUCCESS;
}

static status_t sql_verify_generate_tf_tab(sql_verifier_t *verif, sql_query_t *query, sql_table_t *table)
{
    sql_text_t arg_table;
    word_t word;
    var_word_t var;
    uint32 flags;

    if (!IS_DYNAMIC_TBL_FUNC(table->func.desc)) {
        return CT_SUCCESS;
    }

    if ((table->func.args == NULL) || (table->func.args->root == NULL) ||
        (table->func.args->root->value.type != CT_TYPE_CHAR)) {
        CT_THROW_ERROR(ERR_INVALID_TABFUNC_1ST_ARG);
        return CT_ERROR;
    }

    table->ret_full_fields = CT_TRUE;
    arg_table.value = table->func.args->root->value.v_text;
    arg_table.loc = table->func.args->loc;
    arg_table.implicit = CT_FALSE;

    flags = verif->stmt->session->lex->flags;
    verif->stmt->session->lex->flags = LEX_WITH_OWNER;
    CT_RETURN_IFERR(lex_push(verif->stmt->session->lex, &arg_table));
    if (lex_expected_fetch(verif->stmt->session->lex, &word) != CT_SUCCESS) {
        lex_pop(verif->stmt->session->lex);
        return CT_ERROR;
    }
    if (sql_word_as_table(verif->stmt, &word, &var) != CT_SUCCESS) {
        lex_pop(verif->stmt->session->lex);
        return CT_ERROR;
    }
    lex_pop(verif->stmt->session->lex);
    verif->stmt->session->lex->flags = flags;

    table->user = var.table.user;
    table->name = var.table.name;

    return CT_SUCCESS;
}

static status_t sql_calc_policy_func_value(sql_verifier_t *verif, sql_text_t *sql_text, variant_t *expr_var)
{
    expr_tree_t *plcy_calc_expr = NULL;
    sql_text->loc.column = 1;
    sql_text->loc.line = 1;
    verif->stmt->session->lex->flags = LEX_WITH_OWNER | LEX_WITH_ARG;
    if (CT_SUCCESS != sql_create_expr_from_text(verif->stmt, sql_text, &plcy_calc_expr, WORD_FLAG_NONE)) {
        cm_reset_error();
        CT_THROW_ERROR(ERR_POLICY_FUNC_CLAUSE);
        return CT_ERROR;
    }

    sql_verifier_t func_verf = { 0 };
    verif->stmt->is_verifying = CT_TRUE;
    func_verf.stmt = verif->stmt;
    func_verf.context = verif->stmt->context;
    if (sql_verify_expr(&func_verf, plcy_calc_expr) != CT_SUCCESS) {
        cm_reset_error();
        verif->stmt->is_verifying = CT_FALSE;
        CT_THROW_ERROR(ERR_POLICY_EXEC_FUNC, "Insufficient privilege or function invalid");
        return CT_ERROR;
    }
    if (sql_exec_expr_node(func_verf.stmt, plcy_calc_expr->root, expr_var) != CT_SUCCESS) {
        cm_reset_error();
        verif->stmt->is_verifying = CT_FALSE;
        CT_THROW_ERROR(ERR_POLICY_EXEC_FUNC, "failed to execute");
        return CT_ERROR;
    }
    if (CT_IS_STRING_TYPE(expr_var->type) != CT_TRUE) {
        cm_reset_error();
        verif->stmt->is_verifying = CT_FALSE;
        CT_THROW_ERROR(ERR_POLICY_EXEC_FUNC, "Function return type error");
        return CT_ERROR;
    }
    verif->stmt->is_verifying = CT_FALSE;
    return CT_SUCCESS;
}

static status_t sql_create_policies_cond(sql_verifier_t *verif, sql_query_t *query, text_t *clause_text)
{
    cond_tree_t *plcy_cond_tree = NULL;
    bool32 is_expr = CT_TRUE;
    sql_text_t cond_text;

    if (CM_IS_EMPTY(clause_text)) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(sql_copy_text(verif->stmt->context, clause_text, &cond_text.value));
    cond_text.loc.column = 1;
    cond_text.loc.line = 1;

    CT_RETURN_IFERR(sql_create_cond_from_text(verif->stmt, &cond_text, &plcy_cond_tree, &is_expr));

    if (query->cond == NULL) {
        query->cond = plcy_cond_tree;
        return CT_SUCCESS;
    }
    // merge query->policy_cond into query->cond
    return sql_add_cond_node(query->cond, plcy_cond_tree->root);
}

static bool32 sql_check_policy_type(sql_verifier_t *verif, policy_def_t *table_policy)
{
    // as sub select, return true
    if (verif->select_ctx != NULL && verif->select_ctx->type != SELECT_AS_RESULT) {
        return CT_TRUE;
    }
    // as result, check DML type
    uint32 ctx_type = verif->stmt->context->type;
    switch (ctx_type) {
        case CTSQL_TYPE_SELECT:
            return (bool32)(table_policy->stmt_types & STMT_SELECT);
        case CTSQL_TYPE_UPDATE:
            return (bool32)(table_policy->stmt_types & STMT_UPDATE);
        case CTSQL_TYPE_INSERT:
            return (bool32)(table_policy->stmt_types & STMT_INSERT);
        case CTSQL_TYPE_DELETE:
            return (bool32)(table_policy->stmt_types & STMT_DELETE);
        case CTSQL_TYPE_MERGE:
            return (bool32)(table_policy->stmt_types & STMT_SELECT);
        default:
            return CT_FALSE;
    }
}

static void sql_concat_func_text(text_t *func_txt, const char *schema, policy_def_t *table_policy)
{
    func_txt->len = 0;
    cm_concat_text(func_txt, SQL_POLICY_FUNC_STR_LEN, &table_policy->function_owner);
    cm_concat_string(func_txt, SQL_POLICY_FUNC_STR_LEN, ".");
    cm_concat_text(func_txt, SQL_POLICY_FUNC_STR_LEN, &table_policy->function);
    cm_concat_string(func_txt, SQL_POLICY_FUNC_STR_LEN, "('");
    cm_concat_string(func_txt, SQL_POLICY_FUNC_STR_LEN, schema);
    cm_concat_string(func_txt, SQL_POLICY_FUNC_STR_LEN, "','");
    cm_concat_text(func_txt, SQL_POLICY_FUNC_STR_LEN, &table_policy->object_name);
    cm_concat_string(func_txt, SQL_POLICY_FUNC_STR_LEN, "')");
}

static status_t sql_concat_policies(text_t *clause_text, sql_verifier_t *verif, text_t *alias, table_t *knl_table)
{
    sql_text_t sql_text;
    text_t node_text;
    variant_t expr_value;
    char node_str[SQL_POLICY_FUNC_STR_LEN] = { 0 };
    cm_str2text_safe(node_str, 0, &node_text);
    text_t and_text = {
        .str = " and ",
        .len = 5
    };

    // create expr_node from text, then calculate expr_node value
    for (uint32 i = 0; i < knl_table->policy_set.plcy_count; i++) {
        policy_def_t *table_policy = knl_table->policy_set.policies[i];
        if (table_policy->enable == CT_TRUE) {
            if (!sql_check_policy_type(verif, table_policy)) {
                continue;
            }

            sql_concat_func_text(&node_text, verif->stmt->session->curr_schema, table_policy);
            sql_text.value = node_text;
            CT_RETURN_IFERR(sql_calc_policy_func_value(verif, &sql_text, &expr_value));
            if (CM_IS_EMPTY(&expr_value.v_text)) {
                continue;
            }

            cm_concat_string(clause_text, CT_BUFLEN_4K, "(");
            if (!CM_IS_EMPTY(alias)) {
                cm_concat_text(clause_text, CT_BUFLEN_4K, alias);
                cm_concat_string(clause_text, CT_BUFLEN_4K, ".");
            }
            cm_concat_text(clause_text, CT_BUFLEN_4K, &expr_value.v_text);
            cm_concat_string(clause_text, CT_BUFLEN_4K, ")");
            cm_concat_text(clause_text, CT_BUFLEN_4K, &and_text);
        }
    }

    if (!CM_IS_EMPTY(clause_text)) {
        cm_rtrim_text_func(clause_text, &and_text);
    }
    return CT_SUCCESS;
}

status_t sql_get_table_policies(sql_verifier_t *verif, sql_table_t *table, text_t *clause_text, bool32 *exists)
{
    knl_dictionary_t *dc = &table->entry->dc;
    dc_entity_t *dc_entity = DC_ENTITY(dc);
    table_t knl_table = dc_entity->table;
    *exists = CT_FALSE;
    if (dc->type != DICT_TYPE_TABLE || IS_SYS_TABLE(&knl_table) || IS_DUAL_TABLE(&knl_table) ||
        knl_table.policy_set.plcy_count == 0) {
        verif->context->policy_used = CT_FALSE;
        return CT_SUCCESS;
    }

    verif->context->policy_used = CT_TRUE;
    if (sql_check_policy_exempt(verif->stmt->session)) {
        return CT_SUCCESS;
    }
    *exists = CT_TRUE;
    char *clause_str = NULL;
    if (sql_push(verif->stmt, CT_BUFLEN_4K, (void **)&clause_str) != CT_SUCCESS) {
        return CT_ERROR;
    }
    errno_t errcode = memset_sp(clause_str, CT_BUFLEN_4K, 0, CT_BUFLEN_4K);
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return CT_ERROR;
    }

    text_t alias_txt = table->alias.value;
    cm_str2text(clause_str, clause_text);
    if (sql_concat_policies(clause_text, verif, &alias_txt, &knl_table) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

/* VPD(virtual policy database) condition generator */
static status_t sql_init_table_policies(sql_verifier_t *verif, sql_query_t *query, sql_table_t *table)
{
    text_t clause_text;
    bool32 exists;
    CTSQL_SAVE_STACK(verif->stmt);
    if (sql_get_table_policies(verif, table, &clause_text, &exists) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(verif->stmt);
        return CT_ERROR;
    }

    if (!exists) {
        CTSQL_RESTORE_STACK(verif->stmt);
        return CT_SUCCESS;
    }

    if (sql_create_policies_cond(verif, query, &clause_text) != CT_SUCCESS) {
        cm_reset_error();
        CTSQL_RESTORE_STACK(verif->stmt);
        CT_THROW_ERROR(ERR_POLICY_EXEC_FUNC, "function convert to condition failed");
        return CT_ERROR;
    }
    CTSQL_RESTORE_STACK(verif->stmt);
    return CT_SUCCESS;
}

static inline status_t sql_verify_func_as_table(sql_verifier_t *verif, sql_query_t *query, sql_table_t *table,
    uint32 tab_id)
{
    uint32 saved_flags = verif->excl_flags;
    verif->verify_tables = CT_TRUE;
    CT_BIT_SET(verif->excl_flags, SQL_EXCL_ROWID | SQL_EXCL_ROWNODEID | SQL_EXCL_ROWSCN);
    if (sql_describe_table_func(verif, table, tab_id) != CT_SUCCESS) {
        verif->verify_tables = CT_FALSE;
        return CT_ERROR;
    }
    if (sql_verify_generate_tf_tab(verif, query, table) != CT_SUCCESS) {
        verif->verify_tables = CT_FALSE;
        return CT_ERROR;
    }
    if (table->name.len == 0 && table->alias.len == 0) {
        if (sql_generate_unnamed_table_name(verif->stmt, table, TAB_TYPE_TABLE_FUNC) != CT_SUCCESS) {
            verif->verify_tables = CT_FALSE;
            return CT_ERROR;
        }
    }
    verif->excl_flags = saved_flags;
    verif->verify_tables = CT_FALSE;

    return CT_SUCCESS;
}

static void sql_inherit_table_version(select_node_t *node, sql_table_snapshot_t table_version)
{
    if (node->type == SELECT_NODE_QUERY) {
        for (uint32 i = 0; i < node->query->tables.count; i++) {
            sql_table_t *table = (sql_table_t *)sql_array_get(&node->query->tables, i);
            if (table->version.type == CURR_VERSION) {
                table->version = table_version;
            }
        }
        return;
    }
    sql_inherit_table_version(node->left, table_version);
    sql_inherit_table_version(node->right, table_version);
}

static status_t sql_verify_view_as_table(sql_verifier_t *verif, sql_query_t *query, sql_table_t *table)
{
    SAVE_REFERENCES_LIST(verif->stmt);
    verif->stmt->context->ref_objects = NULL;
    if (sql_verify_subselect_table(verif, query, table) != CT_SUCCESS) {
        if ((g_tls_error.code == ERR_INSUFFICIENT_PRIV)) {
            cm_reset_error();
            CT_THROW_ERROR(ERR_SQL_VIEW_ERROR, T2S(&table->name.value));
        }
        RESTORE_REFERENCES_LIST(verif->stmt);
        return CT_ERROR;
    }
    RESTORE_REFERENCES_LIST(verif->stmt);
    if (table->version.type != CURR_VERSION) {
        sql_inherit_table_version(table->select_ctx->root, table->version);
    }
    return CT_SUCCESS;
}

status_t sql_verify_tables(sql_verifier_t *verif, sql_query_t *query)
{
    sql_array_t *tables = &query->tables;

    verif->tables = NULL;
    for (uint32 i = 0; i < tables->count; i++) {
        sql_table_t *table = (sql_table_t *)sql_array_get(tables, i);
        if (sql_init_normal_table_dc(verif->stmt, table, query) != CT_SUCCESS) {
            cm_reset_error_user(ERR_TABLE_OR_VIEW_NOT_EXIST, T2S(&table->user.value), T2S_EX(&table->name.value),
                ERR_TYPE_TABLE_OR_VIEW);
            cm_set_error_loc(table->user.loc);
            return CT_ERROR;
        }
        // sql_match_cbo_cond
        if (!CT_IS_SUBSELECT_TABLE(table->type) && !IS_ANALYZED_TABLE(table)) {
            verif->stmt->context->opt_by_rbo = CT_TRUE;
        }
        CT_RETURN_IFERR(sql_verify_specify_part_info(verif, table));
        TABLE_CBO_ATTR_OWNER(table) = query->vmc;

        switch (table->type) {
            case VIEW_AS_TABLE:
                CT_RETURN_IFERR(sql_verify_view_as_table(verif, query, table));
                break;

            case SUBSELECT_AS_TABLE:
            case WITH_AS_TABLE:
                CT_RETURN_IFERR(sql_verify_subselect_table(verif, query, table));
                break;

            case FUNC_AS_TABLE:
                CT_RETURN_IFERR(sql_verify_func_as_table(verif, query, table, i));
                break;

            case NORMAL_TABLE:
                CT_RETURN_IFERR(sql_init_table_policies(verif, query, table));
                CT_RETURN_IFERR(sql_create_project_columns(verif->stmt, table));
                break;

            case JSON_TABLE:
                CT_RETURN_IFERR(sql_verify_json_table(verif, query, table));
                break;

            default:
                break;
        }
    }
    return CT_SUCCESS;
}

static status_t sql_create_proj_col_array(sql_stmt_t *stmt, sql_table_t *table, uint32 col_count)
{
    uint32 column_count = col_count;
    if (column_count == 0) {
        CT_THROW_ERROR(ERR_COLUMNS_MISMATCH);
        return CT_ERROR;
    }

    // add one additional column for reserved word:rownodeid,
    // if add new reserved word, please change COL_RESERVED_CEIL
    column_count = column_count + COL_RESERVED_CEIL;

    CT_RETURN_IFERR(
        sql_alloc_mem((void *)(stmt->context), sizeof(project_col_array_t), (void **)&table->project_col_array));
    uint32 size = (column_count - 1) / PROJECT_COL_ARRAY_STEP + 1;
    uint32 proj_col_array_size;
    if (opr_uint32mul_overflow(sizeof(project_col_info_t *), size, &proj_col_array_size)) {
        CT_THROW_ERROR(ERR_TYPE_OVERFLOW, "UINT32");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(
        sql_alloc_mem((void *)(stmt->context), proj_col_array_size, (void **)&table->project_col_array->base));

    for (uint32 i = 0; i < size; i++) {
        CT_RETURN_IFERR(sql_alloc_mem((void *)(stmt->context), sizeof(project_col_info_t) * PROJECT_COL_ARRAY_STEP,
            (void **)&table->project_col_array->base[i]));
    }

    table->project_col_array->count = column_count;
    return CT_SUCCESS;
}

status_t sql_create_project_columns(sql_stmt_t *stmt, sql_table_t *table)
{
    if (table->project_col_array != NULL) {
        return CT_SUCCESS;
    }

    uint32 column_count = 0;
    if (table->type != NORMAL_TABLE) {
        column_count = table->select_ctx->first_query->rs_columns->count;
    } else {
        column_count = knl_get_column_count(table->entry->dc.handle);
    }

    CT_RETURN_IFERR(sql_create_proj_col_array(stmt, table, column_count));

    return CT_SUCCESS;
}

void sql_extract_subslct_projcols(sql_table_t *subslct_tab)
{
    project_col_info_t *project_col_info = NULL;

    uint32 column_count = subslct_tab->select_ctx->first_query->rs_columns->count;
    for (uint32 i = 0; i < column_count; i++) {
        rs_column_t *sub_column = (rs_column_t *)cm_galist_get(subslct_tab->select_ctx->first_query->rs_columns, i);
        project_col_info = sql_get_project_info_col(subslct_tab->project_col_array, i);
        // when col is sub-select column, should use alias, like : select * from (select 1+count(*) from t1) a, (select
        // f1 from t2) b; select * from (select 1+count(*) as Z_ALIAS_0 from t1) a, (select f1 from t2) b; Z_ALIAS_0 is
        // generated in sql_gen_column_z_alias
        if (project_col_info->col_name == NULL) {
            project_col_info->col_name = (sub_column->z_alias.len == 0) ? &sub_column->name : &sub_column->z_alias;
        }
        project_col_info->project_id = i;
        project_col_info->col_name_has_quote = CT_BIT_TEST(sub_column->rs_flag, RS_HAS_QUOTE) ? CT_TRUE : CT_FALSE;
    }
}


#ifdef __cplusplus
}
#endif

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
 * dml_parser.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser/dml_parser.c
 *
 * -------------------------------------------------------------------------
 */
#include "dml_parser.h"
#include "cm_hash.h"
#include "ctsql_context.h"
#include "srv_instance.h"
#include "ctsql_parser.h"
#include "ctsql_transform.h"
#include "ctsql_plan.h"
#include "pl_common.h"
#include "pl_executor.h"
#include "pl_context.h"
#include "ctsql_dependency.h"
#include "plan_rbo.h"
#include "ctsql_serial.h"
#include "pl_compiler.h"
#include "ctsql_privilege.h"
#include "ctsql_json_table.h"
#include "pl_anonymous.h"
#include "pl_memory.h"
#include "base_compiler.h"
#include "ctsql_select_parser.h"
#include "ctsql_insert_parser.h"
#include "ctsql_update_parser.h"
#include "ctsql_delete_parser.h"
#include "ctsql_replace_parser.h"
#include "ctsql_merge_parser.h"


#ifdef __cplusplus
extern "C" {
#endif

status_t sql_create_list(sql_stmt_t *stmt, galist_t **list)
{
    if (sql_alloc_mem(stmt->context, sizeof(galist_t), (void **)list) != CT_SUCCESS) {
        return CT_ERROR;
    }

    cm_galist_init((*list), stmt->context, sql_alloc_mem);
    return CT_SUCCESS;
}

static status_t sql_create_dml_context(sql_stmt_t *stmt, sql_text_t *sql, key_wid_t key_wid)
{
    sql_context_t *ctx = stmt->context;

    // write dml sql into context
    CT_RETURN_IFERR(ctx_write_text(&ctx->ctrl, (text_t *)sql));

    CT_RETURN_IFERR(sql_create_list(stmt, &ctx->params));
    CT_RETURN_IFERR(sql_create_list(stmt, &ctx->csr_params));
    CT_RETURN_IFERR(sql_create_list(stmt, &ctx->ref_objects));
    CT_RETURN_IFERR(sql_create_list(stmt, &ctx->outlines));

    stmt->session->lex->flags = LEX_WITH_OWNER | LEX_WITH_ARG;

    switch (key_wid) {
        case KEY_WORD_SELECT:
        case KEY_WORD_WITH:
            stmt->context->type = CTSQL_TYPE_SELECT;
            return sql_create_select_context(stmt, sql, SELECT_AS_RESULT, (sql_select_t **)&ctx->entry);

        case KEY_WORD_UPDATE:
            stmt->context->type = CTSQL_TYPE_UPDATE;
            return sql_create_update_context(stmt, sql, (sql_update_t **)&ctx->entry);

        case KEY_WORD_INSERT:
            stmt->context->type = CTSQL_TYPE_INSERT;
            return sql_create_insert_context(stmt, sql, (sql_insert_t **)&ctx->entry);

        case KEY_WORD_DELETE:
            stmt->context->type = CTSQL_TYPE_DELETE;
            return sql_create_delete_context(stmt, sql, (sql_delete_t **)&ctx->entry);

        case KEY_WORD_MERGE:
            stmt->context->type = CTSQL_TYPE_MERGE;
            return sql_create_merge_context(stmt, sql, (sql_merge_t **)&ctx->entry);

        case KEY_WORD_REPLACE:
            stmt->context->type = CTSQL_TYPE_REPLACE;
            return sql_create_replace_context(stmt, sql, (sql_replace_t **)&ctx->entry);

        default:
            CT_SRC_THROW_ERROR(sql->loc, ERR_SQL_SYNTAX_ERROR, "missing keyword");
            return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_create_dml(sql_stmt_t *stmt, sql_text_t *sql, key_wid_t key_wid)
{
    CT_RETURN_IFERR(sql_create_dml_context(stmt, sql, key_wid));
    CT_RETURN_IFERR(sql_verify(stmt));
    check_table_stats(stmt);

    return sql_create_dml_plan(stmt);
}

status_t sql_create_dml_currently(sql_stmt_t *stmt, sql_text_t *sql_text, key_wid_t key_wid)
{
    cm_spin_lock(&stmt->session->sess_lock, NULL);
    stmt->session->current_sql = sql_text->value;
    stmt->session->sql_id = stmt->context->ctrl.hash_value;
    cm_spin_unlock(&stmt->session->sess_lock);

    status_t ret = sql_create_dml(stmt, sql_text, key_wid);

    cm_spin_lock(&stmt->session->sess_lock, NULL);
    stmt->session->current_sql = CM_NULL_TEXT;
    stmt->session->sql_id = 0;
    cm_spin_unlock(&stmt->session->sess_lock);
    return ret;
}

bool32 sql_has_ltt(sql_stmt_t *stmt, text_t *sql_text)
{
    // simple scan sql_text to find name starts with `#`
    bool32 quote = CT_FALSE;
    for (uint32 i = 0; i < sql_text->len; i++) {
        if (sql_text->str[i] == '\'') {
            quote = !quote;
        }

        if (quote) {
            continue;
        }

        if (knl_is_llt_by_name2(sql_text->str[i]) && i > 0) {
            char c = sql_text->str[i - 1];
            if (c == '`' || c == '"' || is_splitter(c)) {
                return CT_TRUE;
            }
        }
    }
    return CT_FALSE;
}

uint32 sql_has_special_word(sql_stmt_t *stmt, text_t *sql_text)
{
    // simple scan sql to find name starts with `#`
    bool32 quote = CT_FALSE;
    uint32 result = SQL_HAS_NONE;
    for (uint32 i = 0; i < sql_text->len; i++) {
        if (sql_text->str[i] == '\'') {
            quote = !quote;
        }

        if (quote) {
            continue;
        }

        // dblink
        if (sql_text->str[i] == '@') {
            result |= SQL_HAS_DBLINK;
        }

        // local temporary table
        if (knl_is_llt_by_name2(sql_text->str[i]) && i > 0) {
            char c = sql_text->str[i - 1];
            if (c == '`' || c == '"' || is_splitter(c)) {
                result |= SQL_HAS_LTT;
            }
        }
    }
    return result;
}

/* check ref function/procedures is valid or not */
bool32 sql_check_procedures(sql_stmt_t *stmt, galist_t *dc_lst)
{
    pl_dc_t *pl_dc = NULL;

    if (dc_lst != NULL) {
        for (uint32 i = 0; i < dc_lst->count; i++) {
            pl_dc = (pl_dc_t *)cm_galist_get(dc_lst, i);
            if (!pl_check_dc(pl_dc)) {
                return CT_FALSE;
            }
        }
    }

    return CT_TRUE;
}

static inline void sql_init_plan_count(sql_stmt_t *stmt)
{
    stmt->context->clause_info.union_all_count = 0;
}

void sql_parse_set_context_procinfo(sql_stmt_t *stmt)
{
    CM_POINTER2(stmt, stmt->context);
    /* for the ANONYMOUS BLOCK or CALL statement, there is no procedure oid */
    if ((stmt->pl_compiler != NULL) && ((pl_compiler_t *)stmt->pl_compiler)->proc_oid != 0) {
        stmt->context->stat.proc_oid = ((pl_compiler_t *)stmt->pl_compiler)->proc_oid;
        stmt->context->stat.proc_line = ((pl_compiler_t *)stmt->pl_compiler)->line_loc.line;
    }
}

void sql_enrich_context_for_uncached(sql_stmt_t *stmt, timeval_t *timeval_begin)
{
    timeval_t timeval_end;
    sql_init_context_stat(&stmt->context->stat);
    stmt->context->stat.parse_calls = 1;
    stmt->session->stat.hard_parses++;

    stmt->context->stat.last_load_time = g_timer()->now;
    (void)cm_gettimeofday(&timeval_end);
    stmt->context->stat.parse_time = (uint64)TIMEVAL_DIFF_US(timeval_begin, &timeval_end);
    stmt->context->stat.last_active_time = stmt->context->stat.last_load_time;
    stmt->context->module_kind = SESSION_CLIENT_KIND(stmt->session);
    stmt->context->ctrl.ref_count = 0;
    sql_parse_set_context_procinfo(stmt);
    if (stmt->context->ctrl.memory != NULL) {
        cm_atomic_add(&g_instance->library_cache_info[stmt->lang_type].pins,
            (int64)stmt->context->ctrl.memory->pages.count);
        cm_atomic_inc(&g_instance->library_cache_info[stmt->lang_type].reloads);
    }
}

status_t sql_parse_dml_directly(sql_stmt_t *stmt, key_wid_t key_wid, sql_text_t *sql_text)
{
    CT_RETURN_IFERR(sql_alloc_context(stmt));

    sql_context_uncacheable(stmt->context);
    ((context_ctrl_t *)stmt->context)->uid = stmt->session->knl_session.uid;
    sql_init_plan_count(stmt);

    timeval_t timeval_begin;
    (void)cm_gettimeofday(&timeval_begin);

    CT_RETURN_IFERR(sql_create_dml_currently(stmt, sql_text, key_wid));

    sql_enrich_context_for_uncached(stmt, &timeval_begin);
    return CT_SUCCESS;
}

void sql_prepare_context_ctrl(sql_stmt_t *stmt, uint32 hash_value, context_bucket_t *bucket)
{
    stmt->context->ctrl.uid = stmt->session->curr_schema_id;
    stmt->context->ctrl.hash_value = hash_value;
    stmt->context->ctrl.bucket = bucket;
    sql_init_plan_count(stmt);
}

static void sql_prepare_plc_desc(sql_stmt_t *stmt, uint32 type, plc_desc_t *desc)
{
    desc->proc_oid = 0;
    desc->type = type;
    desc->obj = NULL;
    desc->source_pages.curr_page_id = CT_INVALID_ID32;
    desc->source_pages.curr_page_pos = 0;
    desc->entity = (pl_entity_t *)stmt->pl_context;
}

static status_t sql_parse_anonymous_prepare(sql_stmt_t *stmt)
{
    pl_entity_t *pl_entity = NULL;

    if (sql_alloc_context(stmt) != CT_SUCCESS) {
        return CT_ERROR;
    }
    sql_context_uncacheable(stmt->context);
    stmt->context->type = CTSQL_TYPE_ANONYMOUS_BLOCK;
    if (sql_create_list(stmt, &stmt->context->params) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (pl_alloc_context(&pl_entity, stmt->context) != CT_SUCCESS) {
        return CT_ERROR;
    }
    SET_STMT_PL_CONTEXT(stmt, pl_entity);

    if (pl_alloc_mem((void *)pl_entity, sizeof(anonymous_t), (void **)&pl_entity->anonymous) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_parse_anonymous_directly(sql_stmt_t *stmt, word_t *leader, sql_text_t *sql_text)
{
    timeval_t timeval_begin, timeval_end;
    plc_desc_t desc;
    status_t status = CT_ERROR;

    do {
        CT_BREAK_IF_ERROR(sql_parse_anonymous_prepare(stmt));
        pl_entity_uncacheable(stmt->pl_context);
        sql_init_plan_count(stmt);
        (void)cm_gettimeofday(&timeval_begin);
        sql_prepare_plc_desc(stmt, PL_ANONYMOUS_BLOCK, &desc);
        CT_BREAK_IF_ERROR(pl_write_anony_desc(stmt, &sql_text->value, 0));
        CT_BREAK_IF_ERROR(plc_compile(stmt, &desc, leader));
        pl_set_entity_valid((pl_entity_t *)stmt->pl_context, CT_TRUE);
        status = CT_SUCCESS;
    } while (CT_FALSE);
    if (status != CT_SUCCESS) {
        return CT_ERROR;
    }
    sql_init_context_stat(&stmt->context->stat);
    stmt->context->stat.parse_calls = 1;
    stmt->session->stat.hard_parses++;
    stmt->context->stat.last_load_time = g_timer()->now;
    (void)cm_gettimeofday(&timeval_end);
    stmt->context->stat.parse_time = (uint64)TIMEVAL_DIFF_US(&timeval_begin, &timeval_end);
    stmt->context->stat.last_active_time = stmt->context->stat.last_load_time;
    stmt->context->module_kind = SESSION_CLIENT_KIND(stmt->session);
    stmt->context->ctrl.ref_count = 0;
    if (stmt->context->ctrl.memory != NULL) {
        cm_atomic_add(&g_instance->library_cache_info[stmt->lang_type].pins,
            (int64)stmt->context->ctrl.memory->pages.count);
        cm_atomic_inc(&g_instance->library_cache_info[stmt->lang_type].reloads);
    }
    return CT_SUCCESS;
}

status_t sql_parse_dml(sql_stmt_t *stmt, key_wid_t key_wid)
{
    CT_LOG_DEBUG_INF("Begin parse DML, SQL = %s", T2S(&stmt->session->lex->text.value));
    cm_atomic_inc(&g_instance->library_cache_info[stmt->lang_type].hits);
    // maybe need load entity from proc$
    knl_set_session_scn(&stmt->session->knl_session, CT_INVALID_ID64);

    stmt->session->sql_audit.audit_type = SQL_AUDIT_DML;
    uint32 special_word = sql_has_special_word(stmt, &stmt->session->lex->text.value);
    CT_RETURN_IFERR(sql_parse_dml_directly(stmt, key_wid, &stmt->session->lex->text));
    stmt->context->has_ltt = (special_word & SQL_HAS_LTT);

    return CT_SUCCESS;
}

status_t sql_create_rowid_rs_column(sql_stmt_t *stmt, uint32 id, sql_table_type_t type, galist_t *list)
{
    rs_column_t *rs_column = NULL;

    CT_RETURN_IFERR(cm_galist_new(list, sizeof(rs_column_t), (pointer_t *)&rs_column));
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(expr_tree_t), (void **)&rs_column->expr));
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&rs_column->expr->root));
    rs_column->expr->owner = stmt->context;
    rs_column->type = RS_COL_CALC;

    if (type != NORMAL_TABLE) {
        rs_column->expr->root->size = sizeof(uint32);
        rs_column->expr->root->type = EXPR_NODE_CONST;
        rs_column->expr->root->datatype = CT_TYPE_INTEGER;
        rs_column->expr->root->value.type = CT_TYPE_INTEGER;
        rs_column->expr->root->value.v_int = 0;
    } else {
        rs_column->expr->root->size = ROWID_LENGTH;
        rs_column->expr->root->type = EXPR_NODE_RESERVED;
        rs_column->expr->root->datatype = CT_TYPE_STRING;
        rs_column->expr->root->value.type = CT_TYPE_INTEGER;
        rs_column->expr->root->value.v_rid.res_id = RES_WORD_ROWID;
        rs_column->expr->root->value.v_rid.ancestor = 0;
    }
    rs_column->size = rs_column->expr->root->size;
    rs_column->datatype = rs_column->expr->root->datatype;
    rs_column->expr->root->value.v_rid.tab_id = id;
    return CT_SUCCESS;
}

bool32 sql_check_equal_join_cond(join_cond_t *join_cond)
{
    for (uint32 i = 0; i < join_cond->cmp_nodes.count; i++) {
        cmp_node_t *cmp_node = (cmp_node_t *)cm_galist_get(&join_cond->cmp_nodes, i);
        if (cmp_node->left->root->type == EXPR_NODE_COLUMN && cmp_node->right->root->type == EXPR_NODE_COLUMN &&
            cmp_node->type == CMP_TYPE_EQUAL) {
            return CT_TRUE;
        }
    }

    return CT_FALSE;
}

status_t sql_parse_view_subselect(sql_stmt_t *stmt, text_t *sql, sql_select_t **select_ctx, source_location_t *loc)
{
    sql_text_t sql_text;

    sql_text.value = *sql;
    sql_text.loc = *loc;

    if (sql_create_select_context(stmt, &sql_text, SELECT_AS_TABLE, select_ctx) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

/*
 * sql_set_schema
 *
 * set the stmt schema info
 */
status_t sql_set_schema(sql_stmt_t *stmt, text_t *set_schema, uint32 set_schema_id, char *save_schema,
    uint32 save_schema_maxlen, uint32 *save_schema_id)
{
    uint32 len;

    if (set_schema == NULL || set_schema->len == 0) {
        return CT_ERROR;
    }

    len = (uint32)strlen(stmt->session->curr_schema);
    if (len != 0) {
        MEMS_RETURN_IFERR(strncpy_s(save_schema, save_schema_maxlen, stmt->session->curr_schema, len));
    }
    *save_schema_id = stmt->session->curr_schema_id;

    if (set_schema->len != 0) {
        MEMS_RETURN_IFERR(memcpy_s(stmt->session->curr_schema, CT_NAME_BUFFER_SIZE, set_schema->str, set_schema->len));
    }
    stmt->session->curr_schema[set_schema->len] = '\0';
    stmt->session->curr_schema_id = set_schema_id;

    return CT_SUCCESS;
}


static bool32 sql_get_view_object_addr(object_address_t *depended, knl_dictionary_t *view_dc, text_t *name)
{
    depended->uid = view_dc->uid;
    depended->oid = view_dc->oid;
    depended->tid = OBJ_TYPE_VIEW;
    depended->scn = view_dc->chg_scn;
    if (name->len > 0) {
        MEMS_RETURN_IFERR(memcpy_s(depended->name, CT_NAME_BUFFER_SIZE, name->str, name->len));
    }

    depended->name[name->len] = '\0';

    return CT_TRUE;
}

/* update the dependency info of this view in sys_dependency table */
static void sql_update_view_dependencies(sql_stmt_t *stmt, knl_dictionary_t *view_dc, galist_t *ref_list,
    object_address_t depender, bool32 *is_valid)
{
    bool32 is_successed = CT_FALSE;
    knl_session_t *session = KNL_SESSION(stmt);

    do {
        if (knl_delete_dependency(session, view_dc->uid, (int64)view_dc->oid, (uint32)OBJ_TYPE_VIEW) != CT_SUCCESS) {
            is_successed = CT_FALSE;
            break;
        }

        if (stmt->context == NULL) {
            is_successed = CT_TRUE;
            break;
        }

        if (sql_alloc_mem(stmt->context, sizeof(galist_t), (void **)&ref_list) != CT_SUCCESS) {
            is_successed = CT_FALSE;
            break;
        }

        cm_galist_init(ref_list, stmt->context, sql_alloc_mem);
        if (sql_append_references(ref_list, stmt->context) == CT_SUCCESS &&
            knl_insert_dependency_list(session, &depender, ref_list) == CT_SUCCESS) {
            is_successed = CT_TRUE;
        }
    } while (CT_FALSE);

    if (is_successed) {
        knl_commit(session);
    } else {
        knl_rollback(session, NULL);
        *is_valid = CT_FALSE;
    }
}

bool32 sql_compile_view_sql(sql_stmt_t *stmt, knl_dictionary_t *view_dc, text_t *owner)
{
    uint32 large_page_id = CT_INVALID_ID32;
    source_location_t loc = { 1, 1 };
    saved_schema_t schema;
    text_t sub_sql;
    status_t status;
    bool32 is_successed = CT_FALSE;
    knl_session_t *session = KNL_SESSION(stmt);

    if (knl_get_view_sub_sql(session, view_dc, &sub_sql, &large_page_id) != CT_SUCCESS) {
        return CT_FALSE;
    }

    do {
        status = sql_switch_schema_by_uid(stmt, view_dc->uid, &schema);
        CT_BREAK_IF_ERROR(status);
        if (sql_parse(stmt, &sub_sql, &loc) == CT_SUCCESS) {
            is_successed = CT_TRUE;
        }
        sql_restore_schema(stmt, &schema);
    } while (0);

    if (large_page_id != CT_INVALID_ID32) {
        mpool_free_page(session->kernel->attr.large_pool, large_page_id);
    }
    return is_successed;
}

/*
 * sql_compile_view
 *
 * This function is used to recompile a view.
 */
static bool32 sql_compile_view(sql_stmt_t *stmt, text_t *owner, text_t *name, knl_dictionary_t *view_dc,
    bool32 update_dep)
{
    bool32 is_valid;
    object_address_t depender;
    galist_t *ref_list = NULL;
    lex_t *lex_bak = NULL;

    if (!sql_get_view_object_addr(&depender, view_dc, name)) {
        return CT_FALSE;
    }

    CTSQL_SAVE_PARSER(stmt);
    if (pl_save_lex(stmt, &lex_bak) != CT_SUCCESS) {
        SQL_RESTORE_PARSER(stmt);
        return CT_FALSE;
    }
    bool8 disable_soft_parse = stmt->session->disable_soft_parse;
    stmt->is_explain = CT_FALSE;
    SET_STMT_CONTEXT(stmt, NULL);
    SET_STMT_PL_CONTEXT(stmt, NULL);
    stmt->session->disable_soft_parse = CT_TRUE;
    is_valid = sql_compile_view_sql(stmt, view_dc, owner);

    if (update_dep) {
        sql_update_view_dependencies(stmt, view_dc, ref_list, depender, &is_valid);
    }

    sql_release_context(stmt);

    pl_restore_lex(stmt, lex_bak);
    SQL_RESTORE_PARSER(stmt);
    stmt->session->disable_soft_parse = disable_soft_parse;
    return is_valid;
}

static object_status_t sql_check_synonym_object_valid(sql_stmt_t *stmt, text_t *owner_name, text_t *table_name,
    object_address_t *p_obj)
{
    object_status_t obj_status = OBJ_STATUS_VALID;
    knl_dictionary_t dc;
    errno_t errcode;

    if (dc_open(KNL_SESSION(stmt), owner_name, table_name, &dc) != CT_SUCCESS) {
        return OBJ_STATUS_INVALID;
    }

    if (dc.type == DICT_TYPE_VIEW) {
        obj_status =
            sql_compile_view(stmt, owner_name, table_name, &dc, CT_FALSE) ? OBJ_STATUS_VALID : OBJ_STATUS_INVALID;
        cm_reset_error();
    } else {
        obj_status = OBJ_STATUS_VALID;
    }

    p_obj->uid = dc.uid;
    p_obj->oid = dc.oid;
    p_obj->scn = dc.chg_scn;
    p_obj->tid = knl_get_object_type(dc.type);
    errcode = memcpy_s(p_obj->name, CT_NAME_BUFFER_SIZE, table_name->str, table_name->len);
    if (errcode != EOK) {
        dc_close(&dc);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return OBJ_STATUS_INVALID;
    }
    p_obj->name[table_name->len] = '\0';

    dc_close(&dc);

    return obj_status;
}

static object_status_t sql_check_pl_synonym_object_valid(sql_stmt_t *stmt, text_t *owner_name, text_t *table_name,
    object_address_t *obj_addr, object_type_t syn_type)
{
    object_status_t obj_status = OBJ_STATUS_VALID;
    pl_dc_t dc = { 0 };
    bool32 exist = CT_FALSE;
    var_udo_t var_udo;
    errno_t errcode;
    uint32 type;
    pl_dc_assist_t assist = { 0 };

    sql_init_udo(&var_udo);
    var_udo.name = *table_name;
    var_udo.user = *owner_name;

    type = pl_get_obj_type(syn_type);
    pl_dc_open_prepare(&assist, stmt, owner_name, table_name, type);
    if (pl_dc_open(&assist, &dc, &exist) != CT_SUCCESS || !exist) {
        return OBJ_STATUS_INVALID;
    }

    obj_addr->uid = dc.uid;
    obj_addr->oid = (uint64)dc.oid;
    obj_addr->scn = dc.entry->desc.chg_scn;
    obj_addr->tid = syn_type;
    errcode = memcpy_s(obj_addr->name, CT_NAME_BUFFER_SIZE, table_name->str, table_name->len);
    if (errcode != EOK) {
        pl_dc_close(&dc);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return OBJ_STATUS_INVALID;
    }
    obj_addr->name[table_name->len] = '\0';
    pl_dc_close(&dc);
    return obj_status;
}

static status_t sql_make_object_address(knl_cursor_t *cursor, object_address_t *d_obj, object_status_t *old_status)
{
    text_t tmp_text;

    *old_status = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SYN_FLAG);
    d_obj->oid = (uint64)(*(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SYN_OBJID));
    d_obj->scn = *(uint64 *)CURSOR_COLUMN_DATA(cursor, SYS_SYN_CHG_SCN);
    tmp_text.str = CURSOR_COLUMN_DATA(cursor, SYS_SYN_SYNONYM_NAME);
    tmp_text.len = CURSOR_COLUMN_SIZE(cursor, SYS_SYN_SYNONYM_NAME);
    errno_t err = memcpy_s(d_obj->name, CT_NAME_BUFFER_SIZE, tmp_text.str, tmp_text.len);
    if (err != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return CT_ERROR;
    }

    if (tmp_text.len >= CT_NAME_BUFFER_SIZE) {
        CT_THROW_ERROR(ERR_SOURCE_SIZE_TOO_LARGE_FMT, tmp_text.len, CT_NAME_BUFFER_SIZE - 1);
        return CT_ERROR;
    }
    d_obj->name[tmp_text.len] = '\0';
    return CT_SUCCESS;
}

static status_t sql_check_current_synonym(sql_stmt_t *stmt, knl_session_t *session, knl_cursor_t *cursor,
    bool32 compile_all, uint32 uid)
{
    object_address_t d_obj, p_obj;
    object_status_t old_status, new_status;
    char owner_buf[CT_NAME_BUFFER_SIZE];
    char object_buf[CT_NAME_BUFFER_SIZE];
    text_t table_name, owner_name;

    d_obj.uid = uid;
    CT_RETURN_IFERR(sql_make_object_address(cursor, &d_obj, &old_status));
    owner_name.str = CURSOR_COLUMN_DATA(cursor, SYS_SYN_TABLE_OWNER);
    owner_name.len = CURSOR_COLUMN_SIZE(cursor, SYS_SYN_TABLE_OWNER);
    CT_RETURN_IFERR(cm_text2str(&owner_name, owner_buf, CT_NAME_BUFFER_SIZE));
    owner_name.str = owner_buf;
    table_name.str = CURSOR_COLUMN_DATA(cursor, SYS_SYN_TABLE_NAME);
    table_name.len = CURSOR_COLUMN_SIZE(cursor, SYS_SYN_TABLE_NAME);
    CT_RETURN_IFERR(cm_text2str(&table_name, object_buf, CT_NAME_BUFFER_SIZE));
    table_name.str = object_buf;
    object_type_t syn_type = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SYN_TYPE);

    if (!compile_all && old_status == OBJ_STATUS_VALID) {
        return CT_SUCCESS;
    }
    /* check current synonym valid or not */
    if (IS_PL_SYN(syn_type)) {
        new_status = sql_check_pl_synonym_object_valid(stmt, &owner_name, &table_name, &p_obj, syn_type);
        d_obj.tid = OBJ_TYPE_PL_SYNONYM;
    } else {
        new_status = sql_check_synonym_object_valid(stmt, &owner_name, &table_name, &p_obj);
        d_obj.tid = OBJ_TYPE_SYNONYM;
    }

    if (knl_delete_dependency(session, d_obj.uid, (int64)d_obj.oid, d_obj.tid) != CT_SUCCESS) {
        return CT_SUCCESS;
    }
    if (new_status == OBJ_STATUS_VALID &&
        knl_insert_dependency((knl_handle_t *)session, &d_obj, &p_obj, 0) != CT_SUCCESS) {
        knl_rollback(session, NULL);
        return CT_SUCCESS;
    }
    if (old_status != new_status && sql_update_object_status(session, (obj_info_t *)&d_obj, new_status) != CT_SUCCESS) {
        knl_rollback(session, NULL);
        return CT_SUCCESS;
    }

    knl_commit(session);
    return CT_SUCCESS;
}

/*
 * sql_compile_synonym_by_user
 *
 * This function is used to recompile synonym and update the flag of this synonym.
 */
status_t sql_compile_synonym_by_user(sql_stmt_t *stmt, text_t *schema_name, bool32 compile_all)
{
    knl_cursor_t *cursor = NULL;
    uint32 uid;
    knl_session_t *session = KNL_SESSION(stmt);

    /* check the schema name invalid or not */
    if (!knl_get_user_id(KNL_SESSION(stmt), schema_name, &uid)) {
        CT_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(schema_name));
        return CT_ERROR;
    }

    knl_set_session_scn(session, CT_INVALID_ID64);

    CTSQL_SAVE_STACK(stmt);

    if (sql_push_knl_cursor(session, &cursor) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_STACK_OVERFLOW);
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_SYN_ID, 0);
    knl_init_index_scan(cursor, CT_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&uid,
        sizeof(uint32), 0);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, 1);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, (void *)&uid,
        sizeof(uint32), 0);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, 1);

    while (1) {
        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            return CT_ERROR;
        }
        if (cursor->eof) {
            break;
        }
        if (sql_check_current_synonym(stmt, session, cursor, compile_all, uid) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            return CT_ERROR;
        }
    }

    CTSQL_RESTORE_STACK(stmt);
    return CT_SUCCESS;
}

status_t sql_recompile_view(sql_stmt_t *stmt, text_t *owner_name, text_t *view_name, object_status_t old_status)
{
    knl_dictionary_t dc;
    object_address_t obj;
    object_status_t new_status = OBJ_STATUS_INVALID;

    /* recompile view */
    if (dc_open(KNL_SESSION(stmt), owner_name, view_name, &dc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    obj.uid = dc.uid;
    obj.oid = dc.oid;
    obj.tid = OBJ_TYPE_VIEW;
    obj.scn = KNL_GET_SCN(&KNL_SESSION(stmt)->kernel->min_scn);
    errno_t err = memcpy_s(obj.name, CT_NAME_BUFFER_SIZE, view_name->str, view_name->len);
    if (err != EOK) {
        dc_close(&dc);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return CT_ERROR;
    }

    obj.name[view_name->len] = '\0';

    if (CT_TRUE != sql_compile_view(stmt, owner_name, view_name, &dc, CT_TRUE)) {
        new_status = OBJ_STATUS_INVALID;
    } else {
        new_status = OBJ_STATUS_VALID;
    }

    dc_close(&dc);

    /* update the status of view */
    if (old_status != new_status) {
        CT_RETURN_IFERR(sql_update_object_status(KNL_SESSION(stmt), (obj_info_t *)&obj, new_status));
    }

    knl_commit(KNL_SESSION(stmt));

    return CT_SUCCESS;
}

/*
 * sql_compile_view_by_user
 *
 * This function is used to recompile view and update the status of this synonym.
 */
status_t sql_compile_view_by_user(sql_stmt_t *stmt, text_t *schema_name, bool32 compile_all)
{
    knl_cursor_t *cursor = NULL;
    uint32 uid;
    char object_buf[CT_NAME_BUFFER_SIZE];
    text_t view_name;
    knl_session_t *session = KNL_SESSION(stmt);

    /* check the schema name invalid or not */
    if (!knl_get_user_id(KNL_SESSION(stmt), schema_name, &uid)) {
        CT_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(schema_name));
        return CT_ERROR;
    }

    knl_set_session_scn(session, CT_INVALID_ID64);

    CM_SAVE_STACK(session->stack);

    if (sql_push_knl_cursor(session, &cursor) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_STACK_OVERFLOW);
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_VIEW_ID, 0);
    knl_init_index_scan(cursor, CT_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&uid,
        sizeof(uint32), 0);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, 1);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, (void *)&uid,
        sizeof(uint32), 0);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, 1);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    status_t status = CT_SUCCESS;
    while (!cursor->eof) {
        object_status_t old_status = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_VIEW_FLAG);
        view_name.str = CURSOR_COLUMN_DATA(cursor, SYS_VIEW_NAME);
        view_name.len = CURSOR_COLUMN_SIZE(cursor, SYS_VIEW_NAME);

        status = cm_text2str(&view_name, object_buf, CT_NAME_BUFFER_SIZE);
        CT_BREAK_IF_ERROR(status);
        view_name.str = object_buf;

        if (((compile_all == CT_FALSE && old_status != OBJ_STATUS_VALID) || compile_all == CT_TRUE) &&
            sql_recompile_view(stmt, schema_name, &view_name, old_status) != CT_SUCCESS) {
            cm_reset_error();
        }

        status = knl_fetch(session, cursor);
        CT_BREAK_IF_ERROR(status);
    }

    CM_RESTORE_STACK(session->stack);
    return status;
}

#ifdef __cplusplus
}
#endif

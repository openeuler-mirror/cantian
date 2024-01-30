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
 * pl_dc.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/persist/pl_dc.c
 *
 * -------------------------------------------------------------------------
 */
#include "pl_dc.h"
#include "pl_compiler.h"
#include "srv_instance.h"
#include "ctsql_privilege.h"
#include "ctsql_package.h"
#include "pl_meta_common.h"
#include "ple_common.h"
#include "base_compiler.h"
#include "pl_memory.h"
#include "pl_common.h"
#include "ast_cl.h"
#include "pl_ddl_parser.h"
#include "dml_parser.h"
#include "ctsql_dependency.h"

status_t pl_get_entry_desc(pl_desc_t *desc, pl_entry_t *entry)
{
    desc->uid = entry->desc.uid;
    desc->oid = entry->desc.oid;
    desc->type = entry->desc.type;
    desc->org_scn = entry->desc.org_scn;
    desc->chg_scn = entry->desc.chg_scn;

    MEMS_RETURN_IFERR(strcpy_s(desc->name, CT_NAME_BUFFER_SIZE, entry->desc.name));

    return CT_SUCCESS;
}

static status_t pl_update_compile_result(knl_session_t *session, pl_entity_t *pl_entity, object_status_t obj_status)
{
    pl_desc_t desc;
    pl_entry_t *entry = pl_entity->entry;

    if (entry->desc.status != obj_status) {
        CT_RETURN_IFERR(pl_get_entry_desc(&desc, entry));
        desc.status = obj_status;

        switch (pl_entity->pl_type) {
            case PL_PROCEDURE:
            case PL_FUNCTION:
                CT_RETURN_IFERR(pl_load_entity_update_proc_table(session, &desc, pl_entity));
                break;
            case PL_PACKAGE_SPEC:
                CT_RETURN_IFERR(pl_load_entity_update_pack_def(session, &desc, pl_entity));
                break;
            case PL_PACKAGE_BODY:
                CT_RETURN_IFERR(pl_load_entity_update_pack_body(session, &desc, pl_entity));
                break;
            case PL_TRIGGER:
                CT_RETURN_IFERR(pl_load_entity_update_trigger_table(session, &desc, pl_entity));
                break;
            case PL_TYPE_SPEC:
                CT_RETURN_IFERR(pl_load_entity_update_udt_table(session, &desc, pl_entity));
                break;
            default:
                break;
        }
        pl_update_entry_status(entry, obj_status);
    }

    return CT_SUCCESS;
}

status_t pl_proc_compile_result(knl_session_t *session, pl_entity_t *pl_entity, object_status_t obj_status)
{
    pl_entry_t *entry = pl_entity->entry;
    if (knl_begin_auton_rm(session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    cm_spin_lock(&entry->write_lock, NULL);
    if (pl_update_compile_result(session, pl_entity, obj_status) != CT_SUCCESS) {
        knl_end_auton_rm(session, CT_ERROR);
        cm_spin_unlock(&entry->write_lock);
        return CT_ERROR;
    }
    knl_end_auton_rm(session, CT_SUCCESS);
    cm_spin_unlock(&entry->write_lock);
    return CT_SUCCESS;
}

static bool32 pl_dc_cmp_obj(pl_dc_t *pl_dc, var_udo_t *obj)
{
    var_udo_t *dc_obj = pl_dc->obj;

    return var_udo_text_equal(dc_obj, obj);
}

static status_t pl_record_dc_for_check_priv(sql_verifier_t *verif, pl_dc_t *dc)
{
    if (verif->pl_dc_lst == NULL) {
        return CT_SUCCESS;
    }

    verif->stmt->context->has_pl_objects = CT_TRUE;
    return cm_galist_insert(verif->pl_dc_lst, (pointer_t)dc);
}

knl_dictionary_t *pl_get_regist_knl_dc_core(sql_stmt_t *stmt, text_t *user, text_t *name)
{
    pl_entity_t *pl_entity = (pl_entity_t *)stmt->pl_context;
    galist_t *list = &pl_entity->knl_list;
    knl_dictionary_t *dc = NULL;
    dc_entity_t *knl_entity = NULL;
    dc_entry_t *entry = NULL;
    uint32 uid;

    if (!knl_get_user_id(KNL_SESSION(stmt), user, &uid)) {
        return NULL;
    }

    for (uint32 i = 0; i < list->count; i++) {
        dc = (knl_dictionary_t *)cm_galist_get(list, i);
        knl_entity = (dc_entity_t *)dc->handle;
        entry = knl_entity->entry;
        if (entry->uid == (uint16)uid && cm_text_str_equal(name, entry->name)) {
            return dc;
        }
    }

    return NULL;
}

knl_dictionary_t *pl_get_regist_knl_dc(sql_stmt_t *stmt, var_udo_t *udo_obj)
{
    if (udo_obj->user_explicit) {
        return pl_get_regist_knl_dc_core(stmt, &udo_obj->user, &udo_obj->name);
    }

    knl_dictionary_t *ref_dc = pl_get_regist_knl_dc_core(stmt, &udo_obj->user, &udo_obj->name);
    if (ref_dc != NULL) {
        return ref_dc;
    }

    text_t public_user;
    cm_str2text(PUBLIC_USER, &public_user);
    return pl_get_regist_knl_dc_core(stmt, &public_user, &udo_obj->name);
}

status_t pl_regist_knl_dc(sql_stmt_t *stmt, knl_dictionary_t *dc)
{
    pl_entity_t *entity = (pl_entity_t *)stmt->pl_context;
    galist_t *list = &entity->knl_list;
    knl_dictionary_t *ref_dc = NULL;

    CT_RETURN_IFERR(cm_galist_new(list, sizeof(knl_dictionary_t), (void **)&ref_dc));
    *ref_dc = *dc;
    return CT_SUCCESS;
}

status_t pl_regist_dc(sql_stmt_t *stmt, pl_dc_t *dc, pl_dc_t **reg_dc)
{
    pl_entity_t *entity = (pl_entity_t *)stmt->pl_context;
    galist_t *dc_lst = NULL;
    pl_dc_t *ref_dc = NULL;
    var_udo_t *udo_obj = NULL;

    if (entity != NULL) {
        dc_lst = &entity->dc_lst;
    } else {
        dc_lst = stmt->context->dc_lst;
    }

    if (dc->obj != NULL) {
        CT_RETURN_IFERR(dc_lst->alloc_func(dc_lst->owner, sizeof(var_udo_t), (void **)&udo_obj));
        CT_RETURN_IFERR(sql_clone_text(dc_lst->owner, &dc->obj->user, &udo_obj->user, dc_lst->alloc_func));
        CT_RETURN_IFERR(sql_clone_text(dc_lst->owner, &dc->obj->pack, &udo_obj->pack, dc_lst->alloc_func));
        CT_RETURN_IFERR(sql_clone_text(dc_lst->owner, &dc->obj->name, &udo_obj->name, dc_lst->alloc_func));
    }
    CT_RETURN_IFERR(cm_galist_new(dc_lst, sizeof(pl_dc_t), (void **)&ref_dc));

    *ref_dc = *dc;
    ref_dc->obj = udo_obj;
    *reg_dc = ref_dc;

    return CT_SUCCESS;
}

status_t pl_regist_reference(galist_t *dest, pl_dc_t *dc)
{
    object_address_t obj_addr;
    object_type_t type;
    pl_entry_t *entry = NULL;

    if (dest == NULL) {
        return CT_SUCCESS;
    }

    if (dc->is_sysnonym) {
        type = OBJ_TYPE_PL_SYNONYM;
        entry = dc->syn_entry;
    } else {
        type = pltype_to_objtype(dc->type);
        entry = dc->entry;
    }
    obj_addr.oid = entry->desc.oid;
    obj_addr.tid = type;
    obj_addr.uid = entry->desc.uid;
    obj_addr.scn = dc->chg_scn;
    if (!sql_check_ref_exists(dest, &obj_addr)) {
        MEMS_RETURN_IFERR(strcpy_s(obj_addr.name, CT_NAME_BUFFER_SIZE, entry->desc.name));
        CT_RETURN_IFERR(cm_galist_copy_append(dest, sizeof(object_address_t), &obj_addr));
    }

    return CT_SUCCESS;
}

pl_dc_t *pl_get_regist_dc(sql_stmt_t *stmt, var_udo_t *v_udo, uint32 type)
{
    galist_t *dc_last = NULL;
    pl_dc_t *ref_dc = NULL;
    pl_entity_t *entity = (pl_entity_t *)stmt->pl_context;

    if (entity != NULL) {
        dc_last = &entity->dc_lst;
    } else {
        dc_last = stmt->context->dc_lst;
    }
    CM_ASSERT(dc_last != NULL);

    for (uint32 i = 0; i < dc_last->count; i++) {
        ref_dc = (pl_dc_t *)cm_galist_get(dc_last, i);
        if ((ref_dc->type & type) && pl_dc_cmp_obj(ref_dc, v_udo)) {
            return ref_dc;
        }
        ref_dc = NULL;
    }

    return NULL;
}

static status_t pl_check_dc_priv(pl_dc_assist_t *dc_ass, pl_dc_t *dc)
{
    sql_stmt_t *stmt = dc_ass->stmt;
    text_t curr_user;
    // in previous versions, there was no permission check in pld_open_proc_dc
    if (!dc_ass->priv_check) {
        return CT_SUCCESS;
    }
    // skip if object is synonym
    if (dc->is_sysnonym) {
        return CT_SUCCESS;
    }

    if (stmt->session->switched_schema) {
        cm_str2text(stmt->session->curr_schema, &curr_user);
    } else {
        curr_user = stmt->session->curr_user;
    }

    if (dc->type == PL_TYPE_SPEC) {
        return sql_check_type_priv_core(stmt, dc_ass->user_name, dc_ass->obj_name, &curr_user);
    } else {
        return sql_check_proc_priv_core(stmt, dc_ass->user_name, dc_ass->obj_name, &curr_user);
    }
}

bool32 pl_check_entity(pl_entry_t *entry, pl_entity_t **entity_out)
{
    pl_manager_t *pl_manager = GET_PL_MGR;
    pl_entity_t *entity = NULL;

    pl_entry_lock(entry);
    entity = entry->entity;
    if (entity != NULL) {
        pl_entity_lock(entity);
        if (entity->valid) {
            entity->ref_count++;
            pl_entity_unlock(entity);
            *entity_out = entity;
            pl_entry_unlock(entry);
            pl_lru_shift(&pl_manager->pl_entity_lru[entity->lru_hash], &entity->lru_link, CT_TRUE);
            return CT_TRUE;
        } else {
            pl_entity_unlock(entity);
            entry->entity = NULL;
        }
    }
    pl_entry_unlock(entry);
    return CT_FALSE;
}

void pl_init_lex(lex_t *lex, text_t src_text)
{
    sql_text_t source;

    source.loc.line = 1;
    source.loc.column = 1;
    source.value = src_text;
    lex_init(lex, &source);
}

status_t pl_init_obj(knl_session_t *session, pl_desc_t *desc, pl_entity_t *entity)
{
    dc_user_t *user = NULL;

    if (dc_open_user_by_id(session, desc->uid, &user) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (pl_copy_str(entity, user->desc.name, &entity->def.user) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (pl_copy_str(entity, desc->name, &entity->def.name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    entity->def.name_sensitive = IS_CASE_INSENSITIVE;
    entity->def.pack_sensitive = IS_CASE_INSENSITIVE;

    return CT_SUCCESS;
}


static status_t pl_prepare_load_entity(sql_stmt_t *stmt, pl_entry_t *entry, pl_entity_t *entity,
    load_assist_t *load_assist)
{
    knl_session_t *se = KNL_SESSION(stmt);
    sql_stmt_t *sub_stmt = NULL;
    text_t source;
    pl_compiler_t *compiler = (pl_compiler_t *)stmt->pl_compiler;
    pl_source_pages_t source_pages = { CT_INVALID_ID32, 0 };

    if (compiler != NULL) {
        source_pages = compiler->pages;
    }

    CT_RETURN_IFERR(pl_init_obj(se, &entry->desc, entity));
    CT_RETURN_IFERR(sql_push(stmt, sizeof(sql_stmt_t), (void **)&sub_stmt));

    sql_init_stmt(stmt->session, sub_stmt, stmt->id);
    sub_stmt->context = NULL;
    sub_stmt->pl_context = entity;
    sub_stmt->is_sub_stmt = CT_TRUE;
    sub_stmt->parent_stmt = stmt;
    load_assist->sub_stmt = sub_stmt;
    CT_RETURN_IFERR(sql_alloc_context(sub_stmt));
    entity->context = sub_stmt->context;
    CT_RETURN_IFERR(sql_create_list(sub_stmt, &sub_stmt->context->params));
    plc_diag_ctx_type(entity->context, entity->pl_type);

    CT_RETURN_IFERR(pl_save_lex(stmt, &load_assist->lex_bak));

    if (pl_load_sysproc_source(se, &entry->desc, &source_pages, &source, &load_assist->new_page) != CT_SUCCESS) {
        pl_restore_lex(stmt, load_assist->lex_bak);
        return CT_ERROR;
    }

    load_assist->source_page = source_pages;
    pl_init_lex(sub_stmt->session->lex, source);

    return CT_SUCCESS;
}

static void pl_complete_type_spec_desc(pl_entry_t *entry, pl_entity_t *entity)
{
    if (entry->desc.type == PL_TYPE_SPEC) {
        type_spec_t *spec = entity->type_spec;
        spec->desc.uid = entry->desc.uid;
        spec->desc.oid = entry->desc.oid;
    }
}


static status_t pl_compile_object(load_assist_t *load_ass, pl_entry_t *entry, pl_entity_t *entity)
{
    plc_desc_t desc = { 0 };
    word_t word = { 0 };
    word.type = WORD_TYPE_VARIANT;
    word.text.value = entity->def.name;
    desc.obj = &entity->def;
    desc.type = entry->desc.type;
    desc.proc_oid = entry->desc.oid;
    desc.entity = entity;
    desc.source_pages = load_ass->source_page;
    if (entry->desc.type == PL_TRIGGER) {
        CT_RETURN_IFERR(pl_parse_trigger_desc(load_ass->sub_stmt, &entity->def, &word));
    }
    if (plc_compile(load_ass->sub_stmt, &desc, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (g_tls_plc_error.plc_cnt == 0) {
        reset_tls_plc_error();
    }
    return CT_SUCCESS;
}

#define CONVERT_OBJ_STATUS(obj, cl_ret) (obj) = ((cl_ret) == CT_SUCCESS) ? OBJ_STATUS_VALID : OBJ_STATUS_INVALID

status_t pl_load_entity(sql_stmt_t *stmt, pl_entry_t *entry, pl_entity_t **entity_out)
{
    pl_entity_t *entity = NULL;
    load_assist_t load_ass = { 0 };
    object_status_t obj_status;
    status_t status;
    CT_RETURN_IFERR(pl_alloc_entity(entry, &entity));
    PLE_SAVE_STMT(stmt);

    if (pl_prepare_load_entity(stmt, entry, entity, &load_ass) != CT_SUCCESS) {
        pl_free_entity(entity);
        PLE_RESTORE_STMT(stmt);
        return CT_ERROR;
    }
    stmt->session->current_stmt = load_ass.sub_stmt;
    status = pl_compile_object(&load_ass, entry, entity);
    CONVERT_OBJ_STATUS(obj_status, status);
    status = pl_proc_compile_result(KNL_SESSION(stmt), entity, obj_status);
    if (obj_status != OBJ_STATUS_VALID || status != CT_SUCCESS) {
        pl_free_entity(entity);
        entity = NULL;
    } else {
        sql_free_context(entity->context);
        entity->context = NULL;
        pl_complete_type_spec_desc(entry, entity);
    }

    sql_release_lob_info(load_ass.sub_stmt);
    sql_release_resource(load_ass.sub_stmt, CT_TRUE);
    pl_free_source_page(&load_ass.source_page, load_ass.new_page);
    pl_restore_lex(stmt, load_ass.lex_bak);
    PLE_RESTORE_STMT(stmt);
    *entity_out = entity;

    return status;
}

status_t pl_get_entity(sql_stmt_t *stmt, pl_dc_t *dc)
{
    pl_entry_t *entry = dc->entry;
    pl_entity_t *entity = NULL;

    if (pl_check_entity(entry, &entity)) {
        dc->entity = entity;
        return CT_SUCCESS;
    }

    if (pl_load_entity(stmt, entry, &entity) != CT_SUCCESS || entity == NULL) {
        return CT_ERROR;
    }

    pl_set_entity(entry, &entity);
    dc->entity = entity;
    return CT_SUCCESS;
}

status_t pl_dc_find_subobject(knl_session_t *session, pl_dc_t *dc, text_t *sub_name)
{
    pl_entry_t *entry = dc->entry;
    pl_entity_t *entity = dc->entity;
    plv_decl_t *decl = NULL;
    function_t *func = NULL;
    galist_t *list = NULL;

    // only support package
    if (entry->desc.type != PL_PACKAGE_SPEC && entry->desc.type != PL_SYS_PACKAGE) {
        return CT_ERROR;
    }

    if (entry->desc.type == PL_SYS_PACKAGE) {
        pl_convert_pack_func((uint32)dc->oid, sub_name, &dc->sub_id);
        if (dc->sub_id == (uint8)CT_INVALID_ID32) {
            return CT_ERROR;
        }
        return CT_SUCCESS;
    }

    list = entity->package_spec->defs;
    for (uint32 i = 0; i < list->count; i++) {
        decl = (plv_decl_t *)cm_galist_get(list, i);
        if (cm_text_equal(sub_name, &decl->name)) {
            if (decl->type == PLV_FUNCTION) {
                func = decl->func;
                dc->sub_type = func->desc.pl_type;
                dc->sub_id = func->desc.proc_id - 1;
                dc->lang_type = func->desc.lang_type;
                return CT_SUCCESS;
            }
        }
    }

    return CT_ERROR;
}

void pl_dc_init(pl_dc_t *pl_dc, pl_entry_t *entry)
{
    if (entry == NULL) {
        return;
    }

    pl_dc->is_recursive = CT_FALSE;
    if (entry->desc.type == PL_SYNONYM) {
        pl_dc->is_sysnonym = CT_TRUE;
        pl_dc->syn_entry = entry;
        pl_dc->syn_scn = entry->desc.chg_scn;
        pl_dc->type = PL_SYNONYM;
    } else {
        pl_dc->is_sysnonym = CT_FALSE;
        pl_dc->org_scn = entry->desc.org_scn;
        pl_dc->chg_scn = entry->desc.chg_scn;
        pl_dc->entry = entry;
        pl_dc->type = entry->desc.type;
        pl_dc->oid = entry->desc.oid;
        pl_dc->uid = entry->desc.uid;
    }
}

void pl_dc_reopen(pl_dc_t *pl_dc)
{
    if (pl_dc == NULL || pl_dc->entity == NULL) {
        return;
    }
    pl_entity_ref_inc(pl_dc->entity);
}

void pl_dc_close(pl_dc_t *pl_dc)
{
    if (pl_dc == NULL || pl_dc->entity == NULL || pl_dc->is_recursive) {
        return;
    }

    pl_entity_lock(pl_dc->entity);
    if (!pl_dc->entity->cached) {
        if (pl_dc->entity->ref_count > 1) {
            pl_dc->entity->ref_count--;
            pl_entity_unlock(pl_dc->entity);
        } else {
            pl_dc->entity->ref_count--;
            pl_entity_unlock(pl_dc->entity);
            pl_free_entity(pl_dc->entity);
        }
        return;
    }

    CM_ASSERT(pl_dc->entity->ref_count > 0);
    if (pl_dc->entity->ref_count > 1 || pl_dc->entity->valid) {
        pl_dc->entity->ref_count--;
        pl_entity_unlock(pl_dc->entity);
        return;
    }
    pl_entity_unlock(pl_dc->entity);

    pl_manager_t *pl_manager = GET_PL_MGR;
    pl_list_t *lru_list = &pl_manager->pl_entity_lru[pl_dc->entity->lru_hash];

    pl_list_del(lru_list, &pl_dc->entity->lru_link, CT_TRUE);
    pl_entity_ref_dec(pl_dc->entity);
    pl_free_entity(pl_dc->entity);
}

static void pl_dc_find_entry_core(dc_user_t *dc_user, text_t *name, uint32 type, pl_dc_t *dc, bool32 *is_found,
    bool32 *ready)
{
    pl_manager_t *pl_manager = GET_PL_MGR;
    uint32 bucket_id = cm_hash_string(T2S(name), PL_ENTRY_NAME_BUCKET_SIZE);
    pl_list_t *bucket_lst = &pl_manager->entry_name_buckets[bucket_id];
    pl_entry_t *entry = NULL;
    uint32 uid = dc_user->desc.id;

    *is_found = CT_FALSE;
    cm_latch_s(&bucket_lst->latch, CM_THREAD_ID, CT_FALSE, NULL);
    BILIST_SEARCH(&bucket_lst->lst, pl_entry_t, entry, bucket_link, pl_entry_check(entry, uid, T2S(name), type));
    if (entry != NULL) {
        *is_found = CT_TRUE;
        pl_entry_lock(entry);
        *ready = entry->ready;
        if (*ready) {
            pl_dc_init(dc, entry);
        }

        pl_entry_unlock(entry);
    }
    cm_unlatch(&bucket_lst->latch, NULL);
}

void pl_dc_find(dc_user_t *user, text_t *name, uint32 type, pl_dc_t *dc, bool32 *is_found)
{
    bool32 ready = CT_FALSE;

    while (CT_TRUE) {
        pl_dc_find_entry_core(user, name, type, dc, is_found, &ready);
        if (!*is_found || ready) {
            break;
        }
        cm_sleep(1);
    }
}

static void pl_dc_init_for_recursion(pl_dc_t *pl_dc, pl_compiler_t *compile, var_udo_t *obj)
{
    pl_entity_t *entity = (pl_entity_t *)compile->entity;
    procedure_t *proc = (procedure_t *)compile->proc;

    pl_dc_init(pl_dc, entity->entry);
    pl_dc->is_recursive = CT_TRUE;
    pl_dc->entity = entity;
    pl_dc->type = proc->desc.pl_type;
    pl_dc->obj = obj;
}

static status_t pl_dc_open_synonym_check_recursion(pl_dc_assist_t *dc_ass, pl_dc_t *dc, text_t *user, text_t *name,
    uint32 expect_type, bool32 *is_found)
{
    sql_stmt_t *stmt = dc_ass->stmt;
    pl_compiler_t *compile = NULL;
    var_udo_t obj;

    *is_found = CT_FALSE;
    sql_init_udo_with_text(&obj, user, (text_t *)&g_null_text, name);
    compile = (pl_compiler_t *)stmt->pl_compiler;
    if (compile == NULL || !var_udo_text_equal(&obj, compile->obj) || !(compile->root_type & expect_type)) {
        return CT_SUCCESS;
    }

    *is_found = CT_TRUE;
    if (compile->root_type == PL_TYPE_SPEC) {
        CT_THROW_ERROR_EX(ERR_PL_SYNTAX_ERROR_FMT, "type %s.%s cannot be recursive", T2S(user), T2S_EX(name));
        return CT_ERROR;
    }

    // there are recursive calls in the parameters of the current function, such as default expr
    if (compile->step == PL_COMPILE_INIT) {
        CT_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "unexpected procedure/function");
        return CT_ERROR;
    }
    pl_dc_init_for_recursion(dc, compile, compile->obj);
    return CT_SUCCESS;
}

static status_t pl_dc_open_synonym(pl_dc_assist_t *org_assist, pl_dc_t *dc, bool32 *is_found)
{
    pl_entry_t *syn_entry = dc->syn_entry;
    knl_scn_t syn_scn = dc->syn_scn;
    text_t user, name;
    pl_dc_assist_t dc_ass;
    uint32 expect_type;
    bool32 exist = CT_FALSE;

    cm_str2text(syn_entry->desc.link_user, &user);
    cm_str2text(syn_entry->desc.link_name, &name);
    expect_type = org_assist->expect_type & (~PL_SYNONYM);

    // create procedure A, synonym B for A, create or replace A begin use B
    if (pl_dc_open_synonym_check_recursion(org_assist, dc, &user, &name, expect_type, &exist) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (exist) {
        return CT_SUCCESS;
    }

    pl_dc_open_prepare(&dc_ass, org_assist->stmt, &user, &name, expect_type);
    dc_ass.priv_check = org_assist->priv_check;

    if (pl_dc_open(&dc_ass, dc, is_found) != CT_SUCCESS) {
        return CT_ERROR;
    }

    dc->syn_entry = syn_entry;
    dc->syn_scn = syn_scn;
    dc->is_sysnonym = CT_TRUE;

    return CT_SUCCESS;
}

static status_t pl_dc_open_entry_core(pl_dc_assist_t *dc_ass, pl_dc_t *dc, bool32 *is_found)
{
    if (dc->is_sysnonym) {
        return pl_dc_open_synonym(dc_ass, dc, is_found);
    }

    if (pl_get_entity(dc_ass->stmt, dc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t pl_dc_open_entry(pl_dc_assist_t *dc_ass, pl_dc_t *dc, bool32 *is_found)
{
    pl_entry_t *entry = NULL;
    knl_scn_t scn;
    knl_handle_t sess = (knl_handle_t)KNL_SESSION(dc_ass->stmt);
    pl_entry_info_t entry_info = { 0 };

    if (dc->type == PL_SYS_PACKAGE) {
        return CT_SUCCESS;
    }

    if (dc->is_sysnonym) {
        entry = dc->syn_entry;
        scn = dc->syn_scn;
    } else {
        entry = dc->entry;
        scn = dc->chg_scn;
    }

    entry_info.entry = entry;
    entry_info.scn = scn;
    if (pl_lock_entry_shared(sess, &entry_info) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (pl_dc_open_entry_core(dc_ass, dc, is_found) != CT_SUCCESS) {
        pl_unlock_shared(sess, entry);
        return CT_ERROR;
    }

    pl_unlock_shared(sess, entry);
    return CT_SUCCESS;
}

static void pl_dc_reset(pl_dc_t *dc)
{
    dc->is_sysnonym = CT_FALSE;
    dc->is_recursive = CT_FALSE;
    dc->type = 0;
    dc->sub_type = 0;
    dc->entry = NULL;
    dc->entity = NULL;
    dc->syn_entry = NULL;
}

void pl_dc_open_prepare(pl_dc_assist_t *dc_ass, sql_stmt_t *stmt, text_t *user_name, text_t *obj_name,
    uint32 expect_type)
{
    dc_ass->stmt = stmt;
    dc_ass->user_name = user_name;
    dc_ass->obj_name = obj_name;
    dc_ass->expect_type = expect_type;
    dc_ass->priv_check = CT_TRUE;
}

void pl_dc_open_prepare_for_ignore_priv(pl_dc_assist_t *dc_ass, sql_stmt_t *stmt, text_t *user_name, text_t *obj_name,
    uint32 expect_type)
{
    dc_ass->stmt = stmt;
    dc_ass->user_name = user_name;
    dc_ass->obj_name = obj_name;
    dc_ass->expect_type = expect_type;
    dc_ass->priv_check = CT_FALSE;
}

status_t pl_dc_open(pl_dc_assist_t *dc_ass, pl_dc_t *dc, bool32 *is_found)
{
    knl_session_t *session = KNL_SESSION(dc_ass->stmt);
    pl_manager_t *pl_manager = GET_PL_MGR;
    dc_user_t *user = NULL;

    *is_found = CT_FALSE;
    pl_dc_reset(dc);

    if (!pl_manager->initialized) {
        return CT_SUCCESS;
    }

    if (dc_open_user(session, dc_ass->user_name, &user) != CT_SUCCESS) {
        cm_reset_error();
        return CT_SUCCESS;
    }

    pl_dc_find(user, dc_ass->obj_name, dc_ass->expect_type, dc, is_found);
    if (!*is_found) {
        return CT_SUCCESS;
    }

    if (pl_check_dc_priv(dc_ass, dc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (pl_dc_open_entry(dc_ass, dc, is_found) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc->entity != NULL && !dc->entity->cached) {
        sql_context_uncacheable(dc_ass->stmt->context);
        pl_entity_uncacheable(dc_ass->stmt->pl_context);
    }

    return CT_SUCCESS;
}

status_t pl_check_type_recursion(sql_stmt_t *stmt, var_udo_t *obj)
{
    sql_stmt_t *tmp_stmt = NULL;
    pl_compiler_t *compile = NULL;

    tmp_stmt = stmt;
    while (tmp_stmt != NULL) {
        compile = (pl_compiler_t *)tmp_stmt->pl_compiler;
        if (compile != NULL && compile->type == PL_TYPE_SPEC && var_udo_text_equal(compile->obj, obj)) {
            CT_THROW_ERROR_EX(ERR_PL_SYNTAX_ERROR_FMT, "type %s.%s cannot be recursive", T2S(&obj->user),
                T2S_EX(&obj->name));
            return CT_ERROR;
        }
        tmp_stmt = tmp_stmt->parent_stmt;
    }
    return CT_SUCCESS;
}

static status_t pl_try_find_type_dc_core(sql_stmt_t *stmt, var_udo_t *obj, pl_dc_t *dc, bool32 *is_found)
{
    pl_dc_t *reg_dc = NULL;
    status_t status;
    pl_dc_assist_t dc_ass = { 0 };

    if (pl_check_type_recursion(stmt, obj) != CT_SUCCESS) {
        *is_found = CT_TRUE;
        return CT_ERROR;
    }
    reg_dc = pl_get_regist_dc(stmt, obj, PL_TYPE_SPEC);
    if (reg_dc != NULL) {
        *is_found = CT_TRUE;
        *dc = *reg_dc;
        return CT_SUCCESS;
    }
    pl_dc_open_prepare(&dc_ass, stmt, &obj->user, &obj->name, PL_TYPE_SPEC | PL_SYNONYM);
    dc->obj = obj;
    status = pl_dc_open(&dc_ass, dc, is_found);
    if (!*is_found) {
        pl_revert_last_error(status);
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(status);
    if (pl_regist_dc(stmt, dc, &reg_dc) != CT_SUCCESS) {
        pl_dc_close(dc);
        return CT_ERROR;
    }

    if (pl_regist_reference(stmt->context->ref_objects, reg_dc) != CT_SUCCESS) {
        pl_dc_close(dc);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t pl_try_find_type_dc(sql_stmt_t *stmt, var_udo_t *obj, pl_dc_t *dc, bool32 *is_found)
{
    status_t status;

    if (obj->user_explicit) {
        // A.B just find type B in schema A
        status = pl_try_find_type_dc_core(stmt, obj, dc, is_found);
    } else {
        // B.  1st find type B in current schema, 2nd find type B in public
        status = pl_try_find_type_dc_core(stmt, obj, dc, is_found);
        if (*is_found) {
            return status;
        }
        pl_revert_last_error(status);
        var_udo_t tmp_obj = { 0 };
        text_t pub_user = { PUBLIC_USER, (uint32)strlen(PUBLIC_USER) };
        tmp_obj = *obj;
        tmp_obj.user = pub_user;
        status = pl_try_find_type_dc_core(stmt, &tmp_obj, dc, is_found);
    }

    return status;
}

void pl_set_node_type(expr_node_t *expr_node, expr_node_type_t type, uint8 lang_type, bool8 is_pkg)
{
    expr_node->type = type;
    expr_node->lang_type = lang_type;
    expr_node->is_pkg = is_pkg;
}

uint32 pl_get_node_type(expr_node_t *expr_node)
{
    if (expr_node->type == EXPR_NODE_PROC || expr_node->type == EXPR_NODE_USER_PROC) {
        return PL_PROCEDURE;
    }

    return PL_FUNCTION;
}

static status_t pl_is_out_arg(sql_verifier_t *verif, expr_tree_t *arg, bool32 *is_out)
{
    uint32 dir;
    *is_out = CT_FALSE;

    if (arg->root->type == EXPR_NODE_V_ADDR) {
        var_address_pair_t *pair = sql_get_last_addr_pair(arg->root);
        if (pair == NULL) {
            CT_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "pair is null");
            return CT_ERROR;
        }
        if (pair->type == UDT_STACK_ADDR && pair->stack->decl->type == PLV_PARAM) {
            *is_out = (pair->stack->decl->drct == (uint8)PLV_DIR_OUT);
        }
    } else if ((arg->root->type == EXPR_NODE_PARAM) && (verif->stmt->plsql_mode == PLSQL_DYNBLK)) {
        if (ple_get_dynsql_param_dir(verif->stmt, (uint32)arg->root->value.v_param_id, &dir) != CT_SUCCESS) {
            return CT_ERROR;
        }
        *is_out = (dir == (uint8)PLV_DIR_OUT);
    }

    return CT_SUCCESS;
}

static status_t pl_verify_func_in_arg(sql_verifier_t *verif, expr_node_t *func, expr_tree_t *arg, uint32 i)
{
    uint32 pos = (func->type == EXPR_NODE_USER_FUNC) ? i : (i + 1); // not overflow
    bool32 is_out = CT_FALSE;

    if (pl_is_out_arg(verif, arg, &is_out) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (is_out) {
        CT_SRC_THROW_ERROR(func->loc, ERR_PL_ARG_FMT, pos, T2S(&func->word.func.name),
            "OUT bind variable bound to an in position");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t pl_verify_func_out_arg(sql_verifier_t *verif, expr_node_t *func, expr_tree_t *arg, plv_decl_t *decl,
    uint32 i)
{
    uint32 pos = (func->type == EXPR_NODE_USER_FUNC) ? i : (i + 1); // not overflow
    pl_arg_info_t arg_info = {
        .func = func,
        .pos = pos
    };
    pl_compiler_t *pl_compiler = (pl_compiler_t *)verif->stmt->pl_compiler;
    CT_RETURN_IFERR(plc_verify_out_expr(pl_compiler, arg, &arg_info));

    if (arg->root->type != EXPR_NODE_V_ADDR) {
        return CT_SUCCESS;
    }
    if (pl_compiler == NULL) {
        return CT_SUCCESS;
    }

    if (!sql_pair_type_is_plvar(arg->root)) {
        return CT_SUCCESS;
    }
    var_address_pair_t *pair = (var_address_pair_t *)cm_galist_get(arg->root->value.v_address.pairs, 0);
    plv_decl_t *out_decl = pair->stack->decl;
    if (out_decl->type == PLV_PARAM) {
        // param's datatype equal the type defined by procedure
        if (decl->type == PLV_CUR) {
            out_decl->param.type.datatype = CT_TYPE_CURSOR;
        } else {
            out_decl->param.type = decl->variant.type;
        }
        out_decl->drct = decl->drct;
        arg->root->datatype = out_decl->param.type.datatype;
    } else if (decl->type == PLV_CUR && out_decl->type != PLV_CUR) {
        CT_SRC_THROW_ERROR(arg->loc, ERR_PL_ARG_FMT, pos, T2S(&func->word.func.name),
            "not cursor bound to an OUT cursor position");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t pl_verify_func_arg(sql_verifier_t *verif, expr_node_t *func, expr_tree_t *arg, plv_decl_t *decl,
    uint32 i)
{
    plv_direction_t dir;

    CT_RETURN_IFERR(sql_verify_expr_node(verif, arg->root));

    dir = decl->drct;

    switch (dir) {
        case PLV_DIR_IN:
            return pl_verify_func_in_arg(verif, func, arg, i);
        case PLV_DIR_OUT:
        case PLV_DIR_INOUT:
            return pl_verify_func_out_arg(verif, func, arg, decl, i);
        case PLV_DIR_NONE:
        default:
            return CT_SUCCESS;
    }
}

static inline void pl_calc_func_argsno(expr_tree_t *root, uint32 *cmp_cnts)
{
    expr_tree_t *expr = root;
    uint32 counts = 0;
    while (expr != NULL) {
        counts++;
        expr = expr->next;
    }
    *cmp_cnts = counts;
}

static status_t pl_check_input_args(expr_node_t *func, galist_t *decls, uint32 arg_count)
{
    uint32 start_id = (func->type == EXPR_NODE_USER_PROC) ? 0 : 1;
    expr_tree_t *arg = func->argument;
    plv_decl_t *decl = NULL;
    for (arg = func->argument; arg != NULL; arg = arg->next) {
        CT_CONTINUE_IFTRUE(arg->arg_name.len == 0);
        uint32 i = start_id;
        for (; i < arg_count; i++) {
            decl = (plv_decl_t *)cm_galist_get(decls, i);
            CT_BREAK_IF_TRUE(cm_compare_text(&arg->arg_name, &decl->name) == 0);
        }
        if (i == arg_count) {
            CT_SRC_THROW_ERROR(arg->loc, ERR_ARGUMENT_NOT_FOUND, T2S(&arg->arg_name));
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t pl_verify_func_args(sql_verifier_t *verif, galist_t *arg_list, uint32 arg_count, expr_node_t *func)
{
    expr_tree_t *expr = func->argument;
    plv_decl_t *decl = NULL;
    uint32 cmp_cnts = 0;
    uint32 i;
    uint32 start_id = (func->type == EXPR_NODE_USER_PROC) ? 0 : 1;
    expr_tree_t *arg = NULL;
    CT_RETURN_IFERR(pl_check_input_args(func, arg_list, arg_count));
    for (i = start_id; i < arg_count; ++i) {
        decl = (plv_decl_t *)cm_galist_get(arg_list, i);

        if (expr != NULL && expr->arg_name.len == 0) {
            CT_RETURN_IFERR(pl_verify_func_arg(verif, func, expr, decl, i));
            expr = expr->next;
            continue;
        }

        arg = expr;
        while (arg != NULL) { // '=>'
            if (cm_compare_text(&decl->name, &arg->arg_name) == 0) {
                CT_RETURN_IFERR(pl_verify_func_arg(verif, func, arg, decl, i));
                break;
            }
            arg = arg->next;
        }

        CT_CONTINUE_IFTRUE(arg != NULL);

        if (decl->default_expr == NULL) {
            CT_SRC_THROW_ERROR(func->loc, ERR_TOO_LESS_ARGS, "procedure/function");
            return CT_ERROR;
        }
    }

    pl_calc_func_argsno(func->argument, &cmp_cnts);
    if ((cmp_cnts + start_id) > arg_count) { // not overflow
        CT_SRC_THROW_ERROR(func->loc, ERR_PL_SYNTAX_ERROR_FMT,
            "unexpected more arguments for current procedure/function");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

char *pl_get_node_type_string(expr_node_type_t type)
{
    if (type == EXPR_NODE_FUNC || type == EXPR_NODE_USER_FUNC) {
        return "function";
    }

    return "procedure";
}

status_t pl_try_verify_func_set_error(expr_node_t *node, var_udo_t *obj)
{
    if (node->word.func.count == 1 || node->word.func.count == 0) {
        CT_SRC_THROW_ERROR(node->loc, ERR_USER_OBJECT_NOT_EXISTS, pl_get_node_type_string(node->type), T2S(&obj->user),
            T2S_EX(&obj->name));
        return CT_ERROR;
    } else if (node->word.func.count == 2) {
        CT_SRC_THROW_ERROR(node->loc, ERR_USER_OBJECT_NOT_EXISTS, pl_get_node_type_string(node->type), T2S(&obj->pack),
            T2S_EX(&obj->name));
        return CT_ERROR;
    } else {
        CT_SRC_THROW_ERROR(node->loc, ERR_USER_OBJECT_NOT_EXISTS, pl_get_node_type_string(node->type),
            CC_T2S(&obj->user, &obj->pack, '.'), T2S_EX(&obj->name));
        return CT_ERROR;
    }
}

static status_t pl_verify_func_not_support_sharding(sql_verifier_t *verif, expr_node_t *node, var_func_t *vf)
{
    if (IS_COORDINATOR && IS_APP_CONN(verif->stmt->session) && vf->func_id != CT_INVALID_ID32) {
        switch (g_func_tab[vf->func_id].builtin_func_id) {
            /*
             * sys_context only support local select
             * eg: select sys_context() from sys_dummy;
             * eg: SELECT COUNT(user_name) FROM DV_ME WHERE SID IN (SELECT SYS_CONTEXT('USERENV', 'SID') FROM
             * SYS_DUMMY);
             */
            case ID_FUNC_ITEM_SYS_CONTEXT:
            case ID_FUNC_ITEM_USERENV: {
                if (verif->context->type == CTSQL_TYPE_CREATE_TABLE) {
                    CT_SRC_THROW_ERROR(node->word.func.name.loc, ERR_CAPABILITY_NOT_SUPPORT,
                        "function SYS_CONTEXT/USERENV use for distribute table is");
                    return CT_ERROR;
                }
                break;
            }
            case ID_FUNC_ITEM_AVG:
            case ID_FUNC_ITEM_SUM:
            case ID_FUNC_ITEM_MEDIAN: {
                if (node->dis_info.need_distinct) {
                    CT_SRC_THROW_ERROR(node->word.func.name.loc, ERR_CAPABILITY_NOT_SUPPORT,
                        "distinct in aggr function on coordinator is");
                    return CT_ERROR;
                }
                break;
            }
                /*
                 * group_concat is not ready for z_sharding.
                 * object_id() & connection_id() returns the node-related info.
                 * however, if a built-in function appears in the WHERE clause,
                 * it would be pushed to the remote node and lost its meaning.
                 * so currently we cannot support the node-related built-in function for z_sharding
                 */
                /*
                 * in the future, considering the distribute database usage,
                 * we should divide the function into at least 3 types:
                 * 1. shippable function,
                 * 2. non-shippable function(i.e. CN only) and
                 * 3. the function cannot be used in the distribute database
                 */
            case ID_FUNC_ITEM_GROUPING:
            case ID_FUNC_ITEM_GROUPING_ID:
            case ID_FUNC_ITEM_ARRAY_AGG:
            case ID_FUNC_ITEM_OBJECT_ID:
            case ID_FUNC_ITEM_LAST_INSERT_ID:
            case ID_FUNC_ITEM_UPDATING:
            case ID_FUNC_ITEM_FOUND_ROWS:
            case ID_FUNC_ITEM_TRY_GET_LOCK:
            case ID_FUNC_ITEM_RELEASE_SHARED_LOCK:
            case ID_FUNC_ITEM_GET_SHARED_LOCK:
            case ID_FUNC_ITEM_GET_XACT_LOCK:
            case ID_FUNC_ITEM_TRY_GET_XACT_LOCK:
            case ID_FUNC_ITEM_GET_XACT_SHARED_LOCK:
            case ID_FUNC_ITEM_LISTAGG: {
                CT_SRC_THROW_ERROR(node->word.func.name.loc, ERR_CAPABILITY_NOT_SUPPORT,
                    "this function on coordinator");
                return CT_ERROR;
            }

            case ID_FUNC_ITEM_GROUP_CONCAT:
            case ID_FUNC_ITEM_GET_LOCK:
            case ID_FUNC_ITEM_RELEASE_LOCK: {
                break;
            }
            default:
                break;
        }
    }
    return CT_SUCCESS;
}

static status_t pl_verify_func_array_arg(uint32 func_id, expr_node_t *node)
{
    expr_tree_t *arg = node->argument;
    expr_node_t *arg_node = NULL;

    switch (func_id) {
        case ID_FUNC_ITEM_ARRAY_LENGTH:
        case ID_FUNC_ITEM_DECODE:
        case ID_FUNC_ITEM_CAST:
        case ID_FUNC_ITEM_TO_CHAR:
            break;

        default:
            while (arg != NULL) {
                arg_node = arg->root;
                if (arg_node->typmod.is_array == CT_TRUE) {
                    CT_SRC_THROW_ERROR(NODE_LOC(node), ERR_INVALID_ARG_TYPE);
                    return CT_ERROR;
                }
                arg = arg->next;
            }
            break;
    }

    return CT_SUCCESS;
}

static status_t pl_generate_aggr(sql_verifier_t *verif, expr_node_t *node, uint32 func_id)
{
    expr_node_t *aggr_node = NULL;
    expr_node_t *cndis_column = NULL;

    CT_RETURN_IFERR(cm_galist_new(verif->aggrs, sizeof(expr_node_t), (void **)&aggr_node));

    MEMS_RETURN_IFERR(memcpy_s(aggr_node, sizeof(expr_node_t), node, sizeof(expr_node_t)));
    sql_init_aggr_node(aggr_node, func_id, CT_INVALID_ID32);

    node->type = EXPR_NODE_AGGR;
    node->value.type = CT_TYPE_INTEGER;
    node->value.v_int = (int32)(verif->aggrs->count - 1);

    if (node->dis_info.need_distinct) {
        aggr_node->dis_info.group_id = CT_INVALID_ID32;

        if (CT_IS_LOB_TYPE(TREE_DATATYPE(aggr_node->argument))) {
            CT_SRC_THROW_ERROR(aggr_node->argument->loc, ERR_SQL_SYNTAX_ERROR, "unexpected lob column occurs");
            return CT_ERROR;
        }

        // ignore max and min which don't need do distinct
        if (func_id == ID_FUNC_ITEM_MAX || func_id == ID_FUNC_ITEM_MIN) {
            node->dis_info.need_distinct = CT_FALSE;
            aggr_node->dis_info.need_distinct = CT_FALSE;
        } else {
            node->dis_info.idx = verif->curr_query->aggr_dis_count++;
            aggr_node->dis_info.idx = node->dis_info.idx;

            // record the expr in count(distinct expr), expr is already checked in sql_verify_count
            // and can't be EXPR_NODE_STAR
            if (func_id == ID_FUNC_ITEM_COUNT) {
                SET_NODE_STACK_CURR_QUERY(verif->stmt, verif->curr_query);
                CT_RETURN_IFERR(
                    sql_clone_expr_node(verif->stmt->context, aggr_node->argument->root, &cndis_column, sql_alloc_mem));
                SQL_RESTORE_NODE_STACK(verif->stmt);
                CT_RETURN_IFERR(cm_galist_insert(verif->cntdis_columns, cndis_column));
                aggr_node->dis_info.group_id = verif->cntdis_columns->count - 1;
            }
        }
    }

    if ((func_id == ID_FUNC_ITEM_LISTAGG || func_id == ID_FUNC_ITEM_GROUP_CONCAT) && aggr_node->sort_items != NULL) {
        verif->curr_query->has_aggr_sort = CT_TRUE;
    }

    return CT_SUCCESS;
}

static bool8 pl_try_match_aggr(sql_verifier_t *verif, expr_node_t *node)
{
    expr_node_t *aggr_node = NULL;

    for (uint32 i = 0; i < verif->aggrs->count; i++) {
        aggr_node = (expr_node_t *)cm_galist_get(verif->aggrs, i);
        if (sql_expr_node_equal(verif->stmt, aggr_node, node, NULL)) {
            aggr_node->value.v_func.aggr_ref_count++;
            node->type = EXPR_NODE_AGGR;
            node->value.type = CT_TYPE_INTEGER;
            node->value.v_int = i;
            return CT_TRUE;
        }
    }

    return CT_FALSE;
}

static status_t pl_verify_aggr(sql_verifier_t *verif, expr_node_t *node, uint32 func_id)
{
    if (verif->excl_flags & SQL_EXCL_AGGR) {
        CT_SRC_THROW_ERROR(node->loc, ERR_UNEXPECTED_ARRG, T2S(&node->word.func.name));
        return CT_ERROR;
    }

    verif->incl_flags |= SQL_INCL_AGGR;

    if (pl_try_match_aggr(verif, node)) {
        return CT_SUCCESS;
    }

    if (verif->aggr_flags == 0) {
        CT_SRC_THROW_ERROR(node->loc, ERR_UNEXPECTED_ARRG, T2S(&node->word.func.name));
        return CT_ERROR;
    }

    return pl_generate_aggr(verif, node, func_id);
}

static status_t pl_update_node_type(expr_node_t *node, sql_func_t *func)
{
    CM_ASSERT(func != NULL);
    if (node->type == EXPR_NODE_PROC || node->type == EXPR_NODE_USER_PROC) {
        if (func->options == FO_NORMAL || func->options == FO_PROC) {
            return CT_SUCCESS;
        } else {
            CT_SRC_THROW_ERROR(node->word.func.name.loc, ERR_SQL_SYNTAX_ERROR,
                "expect a procedure here but meet a function");
        }
    } else if (func->options == FO_PROC) {
        node->type = EXPR_NODE_PROC;
    } else {
        node->type = EXPR_NODE_FUNC;
    }
    return CT_SUCCESS;
}

status_t pl_try_verify_builtin_func(sql_verifier_t *verif, expr_node_t *node, var_udo_t *obj, bool32 *is_found)
{
    sql_func_t *func = NULL;

    CM_TEXT_CLEAR(&obj->user);
    CM_TEXT_CLEAR(&obj->pack);
    cm_text_copy(&obj->name, CT_NAME_BUFFER_SIZE, &node->word.func.name.value);

    CM_POINTER2(verif, node);
    var_func_t vf = node->value.v_func;

    vf.func_id = sql_get_func_id((text_t *)&node->word.func.name);
    vf.pack_id = CT_INVALID_ID32;
    vf.is_proc = CT_FALSE;

    /*
     * The avg_collect() does not support input from original sql.
     * It only used for transform of z_sharding.
     */
    if (vf.func_id != CT_INVALID_ID32) {
        *is_found = CT_TRUE;
        func = sql_get_func(&vf);
        node->value.v_func = vf;
    } else {
        *is_found = CT_FALSE;
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(pl_verify_func_not_support_sharding(verif, node, &vf));

    /* check expect type */
    if (node->type == EXPR_NODE_PROC || node->type == EXPR_NODE_USER_PROC) {
        CT_SRC_THROW_ERROR(node->loc, ERR_USER_OBJECT_NOT_EXISTS, "procedure", verif->stmt->session->curr_schema,
            T2S(&node->word.func.name.value));
        return CT_ERROR;
    }

    /*
     * Not support grouping function in aggr
     */
    uint32 saved_flags = verif->excl_flags;
    if (func->aggr_type != AGGR_TYPE_NONE) {
        verif->excl_flags |= SQL_AGGR_EXCL;
    }

    if (func->verify(verif, node) != CT_SUCCESS) {
        return CT_ERROR;
    }
    verif->excl_flags = saved_flags;

    if (pl_verify_func_array_arg(vf.func_id, node) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (func->options == FO_NORMAL) { // this IF branch may be removed when all function are
        sql_infer_func_optmz_mode(verif, node);
    }

    if (func->aggr_type != AGGR_TYPE_NONE) {
        return pl_verify_aggr(verif, node, vf.func_id);
    }
    if (node->dis_info.need_distinct) {
        CT_SRC_THROW_ERROR(node->loc, ERR_UNEXPECTED_KEY, "distinct");
        return CT_ERROR;
    }

    node->value.type = CT_TYPE_INTEGER;
    CT_RETURN_IFERR(pl_update_node_type(node, func));
    return CT_SUCCESS;
}

status_t pl_find_recursion_in_curr_cmpl(sql_verifier_t *verif, expr_node_t *node, var_udo_t *obj, bool32 *is_found)
{
    pl_compiler_t *compile = NULL;
    procedure_t *proc = NULL;
    pl_dc_t pl_dc = { 0 };
    pl_dc_t *reg_dc = NULL;

    *is_found = CT_FALSE;
    // if there are recursive calls, compile info has been saved in current stmt
    compile = (pl_compiler_t *)verif->stmt->pl_compiler;
    if (compile == NULL || compile->type == PL_TYPE_SPEC || !var_udo_text_equal(obj, compile->obj)) {
        return CT_SUCCESS;
    }

    if (compile->root_type != pl_get_node_type(node)) {
        return CT_SUCCESS;
    }

    *is_found = CT_TRUE;
    // there are recursive calls in the parameters of the current function, such as default expr
    if (compile->step == PL_COMPILE_INIT) {
        CT_SRC_THROW_ERROR(node->loc, ERR_PL_SYNTAX_ERROR_FMT, "unexpected procedure/function");
        return CT_ERROR;
    }

    CM_ASSERT(compile->proc != NULL);
    proc = (procedure_t *)compile->proc;
    if (proc->desc.pl_type == PL_FUNCTION) {
        pl_set_node_type(node, EXPR_NODE_USER_FUNC, LANG_PLSQL, CT_FALSE);
        plv_decl_t *ret = (plv_decl_t *)cm_galist_get(proc->desc.params, 0);
        SET_FUNC_RETURN_TYPE(ret, node);
    } else {
        pl_set_node_type(node, EXPR_NODE_USER_PROC, LANG_PLSQL, CT_FALSE);
    }
    CT_RETURN_IFERR(pl_verify_func_args(verif, proc->desc.params, proc->desc.arg_count, node));
    pl_dc_init_for_recursion(&pl_dc, compile, obj);
    CT_RETURN_IFERR(pl_regist_dc(verif->stmt, &pl_dc, &reg_dc));
    sql_set_pl_dc_for_user_func((void *)verif, node, (pointer_t)reg_dc);
    return CT_SUCCESS;
}

status_t pl_check_inter_generation_recursion(sql_verifier_t *verif, expr_node_t *node, var_udo_t *obj, bool32 *is_found)
{
    sql_stmt_t *stmt = verif->stmt;
    pl_compiler_t *compile = NULL;

    stmt = stmt->parent_stmt;
    while (stmt != NULL) {
        compile = (pl_compiler_t *)stmt->pl_compiler;
        if (compile != NULL && compile->type != PL_TYPE_SPEC && var_udo_text_equal(obj, compile->obj)) {
            *is_found = CT_TRUE;
            CT_SRC_THROW_ERROR_EX(node->loc, ERR_PL_SYNTAX_ERROR_FMT, "%s.%s cannot be intergenerational called",
                T2S(&obj->user), T2S_EX(&obj->name));
            return CT_ERROR;
        }
        stmt = stmt->parent_stmt;
    }
    return CT_SUCCESS;
}

static status_t pl_find_func_from_reg_dc(sql_verifier_t *verif, expr_node_t *node, var_udo_t *obj, bool32 *is_found)
{
    pl_dc_t *reg_dc = NULL;
    procedure_t *proc = NULL;
    uint32 type = pl_get_node_type(node);
    pl_compiler_t *compile = (pl_compiler_t *)verif->stmt->pl_compiler;

    *is_found = CT_FALSE;
    reg_dc = pl_get_regist_dc(verif->stmt, obj, type);
    if (reg_dc == NULL) {
        return CT_SUCCESS;
    }

    *is_found = CT_TRUE;
    if (reg_dc->is_recursive) {
        proc = compile->proc;
    } else {
        proc = reg_dc->entity->procedure;
    }

    if (proc->desc.pl_type == PL_FUNCTION) {
        pl_set_node_type(node, EXPR_NODE_USER_FUNC, proc->desc.lang_type, CT_FALSE);
        plv_decl_t *ret = (plv_decl_t *)cm_galist_get(proc->desc.params, 0);
        SET_FUNC_RETURN_TYPE(ret, node);
    } else {
        pl_set_node_type(node, EXPR_NODE_USER_PROC, proc->desc.lang_type, CT_FALSE);
    }
    CT_RETURN_IFERR(pl_verify_func_args(verif, proc->desc.params, proc->desc.arg_count, node));
    sql_set_pl_dc_for_user_func((void *)verif, node, (pointer_t)reg_dc);
    return CT_SUCCESS;
}

static status_t pl_find_recursion_function(sql_verifier_t *verif, expr_node_t *node, var_udo_t *obj, bool32 *is_found)
{
    *is_found = CT_FALSE;

    CT_RETURN_IFERR(pl_find_func_from_reg_dc(verif, node, obj, is_found));
    if (*is_found) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(pl_find_recursion_in_curr_cmpl(verif, node, obj, is_found));
    if (*is_found) {
        return CT_SUCCESS;
    }

    return pl_check_inter_generation_recursion(verif, node, obj, is_found);
}

status_t pl_try_verify_func(sql_verifier_t *verif, expr_node_t *node, var_udo_t *obj, bool32 *is_found)
{
    uint32 type = pl_get_node_type(node);
    text_t *user = &obj->user;
    text_t *name = &obj->name;
    pl_dc_t dc = { 0 };
    pl_dc_t *reg_dc = NULL;
    status_t status = CT_ERROR;
    pl_dc_assist_t dc_ass = { 0 };
    procedure_t *proc = NULL;
    pl_compiler_t *compile = (pl_compiler_t *)verif->stmt->pl_compiler;

    CT_RETURN_IFERR(pl_find_func_from_reg_dc(verif, node, obj, is_found));
    if (*is_found) {
        return CT_SUCCESS;
    }

    dc.obj = obj;
    pl_dc_open_prepare(&dc_ass, verif->stmt, user, name, type | PL_SYNONYM);
    CT_RETURN_IFERR(pl_dc_open(&dc_ass, &dc, is_found));
    if (!*is_found) {
        return CT_SUCCESS;
    }
    do {
        CM_ASSERT(dc.entity != NULL);
        if (dc.is_recursive) {
            proc = compile->proc;
        } else {
            proc = dc.entity->function;
        }
        dc.lang_type = proc->desc.lang_type;
        if (dc.type != PL_FUNCTION) {
            pl_set_node_type(node, EXPR_NODE_USER_PROC, dc.lang_type, CT_FALSE);
        } else {
            pl_set_node_type(node, EXPR_NODE_USER_FUNC, dc.lang_type, CT_FALSE);
            plv_decl_t *ret = (plv_decl_t *)cm_galist_get(proc->desc.params, 0);
            SET_FUNC_RETURN_TYPE(ret, node);
        }
        CT_BREAK_IF_ERROR(pl_verify_func_args(verif, proc->desc.params, proc->desc.arg_count, node));
        CT_BREAK_IF_ERROR(pl_regist_dc(verif->stmt, &dc, &reg_dc));
        CT_BREAK_IF_ERROR(pl_record_dc_for_check_priv(verif, reg_dc));
        CT_BREAK_IF_ERROR(pl_regist_reference(verif->stmt->context->ref_objects, reg_dc));
        sql_set_pl_dc_for_user_func((void *)verif, node, (pointer_t)reg_dc);
        status = CT_SUCCESS;
    } while (0);

    if (status == CT_ERROR) {
        pl_dc_close(&dc);
    }

    return status;
}

status_t pl_try_verify_func1(sql_verifier_t *verif, expr_node_t *node, var_udo_t *obj, bool32 *is_found)
{
    cm_text_copy_from_str(&obj->user, verif->stmt->session->curr_schema, CT_NAME_BUFFER_SIZE);
    CM_TEXT_CLEAR(&obj->pack);
    cm_text_copy(&obj->name, CT_NAME_BUFFER_SIZE, &node->word.func.name.value);

    return pl_try_verify_func(verif, node, obj, is_found);
}

status_t pl_try_verify_recursion_func1(sql_verifier_t *verif, expr_node_t *node, var_udo_t *obj, bool32 *is_found)
{
    *is_found = CT_FALSE;
    cm_text_copy_from_str(&obj->user, verif->stmt->session->curr_schema, CT_NAME_BUFFER_SIZE);
    CM_TEXT_CLEAR(&obj->pack);
    cm_text_copy(&obj->name, CT_NAME_BUFFER_SIZE, &node->word.func.name.value);

    return pl_find_recursion_function(verif, node, obj, is_found);
}

status_t pl_try_verify_recursion_func2(sql_verifier_t *verif, expr_node_t *node, var_udo_t *obj, bool32 *is_found)
{
    *is_found = CT_FALSE;
    cm_text_copy_upper(&obj->user, &node->word.func.user.value);
    CM_TEXT_CLEAR(&obj->pack);
    cm_text_copy(&obj->name, CT_NAME_BUFFER_SIZE, &node->word.func.name.value);

    return pl_find_recursion_function(verif, node, obj, is_found);
}

status_t pl_try_verify_func2(sql_verifier_t *verif, expr_node_t *node, var_udo_t *obj, bool32 *is_found)
{
    *is_found = CT_FALSE;
    cm_text_copy_upper(&obj->user, &node->word.func.user.value);
    CM_TEXT_CLEAR(&obj->pack);
    cm_text_copy(&obj->name, CT_NAME_BUFFER_SIZE, &node->word.func.name.value);

    return pl_try_verify_func(verif, node, obj, is_found);
}

status_t pl_verify_sys_package(sql_verifier_t *verif, expr_node_t *node, pl_dc_t *dc)
{
    sql_func_t *func = NULL;

    node->value.type = CT_TYPE_INTEGER;
    node->value.v_func.pack_id = (uint32)dc->oid;
    node->value.v_func.func_id = dc->sub_id;

    if (node->dis_info.need_distinct) {
        CT_SRC_THROW_ERROR(node->loc, ERR_UNEXPECTED_KEY, "distinct");
        return CT_ERROR;
    }

    func = sql_get_pack_func(&node->value.v_func);
    if (func->options == FO_PROC) {
        pl_set_node_type(node, EXPR_NODE_PROC, LANG_PLSQL, CT_FALSE);
    } else {
        pl_set_node_type(node, EXPR_NODE_FUNC, LANG_PLSQL, CT_FALSE);
    }
    return func->verify(verif, node);
}

static status_t pl_find_pack_func_from_reg_dc(sql_verifier_t *verif, expr_node_t *node, var_udo_t *obj, bool32 *is_found)
{
    pl_dc_t *reg_dc = NULL;
    uint32 sub_type = pl_get_node_type(node);

    *is_found = CT_FALSE;
    reg_dc = pl_get_regist_dc(verif->stmt, obj, PL_PACKAGE_SPEC | PL_SYS_PACKAGE);
    if (reg_dc == NULL) {
        return CT_SUCCESS;
    }
    if (reg_dc->type == PL_SYS_PACKAGE) {
        *is_found = CT_TRUE;
        return pl_verify_sys_package(verif, node, reg_dc);
    }
    if (sub_type != reg_dc->sub_type) {
        return CT_SUCCESS;
    }

    *is_found = CT_TRUE;
    plv_decl_t *decl = (plv_decl_t *)cm_galist_get(reg_dc->entity->package_spec->defs, reg_dc->sub_id);
    function_t *func = decl->func;
    if (reg_dc->sub_type == PL_FUNCTION) {
        pl_set_node_type(node, EXPR_NODE_USER_FUNC, reg_dc->lang_type, CT_TRUE);
        plv_decl_t *ret = (plv_decl_t *)cm_galist_get(func->desc.params, 0);
        SET_FUNC_RETURN_TYPE(ret, node);
    } else {
        pl_set_node_type(node, EXPR_NODE_USER_PROC, reg_dc->lang_type, CT_TRUE);
    }

    CT_RETURN_IFERR(pl_verify_func_args(verif, func->desc.params, func->desc.arg_count, node));
    sql_set_pl_dc_for_user_func((void *)verif, node, (pointer_t)reg_dc);
    return CT_SUCCESS;
}

status_t pl_try_verify_pack_func(sql_verifier_t *verif, expr_node_t *node, var_udo_t *obj, bool32 *is_found)
{
    knl_session_t *sess = &verif->stmt->session->knl_session;
    text_t *user = &obj->user;
    text_t *pack = &obj->pack;
    pl_dc_t *reg_dc = NULL;
    pl_dc_t dc = { 0 };
    status_t status = CT_ERROR;
    pl_dc_assist_t dc_ass = { 0 };

    CT_RETURN_IFERR(pl_find_pack_func_from_reg_dc(verif, node, obj, is_found));
    if (*is_found) {
        return CT_SUCCESS;
    }

    dc.obj = obj;
    pl_dc_open_prepare(&dc_ass, verif->stmt, user, pack, PL_PACKAGE_SPEC | PL_SYS_PACKAGE | PL_SYNONYM);
    CT_RETURN_IFERR(pl_dc_open(&dc_ass, &dc, is_found));
    if (!*is_found) {
        return CT_SUCCESS;
    }
    do {
        if (pl_dc_find_subobject(sess, &dc, &obj->name) != CT_SUCCESS) {
            pl_dc_close(&dc);
            if (node->word.func.count == 1 || node->word.func.count == 0) {
                *is_found = CT_FALSE;
                return CT_SUCCESS;
            }
            return pl_try_verify_func_set_error(node, obj);
        }

        if (dc.type == PL_SYS_PACKAGE) {
            CT_RETURN_IFERR(pl_verify_sys_package(verif, node, &dc));
            CT_RETURN_IFERR(pl_regist_dc(verif->stmt, &dc, &reg_dc));
            CT_RETURN_IFERR(pl_record_dc_for_check_priv(verif, reg_dc));
            return CT_SUCCESS;
        }

        if (dc.sub_type != pl_get_node_type(node)) {
            pl_dc_close(&dc);
            return pl_try_verify_func_set_error(node, obj);
        }

        plv_decl_t *decl = (plv_decl_t *)cm_galist_get(dc.entity->package_spec->defs, dc.sub_id);
        function_t *func = decl->func;
        if (dc.sub_type == PL_FUNCTION) {
            pl_set_node_type(node, EXPR_NODE_USER_FUNC, dc.lang_type, CT_TRUE);
            plv_decl_t *ret = (plv_decl_t *)cm_galist_get(func->desc.params, 0);
            SET_FUNC_RETURN_TYPE(ret, node);
        } else {
            pl_set_node_type(node, EXPR_NODE_USER_PROC, dc.lang_type, CT_TRUE);
        }

        CT_BREAK_IF_ERROR(pl_verify_func_args(verif, func->desc.params, func->desc.arg_count, node));
        CT_BREAK_IF_ERROR(pl_regist_dc(verif->stmt, &dc, &reg_dc));
        CT_BREAK_IF_ERROR(pl_record_dc_for_check_priv(verif, reg_dc));
        CT_BREAK_IF_ERROR(pl_regist_reference(verif->stmt->context->ref_objects, reg_dc));
        sql_set_pl_dc_for_user_func((void *)verif, node, (pointer_t)reg_dc);
        status = CT_SUCCESS;
    } while (0);

    if (status == CT_ERROR) {
        pl_dc_close(&dc);
    }

    return status;
}

status_t pl_try_verify_pack_func1(sql_verifier_t *verif, expr_node_t *node, var_udo_t *obj, bool32 *is_found)
{
    *is_found = CT_FALSE;
    if (verif->obj == NULL || CM_IS_EMPTY(&verif->obj->user)) {
        return CT_SUCCESS;
    }

    cm_text_copy_upper(&obj->user, &verif->obj->user);
    cm_text_copy(&obj->pack, CT_NAME_BUFFER_SIZE, &verif->obj->pack);
    cm_text_copy(&obj->name, CT_NAME_BUFFER_SIZE, &node->word.func.name.value);

    return pl_try_verify_pack_func(verif, node, obj, is_found);
}

status_t pl_try_verify_pack_func2(sql_verifier_t *verif, expr_node_t *node, var_udo_t *obj, bool32 *is_found)
{
    *is_found = CT_FALSE;
    cm_text_copy_from_str(&obj->user, verif->stmt->session->curr_schema, CT_NAME_BUFFER_SIZE);
    cm_text_copy(&obj->pack, CT_NAME_BUFFER_SIZE, &node->word.func.org_user.value);
    cm_text_copy(&obj->name, CT_NAME_BUFFER_SIZE, &node->word.func.name.value);

    return pl_try_verify_pack_func(verif, node, obj, is_found);
}

status_t pl_try_verify_pack_std(sql_verifier_t *verif, expr_node_t *node, var_udo_t *obj, bool32 *is_found)
{
    text_t *func_name = (text_t *)&node->word.func.name;
    sql_func_t *func = NULL;
    var_func_t v_func = node->value.v_func;

    cm_text_copy_from_str(&obj->user, SYS_USER_NAME, CT_NAME_BUFFER_SIZE);
    cm_text_copy_from_str(&obj->pack, "DBE_STD", CT_NAME_BUFFER_SIZE);
    cm_text_copy(&obj->name, CT_NAME_BUFFER_SIZE, &node->word.func.name.value);

    node->value.type = CT_TYPE_INTEGER;
    sql_convert_standard_pack_func(func_name, &v_func);
    if (v_func.func_id == CT_INVALID_ID32) {
        *is_found = CT_FALSE;
        return CT_SUCCESS;
    }
    node->value.v_func = v_func;
    *is_found = CT_TRUE;
    func = sql_get_pack_func(&node->value.v_func);

    CT_RETURN_IFERR(pl_update_node_type(node, func));
    return func->verify(verif, node);
}

static status_t pl_find_sys_pack_from_reg_dc(sql_verifier_t *verif, expr_node_t *node, var_udo_t *obj, bool32 *is_found)
{
    pl_dc_t *pl_dc = NULL;

    *is_found = CT_FALSE;
    pl_dc = pl_get_regist_dc(verif->stmt, obj, PL_SYS_PACKAGE);
    if (pl_dc == NULL) {
        return CT_SUCCESS;
    }

    *is_found = CT_TRUE;
    return pl_verify_sys_package(verif, node, pl_dc);
}

status_t pl_try_verify_sys_pack_func(sql_verifier_t *verif, expr_node_t *node, var_udo_t *obj, bool32 *is_found)
{
    knl_session_t *sess = &verif->stmt->session->knl_session;
    text_t *user = &obj->user;
    text_t *pack = &obj->pack;
    pl_dc_assist_t dc_ass = { 0 };
    pl_dc_t dc = { 0 };
    pl_dc_t *reg_dc = NULL;

    CT_RETURN_IFERR(pl_find_sys_pack_from_reg_dc(verif, node, obj, is_found));
    if (*is_found) {
        return CT_SUCCESS;
    }

    dc.obj = obj;
    pl_dc_open_prepare(&dc_ass, verif->stmt, user, pack, PL_SYS_PACKAGE | PL_SYNONYM);
    status_t status = pl_dc_open(&dc_ass, &dc, is_found);
    if (!*is_found) {
        if (status != CT_SUCCESS) {
            cm_revert_pl_last_error();
        }
        return CT_SUCCESS;
    }
    CT_RETURN_IFERR(status);
    if (pl_dc_find_subobject(sess, &dc, &obj->name) != CT_SUCCESS) {
        CT_SRC_THROW_ERROR(node->loc, ERR_USER_OBJECT_NOT_EXISTS, pl_get_node_type_string(node->type), T2S(&obj->pack),
            T2S_EX(&obj->name));
        return CT_ERROR;
    }

    CT_RETURN_IFERR(pl_verify_sys_package(verif, node, &dc));
    CT_RETURN_IFERR(pl_regist_dc(verif->stmt, &dc, &reg_dc));
    CT_RETURN_IFERR(pl_record_dc_for_check_priv(verif, reg_dc));

    return CT_SUCCESS;
}

status_t pl_try_verify_sys_pack_func2(sql_verifier_t *verif, expr_node_t *node, var_udo_t *obj, bool32 *is_found)
{
    *is_found = CT_FALSE;
    cm_text_copy_from_str(&obj->user, SYS_USER_NAME, CT_NAME_BUFFER_SIZE);
    cm_text_copy_upper(&obj->pack, &node->word.func.org_user.value);
    cm_text_copy_upper(&obj->name, &node->word.func.name.value);

    return pl_try_verify_sys_pack_func(verif, node, obj, is_found);
}

status_t pl_try_verify_sys_pack_func3(sql_verifier_t *verif, expr_node_t *node, var_udo_t *obj, bool32 *is_found)
{
    *is_found = CT_FALSE;
    cm_text_copy_upper(&obj->user, &node->word.func.user.value);
    cm_text_copy_upper(&obj->pack, &node->word.func.pack.value);
    cm_text_copy_upper(&obj->name, &node->word.func.name.value);

    return pl_try_verify_sys_pack_func(verif, node, obj, is_found);
}

status_t pl_try_verify_pack_func3(sql_verifier_t *verif, expr_node_t *node, var_udo_t *obj, bool32 *is_found)
{
    *is_found = CT_FALSE;
    cm_text_copy_upper(&obj->user, &node->word.func.user.value);
    cm_text_copy(&obj->pack, CT_NAME_BUFFER_SIZE, &node->word.func.pack.value);
    cm_text_copy(&obj->name, CT_NAME_BUFFER_SIZE, &node->word.func.name.value);

    return pl_try_verify_pack_func(verif, node, obj, is_found);
}

status_t pl_try_verify_public_func1(sql_verifier_t *verif, expr_node_t *node, var_udo_t *obj, bool32 *is_found)
{
    *is_found = CT_FALSE;
    cm_text_copy_from_str(&obj->user, PUBLIC_USER, CT_NAME_BUFFER_SIZE);
    CM_TEXT_CLEAR(&obj->pack);
    cm_text_copy(&obj->name, CT_NAME_BUFFER_SIZE, &node->word.func.name.value);

    return pl_try_verify_func(verif, node, obj, is_found);
}

status_t pl_try_verify_public_func2(sql_verifier_t *verif, expr_node_t *node, var_udo_t *obj, bool32 *is_found)
{
    *is_found = CT_FALSE;
    cm_text_copy_from_str(&obj->user, PUBLIC_USER, CT_NAME_BUFFER_SIZE);
    cm_text_copy(&obj->pack, CT_NAME_BUFFER_SIZE, &node->word.func.org_user.value);
    cm_text_copy(&obj->name, CT_NAME_BUFFER_SIZE, &node->word.func.name.value);

    return pl_try_verify_pack_func(verif, node, obj, is_found);
}

status_t pl_try_verify_return_error1(sql_verifier_t *verif, expr_node_t *node)
{
    text_t user;
    text_t name = node->word.func.name.value;

    cm_str2text(verif->stmt->session->curr_schema, &user);
    CT_SRC_THROW_ERROR(node->loc, ERR_USER_OBJECT_NOT_EXISTS, pl_get_node_type_string(node->type), T2S(&user),
        T2S_EX(&name));
    return CT_ERROR;
}

status_t pl_try_verify_return_error2(sql_verifier_t *verif, expr_node_t *node)
{
    sql_stmt_t *stmt = verif->stmt;
    text_t user = node->word.func.user.value;
    text_t name = node->word.func.name.value;
    text_t curr_user;

    if (stmt->session->switched_schema) {
        cm_str2text(stmt->session->curr_schema, &curr_user);
    } else {
        curr_user = stmt->session->curr_user;
    }

    CT_RETURN_IFERR(sql_check_proc_priv_core(verif->stmt, &user, &name, &curr_user));
    CT_SRC_THROW_ERROR(node->loc, ERR_USER_OBJECT_NOT_EXISTS, pl_get_node_type_string(node->type), T2S(&user),
        T2S_EX(&name));
    return CT_ERROR;
}

status_t pl_try_verify_return_error3(sql_verifier_t *verif, expr_node_t *node)
{
    sql_stmt_t *stmt = verif->stmt;
    text_t *user = &node->word.func.user.value;
    text_t *pack = &node->word.func.pack.value;
    text_t *name = &node->word.func.name.value;
    text_t curr_user;

    if (stmt->session->switched_schema) {
        cm_str2text(stmt->session->curr_schema, &curr_user);
    } else {
        curr_user = stmt->session->curr_user;
    }

    CT_RETURN_IFERR(sql_check_proc_priv_core(verif->stmt, user, name, &curr_user));
    CT_SRC_THROW_ERROR(node->loc, ERR_USER_OBJECT_NOT_EXISTS, pl_get_node_type_string(node->type),
        CC_T2S(user, pack, '.'), T2S_EX(name));
    return CT_ERROR;
}

status_t pl_dc_open_trig_by_entry(sql_stmt_t *stmt, pl_dc_t *dc, trig_item_t *trig_item)
{
    pl_entry_t *entry = NULL;
    pl_entry_info_t entry_info;

    pl_find_entry_by_oid(trig_item->oid, PL_TRIGGER, &entry_info);
    entry = entry_info.entry;

    if (entry == NULL) {
        CT_THROW_ERROR(ERR_OBJECT_ID_NOT_EXIST, "trigger", trig_item->oid);
        return CT_ERROR;
    }

    if (pl_lock_entry_shared(KNL_SESSION(stmt), &entry_info) != CT_SUCCESS) {
        return CT_ERROR;
    }

    pl_dc_init(dc, entry);
    status_t status = pl_get_entity(stmt, dc);
    pl_unlock_shared(KNL_SESSION(stmt), dc->entry);
    return status;
}

bool32 pl_check_dc(pl_dc_t *dc)
{
    pl_entity_t *entity = dc->entity;
    pl_entry_t *entry = dc->entry;

    if (dc->type == PL_SYS_PACKAGE) {
        return CT_TRUE;
    }

    if (dc->syn_entry != NULL) {
        pl_entry_t *syn_entry = dc->syn_entry;

        if (syn_entry->desc.type != PL_SYNONYM || syn_entry->desc.chg_scn != dc->syn_scn) {
            return CT_FALSE;
        }
    }

    if (entry == NULL || entry->desc.type != dc->type || entry->desc.org_scn != dc->org_scn ||
        entry->desc.chg_scn != dc->chg_scn) {
        return CT_FALSE;
    }

    if (!entity->valid) {
        return CT_FALSE;
    }

    return CT_TRUE;
}

void pl_revert_last_error(status_t status)
{
    if (status != CT_SUCCESS) {
        cm_revert_pl_last_error();
    }
}

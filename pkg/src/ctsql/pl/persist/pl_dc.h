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
 * pl_dc.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/persist/pl_dc.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PL_DC_H__
#define __PL_DC_H__

#include "pl_dc_util.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_pl_dictionary pl_dc_t;
struct st_pl_dictionary {
    uint64 oid;
    uint16 uid;
    uint8 sub_id;
    uint8 lang_type;
    bool8 is_sysnonym;
    bool8 is_recursive;
    uint8 unused[2];
    uint32 type;
    uint32 sub_type;
    pl_entry_t *entry;
    pl_entity_t *entity;
    knl_scn_t org_scn;
    knl_scn_t chg_scn;
    knl_scn_t syn_scn;
    pl_entry_t *syn_entry;
    var_udo_t *obj;
};

typedef struct st_pl_dc_assist pl_dc_assist_t;
struct st_pl_dc_assist {
    text_t *user_name;
    text_t *obj_name;
    sql_stmt_t *stmt;
    uint32 expect_type;
    bool32 priv_check; // for dbe_debug. should not check debug session privilege
};

typedef struct st_load_assist {
    sql_stmt_t *sub_stmt;
    lex_t *lex_bak;
    pl_source_pages_t source_page;
    bool32 new_page;
    uint32 old_status;
} load_assist_t;

void pl_dc_open_prepare(pl_dc_assist_t *dc_ass, sql_stmt_t *stmt, text_t *user_name, text_t *obj_name,
                        uint32 expect_type);
void pl_dc_open_prepare_for_ignore_priv(pl_dc_assist_t *dc_ass, sql_stmt_t *stmt, text_t *user_name, text_t *obj_name,
                                        uint32 expect_type);
status_t pl_dc_open(pl_dc_assist_t *dc_ass, pl_dc_t *dc, bool32 *is_found);
status_t pl_dc_open_trig_by_entry(sql_stmt_t *stmt, pl_dc_t *dc, trig_item_t *trig_item);
void pl_dc_close(pl_dc_t *pl_dc);
void pl_dc_reopen(pl_dc_t *pl_dc);
status_t pl_try_find_type_dc(sql_stmt_t *stmt, var_udo_t *obj, pl_dc_t *dc, bool32 *is_found);
status_t pl_try_verify_builtin_func(sql_verifier_t *verif, expr_node_t *node, var_udo_t *obj, bool32 *is_found);
status_t pl_try_verify_recursion_func1(sql_verifier_t *verif, expr_node_t *node, var_udo_t *obj, bool32 *is_found);
status_t pl_try_verify_recursion_func2(sql_verifier_t *verif, expr_node_t *node, var_udo_t *obj, bool32 *is_found);
status_t pl_try_verify_func1(sql_verifier_t *verif, expr_node_t *node, var_udo_t *obj, bool32 *is_found);
status_t pl_try_verify_func2(sql_verifier_t *verif, expr_node_t *node, var_udo_t *obj, bool32 *is_found);
status_t pl_try_verify_pack_func1(sql_verifier_t *verif, expr_node_t *node, var_udo_t *obj, bool32 *is_found);
status_t pl_try_verify_pack_func2(sql_verifier_t *verif, expr_node_t *node, var_udo_t *obj, bool32 *is_found);
status_t pl_try_verify_pack_func3(sql_verifier_t *verif, expr_node_t *node, var_udo_t *obj, bool32 *is_found);
status_t pl_try_verify_pack_std(sql_verifier_t *verif, expr_node_t *node, var_udo_t *obj, bool32 *is_found);
status_t pl_try_verify_sys_pack_func2(sql_verifier_t *verif, expr_node_t *node, var_udo_t *obj, bool32 *is_found);
status_t pl_try_verify_sys_pack_func3(sql_verifier_t *verif, expr_node_t *node, var_udo_t *obj, bool32 *is_found);
status_t pl_try_verify_public_func1(sql_verifier_t *verif, expr_node_t *node, var_udo_t *obj, bool32 *is_found);
status_t pl_try_verify_public_func2(sql_verifier_t *verif, expr_node_t *node, var_udo_t *obj, bool32 *is_found);
status_t pl_try_verify_return_error1(sql_verifier_t *verif, expr_node_t *node);
status_t pl_try_verify_return_error2(sql_verifier_t *verif, expr_node_t *node);
status_t pl_try_verify_return_error3(sql_verifier_t *verif, expr_node_t *node);
status_t pl_init_obj(knl_session_t *session, pl_desc_t *desc, pl_entity_t *entity);
void pl_init_lex(lex_t *lex, text_t src_text);
status_t pl_regist_dc(sql_stmt_t *stmt, pl_dc_t *dc, pl_dc_t **reg_dc);
status_t pl_regist_reference(galist_t *dest, pl_dc_t *dc);
pl_dc_t *pl_get_regist_dc(sql_stmt_t *stmt, var_udo_t *v_udo, uint32 type);
bool32 pl_check_dc(pl_dc_t *dc);
void pl_revert_last_error(status_t status);
status_t pl_dc_find_subobject(knl_session_t *session, pl_dc_t *dc, text_t *sub_name);
uint32 pl_get_node_type(expr_node_t *expr_node);
char *pl_get_node_type_string(expr_node_type_t type);
status_t pl_load_entity(sql_stmt_t *stmt, pl_entry_t *entry, pl_entity_t **entity_out);
knl_dictionary_t *pl_get_regist_knl_dc(sql_stmt_t *stmt, var_udo_t *udo_obj);
status_t pl_regist_knl_dc(sql_stmt_t *stmt, knl_dictionary_t *dc);
static void inline pl_update_entry_status(pl_entry_t *entry, object_status_t obj_status)
{
    pl_entry_lock(entry);
    entry->desc.status = obj_status;
    pl_entry_unlock(entry);
}

#ifdef __cplusplus
}
#endif

#endif

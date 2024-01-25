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
 * decl.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/ast/decl.c
 *
 * -------------------------------------------------------------------------
 */
#include "decl.h"

/*
 * @brief   check name if equal
 */
void plc_cmp_name(text_t *name1, text_t *name2, bool32 case_sensitive, bool32 *res)
{
    if (case_sensitive == CT_FALSE) {
        *res = cm_text_equal_ins2(name1, name2);
    } else {
        *res = cm_text_equal(name1, name2);
    }
}

/*
 * @brief    find decl in decls' list by name
 */
void plc_find_in_decls(galist_t *decls, text_t *name, bool32 case_sensitive, plv_decl_t **selector)
{
    plv_decl_t *v = NULL;
    bool32 res = CT_FALSE;

    if (decls == NULL) {
        return;
    }

    for (uint32 i = 0; i < decls->count; i++) {
        v = (plv_decl_t *)cm_galist_get(decls, i);
        plc_cmp_name(&v->name, name, case_sensitive, &res);

        if (res) {
            *selector = v;
            return;
        }
    }

    return;
}

/*
 * @brief    check variant name in the decls
 */
void plc_check_duplicate(galist_t *decls, text_t *name, bool32 case_sensitive, bool32 *res)
{
    plv_decl_t *decl = NULL;
    plc_find_in_decls(decls, name, case_sensitive, &decl);
    *res = (decl == NULL) ? CT_FALSE : CT_TRUE;
}

status_t plc_parse_datatype(lex_t *lex, pmode_t pmod, typmode_t *typmod, word_t *typword)
{
    key_word_t *save_key_words = lex->key_words;
    uint32 save_key_word_count = lex->key_word_count;
    key_word_t key_words[] = {
        { (uint32)DTYP_PLS_INTEGER, CT_FALSE, { (char *)"pls_integer", 11 } },
        { (uint32)DTYP_STRING, CT_FALSE, { (char *)"string", 6 } }
    };

    lex->key_words = key_words;
    lex->key_word_count = ELEMENT_COUNT(key_words);
    if (sql_parse_datatype(lex, pmod, typmod, NULL) != CT_SUCCESS) {
        lex->key_words = save_key_words;
        lex->key_word_count = save_key_word_count;
        return CT_ERROR;
    }
    lex->key_words = save_key_words;
    lex->key_word_count = save_key_word_count;
    return CT_SUCCESS;
}

static status_t plv_variant_equal(sql_stmt_t *stmt, plv_decl_t *decl1, plv_decl_t *decl2)
{
    if (decl1->type == PLV_VAR) {
        if (!CM_TYPMODE_IS_EQUAL(&decl1->variant.type, &decl2->variant.type)) {
            return CT_ERROR;
        }
    } else {
        if (!CM_TYPMODE_IS_EQUAL(&decl1->array.type, &decl2->array.type)) {
            return CT_ERROR;
        }
    }

    if (decl1->default_expr == NULL && decl2->default_expr == NULL) {
        return CT_SUCCESS;
    } else if (decl1->default_expr != NULL && decl2->default_expr != NULL) {
        if (sql_expr_node_equal(stmt, decl1->default_expr->root, decl2->default_expr->root, NULL) != CT_TRUE) {
            cm_reset_error();
            return CT_ERROR;
        }
        return CT_SUCCESS;
    } else {
        return CT_ERROR;
    }
}

status_t plc_decl_equal(sql_stmt_t *stmt, plv_decl_t *decl1, plv_decl_t *decl2)
{
    if (decl1->type != decl2->type || !cm_text_equal(&decl1->name, &decl2->name) || decl1->drct != decl2->drct) {
        return CT_ERROR;
    }
    switch (decl1->type) {
        case PLV_CUR:
            return CT_SUCCESS;
        case PLV_VAR:
        case PLV_ARRAY:
            return plv_variant_equal(stmt, decl1, decl2);
        case PLV_RECORD:
            return udt_verify_record_attr(decl1->record, decl2->record);
        case PLV_OBJECT:
            return (decl1->object == decl2->object) ? CT_SUCCESS : CT_ERROR;
        case PLV_COLLECTION:
            return (decl1->collection == decl2->collection) ? CT_SUCCESS : CT_ERROR;
        default:
            return CT_ERROR;
    }
}

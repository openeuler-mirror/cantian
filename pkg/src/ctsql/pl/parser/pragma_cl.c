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
 * pragma_cl.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/parser/pragma_cl.c
 *
 * -------------------------------------------------------------------------
 */
#include "pragma_cl.h"
#include "pragma.h"
#include "pl_common.h"
#include "pl_dc_util.h"
#include "srv_instance.h"

status_t plc_find_line_except(pl_compiler_t *compiler, pl_line_when_t *when_line, pl_exception_t *except_info,
    sql_text_t *except_name)
{
    for (uint32 j = 0; j < when_line->excepts.count; j++) {
        pl_exception_t *line_except = (pl_exception_t *)cm_galist_get(&when_line->excepts, j);
        if (except_info->is_userdef == CT_TRUE && except_info->error_code == ERR_USER_DEFINED_EXCEPTION) {
            if (PL_VID_EQUAL(line_except->vid, except_info->vid)) {
                CT_SRC_THROW_ERROR(except_name->loc, ERR_PL_DUP_OBJ_FMT, T2S(&except_name->value));
                return CT_SUCCESS;
            }
        } else {
            if (line_except->error_code == except_info->error_code) {
                CT_SRC_THROW_ERROR(except_name->loc, ERR_PL_DUP_OBJ_FMT, T2S(&except_name->value));
                return CT_SUCCESS;
            }
        }
        if (line_except->error_code == OTHERS) {
            CT_SRC_THROW_ERROR(except_name->loc, ERR_PL_SYNTAX_ERROR_FMT,
                "OTHERS handler must be last among the exception handlers of a block");
            return CT_SUCCESS;
        }
    }

    return CT_ERROR;
}

/*
 * plc_check_except_exists
 *
 * Check the exception exists or not.
 */
status_t plc_check_except_exists(pl_compiler_t *compiler, galist_t *line_excepts, pl_exception_t *except_info,
    sql_text_t *except_name)
{
    pl_line_when_t *when_line = NULL;
    uint32 i;

    if (line_excepts == NULL) {
        return CT_ERROR;
    }

    for (i = 0; i < line_excepts->count; i++) {
        when_line = (pl_line_when_t *)cm_galist_get(line_excepts, i);
        if (plc_find_line_except(compiler, when_line, except_info, except_name) != CT_ERROR) {
            return CT_SUCCESS;
        }
    }

    return CT_ERROR;
}

status_t plc_try_compile_end_when(pl_compiler_t *compiler, bool32 *result, word_t *word)
{
    if (word->id == KEY_WORD_END || word->id == KEY_WORD_WHEN) {
        *result = CT_TRUE;
        return CT_SUCCESS;
    }

    *result = CT_FALSE;
    return CT_SUCCESS;
}

status_t plc_check_auton_output_valid(pl_compiler_t *compiler, galist_t *decls)
{
    uint32 i;
    plv_decl_t *decl = NULL;
    pl_entity_t *entity = (pl_entity_t *)compiler->entity;

    bool32 auton = entity->is_auton_trans;
    if (!auton) {
        return CT_SUCCESS;
    }
    for (i = 0; i < decls->count; i++) {
        decl = cm_galist_get(decls, i);
        if (decl->type == PLV_CUR && decl->drct != PLV_DIR_IN && decl->drct != PLV_DIR_NONE && auton) {
            CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "in autonomous pl, cursor is not supported as output param");
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t plc_compile_excpt_def(pl_compiler_t *compiler, word_t *word, plv_decl_t *decl)
{
    CT_RETURN_IFERR(pl_copy_object_name_ci(compiler->entity, word->type, (text_t *)&word->text, &decl->name));
    decl->excpt.is_userdef = CT_TRUE;
    decl->excpt.err_code = CT_INVALID_INT32;
    return CT_SUCCESS;
}

/*
 * Syntax:
 * PRAGMA AUTONOMOUS_TRANSACTION;
 */
static status_t plc_compile_auton_tran(pl_compiler_t *compiler, word_t *word)
{
    pl_entity_t *entity = (pl_entity_t *)compiler->entity;
    lex_t *lex = compiler->stmt->session->lex;
    CT_RETURN_IFERR(lex_expected_fetch_word(lex, ";"));

    // in trigger, its stack depth start from 1
    if (compiler->type == PL_TRIGGER && compiler->stack.depth > 1) {
        CT_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "autonomous transaction must be in top stack");
        return CT_ERROR;
    }
    // if compiler->type is anomous block, the AUTONOMOUS_TRANSACTION must be in the top stack
    if (compiler->type != PL_TRIGGER && compiler->stack.depth != 0) {
        CT_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "autonomous transaction must be in top stack");
        return CT_ERROR;
    }
    entity->is_auton_trans = CT_TRUE;
    return CT_SUCCESS;
}

static status_t plc_compile_excpt_init(pl_compiler_t *compiler, galist_t *decls, word_t *word)
{
    plv_decl_t *decl = NULL;
    lex_t *lex = compiler->stmt->session->lex;
    int32 err_code;

    CT_RETURN_IFERR(lex_expected_fetch_word(lex, "("));
    CT_RETURN_IFERR(lex_fetch(lex, word));
    if (!IS_VARIANT(word)) {
        CT_SRC_THROW_ERROR(word->text.loc, ERR_PL_EXPECTED_FAIL_FMT, "user defined exception variant name", W2S(word));
        return CT_ERROR;
    }
    plc_find_in_decls(decls, (text_t *)&word->text, IS_DQ_STRING(word->type), &decl);
    if ((decl == NULL) || ((decl->type & PLV_EXCPT) == 0)) {
        CT_SRC_THROW_ERROR(word->text.loc, ERR_PL_EXPECTED_FAIL_FMT, "user defined exception variant name", W2S(word));
        return CT_ERROR;
    }

    CT_RETURN_IFERR(lex_expected_fetch_word(lex, ","));
    if (lex_expected_fetch_int32(lex, &err_code) != CT_SUCCESS) {
        CT_SRC_THROW_ERROR((lex)->loc, ERR_PROGRAM_ERROR_FMT,
            "second argument to PRAGMA EXCEPTION_INIT must be an integer");
        return CT_ERROR;
    }

    if (!((err_code > ERR_ERRNO_BASE && err_code < ERR_CODE_CEIL) ||
        (err_code >= ERR_MIN_USER_DEFINE_ERROR && err_code <= ERR_MAX_USER_DEFINE_ERROR))) {
        CT_SRC_THROW_ERROR(word->text.loc, ERR_PROGRAM_ERROR_FMT, "illegal error code for PRAGMA EXCEPTION_INIT");
        return CT_ERROR;
    }
    decl->excpt.err_code = (uint32)err_code;

    CT_RETURN_IFERR(lex_expected_fetch_word(lex, ")"));
    return lex_expected_fetch_word(lex, ";");
}

status_t plc_compile_pragma(pl_compiler_t *compiler, galist_t *decls, word_t *word)
{
    uint32 match_id;
    lex_t *lex = compiler->stmt->session->lex;

    // try match 2 possibilities
    CT_RETURN_IFERR(lex_try_fetch_1ofn(lex, &match_id, 2, "AUTONOMOUS_TRANSACTION", "EXCEPTION_INIT"));
    switch (match_id) {
        case AUTON_TRANS:
#ifdef Z_SHARDING
            if (IS_COORDINATOR && IS_APP_CONN(compiler->stmt->session)) {
                CT_SRC_THROW_ERROR(word->loc, ERR_CAPABILITY_NOT_SUPPORT, "AUTONOMOUS_TRANSACTION on coordinator is");
                return CT_ERROR;
            }
#endif
            CT_RETURN_IFERR(plc_compile_auton_tran(compiler, word));
            break;
        case EXCEPTION_INIT:
            CT_RETURN_IFERR(plc_compile_excpt_init(compiler, decls, word));
            break;
        default:
            CT_SRC_THROW_ERROR(word->text.loc, ERR_PL_EXPECTED_FAIL_FMT, "pragma syntax word", W2S(word));
            return CT_ERROR;
    }
    return CT_SUCCESS;
}

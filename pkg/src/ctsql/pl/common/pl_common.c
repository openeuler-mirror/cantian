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
 * pl_common.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/common/pl_common.c
 *
 * -------------------------------------------------------------------------
 */
#include "pl_common.h"
#include "srv_instance.h"
#include "pl_memory.h"

static inline text_t *plm_get_udo_owner(var_udo_t *udo_obj)
{
    if (udo_obj->pack.len == 0) {
        return &udo_obj->user;
    } else {
        return &udo_obj->pack;
    }
}

status_t pl_unfound_error(sql_stmt_t *stmt, var_udo_t *udo_obj, src_loc_t *loc, uint32 type)
{
    text_t *owner = NULL;
    switch (type) {
        case PL_FUNCTION:
            owner = plm_get_udo_owner(udo_obj);
            CT_THROW_ERROR_TRY_SRC(loc, ERR_USER_OBJECT_NOT_EXISTS, "function", T2S(owner), T2S_EX(&udo_obj->name));
            return CT_ERROR;
        case PL_PROCEDURE:
            owner = plm_get_udo_owner(udo_obj);
            CT_THROW_ERROR_TRY_SRC(loc, ERR_USER_OBJECT_NOT_EXISTS, "procedure", T2S(owner), T2S_EX(&udo_obj->name));
            return CT_ERROR;
        case PL_TRIGGER:
            CT_THROW_ERROR_TRY_SRC(loc, ERR_USER_OBJECT_NOT_EXISTS, "trigger",
                                   T2S(&udo_obj->user), T2S_EX(&udo_obj->name));
            return CT_ERROR;
        case PL_PACKAGE_SPEC:
            CT_THROW_ERROR_TRY_SRC(loc, ERR_USER_OBJECT_NOT_EXISTS, "package",
                                   T2S(&udo_obj->user), T2S_EX(&udo_obj->name));
            return CT_ERROR;
        case PL_PACKAGE_BODY:
            CT_THROW_ERROR_TRY_SRC(loc, ERR_USER_OBJECT_NOT_EXISTS, "package body", T2S(&udo_obj->user),
                T2S_EX(&udo_obj->name));
            return CT_ERROR;
        case PL_TYPE_SPEC:
            CT_THROW_ERROR_TRY_SRC(loc, ERR_USER_OBJECT_NOT_EXISTS, "type",
                                   T2S(&udo_obj->user), T2S_EX(&udo_obj->name));
            return CT_ERROR;
        case PL_TYPE_BODY:
            CT_THROW_ERROR_TRY_SRC(loc, ERR_USER_OBJECT_NOT_EXISTS, "type body",
                                   T2S(&udo_obj->user), T2S_EX(&udo_obj->name));
            return CT_ERROR;
        default:
            owner = plm_get_udo_owner(udo_obj);
            CT_THROW_ERROR_TRY_SRC(loc, ERR_USER_OBJECT_NOT_EXISTS, "object", T2S(owner), T2S_EX(&udo_obj->name));
            return CT_ERROR;
    }
}

status_t pl_copy_text(void *context, text_t *src, text_t *dst)
{
    if (pl_alloc_mem((void *)context, src->len, (void **)&dst->str) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (src->len != 0) {
        MEMS_RETURN_IFERR(memcpy_s(dst->str, src->len, src->str, src->len));
    }

    dst->len = src->len;

    return CT_SUCCESS;
}

status_t pl_copy_str(void *context, char *src, text_t *dst)
{
    text_t src_text;
    cm_str2text_safe(src, (uint32)strlen(src), &src_text);
    return pl_copy_text(context, &src_text, dst);
}

status_t pl_copy_name(void *context, text_t *src, text_t *dst)
{
    uint32 i;

    if (src->len > CT_MAX_NAME_LEN) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "'%s' is too long to as name", T2S(src));
        return CT_ERROR;
    }

    if (src->len == 0) {
        dst->len = 0;
        return CT_SUCCESS;
    }

    if (pl_alloc_mem(context, src->len, (void **)&dst->str) != CT_SUCCESS) {
        return CT_ERROR;
    }

    dst->len = src->len;

    for (i = 0; i < dst->len; i++) {
        dst->str[i] = UPPER(src->str[i]);
    }

    return CT_SUCCESS;
}

status_t pl_copy_name_cs(void *entity, text_t *src, text_t *dst, bool32 sensitive)
{
    pl_entity_t *context = (pl_entity_t *)entity;

    if (IS_CASE_INSENSITIVE && !sensitive) {
        return pl_copy_name(context, src, dst);
    }

    if (src->len > CT_MAX_NAME_LEN) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "'%s' is too long to as name", T2S(src));
        return CT_ERROR;
    }

    if (src->len == 0) {
        dst->len = 0;
        return CT_SUCCESS;
    }

    return pl_copy_text(context, src, dst);
}

status_t pl_copy_object_name(void *context, word_type_t type, text_t *src, text_t *dst)
{
    if (IS_DQ_STRING(type)) {
        return pl_copy_text(context, src, dst);
    }

    if (IS_CASE_INSENSITIVE) {
        return pl_copy_name(context, src, dst);
    } else {
        return pl_copy_name_cs(context, src, dst, CT_FALSE);
    }
}

status_t pl_copy_object_name_loc(void *context, word_type_t type, sql_text_t *src, sql_text_t *dst)
{
    dst->loc = src->loc;
    return pl_copy_object_name(context, type, &src->value, &dst->value);
}

status_t pl_copy_object_name_ci(void *context, word_type_t type, text_t *src, text_t *dst)
{
    if (IS_DQ_STRING(type)) {
        return pl_copy_text(context, src, dst);
    }
    return pl_copy_name(context, src, dst);
}

status_t pl_copy_prefix_tenant(void *stmt_in, text_t *src, text_t *dst, pl_copy_func_t pl_copy_func)
{
    text_t name;
    char buf[CT_NAME_BUFFER_SIZE];
    sql_stmt_t *stmt = stmt_in;

    if (IS_CASE_INSENSITIVE) {
        cm_text2str_with_upper(src, buf, CT_NAME_BUFFER_SIZE);
    } else {
        if (cm_text2str(src, buf, CT_NAME_BUFFER_SIZE) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (sql_user_prefix_tenant(stmt->session, buf) != CT_SUCCESS) {
        return CT_ERROR;
    }

    cm_str2text(buf, &name);
    if (pl_copy_func(stmt->pl_context, &name, dst) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t pl_copy_name_prefix_tenant_loc(void *stmt_in, sql_text_t *src, sql_text_t *dst)
{
    sql_stmt_t *stmt = (sql_stmt_t *)stmt_in;

    dst->loc = src->loc;
    return pl_copy_prefix_tenant(stmt, &src->value, &dst->value, pl_copy_name);
}

status_t pl_word_as_table(void *stmt_in, word_t *word, var_word_t *var)
{
    sql_stmt_t *stmt = (sql_stmt_t *)stmt_in;
    if (word->ex_count == 0) {
        if (pl_copy_object_name_loc(stmt->pl_context, word->type, &word->text, &var->table.name) != CT_SUCCESS) {
            return CT_ERROR;
        }
        var->table.user.loc = word->text.loc;
        var->table.user.implicit = CT_TRUE;
        text_t user_name = { stmt->session->curr_schema, (uint32)strlen(stmt->session->curr_schema) };
        if (IS_DUAL_TABLE_NAME(&var->table.name.value)) {
            cm_text_upper(&var->table.name.value);
        }

        if (pl_copy_name(stmt->pl_context, &user_name, (text_t *)&var->table.user) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else if (word->ex_count == 1) {
        if (pl_copy_object_name_loc(stmt->pl_context, word->ex_words[0].type, &word->ex_words[0].text,
            &var->table.name) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (pl_copy_name_prefix_tenant_loc(stmt, &word->text, &var->table.user) != CT_SUCCESS) {
            return CT_ERROR;
        }
        var->table.user.implicit = CT_FALSE;
        if (cm_text_str_equal_ins(&var->table.user.value, "SYS") && IS_DUAL_TABLE_NAME(&var->table.name.value)) {
            cm_text_upper(&var->table.name.value);
        }
    } else {
        CT_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid table name");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}


status_t pl_decode_object_name(sql_stmt_t *stmt, word_t *word, sql_text_t *user, sql_text_t *name)
{
    var_word_t var_word;

    if (pl_word_as_table(stmt, word, &var_word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    *user = var_word.table.user;
    *name = var_word.table.name;

    return CT_SUCCESS;
}


int g_pl2obj_type_map[] = {
    [PL_PROCEDURE] = OBJ_TYPE_PROCEDURE,
    [PL_FUNCTION] = OBJ_TYPE_FUNCTION,
    [PL_TRIGGER] = OBJ_TYPE_TRIGGER,
    [PL_PACKAGE_SPEC] = OBJ_TYPE_PACKAGE_SPEC,
    [PL_PACKAGE_BODY] = OBJ_TYPE_PACKAGE_BODY,
    [PL_TYPE_SPEC] = OBJ_TYPE_TYPE_SPEC,
    [PL_TYPE_BODY] = OBJ_TYPE_TYPE_BODY,
    [PL_SYNONYM] = OBJ_TYPE_PL_SYNONYM,
    [PL_SYS_PACKAGE] = OBJ_TYPE_SYS_PACKAGE,
};

int g_obj2pl_type_map[] = {
    [OBJ_TYPE_PROCEDURE] = PL_PROCEDURE,
    [OBJ_TYPE_FUNCTION] = PL_FUNCTION,
    [OBJ_TYPE_TRIGGER] = PL_TRIGGER,
    [OBJ_TYPE_PACKAGE_SPEC] = PL_PACKAGE_SPEC,
    [OBJ_TYPE_PACKAGE_BODY] = PL_PACKAGE_BODY,
    [OBJ_TYPE_TYPE_SPEC] = PL_TYPE_SPEC,
    [OBJ_TYPE_TYPE_BODY] = PL_TYPE_BODY,
    [OBJ_TYPE_PL_SYNONYM] = PL_SYNONYM,
    [OBJ_TYPE_SYS_PACKAGE] = PL_SYS_PACKAGE,
};


uint32 pl_get_obj_type(object_type_t obj_type)
{
    return g_obj2pl_type_map[obj_type];
}

object_type_t pltype_to_objtype(uint32 obj_type)
{
    return g_pl2obj_type_map[obj_type];
}

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
 * ddl_user_parser.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser_ddl/ddl_user_parser.c
 *
 * -------------------------------------------------------------------------
 */

#include "ddl_user_parser.h"
#include "ddl_parser_common.h"
#include "srv_instance.h"
#include "expr_parser.h"
#include "cm_pbl.h"

/* ****************************************************************************
Description  : verify pwd text.
Input        : session_t *session,
text_t * pwd,
text_t * user
Modification : Create function
**************************************************************************** */
static status_t sql_verify_alter_password(const char *name, const char *old_passwd, const char *passwd,
    uint32 pwd_min_len)
{
    CT_RETURN_IFERR(cm_verify_password_str(name, passwd, pwd_min_len));
    /* new pwd and old pwd should differ by at least two character bits */
    if (!CM_IS_EMPTY_STR(old_passwd) && cm_str_diff_chars(old_passwd, passwd) < 2) {
        CT_THROW_ERROR(ERR_PASSWORD_FORMAT_ERROR,
            "new password and old password should differ by at least two character bits");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t sql_parse_user_keyword(sql_stmt_t *stmt, word_t *word, knl_user_def_t *def, bool32 is_replace)
{
    /* we consider the word following keyword 'by' is pwd or value keyword. */
    if (lex_expected_fetch(stmt->session->lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word->type != WORD_TYPE_VARIANT && word->type != WORD_TYPE_STRING && word->type != WORD_TYPE_DQ_STRING) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "The password must be identifier or string");
        return CT_ERROR;
    }

    if (word->type == WORD_TYPE_STRING) {
        LEX_REMOVE_WRAP(word);
    }
    if (word->text.len == 0) {
        CT_SRC_THROW_ERROR_EX(word->loc, ERR_SQL_SYNTAX_ERROR, "invalid identifier, length 0");
        return CT_ERROR;
    }
    if (is_replace) {
        CT_RETURN_IFERR(cm_text2str((text_t *)&word->text, def->old_password, CT_PASSWORD_BUFFER_SIZE));
    } else {
        CT_RETURN_IFERR(cm_text2str((text_t *)&word->text, def->password, CT_PASSWORD_BUFFER_SIZE));
    }

    return sql_replace_password(stmt, &word->text.value);
}

static status_t sql_parse_keyword_identified(sql_stmt_t *stmt, word_t *word, knl_user_def_t *def, uint32 *oper_flag)
{
    bool32 result = CT_FALSE;
    if (*oper_flag & DDL_USER_PWD) {
        CT_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR,
            "keyword \"identified\" cannot be appear more than once");
        return CT_ERROR;
    }

    /* the word following keyword IDENTIFIED must be keyword by. */
    CT_RETURN_IFERR(lex_expected_fetch_word(stmt->session->lex, "by"));
    def->pwd_loc = stmt->session->lex->loc.column;

    /* we consider the word following keyword 'by' is pwd or value keyword. */
    CT_RETURN_IFERR(sql_parse_user_keyword(stmt, word, def, CT_FALSE));
    CT_RETURN_IFERR(lex_try_fetch(stmt->session->lex, "replace", &result));
    if (result) {
        CT_RETURN_IFERR(sql_parse_user_keyword(stmt, word, def, CT_TRUE));
    } else {
        if (g_instance->kernel.attr.password_verify && cm_text_str_equal(&stmt->session->curr_user, def->name) &&
            !knl_check_sys_priv_by_name(&stmt->session->knl_session, &stmt->session->curr_user, ALTER_USER)) {
            CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "need old password when the parameter "
                "REPLACE_PASSWORD_VERIFY is true");
            return CT_ERROR;
        }
    }

    def->mask |= USER_PASSWORD_MASK;
    *oper_flag |= DDL_USER_PWD;
    stmt->session->knl_session.interactive_altpwd = CT_FALSE;
    return CT_SUCCESS;
}

static status_t ddl_parse_set_tablespace(sql_stmt_t *stmt, word_t *word, knl_user_def_t *def, uint32 *flag)
{
    word_t tmp_word;
    text_t tablespace;

    CM_POINTER3(stmt, word, def);

    if ((*flag & DDL_USER_DEFALT_SPACE) && word->id == (uint32)RES_WORD_DEFAULT) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR,
            "keyword \"default\" cannot be appear more than once");
        return CT_ERROR;
    }

    if ((*flag & DDL_USER_TMP_SPACE) && word->id == (uint32)KEY_WORD_TEMPORARY) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR,
            "keyword \"temporaray\" cannot be appear more than once");
        return CT_ERROR;
    }

    if (lex_expected_fetch_word(stmt->session->lex, "TABLESPACE") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (CT_SUCCESS != lex_expected_fetch_variant(stmt->session->lex, &tmp_word)) {
        return CT_ERROR;
    }

    CT_RETURN_IFERR(sql_copy_object_name(stmt->context, tmp_word.type, (text_t *)&tmp_word.text, &tablespace));

    if (word->id == (uint32)KEY_WORD_TEMPORARY) {
        CT_RETURN_IFERR(cm_text2str(&tablespace, def->temp_space, CT_NAME_BUFFER_SIZE));
        def->mask |= USER_TEMP_SPACE_MASK;
        *flag |= DDL_USER_TMP_SPACE;
    } else if (word->id == (uint32)RES_WORD_DEFAULT) {
        CT_RETURN_IFERR(cm_text2str(&tablespace, def->default_space, CT_NAME_BUFFER_SIZE));
        def->mask |= USER_DATA_SPACE_MASK;
        *flag |= DDL_USER_DEFALT_SPACE;
    }

    return CT_SUCCESS;
}

static status_t sql_parse_password_expire(sql_stmt_t *stmt, word_t *word, knl_user_def_t *def, uint32 *oper_flag)
{
    if (*oper_flag & DDL_USER_PWD_EXPIRE) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR,
            "keyword \"password\" cannot be appear more than once");
        return CT_ERROR;
    }
    /* the word following keyword IDENTIFIED must be keyword by. */
    if (CT_SUCCESS != lex_expected_fetch_word(stmt->session->lex, "EXPIRE")) {
        return CT_ERROR;
    }
    def->is_expire = CT_TRUE;
    *oper_flag |= DDL_USER_PWD_EXPIRE;
    def->mask |= USER_EXPIRE_MASK;
    return CT_SUCCESS;
}

static status_t sql_parse_user_permanent(sql_stmt_t *stmt, word_t *word, knl_user_def_t *def, uint32 *oper_flag)
{
    if (*oper_flag & DDL_USER_PERMANENT) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR,
            "keyword \"permanent\" cannot be appear more than once");
        return CT_ERROR;
    }

    if (!cm_text_str_equal_ins(&stmt->session->curr_user, SYS_USER_NAME)) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "only sys can create the permanent user");
        return CT_ERROR;
    }

    def->is_permanent = CT_TRUE;
    *oper_flag |= DDL_USER_PERMANENT;
    return CT_SUCCESS;
}

static status_t sql_parse_account_lock(sql_stmt_t *stmt, word_t *word, knl_user_def_t *def, uint32 *oper_flag)
{
    uint32 matched_id;

    if (*oper_flag & DDL_USER_ACCOUNT_LOCK) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR,
            "keyword \"account\" cannot be appear more than once");
        return CT_ERROR;
    }

    if (CT_SUCCESS != lex_expected_fetch_1ofn(stmt->session->lex, &matched_id, 2, "lock", "unlock")) {
        return CT_ERROR;
    }

    if (matched_id == 0) {
        def->is_lock = CT_TRUE;
    }

    *oper_flag |= DDL_USER_ACCOUNT_LOCK;
    def->mask |= USER_LOCK_MASK;

    return CT_SUCCESS;
}

static status_t sql_parse_user_name(sql_stmt_t *stmt, char *buf, bool32 for_user)
{
    word_t word;
    lex_t *lex = stmt->session->lex;

    CT_RETURN_IFERR(lex_expected_fetch_variant(lex, &word));

    cm_text2str_with_upper((text_t *)&word.text, buf, CT_NAME_BUFFER_SIZE);

    if (contains_nonnaming_char(buf)) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "invalid variant/object name was found");
        return CT_ERROR;
    }

    /* if it is not the root tenant, prefix the tenant name with the user name */
    if (for_user) {
        if (sql_user_prefix_tenant(stmt->session, buf) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    /* can not create user name default DBA user's name */
    if (strlen(buf) == strlen(SYS_USER_NAME) && !strncmp(buf, SYS_USER_NAME, strlen(buf))) {
        CT_SRC_THROW_ERROR(word.text.loc, ERR_FORBID_CREATE_SYS_USER);
        return CT_ERROR;
    }

    /* can not create user name default DBA user's name:CM_SYSDBA_USER_NAME */
    if (strlen(buf) == strlen(CM_SYSDBA_USER_NAME) && !strncmp(buf, CM_SYSDBA_USER_NAME, strlen(buf))) {
        CT_SRC_THROW_ERROR(word.text.loc, ERR_FORBID_CREATE_SYS_USER);
        return CT_ERROR;
    }

    /* can not create user name default DBA user's name:CM_CLSMGR_USER_NAME */
    if (strlen(buf) == strlen(CM_CLSMGR_USER_NAME) && !strncmp(buf, CM_CLSMGR_USER_NAME, strlen(buf))) {
        CT_SRC_THROW_ERROR(word.text.loc, ERR_FORBID_CREATE_SYS_USER);
        return CT_ERROR;
    }

    if (IS_COMPATIBLE_MYSQL_INST) {
        cm_text2str((text_t *)&word.text, buf, CT_NAME_BUFFER_SIZE);
    }

    return CT_SUCCESS;
}


static status_t sql_parse_identify_clause(sql_stmt_t *stmt, knl_user_def_t *def)
{
    word_t word;

    CT_RETURN_IFERR(lex_expected_fetch_word(stmt->session->lex, "IDENTIFIED"));
    CT_RETURN_IFERR(lex_expected_fetch_word(stmt->session->lex, "BY"));
    CT_RETURN_IFERR(lex_expected_fetch(stmt->session->lex, &word));

    if (word.type != WORD_TYPE_VARIANT && word.type != WORD_TYPE_STRING && word.type != WORD_TYPE_DQ_STRING) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "The password must be identifier or string");
        return CT_ERROR;
    }
    if (word.type == WORD_TYPE_STRING) {
        LEX_REMOVE_WRAP(&word);
        def->pwd_loc = stmt->session->lex->text.len - word.text.len - 1;
    } else {
        def->pwd_loc = stmt->session->lex->text.len - word.text.len;
    }
    def->pwd_len = word.text.len;

    CT_RETURN_IFERR(cm_text2str((text_t *)&word.text, def->password, CT_PASSWORD_BUFFER_SIZE));
    CT_RETURN_IFERR(sql_replace_password(stmt, &word.text.value));
    // for export create user pw from sql client
    return lex_try_fetch(stmt->session->lex, "ENCRYPTED", &def->is_encrypt);
}

static status_t sql_parse_profile(sql_stmt_t *stmt, word_t *word, knl_user_def_t *def, uint32 *oper_flag)
{
    bool32 result = CT_FALSE;
    lex_t *lex = stmt->session->lex;
    text_t default_profile = { DEFAULT_PROFILE_NAME, (uint32)strlen(DEFAULT_PROFILE_NAME) };
    if (*oper_flag & DDL_USER_PROFILE) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR,
            "keyword \"profile\" cannot be appear more than once");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(lex_try_fetch(lex, DEFAULT_PROFILE_NAME, &result));
    if (result) {
        CT_RETURN_IFERR(sql_copy_text(stmt->context, &default_profile, &def->profile));
    } else {
        CT_RETURN_IFERR(lex_expected_fetch_variant(lex, word));
        CT_RETURN_IFERR(sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, &def->profile));
    }

    def->mask |= USER_PROFILE_MASK;
    *oper_flag |= DDL_USER_PROFILE;

    return CT_SUCCESS;
}

static status_t sql_parse_user_attr(sql_stmt_t *stmt, knl_user_def_t *user_def)
{
    uint32 flag = 0;
    word_t word;
    status_t status;
    lex_t *lex = stmt->session->lex;
    text_t mask_word = {
        .str = lex->curr_text->value.str + 1,
        .len = lex->curr_text->value.len - 1
    };
    user_def->is_permanent = CT_FALSE;
    status = sql_parse_identify_clause(stmt, user_def);
    if (status == CT_ERROR) {
        (void)sql_replace_password(stmt, &mask_word); // for audit
        return CT_ERROR;
    }

    if (!g_instance->sql.enable_password_cipher && user_def->is_encrypt) {
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "please check whether supports create user with ciphertext");
        return CT_ERROR;
    }

    status = lex_fetch(stmt->session->lex, &word);
    CT_RETURN_IFERR(status);

    while (word.type != WORD_TYPE_EOF) {
        if (word.id == RES_WORD_DEFAULT || word.id == KEY_WORD_TEMPORARY) {
            status = ddl_parse_set_tablespace(stmt, &word, user_def, &flag);
        } else if (word.id == KEY_WORD_PASSWORD) {
            status = sql_parse_password_expire(stmt, &word, user_def, &flag);
        } else if (word.id == KEY_WORD_ACCOUNT) {
            status = sql_parse_account_lock(stmt, &word, user_def, &flag);
        } else if (word.id == KEY_WORD_PROFILE) {
            status = sql_parse_profile(stmt, &word, user_def, &flag);
        } else if (cm_text_str_equal_ins((text_t *)&word.text, "PERMANENT")) {
            status = sql_parse_user_permanent(stmt, &word, user_def, &flag);
        } else {
            CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "illegal sql text");
            return CT_ERROR;
        }

        if (status != CT_SUCCESS || lex_fetch(stmt->session->lex, &word) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t sql_parse_profile_pwd_len(sql_stmt_t *stmt, knl_user_def_t *user_def, uint64 *pwd_min_len)
{
    profile_t *profile = NULL;
    uint32 profile_id;
    knl_session_t *session = &stmt->session->knl_session;

    if (CM_IS_EMPTY(&user_def->profile)) {
        profile_id = DEFAULT_PROFILE_ID;
    } else {
        if (!profile_find_by_name(session, &user_def->profile, NULL, &profile)) {
            CT_THROW_ERROR(ERR_PROFILE_NOT_EXIST, T2S(&user_def->profile));
            return CT_ERROR;
        }
        profile_id = profile->id;
    }

    if (CT_SUCCESS != profile_get_param_limit(session, profile_id, PASSWORD_MIN_LEN, pwd_min_len)) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_parse_create_user(sql_stmt_t *stmt)
{
    status_t status;
    knl_user_def_t *def = NULL;
    char log_pwd[CT_PWD_BUFFER_SIZE] = {0};
    uint64 pwd_min_len;

    SQL_SET_IGNORE_PWD(stmt->session);

    stmt->context->type = CTSQL_TYPE_CREATE_USER;
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_user_def_t), (void **)&def));

    def->is_readonly = CT_TRUE;
    stmt->context->entry = def;
    CT_RETURN_IFERR(sql_parse_user_name(stmt, def->name, CT_TRUE));
    def->tenant_id = stmt->session->curr_tenant_id;

    do {
        status = sql_parse_user_attr(stmt, def);
        CT_BREAK_IF_ERROR(status);

        if (!def->is_encrypt) {
            if (cm_check_pwd_black_list(GET_PWD_BLACK_CTX, def->name, def->password, log_pwd)) {
                CT_THROW_ERROR_EX(ERR_PASSWORD_FORMAT_ERROR, "The password violates the pbl rule");
                return CT_ERROR;
            }
            status = sql_parse_profile_pwd_len(stmt, def, &pwd_min_len);
            CT_BREAK_IF_ERROR(status);
            status = cm_verify_password_str(def->name, def->password, (uint32)pwd_min_len);
            CT_BREAK_IF_ERROR(status);
        }
    } while (0);

    if (status != CT_SUCCESS) {
        MEMS_RETURN_IFERR(memset_sp(def->old_password, CT_PASSWORD_BUFFER_SIZE, 0, CT_PASSWORD_BUFFER_SIZE));
        MEMS_RETURN_IFERR(memset_sp(def->password, CT_PASSWORD_BUFFER_SIZE, 0, CT_PASSWORD_BUFFER_SIZE));
    }

    return status;
}


status_t sql_parse_drop_user(sql_stmt_t *stmt)
{
    word_t word;
    lex_t *lex = NULL;
    status_t status;
    knl_drop_user_t *def = NULL;
    char user[CT_MAX_NAME_LEN];
    lex = stmt->session->lex;
    lex->flags |= LEX_WITH_OWNER;
    stmt->context->type = CTSQL_TYPE_DROP_USER;

    status = sql_alloc_mem(stmt->context, sizeof(knl_drop_user_t), (void **)&def);
    CT_RETURN_IFERR(status);

    status = sql_try_parse_if_exists(lex, &def->options);
    CT_RETURN_IFERR(status);

    status = lex_expected_fetch_variant(lex, &word);
    CT_RETURN_IFERR(status);

    CT_RETURN_IFERR(cm_text2str((text_t *)&word.text, user, CT_MAX_NAME_LEN));
    if (contains_nonnaming_char(user)) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "invalid variant/object name was found");
        return CT_ERROR;
    }

    sql_copy_func_t sql_copy_func;
    if (IS_COMPATIBLE_MYSQL_INST) {
        sql_copy_func = sql_copy_name_cs;
    } else {
        sql_copy_func = sql_copy_name;
    }

    status = sql_copy_prefix_tenant(stmt, (text_t *)&word.text, &def->owner, sql_copy_func);
    CT_RETURN_IFERR(status);

    status = lex_fetch(lex, &word);
    CT_RETURN_IFERR(status);

    if (word.type == WORD_TYPE_EOF) {
        def->purge = CT_FALSE;
        stmt->context->entry = def;
        return CT_SUCCESS;
    }
    if (cm_text_str_equal_ins((text_t *)&word.text, "CASCADE")) {
        def->purge = CT_TRUE;
        status = lex_expected_end(lex);
        CT_RETURN_IFERR(status);
    } else {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "CASCADE expected, but %s found", T2S((text_t *)&word.text));
        return CT_ERROR;
    }

    stmt->context->entry = def;
    return CT_SUCCESS;
}

status_t sql_parse_drop_tenant(sql_stmt_t *stmt)
{
    word_t word;
    lex_t *lex = NULL;
    status_t status;
    bool32 res;
    knl_drop_tenant_t *def = NULL;
    char tenant[CT_MAX_NAME_LEN];
    lex = stmt->session->lex;

    stmt->context->type = CTSQL_TYPE_DROP_TENANT;

    status = sql_alloc_mem(stmt->context, sizeof(knl_drop_tenant_t), (void **)&def);
    CT_RETURN_IFERR(status);

    CM_MAGIC_SET(def, knl_drop_tenant_t);

    status = sql_try_parse_if_exists(lex, &def->options);
    CT_RETURN_IFERR(status);

    status = lex_expected_fetch_variant(lex, &word);
    CT_RETURN_IFERR(status);

    status = sql_copy_name(stmt->context, (text_t *)&word.text, &def->name);
    CT_RETURN_IFERR(status);
    CT_RETURN_IFERR(cm_text2str(&def->name, tenant, CT_MAX_NAME_LEN));

    if (contains_nonnaming_char(tenant)) {
        CT_SRC_THROW_ERROR(word.text.loc, ERR_SQL_SYNTAX_ERROR, "invalid variant/object name was found");
        return CT_ERROR;
    }
    status = lex_try_fetch(lex, "CASCADE", &res);
    CT_RETURN_IFERR(status);

    if (res) {
        def->options |= DROP_CASCADE_CONS;
    }
    stmt->context->entry = def;
    return lex_expected_end(lex);
}

static status_t sql_parse_alter_profile_pwd_len(sql_stmt_t *stmt, knl_user_def_t *def, dc_user_t *user,
    uint64 *pwd_min_len)
{
    profile_t *profile = NULL;
    uint32 profile_id;
    knl_session_t *session = &stmt->session->knl_session;

    if (CM_IS_EMPTY(&def->profile)) {
        profile_id = user->desc.profile_id;
    } else {
        if (!profile_find_by_name(session, &def->profile, NULL, &profile)) {
            CT_THROW_ERROR(ERR_PROFILE_NOT_EXIST, T2S(&def->profile));
            return CT_ERROR;
        }
        profile_id = profile->id;
    }

    if (CT_SUCCESS != profile_get_param_limit(session, profile_id, PASSWORD_MIN_LEN, pwd_min_len)) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t sql_parse_alter_check_pwd(sql_stmt_t *stmt, knl_user_def_t *def, dc_user_t *user)
{
    char log_pwd[CT_PWD_BUFFER_SIZE] = {0};
    status_t status;
    uint64 pwd_min_len;
    if (!CM_IS_EMPTY_STR(def->password)) {
        if (cm_check_pwd_black_list(GET_PWD_BLACK_CTX, def->name, def->password, log_pwd)) {
            CT_THROW_ERROR_EX(ERR_PASSWORD_FORMAT_ERROR, "The password violates the pbl rule");
            return CT_ERROR;
        }
        status = sql_parse_alter_profile_pwd_len(stmt, def, user, &pwd_min_len);
        CT_RETURN_IFERR(status);
        status = sql_verify_alter_password(def->name, def->old_password, def->password, (uint32)pwd_min_len);
        CT_RETURN_IFERR(status);
    }
    return CT_SUCCESS;
}

static status_t sql_parse_alter_user_attr_core(sql_stmt_t *stmt, knl_user_def_t *user_def, word_t word, text_t mask_word,
    lex_t *lex)
{
    status_t status;
    uint32 flag = 0;
    while (word.type != WORD_TYPE_EOF) {
        switch (word.id) {
            case KEY_WORD_IDENTIFIED:
                status = sql_parse_keyword_identified(stmt, &word, user_def, &flag);
                if (status == CT_ERROR) {
                    (void)sql_replace_password(stmt, &mask_word); // for audit
                }
                break;
            case KEY_WORD_PASSWORD:
                status = sql_parse_password_expire(stmt, &word, user_def, &flag);
                break;
            case KEY_WORD_ACCOUNT:
                status = sql_parse_account_lock(stmt, &word, user_def, &flag);
                break;
            case KEY_WORD_PROFILE:
                status = sql_parse_profile(stmt, &word, user_def, &flag);
                break;
            case RES_WORD_DEFAULT:
            case KEY_WORD_TEMPORARY:
                status = ddl_parse_set_tablespace(stmt, &word, user_def, &flag);
                break;
            default:
                status = CT_ERROR;
                CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "illegal sql text");
        }

        if (status != CT_SUCCESS || lex_fetch(lex, &word) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

static status_t sql_parse_alter_user_attr(sql_stmt_t *stmt, knl_user_def_t *def, dc_user_t *user)
{
    word_t word;
    lex_t *lex = stmt->session->lex;
    text_t mask_word = {
        .str = lex->curr_text->value.str + 1,
        .len = lex->curr_text->value.len - 1
    };
    CT_RETURN_IFERR(lex_expected_fetch(lex, &word));

    CT_RETURN_IFERR(sql_parse_alter_user_attr_core(stmt, def, word, mask_word, lex));
    stmt->context->entry = def;
    CT_RETURN_IFERR(sql_parse_alter_check_pwd(stmt, def, user));

    if (def->mask == 0) {
        CT_THROW_ERROR(ERR_NO_OPTION_SPECIFIED, "alter user");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_parse_alter_user(sql_stmt_t *stmt)
{
    word_t word;
    status_t status;
    text_t owner;
    knl_user_def_t *user_def = NULL;
    dc_user_t *user = NULL;

    SQL_SET_IGNORE_PWD(stmt->session);
    stmt->context->type = CTSQL_TYPE_ALTER_USER;

    status = sql_alloc_mem(stmt->context, sizeof(knl_user_def_t), (void **)&user_def);
    CT_RETURN_IFERR(status);

    user_def->is_readonly = CT_TRUE;
    status = lex_expected_fetch_variant(stmt->session->lex, &word);
    CT_RETURN_IFERR(status);

    cm_text2str_with_upper((text_t *)&word.text, user_def->name, CT_NAME_BUFFER_SIZE);
    if (contains_nonnaming_char(user_def->name)) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "invalid variant/object name was found");
        return CT_ERROR;
    }

    if (sql_user_prefix_tenant(stmt->session, user_def->name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (stmt->session->knl_session.interactive_altpwd && !cm_str_equal_ins(user_def->name, stmt->session->db_user)) {
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "illegal sql text.");
        return CT_ERROR;
    }

    cm_str2text(user_def->name, &owner);
    if (dc_open_user_direct(&stmt->session->knl_session, &owner, &user) != CT_SUCCESS) {
        if (knl_check_sys_priv_by_name(&stmt->session->knl_session, &stmt->session->curr_user, ALTER_USER) ==
            CT_FALSE) {
            cm_reset_error();
            CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
        }
        return CT_ERROR;
    }
    if (user->desc.astatus & ACCOUNT_SATTUS_PERMANENT) {
        if (!cm_str_equal(stmt->session->db_user, SYS_USER_NAME)) {
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "only sys can alter the permanent user");
            return CT_ERROR;
        }
    }

    if (sql_parse_alter_user_attr(stmt, user_def, user) != CT_SUCCESS) {
        MEMS_RETURN_IFERR(memset_sp(user_def->old_password, CT_PASSWORD_BUFFER_SIZE, 0, CT_PASSWORD_BUFFER_SIZE));
        MEMS_RETURN_IFERR(memset_sp(user_def->password, CT_PASSWORD_BUFFER_SIZE, 0, CT_PASSWORD_BUFFER_SIZE));
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static bool32 sql_find_space_in_list(galist_t *space_lst, const text_t *space_name)
{
    uint32 i;
    text_t *tmp_space = NULL;

    for (i = 0; i < space_lst->count; i++) {
        tmp_space = (text_t *)cm_galist_get(space_lst, i);
        if (cm_text_equal_ins(tmp_space, space_name)) {
            return CT_TRUE;
        }
    }

    return CT_FALSE;
}

status_t sql_parse_tenant_space_list(sql_stmt_t *stmt, knl_tenant_def_t *def)
{
    word_t word;
    lex_t *lex = stmt->session->lex;
    text_t *spc_name = NULL;
    status_t status = CT_SUCCESS;

    CM_MAGIC_CHECK(def, knl_tenant_def_t);
    CT_RETURN_IFERR(lex_expected_fetch_word(lex, "TABLESPACES"));
    CT_RETURN_IFERR(lex_expected_fetch_bracket(lex, &word));
    CT_RETURN_IFERR(lex_push(lex, &word.text));
    cm_galist_init(&def->space_lst, stmt->context, sql_alloc_mem);

    while (CT_TRUE) {
        status = lex_expected_fetch_variant(lex, &word);
        CT_BREAK_IF_ERROR(status);

        cm_text_upper(&word.text.value);
        if (sql_find_space_in_list(&def->space_lst, &word.text.value)) {
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "tablespace %s is already exists", T2S(&word.text.value));
            status = CT_ERROR;
            break;
        }
        status = cm_galist_new(&def->space_lst, sizeof(text_t), (pointer_t *)&spc_name);
        CT_BREAK_IF_ERROR(status);
        status = sql_copy_name(stmt->context, &word.text.value, spc_name);
        CT_BREAK_IF_ERROR(status);
        status = lex_fetch(lex, &word);
        CT_BREAK_IF_ERROR(status);

        if (word.type == WORD_TYPE_EOF) {
            break;
        }

        if (!(IS_SPEC_CHAR(&word, ','))) {
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, ", expected, but %s found", T2S(&word.text.value));
            status = CT_ERROR;
            break;
        }

        if (def->space_lst.count >= CT_MAX_SPACES) {
            CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "exclude spaces number out of max spaces number");
            status = CT_ERROR;
            break;
        }
    }

    lex_pop(lex);
    return status;
}

status_t sql_parse_alter_tenant_add_spcs(sql_stmt_t *stmt, knl_tenant_def_t *tenant_def)
{
    CM_MAGIC_CHECK(tenant_def, knl_tenant_def_t);

    tenant_def->sub_type = ALTER_TENANT_TYPE_ADD_SPACE;

    return sql_parse_tenant_space_list(stmt, tenant_def);
}

status_t sql_parse_alter_tenant_defspc(sql_stmt_t *stmt, knl_tenant_def_t *tenant_def)
{
    status_t status;
    word_t word;
    lex_t *lex = stmt->session->lex;

    CM_MAGIC_CHECK(tenant_def, knl_tenant_def_t);

    tenant_def->sub_type = ALTER_TENANT_TYPE_MODEIFY_DEFAULT;

    status = lex_expected_fetch_word(lex, "TABLESPACE");
    CT_RETURN_IFERR(status);

    status = lex_expected_fetch_variant(lex, &word);
    CT_RETURN_IFERR(status);

    (void)cm_text2str_with_upper((text_t *)&word.text, tenant_def->default_tablespace, CT_NAME_BUFFER_SIZE);

    return CT_SUCCESS;
}

status_t sql_parse_alter_tenant(sql_stmt_t *stmt)
{
    word_t word;
    status_t status;
    knl_tenant_def_t *tenant_def = NULL;
    lex_t *lex = stmt->session->lex;

    stmt->context->type = CTSQL_TYPE_ALTER_TENANT;

    status = sql_alloc_mem(stmt->context, sizeof(knl_tenant_def_t), (void **)&tenant_def);
    CT_RETURN_IFERR(status);

    CM_MAGIC_SET(tenant_def, knl_tenant_def_t);

    status = lex_expected_fetch_variant(lex, &word);
    CT_RETURN_IFERR(status);

    cm_text2str_with_upper((text_t *)&word.text, tenant_def->name, CT_NAME_BUFFER_SIZE);

    if (contains_nonnaming_char(tenant_def->name)) {
        CT_SRC_THROW_ERROR(word.text.loc, ERR_SQL_SYNTAX_ERROR, "invalid variant/object name was found");
        return CT_ERROR;
    }

    status = lex_fetch(lex, &word);
    CT_RETURN_IFERR(status);

    switch (word.id) {
        case KEY_WORD_ADD:
            status = sql_parse_alter_tenant_add_spcs(stmt, tenant_def);
            CT_RETURN_IFERR(status);
            break;

        case RES_WORD_DEFAULT:
            status = sql_parse_alter_tenant_defspc(stmt, tenant_def);
            CT_RETURN_IFERR(status);
            break;

        default:
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "ADD or DEFAULT expected, but %s found", T2S((text_t *)&word.text));
            return CT_ERROR;
    }

    stmt->context->entry = tenant_def;
    return lex_expected_end(lex);
}

static status_t sql_parse_role_attr(sql_stmt_t *stmt, word_t *word, knl_role_def_t *def)
{
    status_t status;
    lex_t *lex = stmt->session->lex;
    char log_pwd[CT_PWD_BUFFER_SIZE] = {0};

    if (word->id == KEY_WORD_NOT) {
        status = lex_expected_fetch_word(lex, "IDENTIFIED");
        CT_RETURN_IFERR(status);
    } else if (word->id == KEY_WORD_IDENTIFIED) {
        status = lex_expected_fetch_word(lex, "BY");
        CT_RETURN_IFERR(status);

        status = lex_expected_fetch(lex, word);
        CT_RETURN_IFERR(status);

        if (word->type == WORD_TYPE_STRING) {
            LEX_REMOVE_WRAP(word);
            // for coordinator which is connect from app,save defination sql to send to other node
            def->pwd_loc = stmt->session->lex->text.len - word->text.len - 1;
        } else {
            def->pwd_loc = stmt->session->lex->text.len - word->text.len;
        }
        def->pwd_len = word->text.len;

        CT_RETURN_IFERR(cm_text2str((text_t *)&word->text, def->password, CT_PASSWORD_BUFFER_SIZE));
        status = sql_replace_password(stmt, &word->text.value);
        CT_RETURN_IFERR(status);

        // for export user role pw from sql client
        CT_RETURN_IFERR(lex_try_fetch(stmt->session->lex, "ENCRYPTED", &def->is_encrypt));

        // If it is an encrypted pw, there is no need to verify the length.
        if (!def->is_encrypt) {
            if (cm_check_pwd_black_list(GET_PWD_BLACK_CTX, def->name, def->password, log_pwd)) {
                CT_THROW_ERROR_EX(ERR_PASSWORD_FORMAT_ERROR, "The password violates the pbl rule");
                return CT_ERROR;
            }
            status = cm_verify_password_str(def->name, def->password, CT_PASSWD_MIN_LEN);
            CT_RETURN_IFERR(status);
        }
    } else {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word expected, but %s found", T2S((text_t *)&word->text));
        return CT_ERROR;
    }

    return lex_expected_end(lex);
}

status_t sql_parse_create_role(sql_stmt_t *stmt)
{
    word_t word;
    uint32 word_id;
    text_t mask_word;
    knl_role_def_t *def = NULL;
    lex_t *lex = stmt->session->lex;
    SQL_SET_IGNORE_PWD(stmt->session);
    if (sql_alloc_mem(stmt->context, sizeof(knl_role_def_t), (void **)&def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    def->owner_uid = stmt->session->knl_session.uid;
    stmt->context->type = CTSQL_TYPE_CREATE_ROLE;

    if (sql_parse_user_name(stmt, def->name, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_fetch(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word.type == WORD_TYPE_EOF) {
        stmt->context->entry = def;
        return CT_SUCCESS;
    }
    word_id = word.id;
    mask_word.str = lex->curr_text->value.str + 1;
    mask_word.len = lex->curr_text->value.len - 1;
    if (sql_parse_role_attr(stmt, &word, def) != CT_SUCCESS) {
        if (word_id == KEY_WORD_IDENTIFIED) {
            (void)sql_replace_password(stmt, &mask_word); // for audit
        }
        return CT_ERROR;
    }

    stmt->context->entry = def;
    return CT_SUCCESS;
}

status_t sql_parse_drop_role(sql_stmt_t *stmt)
{
    word_t word;
    knl_drop_def_t *def = NULL;
    lex_t *lex = stmt->session->lex;

    stmt->context->type = CTSQL_TYPE_DROP_ROLE;

    if (sql_alloc_mem(stmt->context, sizeof(knl_drop_def_t), (void **)&def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch_variant(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_copy_name(stmt->context, (text_t *)&word.text, &def->name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_end(lex) != CT_SUCCESS) {
        return CT_ERROR;
    }

    stmt->context->entry = def;
    return CT_SUCCESS;
}

status_t sql_parse_create_tenant(sql_stmt_t *stmt)
{
    word_t word;
    knl_tenant_def_t *def = NULL;
    lex_t *lex = stmt->session->lex;
    bool32 result;

    stmt->context->type = CTSQL_TYPE_CREATE_TENANT;

    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_tenant_def_t), (void **)&def));
    CM_MAGIC_SET(def, knl_tenant_def_t);

    CT_RETURN_IFERR(lex_expected_fetch_variant(lex, &word));
    if (word.text.len > CT_TENANT_NAME_LEN) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "'%s' is too long to as tenant name",
            T2S(&word.text));
        return CT_ERROR;
    }
    cm_text2str_with_upper(&word.text.value, def->name, CT_TENANT_BUFFER_SIZE);
    if (contains_nonnaming_char_ex(def->name)) {
        CT_SRC_THROW_ERROR(word.text.loc, ERR_SQL_SYNTAX_ERROR, "invalid variant/object name was found");
        return CT_ERROR;
    }

    if (cm_text_str_equal(&g_tenantroot, def->name)) {
        CT_SRC_THROW_ERROR(word.text.loc, ERR_SQL_SYNTAX_ERROR, "can not create TENANT$ROOT");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(sql_parse_tenant_space_list(stmt, def));
    CT_RETURN_IFERR(lex_try_fetch2(lex, "DEFAULT", "TABLESPACE", &result));
    if (result) {
        CT_RETURN_IFERR(lex_expected_fetch_variant(lex, &word));
        cm_text_upper(&word.text.value);
        if (!sql_find_space_in_list(&def->space_lst, &word.text.value)) {
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "tablespace %s has not been declared previously",
                T2S(&word.text.value));
            return CT_ERROR;
        }
        cm_text2str_with_upper(&word.text.value, def->default_tablespace, CT_NAME_BUFFER_SIZE);
    } else {
        text_t *tmp_space = (text_t *)cm_galist_get(&def->space_lst, 0);
        cm_text2str_with_upper(tmp_space, def->default_tablespace, CT_NAME_BUFFER_SIZE);
    }

    stmt->context->entry = def;
    return lex_expected_end(lex);
}

static status_t sql_get_timetype_value(knl_profile_def_t *def, variant_t *value, lex_t *lex, uint32 id, dec8_t *unlimit)
{
    dec8_t result;
    if (CT_SUCCESS != cm_int64_mul_dec((int64)SECONDS_PER_DAY, &(value->v_dec), &result)) {
        return CT_ERROR;
    }

    if (cm_dec_cmp(&result, unlimit) > 0) {
        CT_SRC_THROW_ERROR(lex->loc, ERR_INVALID_RESOURCE_LIMIT);
        return CT_ERROR;
    }

    int64 check_scale = 0;
    if (cm_dec_to_int64(&result, (int64 *)&check_scale, ROUND_HALF_UP) != CT_SUCCESS || check_scale < 1) {
        CT_SRC_THROW_ERROR(lex->loc, ERR_INVALID_RESOURCE_LIMIT);
        return CT_ERROR;
    }
    value->v_dec = result;

    if (cm_dec_to_int64(&(value->v_dec), (int64 *)&def->limit[id].value, ROUND_HALF_UP)) {
        CT_SRC_THROW_ERROR(lex->loc, ERR_INVALID_RESOURCE_LIMIT);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t sql_get_extra_values(knl_profile_def_t *def, variant_t *value, lex_t *lex, uint32 id, dec8_t *unlimit)
{
    if (CT_TRUE != cm_dec_is_integer(&(value->v_dec))) {
        CT_SRC_THROW_ERROR(lex->loc, ERR_INVALID_RESOURCE_LIMIT);
        return CT_ERROR;
    }

    if (cm_dec_to_int64(&(value->v_dec), (int64 *)&def->limit[id].value, ROUND_HALF_UP)) {
        CT_SRC_THROW_ERROR(lex->loc, ERR_INVALID_RESOURCE_LIMIT);
        return CT_ERROR;
    }

    if (id == SESSIONS_PER_USER) {
        if (def->limit[id].value > CT_MAX_SESSIONS) {
            CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "SESSIONS_PER_USER", (int64)CT_MAX_SESSIONS);
            return CT_ERROR;
        }
    }

    if (id == PASSWORD_MIN_LEN) {
        if (def->limit[id].value < CT_PASSWD_MIN_LEN || def->limit[id].value > CT_PASSWD_MAX_LEN) {
            CT_SRC_THROW_ERROR(lex->loc, ERR_INVALID_RESOURCE_LIMIT);
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static check_profile_t g_check_pvalues[] = {
    [FAILED_LOGIN_ATTEMPTS] = { sql_get_extra_values },
    [PASSWORD_LIFE_TIME]    = { sql_get_timetype_value  },
    [PASSWORD_REUSE_TIME]   = { sql_get_timetype_value },
    [PASSWORD_REUSE_MAX]    = { sql_get_extra_values },
    [PASSWORD_LOCK_TIME]    = { sql_get_timetype_value },
    [PASSWORD_GRACE_TIME]   = { sql_get_timetype_value },
    [SESSIONS_PER_USER]     = { sql_get_extra_values },
    [PASSWORD_MIN_LEN]      = { sql_get_extra_values },
};

static status_t sql_get_profile_parameters_value(sql_stmt_t *stmt, knl_profile_def_t *def, lex_t *lex, uint32 id)
{
    word_t word;
    dec8_t unlimit;
    status_t status;
    expr_tree_t *expr = NULL;
    sql_verifier_t verf = { 0 };
    variant_t value;

    CT_RETURN_IFERR(sql_create_expr_until(stmt, &expr, &word));
    verf.context = stmt->context;
    verf.stmt = stmt;
    verf.excl_flags = SQL_NON_NUMERIC_FLAGS;

    CT_RETURN_IFERR(sql_verify_expr(&verf, expr));

    if (!sql_is_const_expr_tree(expr)) {
        CT_SRC_THROW_ERROR(lex->loc, ERR_INVALID_RESOURCE_LIMIT);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(sql_exec_expr(stmt, expr, &value));

    CT_RETURN_IFERR(sql_convert_variant(stmt, &value, CT_TYPE_NUMBER));

    cm_int32_to_dec(CT_INVALID_INT32, &unlimit);
    if (value.is_null || IS_DEC8_NEG(&value.v_dec) || DECIMAL8_IS_ZERO(&value.v_dec) ||
        cm_dec_cmp(&value.v_dec, &unlimit) >= 0) {
        CT_SRC_THROW_ERROR(lex->loc, ERR_INVALID_RESOURCE_LIMIT);
        return CT_ERROR;
    }

    check_profile_t *handle = &g_check_pvalues[id];
    if (handle->func == NULL) {
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "the req cmd is not valid");
        return CT_ERROR;
    }

    status = handle->func(def, &value, lex, id, &unlimit);
    CT_RETURN_IFERR(status);

    lex_back(lex, &word);
    return CT_SUCCESS;
}


static status_t sql_parse_profile_parameters(sql_stmt_t *stmt, knl_profile_def_t *def)
{
    word_t word;
    status_t status;
    uint32 id;
    uint32 matched_id;
    lex_t *lex = stmt->session->lex;
    static const char *parameters[] = { "FAILED_LOGIN_ATTEMPTS",
                                        "PASSWORD_LIFE_TIME", "PASSWORD_REUSE_TIME", "PASSWORD_REUSE_MAX",
                                        "PASSWORD_LOCK_TIME", "PASSWORD_GRACE_TIME", "SESSIONS_PER_USER",
                                        "PASSWORD_MIN_LEN"
                                      };
    while (1) {
        status = lex_expected_fetch_1ofn(lex, &id, ELEMENT_COUNT(parameters), parameters[0], parameters[1],
            parameters[2], parameters[3], parameters[4], parameters[5], parameters[6], parameters[7]);
        CT_RETURN_IFERR(status);
        if (CT_BIT_TEST(def->mask, CT_GET_MASK(id))) {
            CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "keyword \"%s\" cannot be appear more than once",
                parameters[id]);
            return CT_ERROR;
        }
        CT_BIT_SET(def->mask, CT_GET_MASK(id));

        status = lex_try_fetch_1ofn(lex, &matched_id, 2, "UNLIMITED", "DEFAULT");
        CT_RETURN_IFERR(status);

        if (id == PASSWORD_MIN_LEN && matched_id == LEX_MATCH_FIRST_WORD) {
            CT_SRC_THROW_ERROR(lex->loc, ERR_INVALID_RESOURCE_LIMIT);
            return CT_ERROR;
        }

        if (matched_id == LEX_MATCH_FIRST_WORD) {
            def->limit[id].type = VALUE_UNLIMITED;
        } else if (matched_id == LEX_MATCH_SECOND_WORD) {
            def->limit[id].type = VALUE_DEFAULT;
        } else {
            def->limit[id].type = VALUE_NORMAL;
            if (sql_get_profile_parameters_value(stmt, def, lex, id) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }

        status = lex_fetch(lex, &word);
        CT_RETURN_IFERR(status);
        if (word.type == WORD_TYPE_EOF) {
            break;
        }

        lex_back(lex, &word);
    }

    if (stmt->context->type == CTSQL_TYPE_CREATE_PROFILE) {
        for (int i = FAILED_LOGIN_ATTEMPTS; i < RESOURCE_PARAM_END; i++) {
            if (!CT_BIT_TEST(def->mask, CT_GET_MASK(i))) {
                CT_BIT_SET(def->mask, CT_GET_MASK(i));
                def->limit[i].type = VALUE_DEFAULT;
            }
        }
    }
    return CT_SUCCESS;
}

status_t sql_parse_create_profile(sql_stmt_t *stmt, bool32 is_replace)
{
    word_t word;
    status_t status;
    bool32 result = CT_FALSE;
    knl_profile_def_t *def = NULL;
    lex_t *lex = stmt->session->lex;
    text_t default_profile = { DEFAULT_PROFILE_NAME, (uint32)strlen(DEFAULT_PROFILE_NAME) };

    status = sql_alloc_mem(stmt->context, sizeof(knl_profile_def_t), (void **)&def);
    CT_RETURN_IFERR(status);

    def->is_replace = is_replace;

    status = lex_try_fetch(lex, DEFAULT_PROFILE_NAME, &result);
    CT_RETURN_IFERR(status);
    if (result) {
        status = sql_copy_text(stmt->context, &default_profile, &def->name);
        CT_RETURN_IFERR(status);
    } else {
        status = lex_expected_fetch_variant(lex, &word);
        CT_RETURN_IFERR(status);
        status = sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &def->name);
        CT_RETURN_IFERR(status);
    }

    status = lex_expected_fetch_word(lex, "limit");
    CT_RETURN_IFERR(status);

    stmt->context->entry = (void *)def;
    stmt->context->type = CTSQL_TYPE_CREATE_PROFILE;

    return sql_parse_profile_parameters(stmt, def);
}

status_t sql_parse_alter_profile(sql_stmt_t *stmt)
{
    word_t word;
    status_t status;
    bool32 result = CT_FALSE;
    text_t default_profile = { DEFAULT_PROFILE_NAME, (uint32)strlen(DEFAULT_PROFILE_NAME) };
    knl_profile_def_t *def = NULL;
    lex_t *lex = stmt->session->lex;

    status = sql_alloc_mem(stmt->context, sizeof(knl_profile_def_t), (void **)&def);
    CT_RETURN_IFERR(status);

    status = lex_try_fetch(lex, DEFAULT_PROFILE_NAME, &result);
    CT_RETURN_IFERR(status);
    if (result) {
        status = sql_copy_text(stmt->context, &default_profile, &def->name);
        CT_RETURN_IFERR(status);
    } else {
        status = lex_expected_fetch_variant(lex, &word);
        CT_RETURN_IFERR(status);
        status = sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &def->name);
        CT_RETURN_IFERR(status);
    }

    status = lex_expected_fetch_word(lex, "limit");
    CT_RETURN_IFERR(status);

    stmt->context->entry = (void *)def;
    stmt->context->type = CTSQL_TYPE_ALTER_PROFILE;

    return sql_parse_profile_parameters(stmt, def);
}

status_t sql_parse_drop_profile(sql_stmt_t *stmt)
{
    word_t word;
    knl_drop_def_t *def = NULL;
    lex_t *lex = stmt->session->lex;
    bool32 result = CT_FALSE;
    status_t status;
    text_t default_profile = { DEFAULT_PROFILE_NAME, (uint32)strlen(DEFAULT_PROFILE_NAME) };
    stmt->context->type = CTSQL_TYPE_DROP_PROFILE;

    status = sql_alloc_mem(stmt->context, sizeof(knl_drop_def_t), (void **)&def);
    CT_RETURN_IFERR(status);

    status = lex_try_fetch(lex, DEFAULT_PROFILE_NAME, &result);
    CT_RETURN_IFERR(status);
    if (result) {
        status = sql_copy_text(stmt->context, &default_profile, &def->name);
        CT_RETURN_IFERR(status);
    } else {
        status = lex_expected_fetch_variant(lex, &word);
        CT_RETURN_IFERR(status);
        status = sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &def->name);
        CT_RETURN_IFERR(status);
    }

    if (cm_text_str_equal(&def->name, DEFAULT_PROFILE_NAME)) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "cannot drop PUBLIC_DEFAULT profile");
        return CT_ERROR;
    }

    status = lex_try_fetch(lex, "cascade", &result);
    CT_RETURN_IFERR(status);

    if (result) {
        def->options |= DROP_CASCADE_CONS;
    }
    stmt->context->entry = def;

    return lex_expected_end(lex);
}

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
 * ddl_privilege_parser.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser_ddl/ddl_privilege_parser.c
 *
 * -------------------------------------------------------------------------
 */

#include "ddl_privilege_parser.h"
#include "ctsql_privilege.h"
#include "ctsql_package.h"
#include "pl_library.h"

status_t sql_check_privs_duplicated(galist_t *priv_list, const text_t *priv_str, priv_type_def priv_type)
{
    uint32 i;
    knl_priv_def_t *priv_def = NULL;

    for (i = 0; i < priv_list->count; i++) {
        priv_def = (knl_priv_def_t *)cm_galist_get(priv_list, i);
        if (cm_text_equal_ins(&priv_def->priv_name, priv_str)) {
            return CT_ERROR;
        }

        if (priv_def->priv_type == PRIV_TYPE_ALL_PRIV || priv_type == PRIV_TYPE_ALL_PRIV) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t sql_check_duplicate_holders(galist_t *holders, const text_t *hold_name)
{
    uint32 i;
    knl_holders_def_t *holder_def = NULL;

    for (i = 0; i < holders->count; i++) {
        holder_def = (knl_holders_def_t *)cm_galist_get(holders, i);
        if (cm_text_equal(&holder_def->name, hold_name)) {
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "user or role %s is already exists", T2S(hold_name));
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t sql_parse_priv_type(sql_stmt_t *stmt, priv_info *priv, priv_type_def *priv_type, uint32 *priv_id)
{
    uint32 rid;
    sys_privs_id sys_pid;
    obj_privs_id obj_pid;
    user_privs_id user_pid;

    if (cm_text_str_equal_ins(&priv->priv_name, "ALL") || cm_text_str_equal_ins(&priv->priv_name, "ALL PRIVILEGES")) {
        *priv_type = PRIV_TYPE_ALL_PRIV;
        *priv_id = (uint32)ALL_PRIVILEGES;
        return CT_SUCCESS;
    }

    if (knl_sys_priv_match(&priv->priv_name, &sys_pid)) {
        *priv_type = PRIV_TYPE_SYS_PRIV;
        *priv_id = (uint32)sys_pid;
        return CT_SUCCESS;
    }

    if (knl_obj_priv_match(&priv->priv_name, &obj_pid)) {
        *priv_type = PRIV_TYPE_OBJ_PRIV;
        *priv_id = (uint32)obj_pid;
        return CT_SUCCESS;
    }

    if (knl_user_priv_match(&priv->priv_name, &user_pid)) {
        *priv_type = PRIV_TYPE_USER_PRIV;
        *priv_id = (uint32)user_pid;
        return CT_SUCCESS;
    }

    if (knl_get_role_id(&stmt->session->knl_session, &priv->priv_name, &rid)) {
        *priv_type = PRIV_TYPE_ROLE;
        *priv_id = rid;
        return CT_SUCCESS;
    }

    CT_SRC_THROW_ERROR_EX(priv->start_loc, ERR_SQL_SYNTAX_ERROR, "invalid privilege or role name");

    return CT_ERROR;
}

status_t sql_parse_priv_name(sql_stmt_t *stmt, word_t *word, galist_t *privs, priv_info *priv)
{
    knl_priv_def_t *priv_def = NULL;
    priv_type_def priv_type;
    uint32 priv_id;
    status_t status;

    if (priv->priv_name.len == 0) {
        CT_SRC_THROW_ERROR_EX(word->loc, ERR_SQL_SYNTAX_ERROR, "missing or invalid privilege");
        return CT_ERROR;
    }

    status = sql_parse_priv_type(stmt, priv, &priv_type, &priv_id);
    CT_RETURN_IFERR(status);

    if (sql_check_privs_duplicated(privs, &priv->priv_name, priv_type) != CT_SUCCESS) {
        CT_SRC_THROW_ERROR_EX(priv->start_loc, ERR_SQL_SYNTAX_ERROR, "duplicate privilege listed");
        return CT_ERROR;
    }

    status = cm_galist_new(privs, sizeof(knl_priv_def_t), (pointer_t *)&priv_def);
    CT_RETURN_IFERR(status);

    status = sql_copy_name(stmt->context, &priv->priv_name, &priv_def->priv_name);
    CT_RETURN_IFERR(status);

    priv_def->priv_id = priv_id;
    priv_def->priv_type = priv_type;
    /* can not check the priv_type now because we do not known the privilege is system privilege type or object
    privilege type yet. so we save the privilege name location for sql_check_privs_type */
    priv_def->start_loc = priv->start_loc;
    return CT_SUCCESS;
}

status_t sql_parse_objpriv_column(knl_grant_def_t *def)
{
    return CT_SUCCESS;
}

static status_t sql_try_parse_special_privs(lex_t *lex, word_t *word, priv_info *priv, bool32 *reserved)
{
    bool32 res = CT_FALSE;

    *reserved = CT_FALSE;
    if (word->id == KEY_WORD_ON) {
        CT_RETURN_IFERR(lex_try_fetch2(lex, "COMMIT", "REFRESH", &res));
        if (res) {
            /* continue parse a privilege name */
            if (priv->priv_name.len > 0) {
                CM_TEXT_APPEND(&priv->priv_name, ' ');
            } else {
                priv->start_loc = word->loc;
            }
            text_t priv_name = { "ON COMMIT REFRESH", 17 };
            cm_concat_text_upper(&priv->priv_name, &priv_name);
            return lex_expected_fetch(lex, word);
        } else {
            *reserved = CT_TRUE;
        }
    }
    return CT_SUCCESS;
}

static status_t sql_try_parse_dir_privs(lex_t *lex, word_t *word, priv_info *priv, bool32 *dire_priv)
{
    bool32 res = CT_FALSE;

    if (word->id == KEY_WORD_ON) {
        CT_RETURN_IFERR(lex_try_fetch(lex, "DIRECTORY", &res));
        if (res) {
            if (priv->priv_name.len > 0) {
                CM_TEXT_APPEND(&priv->priv_name, ' ');
            } else {
                priv->start_loc = word->loc;
            }
            text_t priv_name = { "ON DIRECTORY", 12 };
            cm_concat_text_upper(&priv->priv_name, &priv_name);
            *dire_priv = CT_TRUE;
        }
    }

    return CT_SUCCESS;
}

static status_t sql_try_parse_user_privs(lex_t *lex, word_t *word, priv_info *priv, bool32 *user_priv)
{
    bool32 res = CT_FALSE;

    if (word->id == KEY_WORD_ON) {
        CT_RETURN_IFERR(lex_try_fetch(lex, "USER", &res));
        if (res) {
            *user_priv = CT_TRUE;
        }
    }

    return CT_SUCCESS;
}

status_t sql_parse_privs(sql_stmt_t *stmt, galist_t *privs, priv_type_def *priv_type)
{
    uint32 kid;
    bool32 dire_priv = CT_FALSE;
    bool32 user_priv = CT_FALSE;
    bool32 reserved = CT_FALSE;
    word_t word;
    lex_t *lex = stmt->session->lex;

    priv_info priv = { { NULL, 0 }, { 0, 0 } };

    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, CT_NAME_BUFFER_SIZE, (void **)&priv.priv_name.str));

    CT_RETURN_IFERR(lex_expected_fetch(lex, &word));

    kid = stmt->context->type == CTSQL_TYPE_GRANT ? KEY_WORD_TO : KEY_WORD_FROM;
    while (word.id != kid) {
        CT_RETURN_IFERR(sql_try_parse_dir_privs(lex, &word, &priv, &dire_priv));
        if (word.id == kid || dire_priv) {
            break;
        }

        CT_RETURN_IFERR(sql_try_parse_user_privs(lex, &word, &priv, &user_priv));
        if (word.id == kid || user_priv) {
            break;
        }

        CT_RETURN_IFERR(sql_try_parse_special_privs(lex, &word, &priv, &reserved));
        if (word.id == kid || reserved) {
            break;
        }

        if (IS_SPEC_CHAR(&word, ',')) {
            /* find an entire privilege name */
            CT_RETURN_IFERR(sql_parse_priv_name(stmt, &word, privs, &priv));
            CM_TEXT_CLEAR(&priv.priv_name);
            priv.start_loc.column = 0;
            priv.start_loc.line = 0;
        } else {
            /* continue parse a privilege name */
            if (priv.priv_name.len > 0) {
                CM_TEXT_APPEND(&priv.priv_name, ' ');
            } else {
                priv.start_loc = word.loc;
            }

            if (priv.priv_name.len + word.text.value.len >= CT_NAME_BUFFER_SIZE) {
                CT_SRC_THROW_ERROR(word.loc, ERR_BUFFER_OVERFLOW, priv.priv_name.len + word.text.value.len,
                    CT_NAME_BUFFER_SIZE);
                return CT_ERROR;
            }

            cm_concat_text_upper(&priv.priv_name, &word.text.value);
        }

        CT_RETURN_IFERR(lex_expected_fetch(lex, &word));
    }

    *priv_type = (word.id == KEY_WORD_ON) ? PRIV_TYPE_OBJ_PRIV : PRIV_TYPE_SYS_PRIV;

    if (user_priv) {
        *priv_type = PRIV_TYPE_USER_PRIV;
    }

    /* parse the last privilege name before on/to key word */
    return sql_parse_priv_name(stmt, &word, privs, &priv);
}

status_t sql_check_privs_type(sql_stmt_t *stmt, galist_t *privs, priv_type_def priv_type, object_type_t obj_type,
    text_t *type_name)
{
    uint32 i;
    knl_priv_def_t *priv_def = NULL;

    for (i = 0; i < privs->count; i++) {
        priv_def = cm_galist_get(privs, i);
        if (priv_def->priv_type == PRIV_TYPE_ALL_PRIV) {
            continue;
        }

        if (priv_type == PRIV_TYPE_USER_PRIV) {
            if (priv_def->priv_type != PRIV_TYPE_USER_PRIV) {
                CT_SRC_THROW_ERROR_EX(priv_def->start_loc, ERR_SQL_SYNTAX_ERROR, "invalid privilege");
                return CT_ERROR;
            }
            continue;
        }

        if (priv_type == PRIV_TYPE_SYS_PRIV &&
            !(priv_def->priv_type == PRIV_TYPE_SYS_PRIV || priv_def->priv_type == PRIV_TYPE_ROLE)) {
            CT_SRC_THROW_ERROR_EX(priv_def->start_loc, ERR_SQL_SYNTAX_ERROR, "invalid privilege");
            return CT_ERROR;
        }

        if (priv_type == PRIV_TYPE_OBJ_PRIV) {
            if (priv_def->priv_type != PRIV_TYPE_OBJ_PRIV) {
                CT_SRC_THROW_ERROR_EX(priv_def->start_loc, ERR_SQL_SYNTAX_ERROR, "invalid privilege");
                return CT_ERROR;
            } else {
                /* check priv by object type
                e.g. grant select privilege on function to a user is invalid */
                if (knl_check_obj_priv_scope(priv_def->priv_id, obj_type) != CT_SUCCESS) {
                    CT_SRC_THROW_ERROR_EX(priv_def->start_loc, ERR_SQL_SYNTAX_ERROR, "%s privilege not allowed for %s",
                        T2S(&priv_def->priv_name), T2S_EX(type_name));
                    return CT_ERROR;
                }
            }
        }
    }

    return CT_SUCCESS;
}

status_t sql_parse_grant_privs(sql_stmt_t *stmt, knl_grant_def_t *def)
{
    status_t status;

    status = sql_parse_privs(stmt, &def->privs, &def->priv_type);
    CT_RETURN_IFERR(status);

    if (def->priv_type == PRIV_TYPE_OBJ_PRIV) {
        status = sql_parse_objpriv_column(def);
    }

    return status;
}

status_t sql_parse_revoke_privs(sql_stmt_t *stmt, knl_revoke_def_t *revoke_def)
{
    return sql_parse_privs(stmt, &revoke_def->privs, &revoke_def->priv_type);
}


status_t sql_try_parse_expected_object_type(lex_t *lex, object_type_t *obj_type)
{
    word_t word;
    uint32 matched_id;

    LEX_SAVE(lex);

    if (lex_expected_fetch(lex, &word) != CT_SUCCESS ||
        lex_try_fetch_1of2(lex, "TO", "FROM", &matched_id) != CT_SUCCESS) {
        LEX_RESTORE(lex);
        return CT_ERROR;
    }

    if (matched_id != CT_INVALID_ID32) {
        LEX_RESTORE(lex);
        return CT_SUCCESS;
    }

    if (word.type != WORD_TYPE_KEYWORD) {
        CT_SRC_THROW_ERROR(word.loc, ERR_SQL_SYNTAX_ERROR, "invalid object type");
        return CT_ERROR;
    }

    switch (word.id) {
        case KEY_WORD_TABLE:
            *obj_type = OBJ_TYPE_TABLE;
            return CT_SUCCESS;
        case KEY_WORD_VIEW:
            *obj_type = OBJ_TYPE_VIEW;
            return CT_SUCCESS;
        case KEY_WORD_SEQUENCE:
            *obj_type = OBJ_TYPE_SEQUENCE;
            return CT_SUCCESS;
        case KEY_WORD_PACKAGE:
            *obj_type = OBJ_TYPE_PACKAGE_SPEC;
            return CT_SUCCESS;
        case KEY_WORD_PROCEDURE:
            *obj_type = OBJ_TYPE_PROCEDURE;
            return CT_SUCCESS;
        case KEY_WORD_FUNCTION:
            *obj_type = OBJ_TYPE_FUNCTION;
            return CT_SUCCESS;
        case KEY_WORD_DIRECTORY:
            *obj_type = OBJ_TYPE_DIRECTORY;
            return CT_SUCCESS;
        case KEY_WORD_LIBRARY:
            *obj_type = OBJ_TYPE_LIBRARY;
            return CT_SUCCESS;
        default:
            CT_SRC_THROW_ERROR(word.loc, ERR_SQL_SYNTAX_ERROR, "invalid object type");
            return CT_ERROR;
    }
}

status_t sql_parse_dc_info(sql_stmt_t *stmt, text_t *schema, text_t *objname, bool32 owner_explict,
    object_type_t *obj_type, text_t *typename)
{
    knl_dictionary_t dc;
    knl_dict_type_t dict_type;

    if (CT_SUCCESS == knl_open_dc_with_public(&stmt->session->knl_session, schema, !owner_explict, objname, &dc)) {
        if (dc.is_sysnonym) {
            knl_get_link_name(&dc, schema, objname);
        }

        dict_type = dc.type;
        knl_close_dc(&dc);
        switch (dict_type) {
            case DICT_TYPE_TABLE:
            case DICT_TYPE_TEMP_TABLE_TRANS:
            case DICT_TYPE_TEMP_TABLE_SESSION:
            case DICT_TYPE_TABLE_NOLOGGING:
            case DICT_TYPE_TABLE_EXTERNAL:
                *obj_type = OBJ_TYPE_TABLE;
                CT_RETURN_IFERR(sql_copy_str(stmt->context, "tables", typename));
                break;
            case DICT_TYPE_VIEW:
            case DICT_TYPE_DYNAMIC_VIEW:
                *obj_type = OBJ_TYPE_VIEW;
                CT_RETURN_IFERR(sql_copy_str(stmt->context, "views", typename));
                break;
            case DICT_TYPE_GLOBAL_DYNAMIC_VIEW:
                *obj_type = OBJ_TYPE_VIEW;
                CT_RETURN_IFERR(sql_copy_str(stmt->context, "global views", typename));
                break;
            default:
                return CT_ERROR;
        }
        return CT_SUCCESS;
    }

    return CT_SUCCESS;
}

status_t sql_parse_sequence_info(sql_stmt_t *stmt, text_t *schema, text_t *objname, object_type_t *obj_type,
    text_t *typename)
{
    knl_dictionary_t dc;

    if (CT_SUCCESS == knl_open_seq_dc(&stmt->session->knl_session, schema, objname, &dc)) {
        cm_reset_error();
        *obj_type = OBJ_TYPE_SEQUENCE;
        dc_seq_close(&dc);
        return sql_copy_str(stmt->context, "sequences", typename);
    }
    return CT_SUCCESS;
}

status_t sql_parse_pl_info(sql_stmt_t *stmt, text_t *schema, text_t *objname, bool32 owner_explict,
    object_type_t *obj_type, text_t *type_name)
{
    bool32 exist = CT_FALSE;
    pl_entry_t *entry = NULL;
    dc_user_t *dc_user = NULL;

    if (pl_find_entry_with_public(KNL_SESSION(stmt), schema, objname, owner_explict, PL_OBJECTS, &entry, &exist) !=
        CT_SUCCESS) {
        return CT_SUCCESS;
    }

    if (!exist) {
        return CT_SUCCESS;
    }

    if (dc_open_user_by_id(KNL_SESSION(stmt), entry->desc.uid, &dc_user) != CT_SUCCESS) {
        return CT_SUCCESS;
    }

    cm_reset_error();
    *obj_type = OBJ_TYPE_PROCEDURE;
    cm_str2text(dc_user->desc.name, schema);
    cm_str2text(entry->desc.name, objname);
    switch (entry->desc.type) {
        case PL_PROCEDURE:
        case PL_SYS_PACKAGE:
            return sql_copy_str(stmt->context, "procedure", type_name);
        case PL_FUNCTION:
            return sql_copy_str(stmt->context, "function", type_name);
        case PL_PACKAGE_SPEC:
            return sql_copy_str(stmt->context, "package", type_name);
        case PL_TYPE_SPEC:
            return sql_copy_str(stmt->context, "type", type_name);
        default:
            break;
    }

    return CT_SUCCESS;
}

status_t sql_parse_directory_info(sql_stmt_t *stmt, text_t *schema, object_type_t *obj_type, text_t *type_name)
{
    *obj_type = OBJ_TYPE_DIRECTORY;
    CT_RETURN_IFERR(sql_copy_str(stmt->context, "SYS", schema));
    CT_RETURN_IFERR(sql_copy_str(stmt->context, "DIRECTORY", type_name));
    return CT_SUCCESS;
}

static void sql_set_error_for_object(sql_stmt_t *stmt, object_type_t *expected_objtype, text_t *schema, text_t *objname)
{
    switch (*expected_objtype) {
        case OBJ_TYPE_TABLE:
            CT_THROW_ERROR(ERR_USER_OBJECT_NOT_EXISTS, "table", T2S(schema), T2S_EX(objname));
            break;
        case OBJ_TYPE_VIEW:
            CT_THROW_ERROR(ERR_USER_OBJECT_NOT_EXISTS, "view", T2S(schema), T2S_EX(objname));
            break;
        case OBJ_TYPE_SEQUENCE:
            CT_THROW_ERROR(ERR_USER_OBJECT_NOT_EXISTS, "sequence", T2S(schema), T2S_EX(objname));
            break;
        case OBJ_TYPE_PROCEDURE:
            CT_THROW_ERROR(ERR_USER_OBJECT_NOT_EXISTS, "procedure", T2S(schema), T2S_EX(objname));
            break;
        case OBJ_TYPE_PACKAGE_SPEC:
            CT_THROW_ERROR(ERR_USER_OBJECT_NOT_EXISTS, "package", T2S(schema), T2S_EX(objname));
            break;
        case OBJ_TYPE_FUNCTION:
            CT_THROW_ERROR(ERR_USER_OBJECT_NOT_EXISTS, "function", T2S(schema), T2S_EX(objname));
            break;
        case OBJ_TYPE_DIRECTORY:
            CT_THROW_ERROR(ERR_USER_OBJECT_NOT_EXISTS, "directory", T2S(schema), T2S_EX(objname));
            break;
        case OBJ_TYPE_LIBRARY:
            CT_THROW_ERROR(ERR_USER_OBJECT_NOT_EXISTS, "library", T2S(schema), T2S_EX(objname));
            break;
        case OBJ_TYPE_USER:
            CT_THROW_ERROR(ERR_USER_OBJECT_NOT_EXISTS, "user", T2S(schema), T2S_EX(objname));
            break;
        default:
            CT_THROW_ERROR(ERR_USER_OBJECT_NOT_EXISTS, "object", T2S(schema), T2S_EX(objname));
            break;
    }
    return;
}

status_t sql_check_object_type(sql_stmt_t *stmt, object_type_t *expected_objtype, text_t *type_name, text_t *schema,
    text_t *objname)
{
    if (type_name->len != 0) {
        if (cm_text_str_equal_ins(type_name, "tables") && OBJ_IS_TABLE_TYPE(*expected_objtype)) {
            return CT_SUCCESS;
        }

        if ((cm_text_str_equal_ins(type_name, "views") || cm_text_str_equal_ins(type_name, "global views")) &&
            OBJ_IS_VIEW_TYPE(*expected_objtype)) {
            return CT_SUCCESS;
        }

        if (cm_text_str_equal_ins(type_name, "sequences") && OBJ_IS_SEQUENCE_TYPE(*expected_objtype)) {
            return CT_SUCCESS;
        }

        if (cm_text_str_equal_ins(type_name, "package") && OBJ_IS_PACKAGE_TYPE(*expected_objtype)) {
            return CT_SUCCESS;
        }

        if (cm_text_str_equal_ins(type_name, "procedure") && OBJ_IS_PROCEDURE_TYPE(*expected_objtype)) {
            return CT_SUCCESS;
        }

        if (cm_text_str_equal_ins(type_name, "function") && OBJ_IS_FUNCTION_TYPE(*expected_objtype)) {
            return CT_SUCCESS;
        }

        if (cm_text_str_equal_ins(type_name, "directory") && OBJ_IS_DIRECTORY_TYPE(*expected_objtype)) {
            return CT_SUCCESS;
        }
        if (cm_text_str_equal_ins(type_name, "type") && OBJ_IS_TYPE_TYPE(*expected_objtype)) {
            return CT_SUCCESS;
        }
        if (cm_text_str_equal_ins(type_name, "library") && OBJ_IS_LIBRARY_TYPE(*expected_objtype)) {
            return CT_SUCCESS;
        }

        if (cm_text_str_equal_ins(type_name, "user") && OBJ_IS_USER_TYPE(*expected_objtype)) {
            return CT_SUCCESS;
        }

        if (cm_text_str_equal_ins(type_name, "trigger") && OBJ_IS_TRIGGER_TYPE(*expected_objtype)) {
            return CT_SUCCESS;
        }
    }

    sql_check_user_priv(stmt, schema);

    sql_set_error_for_object(stmt, expected_objtype, schema, objname);

    return CT_ERROR;
}

status_t sql_parse_lib_info(sql_stmt_t *stmt, text_t *schema, text_t *objname, object_type_t *obj_type, text_t *typename)
{
    knl_session_t *session = &stmt->session->knl_session;
    bool32 exists = CT_FALSE;
    uint32 uid = 0;
    pl_library_t library;
    if (!knl_get_user_id((knl_handle_t)session, schema, &uid)) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(pl_find_library((knl_handle_t)session, uid, objname, &library, &exists));
    if (exists) {
        cm_reset_error();
        *obj_type = OBJ_TYPE_LIBRARY;
        return sql_copy_str(stmt->context, "library", typename);
    }

    return CT_SUCCESS;
}


static status_t sql_parse_expect_type(sql_stmt_t *stmt, text_t *schema, text_t *objname, bool32 owner_explict,
    object_type_t *obj_type, text_t *typename, object_type_t expected_objtype)
{
    switch (expected_objtype) {
        case OBJ_TYPE_TABLE:
        case OBJ_TYPE_VIEW:
            CT_RETURN_IFERR(sql_parse_dc_info(stmt, schema, objname, owner_explict, obj_type, typename));
            break;
        case OBJ_TYPE_SEQUENCE:
            CT_RETURN_IFERR(sql_parse_sequence_info(stmt, schema, objname, obj_type, typename));
            break;
        case OBJ_TYPE_PROCEDURE:
        case OBJ_TYPE_PACKAGE_SPEC:
        case OBJ_TYPE_FUNCTION:
            CT_RETURN_IFERR(sql_parse_pl_info(stmt, schema, objname, owner_explict, obj_type, typename));
            break;
        case OBJ_TYPE_DIRECTORY:
            CT_RETURN_IFERR(sql_parse_directory_info(stmt, schema, obj_type, typename));
            break;
        case OBJ_TYPE_LIBRARY:
            CT_RETURN_IFERR(sql_parse_lib_info(stmt, schema, objname, obj_type, typename));
            break;
        default:
            break;
    }
    return sql_check_object_type(stmt, &expected_objtype, typename, schema, objname);
}


status_t sql_parse_object_info(sql_stmt_t *stmt, lex_t *lex, text_t *schema, text_t *objname, object_type_t *obj_type,
    text_t *typename)
{
    word_t word;
    typename->len = 0;
    object_type_t expected_objtype = OBJ_TYPE_INVALID;
    bool32 owner_explict = CT_FALSE;

    if (OBJ_IS_DIRECTORY_TYPE(*obj_type)) {
        expected_objtype = OBJ_TYPE_DIRECTORY;
    } else if (OBJ_IS_USER_TYPE(*obj_type)) {
        expected_objtype = OBJ_TYPE_USER;
    } else {
        CT_RETURN_IFERR(sql_try_parse_expected_object_type(lex, &expected_objtype));
    }

    CT_RETURN_IFERR(lex_expected_fetch_variant(lex, &word));
    CT_RETURN_IFERR(sql_convert_object_name(stmt, &word, schema, &owner_explict, objname));

    if (OBJ_IS_INVALID_TYPE(expected_objtype)) {
        CT_RETURN_IFERR(sql_parse_dc_info(stmt, schema, objname, owner_explict, obj_type, typename));
        CT_RETSUC_IFTRUE(typename->len != 0);

        CT_RETURN_IFERR(sql_parse_sequence_info(stmt, schema, objname, obj_type, typename));
        CT_RETSUC_IFTRUE(typename->len != 0);

        CT_RETURN_IFERR(sql_parse_pl_info(stmt, schema, objname, owner_explict, obj_type, typename));
        CT_RETSUC_IFTRUE(typename->len != 0);

        CT_RETURN_IFERR(sql_parse_lib_info(stmt, schema, objname, obj_type, typename));
        CT_RETSUC_IFTRUE(typename->len != 0);
    } else {
        return sql_parse_expect_type(stmt, schema, objname, owner_explict, obj_type, typename, expected_objtype);
    }
    sql_check_user_priv(stmt, schema);
    int32 code = cm_get_error_code();
    if (code != ERR_INSUFFICIENT_PRIV) {
        cm_reset_error();
        CT_THROW_ERROR(ERR_USER_OBJECT_NOT_EXISTS, "object", T2S(schema), T2S_EX(objname));
    }
    return CT_ERROR;
}

status_t sql_parse_user_priv_info(sql_stmt_t *stmt, lex_t *lex, text_t *objname, text_t *typename)
{
    word_t word;
    knl_session_t *session = &stmt->session->knl_session;
    uint32 uid = 0;
    text_t schema;

    CT_RETURN_IFERR(lex_expected_fetch_variant(lex, &word));
    CT_RETURN_IFERR(sql_convert_object_name(stmt, &word, &schema, NULL, objname));
    if (!knl_get_user_id((knl_handle_t)session, objname, &uid)) {
        CT_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(objname));
        return CT_ERROR;
    }
    CT_RETURN_IFERR(sql_copy_str(stmt->context, "USER", typename));
    return CT_SUCCESS;
}

status_t sql_parse_grant_objprivs_def(sql_stmt_t *stmt, lex_t *lex, knl_grant_def_t *def)
{
    if (OBJ_IS_USER_TYPE(def->objtype)) {
        CT_RETURN_IFERR(sql_parse_user_priv_info(stmt, lex, &def->objname, &def->type_name));
    } else {
        CT_RETURN_IFERR(sql_parse_object_info(stmt, lex, &def->schema, &def->objname, &def->objtype, &def->type_name));
    }
    return lex_expected_fetch_word(lex, "TO");
}

status_t sql_parse_revoke_objprivs_def(sql_stmt_t *stmt, lex_t *lex, knl_revoke_def_t *def)
{
    if (OBJ_IS_USER_TYPE(def->objtype)) {
        CT_RETURN_IFERR(sql_parse_user_priv_info(stmt, lex, &def->objname, &def->type_name));
    } else {
        CT_RETURN_IFERR(sql_parse_object_info(stmt, lex, &def->schema, &def->objname, &def->objtype, &def->type_name));
    }
    return lex_expected_fetch_word(lex, "FROM");
}

status_t sql_check_dir_priv(galist_t *privs, bool32 *dire_priv)
{
    bool32 is_only_dire = CT_TRUE;
    knl_priv_def_t *priv_def = NULL;

    *dire_priv = CT_FALSE;
    for (uint32 i = 0; i < privs->count; i++) {
        priv_def = cm_galist_get(privs, i);
        if (priv_def->priv_id != CT_PRIV_DIRE_EXECUTE && priv_def->priv_id != CT_PRIV_DIRE_WRITE &&
            priv_def->priv_id != CT_PRIV_DIRE_READ) {
            is_only_dire = CT_FALSE; // privilege on directory can not be grant with other privilege
        } else {
            *dire_priv = CT_TRUE;
        }
    }

    if (*dire_priv && !is_only_dire) {
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "invalid privilege on directory");
        return CT_ERROR;
    } else {
        return CT_SUCCESS;
    }
}

status_t sql_check_user_privileges(galist_t *privs)
{
    knl_priv_def_t *priv_def = cm_galist_get(privs, 0);

    if (privs->count != 1 || priv_def->priv_id != CT_PRIV_INHERIT_PRIVILEGES) {
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "invalid privilege on user");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}


status_t sql_parse_revoke_cascade_option(lex_t *lex, knl_revoke_def_t *def)
{
    if (def->priv_type == PRIV_TYPE_SYS_PRIV) {
        CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "expected end but CASCADE found");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(lex_expected_fetch_word(lex, "CONSTRAINTS"));
    CT_RETURN_IFERR(lex_expected_end(lex));

    def->cascade_opt = 1;
    return CT_SUCCESS;
}


status_t sql_parse_grant_option_def(lex_t *lex, knl_grant_def_t *def, word_t *word)
{
    uint32 i;
    knl_holders_def_t *grantee = NULL;

    /* with grant option ? */
    CT_RETURN_IFERR(lex_expected_fetch_word(lex, "GRANT"));
    CT_RETURN_IFERR(lex_expected_fetch_word(lex, "OPTION"));
    CT_RETURN_IFERR(lex_expected_end(lex));

    for (i = 0; i < def->grantees.count; i++) {
        grantee = cm_galist_get(&def->grantees, i);
        if (grantee->type == TYPE_ROLE) {
            CT_SRC_THROW_ERROR_EX(word->loc, ERR_SQL_SYNTAX_ERROR, "cannot GRANT to a role WITH GRANT OPTION");
            return CT_ERROR;
        }
    }

    def->grant_opt = 1;
    return CT_SUCCESS;
}

status_t sql_parse_holder_type(sql_stmt_t *stmt, word_t *word, knl_holders_def_t *holder)
{
    uint32 id;

    if (knl_get_user_id(&stmt->session->knl_session, &holder->name, &id)) {
        holder->type = TYPE_USER;
        return CT_SUCCESS;
    }

    if (knl_get_role_id(&stmt->session->knl_session, &holder->name, &id)) {
        holder->type = TYPE_ROLE;
        return CT_SUCCESS;
    }

    CT_SRC_THROW_ERROR_EX(word->loc, ERR_SQL_SYNTAX_ERROR, "user or role '%s' does not exist", T2S(&holder->name));
    return CT_ERROR;
}
bool32 sql_parse_holder_no_prefix_tenant(sql_stmt_t *stmt, word_t *word)
{
    uint32 id;
    text_t public_user = { PUBLIC_USER, (uint32)strlen(PUBLIC_USER) };
    if (knl_get_role_id(&stmt->session->knl_session, &word->text.value, &id)) {
        return CT_TRUE;
    }
    if (cm_text_equal_ins(&word->text.value, &public_user)) {
        return CT_TRUE;
    }
    return CT_FALSE;
}
status_t sql_parse_holder_check_name(sql_stmt_t *stmt, galist_t *list, word_t *word, sql_priv_check_t *priv_check,
    text_t *name)
{
    sql_copy_func_t sql_copy_func;
    if (IS_COMPATIBLE_MYSQL_INST) {
        sql_copy_func = sql_copy_name_cs;
    } else {
        sql_copy_func = sql_copy_name;
    }

    if (sql_parse_holder_no_prefix_tenant(stmt, word)) {
        sql_copy_name(stmt->context, &word->text.value, name);
    } else {
        CT_RETURN_IFERR(sql_copy_prefix_tenant(stmt, (text_t *)&word->text, name, sql_copy_func));
    }

    if (stmt->context->type == CTSQL_TYPE_REVOKE &&
        (cm_text_str_equal_ins(name, DBA_ROLE) || (cm_text_str_equal_ins(name, SYS_USER_NAME) &&
        priv_check->priv_type != PRIV_TYPE_OBJ_PRIV && priv_check->priv_type != PRIV_TYPE_USER_PRIV))) {
        CT_THROW_ERROR(ERR_INVALID_REVOKEE, T2S_CASE(name, 0));
        return CT_ERROR;
    }

    return sql_check_duplicate_holders(list, name);
}

status_t sql_parse_holder(sql_stmt_t *stmt, galist_t *list, word_t *word, sql_priv_check_t *priv_check)
{
    text_t name;
    knl_holders_def_t *holder = NULL;
    status_t ret, ret_ck;

    CT_RETURN_IFERR(sql_parse_holder_check_name(stmt, list, word, priv_check, &name));

    CT_RETURN_IFERR(cm_galist_new(list, sizeof(knl_holders_def_t), (pointer_t *)&holder));

    holder->name = name;
    ret = sql_parse_holder_type(stmt, word, holder);
    if (ret == CT_ERROR) {
        ret_ck = sql_check_grant_revoke_priv(stmt, priv_check);
        if (ret_ck == CT_ERROR) {
            cm_reset_error();
            CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
        }
    }
    return ret;
}

status_t sql_parse_revokee_def(sql_stmt_t *stmt, lex_t *lex, knl_revoke_def_t *revoke_def)
{
    word_t word;
    status_t status = CT_SUCCESS;
    bool32 revokee_expect = CT_TRUE;

    CT_RETURN_IFERR(lex_fetch(lex, &word));

    sql_priv_check_t priv_check;
    priv_check.objowner = &revoke_def->schema;
    priv_check.objname = &revoke_def->objname;
    priv_check.priv_list = &revoke_def->privs;
    priv_check.objtype = revoke_def->objtype;
    priv_check.priv_type = revoke_def->priv_type;

    while (word.type != WORD_TYPE_EOF && word.id != KEY_WORD_CASCADE) {
        /* got a revokee */
        if (!IS_SPEC_CHAR(&word, ',')) {
            if (revokee_expect) {
                status = sql_parse_holder(stmt, &revoke_def->revokees, &word, &priv_check);
                CT_RETURN_IFERR(status);
                revokee_expect = CT_FALSE;
            } else {
                CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, ", expected, but %s found", T2S(&word.text.value));
                return CT_ERROR;
            }
        } else {
            if (revokee_expect) {
                CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "revokee expected, but , found");
                return CT_ERROR;
            } else {
                revokee_expect = CT_TRUE;
            }
        }

        CT_RETURN_IFERR(lex_fetch(lex, &word));
    }

    if (revokee_expect) {
        CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "revokee expected, but %s found", T2S(&word.text.value));
        return CT_ERROR;
    }

    if (word.id == KEY_WORD_CASCADE) {
        status = sql_parse_revoke_cascade_option(lex, revoke_def);
    }

    return status;
}

status_t sql_parse_admin_option_def(lex_t *lex, knl_grant_def_t *def)
{
    /* with admin option ? */
    CT_RETURN_IFERR(lex_expected_fetch_word(lex, "ADMIN"));
    CT_RETURN_IFERR(lex_expected_fetch_word(lex, "OPTION"));
    CT_RETURN_IFERR(lex_expected_end(lex));
    def->admin_opt = 1;
    return CT_SUCCESS;
}


status_t sql_parse_with_clause(lex_t *lex, knl_grant_def_t *def, word_t *word)
{
    if (def->priv_type == PRIV_TYPE_SYS_PRIV) {
        return sql_parse_admin_option_def(lex, def);
    } else if (def->priv_type == PRIV_TYPE_OBJ_PRIV) {
        return sql_parse_grant_option_def(lex, def, word);
    } else if (def->priv_type == PRIV_TYPE_USER_PRIV) {
        CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "cannot GRANT to a user privilege WITH GRANT OPTION now");
        return CT_ERROR;
    }

    return CT_ERROR;
}

status_t sql_parse_grantee_def(sql_stmt_t *stmt, lex_t *lex, knl_grant_def_t *grant_def)
{
    word_t word;
    status_t status;
    bool32 grantee_expect = CT_TRUE;

    grant_def->grant_opt = 0;
    grant_def->admin_opt = 0;

    CT_RETURN_IFERR(lex_fetch(lex, &word));

    sql_priv_check_t priv_check;
    priv_check.objowner = &grant_def->schema;
    priv_check.objname = &grant_def->objname;
    priv_check.priv_list = &grant_def->privs;
    priv_check.objtype = grant_def->objtype;
    priv_check.priv_type = grant_def->priv_type;

    while (word.type != WORD_TYPE_EOF && word.id != KEY_WORD_WITH) {
        /* got a grantee */
        if (!IS_SPEC_CHAR(&word, ',')) {
            if (grantee_expect) {
                status = sql_parse_holder(stmt, &grant_def->grantees, &word, &priv_check);
                CT_RETURN_IFERR(status);
                grantee_expect = CT_FALSE;
            } else {
                CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, ", expected, but %s found", T2S(&word.text.value));
                return CT_ERROR;
            }
        } else {
            if (grantee_expect) {
                CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "grantee expected, but , found");
                return CT_ERROR;
            } else {
                grantee_expect = CT_TRUE;
            }
        }

        CT_RETURN_IFERR(lex_fetch(lex, &word));
    }

    if (grantee_expect) {
        CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "grantee expected, but %s found", T2S(&word.text.value));
        return CT_ERROR;
    }

    if (word.id == KEY_WORD_WITH) {
        status = sql_parse_with_clause(lex, grant_def, &word);
    }

    return status;
}

status_t sql_parse_proc_def(sql_stmt_t *stmt, lex_t *lex, galist_t *program_units, uint32 wid)
{
    status_t status;
    word_t word;
    knl_program_unit_def *program = NULL;

    lex->flags |= LEX_WITH_OWNER;

    for (;;) {
        status = lex_fetch(lex, &word);
        CT_RETURN_IFERR(status);

        if (word.type == WORD_TYPE_EOF) {
            return CT_SUCCESS;
        }

        if (word.id == KEY_WORD_FUNCTION || word.id == KEY_WORD_PROCEDURE) {
            status = lex_expected_fetch(lex, &word);
            CT_RETURN_IFERR(status);

            status = cm_galist_new(program_units, sizeof(knl_program_unit_def), (pointer_t *)&program);
            CT_RETURN_IFERR(status);

            status = sql_convert_object_name(stmt, &word, &program->schema, NULL, &program->prog_name);
            CT_RETURN_IFERR(status);

            /* check first if the function/procedure exists by name */
            program->prog_type = (word.id == KEY_WORD_FUNCTION ? PROGRAM_TYPE_FUNCTION : PROGRAM_TYPE_PROCEDURE);
        } else {
            CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "function or procedure expect, but %s found",
                T2S((text_t *)&word.text));
            return CT_ERROR;
        }
    }
}

status_t sql_check_obj_owner(lex_t *lex, const text_t *curr_user, galist_t *holders)
{
    uint32 i;
    knl_holders_def_t *holder = NULL;

    for (i = 0; i < holders->count; i++) {
        holder = cm_galist_get(holders, i);
        if (cm_text_equal_ins(curr_user, &holder->name)) {
            CT_SRC_THROW_ERROR(LEX_LOC, ERR_PRI_GRANT_SELF);
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t sql_check_obj_schema(lex_t *lex, text_t *schema, galist_t *holders)
{
    uint32 i;
    knl_holders_def_t *holder = NULL;

    for (i = 0; i < holders->count; i++) {
        holder = cm_galist_get(holders, i);
        if (cm_text_equal_ins(schema, &holder->name)) {
            CT_SRC_THROW_ERROR(LEX_LOC, ERR_REVOKE_FROM_OBJ_HOLDERS);
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

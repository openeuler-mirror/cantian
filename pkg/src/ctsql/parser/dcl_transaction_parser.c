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
 * dcl_transaction_parser.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser/dcl_transaction_parser.c
 *
 * -------------------------------------------------------------------------
 */
#include "dcl_transaction_parser.h"
#include "srv_instance.h"


#ifdef __cplusplus
extern "C" {
#endif

static status_t sql_parse_gtid(sql_stmt_t *stmt, const text_t *txt_xid)
{
    text_t fmt_id;
    text_t gtrid;
    text_t bqual;
    text_t part;
    xa_xid_t *xid = NULL;
    uint32 xid_len;

    cm_split_text(txt_xid, '.', '\0', &fmt_id, &part);
    cm_split_text(&part, '.', '\0', &gtrid, &bqual);

    if (fmt_id.len == 0 || bqual.len > CT_MAX_XA_BASE16_BQUAL_LEN || gtrid.len > CT_MAX_XA_BASE16_GTRID_LEN ||
        gtrid.len == 0) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "invalid XID : %s", T2S(txt_xid));
        return CT_ERROR;
    }

    xid_len = (uint32)(KNL_XA_XID_DATA_OFFSET + gtrid.len + bqual.len);
    if (sql_alloc_mem(stmt->context, xid_len, (void **)&xid) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cm_text2uint64_ex(&fmt_id, &xid->fmt_id) != NERR_SUCCESS) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "invalid format ID : %s", T2S(&fmt_id));
        return CT_ERROR;
    }

    // check whether the string is valid base64 string
    if (cm_chk_and_upper_base16(&gtrid) != CT_SUCCESS) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "invalid global transaction ID : %s", T2S(&gtrid));
        return CT_ERROR;
    }

    if (memcpy_s(xid->data, xid_len - KNL_XA_XID_DATA_OFFSET, gtrid.str, (size_t)gtrid.len) != EOK) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "invalid global transaction ID length: %u", gtrid.len);
        return CT_ERROR;
    }
    xid->gtrid_len = (uint8)gtrid.len;

    if (bqual.len == 0) {
        xid->bqual_len = 0;
        stmt->context->entry = xid;
        return CT_SUCCESS;
    }

    if (cm_chk_and_upper_base16(&bqual) != CT_SUCCESS) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "invalid transaction branch ID : %s", T2S(&bqual));
        return CT_ERROR;
    }
    if (memcpy_s(xid->data + gtrid.len, xid_len - KNL_XA_XID_DATA_OFFSET - gtrid.len, bqual.str, (size_t)bqual.len) !=
        EOK) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "invalid transaction branch ID length : %u", bqual.len);
        return CT_ERROR;
    }
    xid->bqual_len = (uint8)bqual.len;

    stmt->context->entry = xid;
    return CT_SUCCESS;
}


status_t sql_parse_commit_phase1(sql_stmt_t *stmt)
{
    word_t word;
    lex_t *lex = stmt->session->lex;

    stmt->session->sql_audit.audit_type = SQL_AUDIT_DML;
    stmt->context->type = CTSQL_TYPE_COMMIT_PHASE1;

    if (IS_COORDINATOR && IS_APP_CONN(stmt->session)) {
        CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "prepare transaction on coordinator");
        return CT_ERROR;
    }

    if (lex_expected_fetch_word(lex, "TRANSACTION") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch_string(lex, &word) != CT_SUCCESS) {
        cm_try_set_error_loc(word.text.loc);
        return CT_ERROR;
    }

    if (sql_parse_gtid(stmt, &word.text.value) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return lex_expected_end(lex);
}

status_t sql_parse_commit_phase2(sql_stmt_t *stmt, word_t *word)
{
    lex_t *lex = stmt->session->lex;

    stmt->context->type = CTSQL_TYPE_COMMIT_PHASE2;

    if (IS_COORDINATOR && IS_APP_CONN(stmt->session)) {
        CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "commit prepared on coordinator");
        return CT_ERROR;
    }

    if (lex_expected_fetch_string(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_parse_gtid(stmt, &word->text.value) != CT_SUCCESS) {
        cm_try_set_error_loc(word->text.loc);
        return CT_ERROR;
    }

    return lex_expected_end(lex);
}

static status_t sql_parse_ltid(text_t *value, knl_xid_t *xid)
{
    text_t seg_id;
    text_t part;
    text_t slot;
    text_t xnum;

    cm_split_text(value, '.', '\0', &seg_id, &part);
    cm_split_text(&part, '.', '\0', &slot, &xnum);

    if (seg_id.len == 0 || cm_text2uint16(&seg_id, &xid->seg_id) != CT_SUCCESS) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "invalid seg_id = %s", T2S(&seg_id));
        return CT_ERROR;
    }

    if (slot.len == 0 || cm_text2uint16(&slot, &xid->slot) != CT_SUCCESS) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "invalid slot = %s", T2S(&slot));
        return CT_ERROR;
    }

    if (xnum.len == 0 || cm_text2uint32(&xnum, &xid->xnum) != CT_SUCCESS) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "invalid xnum = %s", T2S(&xnum));
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t sql_parse_commit_force(sql_stmt_t *stmt, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    knl_xid_t *xid = NULL;

    if (lex_expected_fetch_string(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_alloc_mem(stmt->context, sizeof(knl_xid_t), (void **)&xid) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_parse_ltid(&word->text.value, xid) != CT_SUCCESS) {
        cm_try_set_error_loc(word->text.loc);
        return CT_ERROR;
    }

    stmt->context->entry = xid;

    return lex_expected_end(lex);
}

status_t sql_parse_commit(sql_stmt_t *stmt)
{
    status_t status;
    word_t word;
    lex_t *lex = stmt->session->lex;

    stmt->session->sql_audit.audit_type = SQL_AUDIT_DML;

    stmt->context->entry = NULL;
    stmt->context->type = CTSQL_TYPE_COMMIT;

    if (lex_fetch(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word.id == KEY_WORD_TRANSACTION) {
        return lex_expected_end(lex);
    }

    if (word.type == WORD_TYPE_EOF) {
        return CT_SUCCESS;
    }

    switch ((key_wid_t)word.id) {
        case KEY_WORD_PREPARED:
            status = sql_parse_commit_phase2(stmt, &word);
            break;
        case KEY_WORD_FORCE:
#ifdef Z_SHARDING
            if (IS_COORDINATOR) {
                CT_THROW_ERROR_EX(ERR_CAPABILITY_NOT_SUPPORT, "COMMIT FORCE xid on coordinator");
                status = CT_ERROR;
                break;
            }
#endif
            status = sql_parse_commit_force(stmt, &word);
            break;
        default:
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word expected but %s found", W2S(&word));
            status = CT_ERROR;
            break;
    }

    return status;
}

static status_t sql_parse_rollback_phase2(sql_stmt_t *stmt)
{
    word_t word;
    lex_t *lex = stmt->session->lex;

    stmt->context->type = CTSQL_TYPE_ROLLBACK_PHASE2;

    if (IS_COORDINATOR && IS_APP_CONN(stmt->session)) {
        CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "rollback prepared on coordinator");
        return CT_ERROR;
    }

    if (lex_expected_fetch_string(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_parse_gtid(stmt, &word.text.value) != CT_SUCCESS) {
        cm_try_set_error_loc(word.text.loc);
        return CT_ERROR;
    }

    return lex_expected_end(lex);
}

status_t sql_parse_rollback(sql_stmt_t *stmt)
{
    status_t status;
    word_t word;
    text_t *name = NULL;
    lex_t *lex = stmt->session->lex;
    bool32 is_transaction;
    bool32 result = CT_FALSE;

    stmt->session->sql_audit.audit_type = SQL_AUDIT_DML;

    status = lex_fetch(lex, &word);
    CT_RETURN_IFERR(status);

    is_transaction = CT_FALSE;

    // rollback transaction will do same with rollback.
    if (word.id == KEY_WORD_TRANSACTION) {
        status = lex_fetch(lex, &word);
        CT_RETURN_IFERR(status);
        is_transaction = CT_TRUE;
    } else if (word.id == KEY_WORD_PREPARED) {
        return sql_parse_rollback_phase2(stmt);
    }

    if (word.type == WORD_TYPE_EOF) {
        stmt->context->entry = NULL;
        stmt->context->type = CTSQL_TYPE_ROLLBACK;
        return CT_SUCCESS;
    } else if (word.id != KEY_WORD_TO) {
        if (is_transaction) {
            CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "to expected but %s found", T2S(&word.text.value));
        } else {
            CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "prepared or to expected but %s found",
                T2S(&word.text.value));
        }
        return CT_ERROR;
    }

    stmt->context->type = CTSQL_TYPE_ROLLBACK_TO;

    status = sql_alloc_mem(stmt->context, sizeof(text_t), (void **)&name);
    CT_RETURN_IFERR(status);

    stmt->context->entry = name;

    status = lex_try_fetch(lex, "SAVEPOINT", &result);
    CT_RETURN_IFERR(status);

    status = lex_expected_fetch_variant(lex, &word);
    CT_RETURN_IFERR(status);

    status = sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, name);
    CT_RETURN_IFERR(status);

    return lex_expected_end(lex);
}

static status_t sql_parse_set_trans(sql_stmt_t *stmt)
{
    word_t word;
    lex_t *lex = stmt->session->lex;
    isolation_level_t *isolevel = NULL;

    stmt->context->type = CTSQL_TYPE_SET_TRANS;

    if (sql_alloc_mem(stmt->context, sizeof(isolation_level_t), (void **)&isolevel) != CT_SUCCESS) {
        return CT_ERROR;
    }

    stmt->context->entry = isolevel;

    if (lex_expected_fetch_word(lex, "ISOLATION") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch_word(lex, "LEVEL") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_fetch(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word.id == KEY_WORD_SERIALIZABLE) {
        *isolevel = ISOLATION_SERIALIZABLE;
    } else if (word.id == KEY_WORD_READ) {
        if (lex_expected_fetch_word(lex, "COMMITTED") != CT_SUCCESS) {
            return CT_ERROR;
        }
        *isolevel = ISOLATION_READ_COMMITTED;
    } else if (word.id == KEY_WORD_CURRENT) {
        if (lex_expected_fetch_word(lex, "COMMITTED") != CT_SUCCESS) {
            return CT_ERROR;
        }
        *isolevel = ISOLATION_CURR_COMMITTED;
    } else {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "syntax error at or near \"%s\"",
            T2S(&word.text.value));
        return CT_ERROR;
    }

    return lex_expected_end(lex);
}

status_t sql_parse_set(sql_stmt_t *stmt)
{
    word_t word;
    status_t status;
    if (lex_expected_fetch(stmt->session->lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    switch ((key_wid_t)word.id) {
        case KEY_WORD_TRANSACTION:
            status = sql_parse_set_trans(stmt);
            break;

        default:
            CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "key word expected");
            status = CT_ERROR;
            break;
    }
    return status;
}

status_t sql_parse_release_savepoint(sql_stmt_t *stmt)
{
    word_t word;
    text_t *name = NULL;
    lex_t *lex = stmt->session->lex;

    stmt->context->type = CTSQL_TYPE_RELEASE_SAVEPOINT;

    if (lex_expected_fetch_word(lex, "SAVEPOINT") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_alloc_mem(stmt->context, sizeof(text_t), (void **)&name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    stmt->context->entry = name;

    if (lex_expected_fetch_variant(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return lex_expected_end(lex);
}

status_t sql_parse_savepoint(sql_stmt_t *stmt)
{
    word_t word;
    text_t *name = NULL;
    lex_t *lex = stmt->session->lex;

    stmt->context->type = CTSQL_TYPE_SAVEPOINT;

    if (sql_alloc_mem(stmt->context, sizeof(text_t), (void **)&name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    stmt->context->entry = name;

    if (lex_expected_fetch_variant(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return lex_expected_end(lex);
}

#ifdef __cplusplus
}
#endif
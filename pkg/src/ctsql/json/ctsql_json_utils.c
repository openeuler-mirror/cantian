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
 * ctsql_json_utils.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/json/ctsql_json_utils.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_defs.h"
#include "cm_error.h"
#include "cm_decimal.h"
#include "cm_lex.h"
#include "ctsql_func.h"

#include "ctsql_json_utils.h"
#include "ctsql_json.h"


typedef enum chr_key {
    CHAR_KEY_QUOTATION = '"',
    CHAR_KEY_RSTASH = '\\',
    CHAR_KEY_LSTASH = '/',
    CHAR_KEY_BACKS = 'b',
    CHAR_KEY_FORMF = 'f',
    CHAR_KEY_WRAP = 'n',
    CHAR_KEY_RETURN = 'r',
    CHAR_KEY_TABS = 't',

    CHAR_FUN_BACKSPACE = '\b',
    CHAR_FUN_FORMFEED = '\f',
    CHAR_FUN_WRAP = '\n',
    CHAR_FUN_RETURN = '\r',
    CHAR_FUN_TABS = '\t'
} ct_chr_keywords_t;

char *g_json_type_str[] = {
    "null", "boolean", "string", "number", "array", "object"
};

// ============================================================================
// JSON MEMORY MANAGEMENT FOR:
//     - JSON SQL FUNCTION ARGUMENTS EVALUTION
//     - JSON PARSE
static status_t json_flatten_lob_knl(json_assist_t *json_ass, variant_t *var)
{
    knl_handle_t loc = (knl_handle_t)var->v_lob.knl_lob.bytes;
    char *lob_buf = NULL;
    uint32 lob_size = knl_lob_size(loc);
    uint32 remain_size = lob_size;
    uint32 read_size = 0;
    uint32 offset = 0;

    JSON_CHECK_MAX_SIZE(lob_size);
    if (lob_size == 0) {
        var->is_null = CT_TRUE;
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(JSON_ALLOC(json_ass, lob_size, (void **)&lob_buf));
    while (remain_size > 0) {
        CT_RETURN_IFERR(
            knl_read_lob(json_ass->stmt->session, loc, offset, lob_buf + offset, remain_size, &read_size, NULL));
        remain_size -= read_size;
        offset += read_size;
    }

    var->v_text.str = lob_buf;
    var->v_text.len = lob_size;
    var->type = CT_TYPE_VARCHAR;

    return CT_SUCCESS;
}

static status_t json_flatten_lob_vm(json_assist_t *json_ass, variant_t *var)
{
    sql_stmt_t *stmt = json_ass->stmt;
    char *lob_buffer = NULL;
    uint32 lob_size = var->v_lob.vm_lob.size;
    uint32 remain_size = lob_size;
    uint32 offset = 0;
    uint32 v_mid;
    errno_t ret;

    JSON_CHECK_MAX_SIZE(lob_size);
    if (lob_size == 0) {
        var->is_null = CT_TRUE;
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(JSON_ALLOC(json_ass, lob_size, (void **)&lob_buffer));

    v_mid = var->v_lob.vm_lob.entry_vmid;
    while (remain_size > 0) {
        uint32 copy_size;
        vm_page_t *page = NULL;

        CT_RETURN_IFERR(vm_open(stmt->session, stmt->mtrl.pool, v_mid, &page));

        copy_size = remain_size > CT_VMEM_PAGE_SIZE ? CT_VMEM_PAGE_SIZE : remain_size;
        ret = memcpy_s(lob_buffer + offset, copy_size, page->data, copy_size);
        if (ret != EOK) {
            vm_close(stmt->session, stmt->mtrl.pool, v_mid, VM_ENQUE_HEAD);
            CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
            return CT_ERROR;
        }
        remain_size -= copy_size;
        offset += copy_size;

        vm_close(stmt->session, stmt->mtrl.pool, v_mid, VM_ENQUE_HEAD);
        v_mid = vm_get_ctrl(stmt->mtrl.pool, v_mid)->sort_next;
    }

    var->v_text.str = lob_buffer;
    var->v_text.len = lob_size;
    var->type = CT_TYPE_VARCHAR;

    return CT_SUCCESS;
}

static status_t json_flatten_lob_normal(json_assist_t *json_ass, variant_t *var)
{
    text_t text;
    uint32 lob_size = var->v_lob.normal_lob.value.len;

    if (lob_size == 0) {
        var->is_null = CT_TRUE;
        return CT_SUCCESS;
    }

    text = var->v_lob.normal_lob.value;
    var->v_text = text;
    var->type = CT_TYPE_VARCHAR;

    return CT_SUCCESS;
}

// @var: INOUT, var->v_text AS flattened continuous memory
static status_t json_flatten_lob(json_assist_t *json_ass, variant_t *var)
{
    switch (var->v_lob.type) {
        case CT_LOB_FROM_KERNEL:
            return json_flatten_lob_knl(json_ass, var);
        case CT_LOB_FROM_VMPOOL:
            return json_flatten_lob_vm(json_ass, var);
        case CT_LOB_FROM_NORMAL:
            return json_flatten_lob_normal(json_ass, var);
        default:
            CT_THROW_ERROR(ERR_UNKNOWN_LOB_TYPE, "do json flatten lob");
            return CT_ERROR;
    }
}

status_t json_item_array_init(json_assist_t *json_ass, galist_t **galist, json_mem_type_t type)
{
    if (type == JSON_MEM_LARGE_POOL_SORT) {
        CT_RETURN_IFERR(JSON_ALLOC_LARGE(&json_ass->jsa, sizeof(galist_t), (void **)galist));
        cm_galist_init(*galist, &json_ass->jsa, (ga_alloc_func_t)(JSON_ALLOC_LARGE));
    } else if (type == JSON_MEM_LARGE_POOL || json_ass->vmc == NULL) {
        CT_RETURN_IFERR(JSON_ALLOC_LARGE(&json_ass->jta, sizeof(galist_t), (void **)galist));
        cm_galist_init(*galist, &json_ass->jta, (ga_alloc_func_t)(JSON_ALLOC_LARGE));
    } else {
        CT_RETURN_IFERR(vmc_alloc(json_ass->vmc, sizeof(galist_t), (void **)galist));
        cm_galist_init(*galist, json_ass->vmc, vmc_alloc);
    }
    return CT_SUCCESS;
}

// @result: set to null if arg null
// @var   : var to eval arg
//        : CAUTION!!!: var->v_text keeps flattened continuous memory
// this func is used in loading clob or string data from value-expr into a continuous memory.
status_t sql_exec_json_func_arg(json_assist_t *json_ass, expr_tree_t *arg, variant_t *var, variant_t *result)
{
    sql_stmt_t *stmt = json_ass->stmt;

    CM_POINTER(arg);
    CTSQL_SAVE_STACK(stmt);
    result->is_null = CT_FALSE;
    SQL_EXEC_FUNC_ARG_EX3(arg, var, result, stmt);
    sql_keep_stack_variant(stmt, var);

    if (CT_IS_CLOB_TYPE(var->type)) {
        if (json_flatten_lob(json_ass, var) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            return CT_ERROR;
        }
    } else if (!CT_IS_STRING_TYPE(var->type)) {
        switch (var->type) {
            case CT_TYPE_INTEGER:
            case CT_TYPE_BIGINT:
            case CT_TYPE_REAL:
            case CT_TYPE_NUMBER:
            case CT_TYPE_NUMBER2:
            case CT_TYPE_BOOLEAN:
                arg->root->format_json = CT_TRUE;
                break;

            case CT_TYPE_DATE:
            case CT_TYPE_TIMESTAMP:
            case CT_TYPE_TIMESTAMP_TZ_FAKE:
            case CT_TYPE_TIMESTAMP_TZ:
            case CT_TYPE_TIMESTAMP_LTZ:
            case CT_TYPE_INTERVAL_DS:
            case CT_TYPE_INTERVAL_YM:
                arg->root->format_json = CT_FALSE;
                break;

            default:
                cm_set_error_loc(arg->loc);
                CT_THROW_ERROR(ERR_UNKNOWN_LOB_TYPE, "Input to JSON generation function has unsupported data type.");
                CTSQL_RESTORE_STACK(stmt);
                return CT_ERROR;
        }

        if (sql_var_as_string(stmt, var) != CT_SUCCESS) {
            cm_set_error_loc(arg->loc);
            CTSQL_RESTORE_STACK(stmt);
            return CT_ERROR;
        }
    }

    if (var->is_null || var->v_text.len == 0) {
        var->is_null = CT_TRUE;
        result->is_null = CT_TRUE;
        result->type = CT_TYPE_STRING;
    }
    return CT_SUCCESS;
}

// @result: set to null if arg null
// @var   : var(any type) to var(varchar type)
//        : CAUTION!!!: var->v_text keeps flattened continuous memory
// this func is used in inserting data into jsonb column, convert clob or string value into a continuous memory.
status_t sql_exec_flatten_to_varchar(json_assist_t *json_ass, variant_t *var)
{
    sql_stmt_t *stmt = json_ass->stmt;

    CTSQL_SAVE_STACK(stmt);
    sql_keep_stack_variant(stmt, var);

    if (CT_IS_CLOB_TYPE(var->type)) {
        if (json_flatten_lob(json_ass, var) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            return CT_ERROR;
        }
    } else if (!CT_IS_STRING_TYPE(var->type)) {
        CT_THROW_ERROR(ERR_UNKNOWN_LOB_TYPE, "Input to JSON generation function has unsupported data type.");
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

// ============================================================================
// JSON PARSE AND SERIALIZATION
#define JSON_CHECK_UNCOMPLETE_ESCAPE(_src, _expect_len)                        \
    do {                                                                       \
        if ((_src)->len < (_expect_len)) {                                     \
            CT_THROW_ERROR(ERR_JSON_SYNTAX_ERROR, "escapse sequence invalid"); \
        }                                                                      \
    } while (0)

void json_unicode_to_utf8(uint32 ch, uchar *utf8_str, uint32 *len)
{
    if (ch <= 0x7F) {
        utf8_str[0] = ch;
        *len = 1;
    } else if (ch <= 0x7FF) {
        utf8_str[0] = 0xC0 | ((ch >> 6) & 0x1F);
        utf8_str[1] = 0x80 | (ch & 0x3F);
        *len = 2;
    } else if (ch <= 0xFFFF) {
        utf8_str[0] = 0xE0 | ((ch >> 12) & 0x0F);
        utf8_str[1] = 0x80 | ((ch >> 6) & 0x3F);
        utf8_str[2] = 0x80 | (ch & 0x3F);
        *len = 3;
    } else {
        utf8_str[0] = 0xF0 | ((ch >> 18) & 0x07);
        utf8_str[1] = 0x80 | ((ch >> 12) & 0x3F);
        utf8_str[2] = 0x80 | ((ch >> 6) & 0x3F);
        utf8_str[3] = 0x80 | (ch & 0x3F);
        *len = 4;
    }
}

static inline status_t json_unescape_char_unicode(text_t *escaped_txt, uint32 *escaped_len, text_buf_t *unescaped_buf)
{
    text_t src = *escaped_txt;
    uint32 ch = 0;

    // for example: '\u4e2d'
    JSON_CHECK_UNCOMPLETE_ESCAPE(&src, 6);

    // skip \u
    CM_REMOVE_FIRST_N(&src, 2);
    for (int i = 0; i < 4; i++) {
        char ch_str = CM_TEXT_FIRST(&src);
        if (ch_str >= '0' && ch_str <= '9') {
            ch = (ch * 16) + (ch_str - '0');
        } else if (ch_str >= 'a' && ch_str <= 'f') {
            ch = (ch * 16) + (ch_str - 'a') + 10;
        } else if (ch_str >= 'A' && ch_str <= 'F') {
            ch = (ch * 16) + (ch_str - 'A') + 10;
        } else {
            CT_THROW_ERROR(ERR_JSON_SYNTAX_ERROR, "escapse sequence invalid");
            return CT_ERROR;
        }

        CM_REMOVE_FIRST(&src);
    }

    if (escaped_len) {
        *escaped_len = 6;
    }
    if (unescaped_buf) {
        json_unicode_to_utf8(ch, (uchar *)unescaped_buf->str, &unescaped_buf->len);
    }

    return CT_SUCCESS;
}

static inline status_t json_unescape_char_normal(text_t *escaped_txt, uint32 *escaped_len, text_buf_t *unescaped_buf)
{
    char ch_str;

    CM_ASSERT(escaped_txt->len > 1 && escaped_txt->str[0] == '\\');

    ch_str = escaped_txt->str[1];
    switch (ch_str) {
        case CHAR_KEY_QUOTATION:
        case CHAR_KEY_RSTASH:
        case CHAR_KEY_LSTASH:
            break;
        case CHAR_KEY_BACKS:
            ch_str = CHAR_FUN_BACKSPACE;
            break;
        case CHAR_KEY_FORMF:
            ch_str = CHAR_FUN_FORMFEED;
            break;
        case CHAR_KEY_WRAP:
            ch_str = CHAR_FUN_WRAP;
            break;
        case CHAR_KEY_RETURN:
            ch_str = CHAR_FUN_RETURN;
            break;
        case CHAR_KEY_TABS:
            ch_str = CHAR_FUN_TABS;
            break;
        default:
            CT_THROW_ERROR(ERR_JSON_SYNTAX_ERROR, "invalid escape in JSON data");
            return CT_ERROR;
    }

    if (escaped_len) {
        *escaped_len = 2;
    }
    if (unescaped_buf) {
        unescaped_buf->str[0] = ch_str;
        unescaped_buf->len = 1;
    }

    return CT_SUCCESS;
}

static inline status_t json_unescape_char(text_t *escaped_txt, uint32 *escaped_len, text_buf_t *unescaped_buf)
{
    CM_ASSERT(escaped_txt->len >= 1 && escaped_txt->str[0] == '\\');
    JSON_CHECK_UNCOMPLETE_ESCAPE(escaped_txt, 2);

    if (SECUREC_UNLIKELY(escaped_txt->str[1] == 'u')) {
        return json_unescape_char_unicode(escaped_txt, escaped_len, unescaped_buf);
    } else {
        return json_unescape_char_normal(escaped_txt, escaped_len, unescaped_buf);
    }
}

// json.string --> string: a\"b --> a"b
status_t json_unescape_string(text_t *src, text_buf_t *unescaped_buf)
{
    text_t escaped_txt = *src;
    uint32 escaped_len;

    unescaped_buf->value.len = 0;
    while (!CM_IS_EMPTY(&escaped_txt)) {
        if (escaped_txt.str[0] != '\\') {
            JSON_TXTBUF_APPEND_CHAR(unescaped_buf, escaped_txt.str[0]);
            escaped_txt.len--;
            escaped_txt.str++;
        } else {
#define MAX_UTF8_BYTES 4
            char bytes[MAX_UTF8_BYTES];
            text_buf_t tmp;

            CM_INIT_TEXTBUF(&tmp, MAX_UTF8_BYTES, bytes);
            CT_RETURN_IFERR(json_unescape_char(&escaped_txt, &escaped_len, &tmp));
            JSON_TXTBUF_APPEND_TEXT(unescaped_buf, &tmp.value);

            escaped_txt.len -= (uint32)escaped_len;
            escaped_txt.str += (uint32)escaped_len;
        }
    }

    return CT_SUCCESS;
}

// string --> json.string: a"b --> a\"b
status_t json_escape_string(text_t *src, text_buf_t *escaped_buf)
{
    text_t plain_txt = *src;

    escaped_buf->len = 0;
    while (!CM_IS_EMPTY(&plain_txt)) {
        switch (plain_txt.str[0]) {
            case '"':
                JSON_TXTBUF_APPEND_CHAR(escaped_buf, '\\');
                JSON_TXTBUF_APPEND_CHAR(escaped_buf, '"');
                break;
            case '\\':
                JSON_TXTBUF_APPEND_CHAR(escaped_buf, '\\');
                JSON_TXTBUF_APPEND_CHAR(escaped_buf, '\\');
                break;
            case '/':
                JSON_TXTBUF_APPEND_CHAR(escaped_buf, '\\');
                JSON_TXTBUF_APPEND_CHAR(escaped_buf, '/');
                break;
            case '\b':
                JSON_TXTBUF_APPEND_CHAR(escaped_buf, '\\');
                JSON_TXTBUF_APPEND_CHAR(escaped_buf, 'b');
                break;
            case '\f':
                JSON_TXTBUF_APPEND_CHAR(escaped_buf, '\\');
                JSON_TXTBUF_APPEND_CHAR(escaped_buf, 'f');
                break;
            case '\n':
                JSON_TXTBUF_APPEND_CHAR(escaped_buf, '\\');
                JSON_TXTBUF_APPEND_CHAR(escaped_buf, 'n');
                break;
            case '\r':
                JSON_TXTBUF_APPEND_CHAR(escaped_buf, '\\');
                JSON_TXTBUF_APPEND_CHAR(escaped_buf, 'r');
                break;
            case '\t':
                JSON_TXTBUF_APPEND_CHAR(escaped_buf, '\\');
                JSON_TXTBUF_APPEND_CHAR(escaped_buf, 't');
                break;
            default:
                if ((unsigned char)plain_txt.str[0] < 32) {
                    CT_THROW_ERROR(ERR_JSON_SYNTAX_ERROR, "character < 32 must be escaped");
                    return CT_ERROR;
                }
                JSON_TXTBUF_APPEND_CHAR(escaped_buf, plain_txt.str[0]);
        }

        plain_txt.len--;
        plain_txt.str++;
    }
    return CT_SUCCESS;
}

static inline source_location_t JSON_ERR_LOC(lex_t *lex)
{
    char *str;
    char *err_pos = (LEX_CURR(lex) == LEX_END) ? lex->text.str + lex->text.len - 1 : lex->curr_text->str;

    for (str = lex->text.str; str <= err_pos; str++) {
        if (*str == '\n') {
            lex->loc.line++;
            lex->loc.column = 1;
        } else {
            lex->loc.column++;
        }
    }
    return lex->loc;
}

#define LEX_CURR_EX(lex) (((lex)->curr_text->len == 0) ? LEX_END : (lex)->curr_text->str[0])

static inline char json_lex_move(lex_t *curr_lex)
{
    if (SECUREC_UNLIKELY(curr_lex->curr_text->len == 0)) {
        return LEX_END;
    }

    curr_lex->curr_text->str++;
    curr_lex->curr_text->len--;
    return LEX_CURR(curr_lex);
}

static inline char json_lex_move_n(lex_t *lex, int n)
{
    int cnt = n;
    CM_ASSERT((int64)(lex->curr_text->len) >= (int64)n);
    while (cnt-- > 0) {
        lex->curr_text->str++;
        lex->curr_text->len--;
    }
    return LEX_CURR(lex);
}

static inline bool32 json_is_blank(uchar c)
{
    if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
        return CT_TRUE;
    }
    return CT_FALSE;
}

static inline void json_lex_trim(sql_text_t *text)
{
    uchar chr;
    while (text->len > 0) {
        chr = (uchar)CM_TEXT_BEGIN(text);
        if (!json_is_blank(chr)) {
            break;
        }
        text->str++;
        text->len--;
    }
}

static inline char json_lex(lex_t *lex)
{
    (void)json_lex_move(lex);
    (void)json_lex_trim(lex->curr_text);
    return LEX_CURR(lex);
}

static inline uint32 json_lex_number_len(lex_t *lex)
{
    char *str;
    for (str = lex->curr_text->str; str < lex->curr_text->str + lex->curr_text->len; str++) {
        if (!(*str == '+' || *str == '-' || *str == 'e' || *str == 'E' || *str == '.' || (*str >= '0' && *str <= '9'))) {
            break;
        }
    }

    return (uint32)(str - lex->curr_text->str);
}

static inline status_t json_lex_expect_char(lex_t *lex, char c)
{
    if (c != LEX_CURR(lex)) {
        CT_SRC_THROW_ERROR_EX(JSON_ERR_LOC(lex), ERR_JSON_SYNTAX_ERROR, "unexpected %c found", LEX_CURR(lex));
        return CT_ERROR;
    }

    (void)json_lex(lex);
    return CT_SUCCESS;
}

static status_t json_parse_value(json_assist_t *json_ass, lex_t *lex, json_value_t *json_val, uint32 temp_level);
static inline status_t json_parse_string_escape(lex_t *lex)
{
    uint32 escaped_len;
    if (json_unescape_char(&lex->curr_text->value, &escaped_len, NULL) != CT_SUCCESS) {
        cm_set_error_loc(JSON_ERR_LOC(lex));
        return CT_ERROR;
    }

    (void)json_lex_move_n(lex, (int)(escaped_len - 1));
    (void)json_lex(lex);
    return CT_SUCCESS;
}

static status_t json_parse_string(lex_t *lex, json_value_t *json_val, json_assist_t *json_ass)
{
    bool32 valid_only = (json_val == NULL);
    char curr;
    char *start = NULL;

    if (LEX_CURR(lex) != '"') {
        CT_SRC_THROW_ERROR_EX(JSON_ERR_LOC(lex), ERR_JSON_SYNTAX_ERROR, "\" expected but %c found", LEX_CURR(lex));
        return CT_ERROR;
    }

    curr = json_lex_move(lex);
    start = lex->curr_text->str;
    while (curr != LEX_END) {
        if (curr == '"') {
            break;
        } else if ((unsigned char)curr < 32) {
            CT_SRC_THROW_ERROR(JSON_ERR_LOC(lex), ERR_JSON_SYNTAX_ERROR, "character < 32 must be escaped");

            return CT_ERROR;
        } else if (curr == '\\') {
            CT_RETURN_IFERR(json_parse_string_escape(lex));
            curr = LEX_CURR(lex);
        } else {
            curr = json_lex_move(lex);
        }
    }
    if (curr == LEX_END) {
        CT_SRC_THROW_ERROR(JSON_ERR_LOC(lex), ERR_JSON_SYNTAX_ERROR, "uncomplete string");

        return CT_ERROR;
    }

    if (!valid_only) {
        json_val->type = JSON_VAL_STRING;
        json_val->string.str = start;
        json_val->string.len = (uint32)(lex->curr_text->str - start);
    }

    (void)json_lex(lex);
    return CT_SUCCESS;
}

static inline status_t json_parse_scalar_true(lex_t *lex, json_value_t *json_val)
{
    bool32 valid_only = (json_val == NULL);

    if (lex->curr_text->len >= 4 && lex->curr_text->str[0] == 't' && lex->curr_text->str[1] == 'r' &&
        lex->curr_text->str[2] == 'u' && lex->curr_text->str[3] == 'e') {
        (void)json_lex_move_n(lex, 4 - 1);
        (void)json_lex(lex);

        CT_RETSUC_IFTRUE(valid_only);

        json_val->type = JSON_VAL_BOOL;
        json_val->boolean = CT_TRUE;

        return CT_SUCCESS;
    }

    CT_SRC_THROW_ERROR_EX(JSON_ERR_LOC(lex), ERR_JSON_SYNTAX_ERROR, "unexpected %c found", LEX_CURR(lex));
    return CT_ERROR;
}

static inline status_t json_parse_scalar_false(lex_t *lex, json_value_t *json_val)
{
    bool32 valid_only = (json_val == NULL);

    if (lex->curr_text->len >= 5 && lex->curr_text->str[0] == 'f' && lex->curr_text->str[1] == 'a' &&
        lex->curr_text->str[2] == 'l' && lex->curr_text->str[3] == 's' && lex->curr_text->str[4] == 'e') {
        (void)json_lex_move_n(lex, 5 - 1);
        (void)json_lex(lex);

        CT_RETSUC_IFTRUE(valid_only);

        json_val->type = JSON_VAL_BOOL;
        json_val->boolean = CT_FALSE;
        return CT_SUCCESS;
    }

    CT_SRC_THROW_ERROR_EX(JSON_ERR_LOC(lex), ERR_JSON_SYNTAX_ERROR, "unexpected %c found", LEX_CURR(lex));
    return CT_ERROR;
}

static inline status_t json_parse_scalar_null(lex_t *lex, json_value_t *json_val)
{
    bool32 valid_only = (json_val == NULL);

    if (lex->curr_text->len >= 4 && lex->curr_text->str[0] == 'n' && lex->curr_text->str[1] == 'u' &&
        lex->curr_text->str[2] == 'l' && lex->curr_text->str[3] == 'l') {
        (void)json_lex_move_n(lex, 4 - 1);
        (void)json_lex(lex);

        CT_RETSUC_IFTRUE(valid_only);

        json_val->type = JSON_VAL_NULL;
        return CT_SUCCESS;
    }

    CT_SRC_THROW_ERROR_EX(JSON_ERR_LOC(lex), ERR_JSON_SYNTAX_ERROR, "unexpected %c found", LEX_CURR(lex));
    return CT_ERROR;
}

status_t json_parse_scalar_number(lex_t *lex, json_value_t *json_val)
{
    bool32 valid_only = (json_val == NULL);
    dec8_t dec;
    text_t dec_text;
    text_t dec_text_temp;

    dec_text.str = lex->curr_text->str;
    dec_text.len = json_lex_number_len(lex);

    dec_text_temp = dec_text;
    cm_trim_text(&dec_text_temp);
    if (cm_text_to_dec(&dec_text_temp, &dec)) {
        cm_reset_error();
        CT_SRC_THROW_ERROR_EX(JSON_ERR_LOC(lex), ERR_JSON_SYNTAX_ERROR, "invalid json number format %s",
            T2S(&dec_text));
        return CT_ERROR;
    }

    if (!valid_only) {
        json_val->type = JSON_VAL_NUMBER;
        json_val->number = dec_text_temp;
    }

    (void)json_lex_move_n(lex, (int)(dec_text.len - 1));
    (void)json_lex(lex);

    return CT_SUCCESS;
}

status_t json_parse_scalar(lex_t *lex, json_value_t *json_val, json_assist_t *json_ass)
{
    switch (LEX_CURR(lex)) {
        case '"':
            return json_parse_string(lex, json_val, json_ass);
        case 't':
            return json_parse_scalar_true(lex, json_val);
        case 'f':
            return json_parse_scalar_false(lex, json_val);
        case 'n':
            return json_parse_scalar_null(lex, json_val);
        case '-':
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
            return json_parse_scalar_number(lex, json_val);
        default:
            CT_SRC_THROW_ERROR_EX(JSON_ERR_LOC(lex), ERR_JSON_SYNTAX_ERROR, "unexpected %c found", LEX_CURR(lex));
            return CT_ERROR;
    }
}

// retval: true: need alloc tree node, false: not need alloc tree node
// is_placeholder: when retval is true, is_placeholder means tree node is a place holder
static bool8 json_filter_array_step(json_assist_t *json_ass, uint32 level, uint32 index, bool8 *is_placeholder)
{
    json_path_step_t *step = NULL;
    bool8 need_alloc;

    *is_placeholder = CT_FALSE;

    if (json_ass->filter_path == NULL || level >= json_ass->filter_path->count) {
        return CT_TRUE;
    }

    step = &json_ass->filter_path->steps[level];
    if (step->type != JSON_PATH_STEP_ARRAY && step->type != JSON_PATH_STEP_HEAD) {
        return CT_TRUE;
    }

    if ((step->index_flag & JSON_PATH_INDEX_IS_STAR) || step->index_pairs_count == 0) {
        return CT_TRUE;
    }

    need_alloc = CT_FALSE;
    *is_placeholder = CT_TRUE;
    for (uint32 i = 0; i < step->index_pairs_count; i++) {
        if (index <= step->index_pairs_list[i].to_index) {
            need_alloc = CT_TRUE;
            if (index >= step->index_pairs_list[i].from_index) {
                *is_placeholder = CT_FALSE;
            }
        }
    }
    return need_alloc;
}

// retval: true: need alloc tree node, false: not need alloc tree node
static bool8 json_filter_key_step(json_assist_t *json_ass, uint32 level, text_t *key)
{
    json_path_step_t *step = NULL;

    if (json_ass->filter_path == NULL || level >= json_ass->filter_path->count) {
        return CT_TRUE;
    }

    step = &json_ass->filter_path->steps[level];
    if (step->type != JSON_PATH_STEP_ARRAY && step->type != JSON_PATH_STEP_KEYNAME) {
        return CT_TRUE;
    }

    return (step->keyname_flag & JSON_PATH_KEYNAME_IS_STAR) || (bool8)cm_text_str_equal_ins(key, step->keyname);
}

status_t json_parse_array(json_assist_t *json_ass, lex_t *lex, json_value_t *json_val, uint32 level)
{
    bool32 valid_only = (json_val == NULL);
    bool32 filterd;
    bool8 is_placeholder = CT_FALSE;
    uint32 index = 0;

    if (!valid_only) {
        json_val->type = JSON_VAL_ARRAY;
        CT_RETURN_IFERR(json_item_array_init(json_ass, &json_val->array, JSON_MEM_VMC));
    }

    // empty object
    if (LEX_CURR(lex) == ']') {
        (void)json_lex(lex);
        return CT_SUCCESS;
    }

    for (;;) {
        json_value_t *elem = NULL;

        json_ass->parent_jv = json_val;
        filterd = valid_only || (!json_filter_array_step(json_ass, level, index, &is_placeholder));
        if (!filterd) {
            CT_RETURN_IFERR(cm_galist_new(json_val->array, sizeof(json_value_t), (pointer_t *)&elem));
            elem->type = JSON_VAL_NULL;
        }

        CT_RETURN_IFERR(json_parse_value(json_ass, lex, (filterd || is_placeholder) ? NULL : elem, level));

        if (LEX_CURR(lex) == ',') {
            (void)json_lex(lex);
            index++;
            continue;
        } else if (LEX_CURR(lex) == ']') {
            break;
        } else {
            CT_SRC_THROW_ERROR_EX(JSON_ERR_LOC(lex), ERR_JSON_SYNTAX_ERROR, "\",\" expected but %c found",
                LEX_CURR(lex));
            return CT_ERROR;
        }
    }
    (void)json_lex(lex);
    return CT_SUCCESS;
}

status_t json_parse_object(json_assist_t *json_ass, lex_t *lex, json_value_t *json_val, uint32 level)
{
    bool32 valid_only = (json_val == NULL);
    bool32 filterd;
    json_value_t key;

    if (!valid_only) {
        json_val->type = JSON_VAL_OBJECT;
        CT_RETURN_IFERR(json_item_array_init(json_ass, &json_val->object, JSON_MEM_VMC));
    }

    // empty object
    if (LEX_CURR(lex) == '}') {
        (void)json_lex(lex);
        return CT_SUCCESS;
    }

    for (;;) {
        json_pair_t *pair = NULL;

        // parse pair.key
        CT_RETURN_IFERR(json_parse_string(lex, &key, json_ass));

        json_ass->parent_jv = json_val;
        filterd = valid_only || (!json_filter_key_step(json_ass, level, &key.string));
        if (!filterd) {
            CT_RETURN_IFERR(cm_galist_new(json_val->object, sizeof(json_pair_t), (pointer_t *)&pair));
            pair->key = key;
        }

        // parse ':'
        CT_RETURN_IFERR(json_lex_expect_char(lex, ':'));

        // parse pair.value
        CT_RETURN_IFERR(json_parse_value(json_ass, lex, filterd ? NULL : &pair->val, level));

        if (LEX_CURR(lex) == ',') {
            (void)json_lex(lex);
            continue;
        } else if (LEX_CURR(lex) == '}') {
            break;
        } else {
            CT_SRC_THROW_ERROR_EX(JSON_ERR_LOC(lex), ERR_JSON_SYNTAX_ERROR, "\",\" expected but %c found",
                LEX_CURR(lex));
            return CT_ERROR;
        }
    }
    (void)json_lex(lex);
    return CT_SUCCESS;
}

static status_t json_parse_value(json_assist_t *json_ass, lex_t *lex, json_value_t *json_val, uint32 temp_level)
{
    uint32 level = temp_level;
    JSON_RETURN_ERROR_IF_STACK_OVERFLOW(json_ass, level);

    switch (LEX_CURR(lex)) {
        case '{':
            (void)json_lex(lex);
            TO_UINT32_OVERFLOW_CHECK((uint64)(level) + 1, uint64);
            return json_parse_object(json_ass, lex, json_val, level + 1);

        case '[':
            (void)json_lex(lex);
            if (json_ass->parent_jv != NULL && json_ass->parent_jv->type == JSON_VAL_ARRAY) {
                TO_UINT32_OVERFLOW_CHECK((uint64)(level) + 1, uint64);
                level++;
            }
            return json_parse_array(json_ass, lex, json_val, level);

        default:
            return json_parse_scalar(lex, json_val, json_ass);
    }
}

static inline status_t json_parse_core(json_assist_t *json_ass, lex_t *lex, json_value_t *json_val, uint32 level)
{
    CT_RETURN_IFERR(json_parse_value(json_ass, lex, json_val, level));
    if (LEX_CURR_EX(lex) != LEX_END) {
        CT_SRC_THROW_ERROR_EX(JSON_ERR_LOC(lex), ERR_JSON_SYNTAX_ERROR, "unexpected terminate %c found",
            LEX_CURR_EX(lex));
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t json_array_parse(json_assist_t *json_ass, text_t *src, json_value_t *json_val, source_location_t loc)
{
    sql_text_t text;
    lex_t lex;
    text.value = *src;
    text.loc = loc;

    lex_init(&lex, &text);
    lex.loc = loc;
    json_lex_trim(lex.curr_text);
    if (lex.curr_text->len == 0 || lex.curr_text->str[0] != '[') {
        // scaler type is not allowed
        CT_SRC_THROW_ERROR_EX(JSON_ERR_LOC(&lex), ERR_JSON_SYNTAX_ERROR, "unexpected %c found", LEX_CURR_EX(&lex));
        return CT_ERROR;
    }

    return json_parse_core(json_ass, &lex, json_val, 0);
}

status_t json_parse(json_assist_t *json_ass, text_t *src, json_value_t *json_val, source_location_t loc)
{
    sql_text_t text;
    lex_t lex;
    bool32 valid_only = (json_val == NULL);

    text.value = *src;
    text.loc = loc;

    lex_init(&lex, &text);
    lex.loc = loc;
    json_lex_trim(lex.curr_text);

    if (lex.curr_text->len == 0 || (valid_only && lex.curr_text->str[0] != '{' && lex.curr_text->str[0] != '[')) {
        // scaler type is not allowed
        CT_SRC_THROW_ERROR_EX(JSON_ERR_LOC(&lex), ERR_JSON_SYNTAX_ERROR, "unexpected %c found", LEX_CURR_EX(&lex));
        return CT_ERROR;
    }

    return json_parse_core(json_ass, &lex, json_val, 0);
}

static status_t json_deparse_value(json_value_t *json_val, json_assist_write_t *jaw, uint32 level);
static status_t json_deparse_string(json_value_t *json_val, json_assist_write_t *jaw, uint32 level)
{
    if (!jaw->is_scalar) {
        CT_RETURN_IFERR(jaw->json_write(jaw, "\"", 1));
    }

    CT_RETURN_IFERR(jaw->json_write(jaw, json_val->string.str, json_val->string.len));

    if (!jaw->is_scalar) {
        CT_RETURN_IFERR(jaw->json_write(jaw, "\"", 1));
    }

    return CT_SUCCESS;
}

static status_t json_deparse_number(json_value_t *json_val, json_assist_write_t *jaw, uint32 level)
{
    CT_RETURN_IFERR(jaw->json_write(jaw, json_val->number.str, json_val->number.len));

    return CT_SUCCESS;
}

static status_t json_deparse_null(json_value_t *json_val, json_assist_write_t *jaw, uint32 level)
{
    CT_RETURN_IFERR(jaw->json_write(jaw, "null", 4));

    return CT_SUCCESS;
}

static status_t json_deparse_bool(json_value_t *json_val, json_assist_write_t *jaw, uint32 level)
{
    if (json_val->boolean) {
        CT_RETURN_IFERR(jaw->json_write(jaw, "true", 4));
    } else {
        CT_RETURN_IFERR(jaw->json_write(jaw, "false", 5));
    }

    return CT_SUCCESS;
}

static status_t json_deparse_array(json_value_t *json_val, json_assist_write_t *jaw, uint32 level)
{
    CT_RETURN_IFERR(jaw->json_write(jaw, "[", 1));

    for (uint32 i = 0; i < JSON_ARRAY_SIZE(json_val); i++) {
        CT_RETURN_IFERR(json_deparse_value(JSON_ARRAY_ITEM(json_val, i), jaw, level));

        // not last elem
        if (i != (uint32)(JSON_ARRAY_SIZE(json_val) - 1)) {
            CT_RETURN_IFERR(jaw->json_write(jaw, ",", 1));
        }
    }

    CT_RETURN_IFERR(jaw->json_write(jaw, "]", 1));

    return CT_SUCCESS;
}

static status_t json_deparse_object(json_value_t *json_val, json_assist_write_t *jaw, uint32 level)
{
    CT_RETURN_IFERR(jaw->json_write(jaw, "{", 1));

    for (uint32 i = 0; i < JSON_OBJECT_SIZE(json_val); i++) {
        CT_RETURN_IFERR(json_deparse_value(&JSON_OBJECT_ITEM(json_val, i)->key, jaw, level));

        CT_RETURN_IFERR(jaw->json_write(jaw, ":", 1));

        CT_RETURN_IFERR(json_deparse_value(&JSON_OBJECT_ITEM(json_val, i)->val, jaw, level));

        // not last pair
        if (i != JSON_OBJECT_SIZE(json_val) - 1) {
            CT_RETURN_IFERR(jaw->json_write(jaw, ",", 1));
        }
    }

    CT_RETURN_IFERR(jaw->json_write(jaw, "}", 1));

    return CT_SUCCESS;
}

static status_t json_deparse_value(json_value_t *json_val, json_assist_write_t *jaw, uint32 level)
{
    switch (json_val->type) {
        case JSON_VAL_NULL:
            return json_deparse_null(json_val, jaw, level);

        case JSON_VAL_BOOL:
            return json_deparse_bool(json_val, jaw, level);

        case JSON_VAL_STRING:
            return json_deparse_string(json_val, jaw, level);

        case JSON_VAL_NUMBER:
            return json_deparse_number(json_val, jaw, level);

        case JSON_VAL_ARRAY:
            TO_UINT32_OVERFLOW_CHECK((uint64)(level + 1), uint64);
            return json_deparse_array(json_val, jaw, level + 1);

        case JSON_VAL_OBJECT:
            TO_UINT32_OVERFLOW_CHECK((uint64)(level + 1), uint64);
            return json_deparse_object(json_val, jaw, level + 1);

        default:
            CT_THROW_ERROR(ERR_JSON_UNKNOWN_TYPE, (int)json_val->type, "do json deparse");
            return CT_ERROR;
    }
}

static status_t json_deparse(json_value_t *json_val, json_assist_write_t *json_ass_w)
{
    return json_deparse_value(json_val, json_ass_w, 0);
}

status_t json_write_to_textbuf_unescaped(json_assist_write_t *json_ass_w, char *str, uint32 len)
{
    text_t text;
    text_buf_t *text_buf = (text_buf_t *)json_ass_w->arg;

    cm_str2text_safe(str, len, &text);
    return json_unescape_string(&text, text_buf);
}

status_t json_write_to_textbuf(json_assist_write_t *json_ass_w, char *str, uint32 len)
{
    text_t text;
    text_buf_t *text_buf = (text_buf_t *)json_ass_w->arg;

    cm_str2text_safe(str, len, &text);
    JSON_TXTBUF_APPEND_TEXT(text_buf, &text);

    return CT_SUCCESS;
}

status_t json_write_to_lob_vm(json_assist_write_t *json_ass_w, char *str, uint32 len)
{
    sql_stmt_t *stmt = json_ass_w->stmt;
    json_vlob_t *ja_vlob = (json_vlob_t *)json_ass_w->arg;
    uint32 remain_size = len;
    id_list_t *vm_list = sql_get_exec_lob_list(json_ass_w->stmt);
    uint32 copy_size;

    while (remain_size > 0) {
        copy_size = 0;

        JSON_EXTEND_LOB_VMEM_IF_NEEDED(ja_vlob, stmt);

        copy_size = MIN((uint32)ja_vlob->last_free_size, remain_size);
        MEMS_RETURN_IFERR(memcpy_s(ja_vlob->last_page->data + CT_VMEM_PAGE_SIZE - ja_vlob->last_free_size, copy_size,
            str + len - remain_size, copy_size));

        ja_vlob->last_free_size -= copy_size;
        remain_size -= copy_size;
        ja_vlob->vlob.size += copy_size;
    }

    if (ja_vlob->last_free_size == 0) {
        vm_close(json_ass_w->stmt->session, json_ass_w->stmt->mtrl.pool, vm_list->last, VM_ENQUE_TAIL);
        ja_vlob->last_page = NULL;
    }

    return CT_SUCCESS;
}

static status_t json_serialize_to_string_core(json_assist_t *json_ass, json_value_t *json_val,
                                              variant_t *result, bool32 is_scalar)
{
    json_assist_write_t json_ass_w;
    text_buf_t arg;
    char *buf = NULL;

    if (is_scalar && !JSON_VAL_IS_SCALAR(json_val)) {
        CT_THROW_ERROR_EX(ERR_JSON_SYNTAX_ERROR, "unexpected non-scalar type");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(JSON_ALLOC(json_ass, JSON_MAX_STRING_LEN, (void **)&buf));
    CM_INIT_TEXTBUF(&arg, JSON_MAX_STRING_LEN, buf);

    JSON_INIT_ASSIST_WRITE(&json_ass_w, json_ass->stmt, is_scalar ? json_write_to_textbuf_unescaped : json_write_to_textbuf, &arg,
        is_scalar);

    CT_RETURN_IFERR(json_deparse(json_val, &json_ass_w));

    result->type = CT_TYPE_STRING;
    result->is_null = CT_FALSE;
    result->v_text = arg.value;

    return CT_SUCCESS;
}

status_t json_serialize_to_string_scalar(json_assist_t *json_ass, json_value_t *json_val, variant_t *result)
{
    return json_serialize_to_string_core(json_ass, json_val, result, CT_TRUE);
}

status_t json_serialize_to_string(json_assist_t *json_ass, json_value_t *json_val, variant_t *result)
{
    return json_serialize_to_string_core(json_ass, json_val, result, CT_FALSE);
}

static status_t json_serialize_to_lob_normal_core(json_assist_t *json_ass, json_value_t *json_val, variant_t *result,
    bool32 is_scalar)
{
    json_assist_write_t json_ass_w;
    text_buf_t arg;
    char *buf = NULL;

    if (is_scalar && !JSON_VAL_IS_SCALAR(json_val)) {
        CT_THROW_ERROR_EX(ERR_JSON_SYNTAX_ERROR, "unexpected non-scalar type");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(JSON_ALLOC(json_ass, CT_MAX_EXEC_LOB_SIZE, (void **)&buf));
    CM_INIT_TEXTBUF(&arg, CT_MAX_EXEC_LOB_SIZE, buf);

    JSON_INIT_ASSIST_WRITE(&json_ass_w, json_ass->stmt, is_scalar ? json_write_to_textbuf_unescaped : json_write_to_textbuf, &arg,
        is_scalar);

    CT_RETURN_IFERR(json_deparse(json_val, &json_ass_w));

    result->type = CT_TYPE_CLOB;
    result->v_lob.type = CT_LOB_FROM_NORMAL;
    result->v_lob.normal_lob.type = CT_LOB_FROM_NORMAL;
    result->v_lob.normal_lob.size = arg.value.len;
    result->v_lob.normal_lob.value = arg.value;

    return CT_SUCCESS;
}

status_t json_serialize_to_lob_normal_scalar(json_assist_t *json_ass, json_value_t *json_val, variant_t *result)
{
    return json_serialize_to_lob_normal_core(json_ass, json_val, result, CT_TRUE);
}

status_t json_serialize_to_lob_vm(json_assist_t *json_ass, json_value_t *json_val, variant_t *result)
{
    json_vlob_t arg;
    json_assist_write_t json_ass_w;
    id_list_t *vm_list = sql_get_exec_lob_list(json_ass->stmt);

    JSON_INIT_VLOB(&arg);
    JSON_INIT_ASSIST_WRITE(&json_ass_w, json_ass->stmt, json_write_to_lob_vm, &arg, CT_FALSE);

    CT_RETURN_IFERR(json_deparse(json_val, &json_ass_w));

    // avoid last page not closed
    if (arg.last_free_size != 0) {
        vm_close(json_ass->stmt->session, json_ass->stmt->mtrl.pool, vm_list->last, VM_ENQUE_TAIL);
    }

    result->type = CT_TYPE_CLOB;
    result->v_lob.type = CT_LOB_FROM_VMPOOL;
    result->v_lob.vm_lob = arg.vlob;

    return CT_SUCCESS;
}

// ============================================================================
// JSON SQL FUNC PARSE, SUB CLAUSE HANDLE, RETRIEVE
// add more inner func here.
status_t json_func_step_type(sql_stmt_t *stmt, json_value_t *json_val)
{
    CM_POINTER2(stmt, json_val);

    json_val->string.str = JSON_TYPE_STR(json_val->type);
    json_val->string.len = (uint32)strlen(json_val->string.str);
    json_val->type = JSON_VAL_STRING;

    return CT_SUCCESS;
}

static json_func_step_item_t g_json_func_step_items[] = {
    {"TYPE", 4, JFUNC_FUNC_STEP_TYPE, json_func_step_type},
};

static json_func_step_item_t *json_func_step_match_item(text_t *src)
{
    cm_trim_text(src);
    for (uint32 i = 0; i < sizeof(g_json_func_step_items) / sizeof(json_func_step_item_t); i++) {
        if (cm_compare_text_str_ins(src, g_json_func_step_items[i].name) == 0) {
            return &g_json_func_step_items[i];
        }
    }
    return NULL;
}

// ============================================================================
typedef struct st_json_func_att_item {
    char *tag;
    uint32 len;
    json_func_att_id_t id;
} json_func_att_item_t;
static json_func_att_item_t g_json_func_att_items[] = {
    { "ABSENT ON NULL", 14, JSON_FUNC_ATT_ABSENT_ON_NULL },
    { "EMPTY ARRAY ON EMPTY", 20, JSON_FUNC_ATT_EMPTY_ARRAY_ON_EMPTY },
    { "EMPTY ARRAY ON ERROR", 20, JSON_FUNC_ATT_EMPTY_ARRAY_ON_ERROR },
    { "EMPTY OBJECT ON EMPTY", 21, JSON_FUNC_ATT_EMPTY_OBJECT_ON_EMPTY },
    { "EMPTY OBJECT ON ERROR", 21, JSON_FUNC_ATT_EMPTY_OBJECT_ON_ERROR },
    { "EMPTY ON EMPTY", 14, JSON_FUNC_ATT_EMPTY_ON_EMPTY },
    { "EMPTY ON ERROR", 14, JSON_FUNC_ATT_EMPTY_ON_ERROR },
    { "ERROR ON EMPTY", 14, JSON_FUNC_ATT_ERROR_ON_EMPTY },
    { "ERROR ON ERROR", 14, JSON_FUNC_ATT_ERROR_ON_ERROR },
    { "FALSE ON ERROR", 14, JSON_FUNC_ATT_FALSE_ON_ERROR },
    { "NULL ON EMPTY", 13, JSON_FUNC_ATT_NULL_ON_EMPTY },
    { "NULL ON ERROR", 13, JSON_FUNC_ATT_NULL_ON_ERROR },
    { "NULL ON NULL", 12, JSON_FUNC_ATT_NULL_ON_NULL },
    { "RETURNING CLOB", 14, JSON_FUNC_ATT_RETURNING_CLOB},
    { "RETURNING JSONB", 15, JSON_FUNC_ATT_RETURNING_JSONB},
    { "RETURNING VARCHAR2", 18, JSON_FUNC_ATT_RETURNING_VARCHAR2},
    { "TRUE ON ERROR", 13, JSON_FUNC_ATT_TRUE_ON_ERROR },
    { "WITH ARRAY WRAPPER", 18, JSON_FUNC_ATT_WITH_WRAPPER },
    { "WITH CONDITIONAL ARRAY WRAPPER", 30, JSON_FUNC_ATT_WITH_CON_WRAPPER },
    { "WITH CONDITIONAL WRAPPER", 24, JSON_FUNC_ATT_WITH_CON_WRAPPER },
    { "WITH UNCONDITIONAL ARRAY WRAPPER", 32, JSON_FUNC_ATT_WITH_WRAPPER },
    { "WITH UNCONDITIONAL WRAPPER", 26, JSON_FUNC_ATT_WITH_WRAPPER },
    { "WITH WRAPPER", 12, JSON_FUNC_ATT_WITH_WRAPPER },
    { "WITHOUT ARRAY WRAPPER", 21, JSON_FUNC_ATT_WITHOUT_WRAPPER },
    { "WITHOUT WRAPPER", 15, JSON_FUNC_ATT_WITHOUT_WRAPPER },
};

static status_t json_func_att_format(text_t *src, text_t *dst)
{
    bool32 skip_space = CT_FALSE;
    dst->len = 0;
    for (uint32 i = 0; i < src->len; i++) {
        if (src->str[i] == ' ' || src->str[i] == '\t' || src->str[i] == '\n' || src->str[i] == '\r') {
            if (skip_space) {
                continue;
            } else {
                CM_TEXT_APPEND(dst, ' ');
                skip_space = CT_TRUE;
            }
        } else {
            CM_TEXT_APPEND(dst, UPPER(src->str[i]));
            skip_space = CT_FALSE;
        }
    }

    cm_trim_text(dst);
    return CT_SUCCESS;
}

static json_func_att_item_t *json_func_att_match_item(text_t *src, bool32 ignore_returning)
{
    uint32 cmp_len, start_offset;

    cm_trim_text(src);
    for (uint32 i = 0; i < sizeof(g_json_func_att_items) / sizeof(json_func_att_item_t); i++) {
        start_offset = (ignore_returning && JSON_FUNC_ATT_HAS_RETURNING((uint32)g_json_func_att_items[i].id)) ?
            (sizeof("returning ") - 1) :
            0;
        cmp_len = g_json_func_att_items[i].len - start_offset;
        if (src->len >= cmp_len && strncmp(g_json_func_att_items[i].tag + start_offset, src->str, cmp_len) == 0) {
            // check right boundry
            if (src->len > cmp_len && src->str[cmp_len] != ' ' && src->str[cmp_len] != '(' &&
                src->str[cmp_len] != ',') {
                return NULL;
            }

            CM_REMOVE_FIRST_N(src, cmp_len);
            cm_trim_text(src);
            return &g_json_func_att_items[i];
        }
    }

    return NULL;
}

status_t json_func_att_match_returning(text_t *src, json_func_attr_t *attr)
{
    text_t tmp_text = *src;
    bool32 ignore_returning = attr->ignore_returning;
    json_func_att_item_t *item = json_func_att_match_item(&tmp_text, ignore_returning);

    if (item == NULL || !JSON_FUNC_ATT_HAS_RETURNING((uint32)item->id)) {
        return CT_SUCCESS;
    }

    if (item->id == JSON_FUNC_ATT_RETURNING_VARCHAR2) {
        text_t txt_size;
        uint32 i;

        cm_trim_text(&tmp_text);
        if (CM_IS_EMPTY(&tmp_text) || tmp_text.str[0] != '(') {
            attr->return_size = JSON_FUNC_LEN_DEFAULT;
            attr->ids |= JSON_FUNC_ATT_RETURNING_VARCHAR2;
            *src = tmp_text;
            return CT_SUCCESS;
        }

        CM_REMOVE_FIRST(&tmp_text);
        for (i = 0; i < tmp_text.len; i++) {
            if (tmp_text.str[i] == ')') {
                break;
            }
        }
        // not found ')'
        if (i == tmp_text.len) {
            CT_THROW_ERROR(ERR_JSON_INVLID_CLAUSE, "RETURNING", "expect ) not found");
            return CT_ERROR;
        }
        txt_size.str = tmp_text.str;
        txt_size.len = i;
        if (cm_text2uint16(&txt_size, &attr->return_size) != CT_SUCCESS || attr->return_size == 0 ||
            attr->return_size > JSON_MAX_STRING_LEN) {
            CT_THROW_ERROR(ERR_JSON_INVLID_CLAUSE, "RETURNING", "specified length invalid for its datatype");
            return CT_ERROR;
        }
        CM_REMOVE_FIRST_N(&tmp_text, i + 1);
    }

    attr->ids |= (uint32)item->id;
    *src = tmp_text;

    return CT_SUCCESS;
}

status_t json_func_att_match_on_error(text_t *src, json_func_attr_t *attr)
{
    text_t tmp = *src;
    json_func_att_item_t *item = json_func_att_match_item(&tmp, CT_FALSE);

    if (item == NULL || !JSON_FUNC_ATT_HAS_ON_ERROR((uint32)item->id)) {
        return CT_SUCCESS;
    }

    attr->ids |= (uint32)item->id;
    *src = tmp;
    return CT_SUCCESS;
}

status_t json_func_att_match_wrapper(text_t *src, json_func_attr_t *attr)
{
    text_t tmp = *src;
    json_func_att_item_t *item = json_func_att_match_item(&tmp, CT_FALSE);

    if (item == NULL || !JSON_FUNC_ATT_HAS_WRAPPER((uint32)item->id)) {
        return CT_SUCCESS;
    }

    attr->ids |= (uint32)item->id;
    *src = tmp;
    return CT_SUCCESS;
}

static status_t json_func_att_match_on_empty(text_t *src, json_func_attr_t *attr)
{
    text_t tmp = *src;
    json_func_att_item_t *item = json_func_att_match_item(&tmp, CT_FALSE);

    if (item == NULL || !JSON_FUNC_ATT_HAS_ON_EMPTY((uint32)item->id)) {
        // As ERROR if on_empty_clause not specified
        return CT_SUCCESS;
    }

    attr->ids |= (uint32)item->id;
    *src = tmp;
    return CT_SUCCESS;
}

static status_t json_func_att_match_on_null(text_t *src, json_func_attr_t *attr)
{
    text_t tmp = *src;
    json_func_att_item_t *item = json_func_att_match_item(&tmp, CT_FALSE);

    if (item == NULL || !JSON_FUNC_ATT_HAS_ON_NULL((uint32)item->id)) {
        return CT_SUCCESS;
    }

    attr->ids |= (uint32)item->id;
    *src = tmp;
    return CT_SUCCESS;
}

void json_func_att_init(json_func_attr_t *attr)
{
    attr->ids = JSON_FUNC_ATT_INVALID;
    attr->return_size = JSON_FUNC_LEN_DEFAULT;
    attr->ignore_returning = CT_FALSE;
}

#define JSON_MAX_FUNC_ATT_LEN SIZE_K(1)
status_t json_func_att_match(text_t *src, json_func_attr_t *attr)
{
    char str[JSON_MAX_FUNC_ATT_LEN];
    text_t tmp = { str, JSON_MAX_FUNC_ATT_LEN };

    if (src->len > JSON_MAX_FUNC_ATT_LEN) {
        CT_THROW_ERROR(ERR_JSON_INVLID_CLAUSE, "RETURNING/ON", "JSON func attr too long(maximum: 1024)");
        return CT_ERROR;
    }

    json_func_att_init(attr);

    CT_RETURN_IFERR(json_func_att_format(src, &tmp));

    CT_RETURN_IFERR(json_func_att_match_on_null(&tmp, attr));

    CT_RETURN_IFERR(json_func_att_match_returning(&tmp, attr));

    CT_RETURN_IFERR(json_func_att_match_wrapper(&tmp, attr));

    CT_RETURN_IFERR(json_func_att_match_on_error(&tmp, attr));

    CT_RETURN_IFERR(json_func_att_match_on_empty(&tmp, attr));

    cm_trim_text(&tmp);
    if (tmp.len > 0) {
        CT_THROW_ERROR(ERR_JSON_INVLID_CLAUSE, "RETURNING/ON", "");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t handle_on_error_clause(json_func_attr_t att, variant_t *result)
{
    switch (JSON_FUNC_ATT_GET_ON_ERROR(att.ids)) {
        case JSON_FUNC_ATT_NULL_ON_ERROR:
            result->is_null = CT_TRUE;
            result->type = CT_TYPE_STRING;
            break;

        case JSON_FUNC_ATT_ERROR_ON_ERROR:
            return CT_ERROR;

        case JSON_FUNC_ATT_EMPTY_OBJECT_ON_ERROR:
            result->is_null = CT_FALSE;
            result->type = CT_TYPE_STRING;
            result->v_text.str = "{}";
            result->v_text.len = 2;
            break;

        case JSON_FUNC_ATT_EMPTY_ON_ERROR:
        case JSON_FUNC_ATT_EMPTY_ARRAY_ON_ERROR:
            result->is_null = CT_FALSE;
            result->type = CT_TYPE_STRING;
            result->v_text.str = "[]";
            result->v_text.len = 2;
            break;

        case JSON_FUNC_ATT_FALSE_ON_ERROR:
            result->is_null = CT_FALSE;
            result->type = CT_TYPE_BOOLEAN;
            result->v_bool = CT_FALSE;
            break;

        case JSON_FUNC_ATT_TRUE_ON_ERROR:
            result->is_null = CT_FALSE;
            result->type = CT_TYPE_BOOLEAN;
            result->v_bool = CT_TRUE;
            break;

        default:
            // Never reached here.
            CM_ASSERT(0);
            break;
    }

    cm_reset_error();
    return CT_SUCCESS;
}

status_t handle_on_empty_clause(json_assist_t *json_ass, json_func_attr_t att, variant_t *result)
{
    switch (JSON_FUNC_ATT_GET_ON_EMPTY(att.ids)) {
        case JSON_FUNC_ATT_NULL_ON_EMPTY:
            result->is_null = CT_TRUE;
            result->type = CT_TYPE_STRING;
            break;

        case JSON_FUNC_ATT_ERROR_ON_EMPTY:
            CT_THROW_ERROR(ERR_JSON_VALUE_MISMATCHED, json_ass->is_json_retrieve ? "JSON_VALUE" : "JSONB_VALUE", "no");
            return CT_ERROR;

        case JSON_FUNC_ATT_EMPTY_OBJECT_ON_EMPTY:
            result->is_null = CT_FALSE;
            result->type = CT_TYPE_STRING;
            result->v_text.str = "{}";
            result->v_text.len = 2;
            break;

        case JSON_FUNC_ATT_EMPTY_ON_EMPTY:
        case JSON_FUNC_ATT_EMPTY_ARRAY_ON_EMPTY:
            result->is_null = CT_FALSE;
            result->type = CT_TYPE_STRING;
            result->v_text.str = "[]";
            result->v_text.len = 2;
            break;

        default:
            CM_ASSERT(JSON_FUNC_ATT_GET_ON_EMPTY(att.ids) == JSON_FUNC_ATT_INVALID);
            // As ERROR if on_empty_clause not specified
            CT_THROW_ERROR(ERR_JSON_VALUE_MISMATCHED, json_ass->is_json_retrieve ? "JSON_VALUE" : "JSONB_VALUE", "no");
            JSON_RETURN_IF_ON_ERROR_HANDLED(CT_ERROR, json_ass, att, result);
            break;
    }

    cm_reset_error();
    return CT_SUCCESS;
}

status_t handle_returning_clause(json_assist_t *json_ass, json_value_t *json_val, json_func_attr_t json_func_attr,
    variant_t *result, bool32 scalar_retrieve)
{
    json_func_att_id_t return_type = JSON_FUNC_ATT_GET_RETURNING(json_func_attr.ids);

    result->is_null = CT_FALSE;
    switch (return_type) {
        case JSON_FUNC_ATT_RETURNING_VARCHAR2:
            if (scalar_retrieve) {
                CT_RETURN_IFERR(json_serialize_to_string_scalar(json_ass, json_val, result));
            } else {
                CT_RETURN_IFERR(json_serialize_to_string(json_ass, json_val, result));
            }
            if (result->v_text.len > json_func_attr.return_size) {
                CT_THROW_ERROR(ERR_JSON_OUTPUT_TOO_LARGE);
                return CT_ERROR;
            }
            break;

        case JSON_FUNC_ATT_RETURNING_CLOB:
            if (scalar_retrieve && ((json_val->type == JSON_VAL_NULL || json_val->type == JSON_VAL_BOOL) ||
                ((json_val->type == JSON_VAL_STRING || json_val->type == JSON_VAL_NUMBER) &&
                                     json_val->string.len <= CT_MAX_EXEC_LOB_SIZE))) {
                CT_RETURN_IFERR(json_serialize_to_lob_normal_scalar(json_ass, json_val, result));
            } else {
                CT_RETURN_IFERR(json_serialize_to_lob_vm(json_ass, json_val, result));
            }
            break;

        default:
            CT_THROW_ERROR(ERR_JSON_INVLID_CLAUSE, "RETURNING", "unexpected returning type");
            return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t handle_wrapper_clause(json_assist_t *json_ass, json_func_attr_t attr, json_value_t *jv_result_array,
    variant_t *result)
{
    json_value_t *jv_result = NULL;
    jv_result = (json_value_t *)cm_galist_get(jv_result_array->array, 0);
    switch (JSON_FUNC_ATT_GET_WRAPPER(attr.ids)) {
        case JSON_FUNC_ATT_WITHOUT_WRAPPER:
            if (jv_result_array->array->count > 1) {
                CT_THROW_ERROR(ERR_JSON_VALUE_MISMATCHED, json_ass->is_json_retrieve ? "JSON_VALUE" : "JSONB_VALUE",
                    "multiple");
                JSON_RETURN_IF_ON_ERROR_HANDLED(CT_ERROR, json_ass, attr, result);
            }
            if (JSON_VAL_IS_SCALAR(jv_result)) {
                CT_THROW_ERROR(ERR_JSON_VALUE_MISMATCHED, json_ass->is_json_retrieve ? "JSON_VALUE" : "JSONB_VALUE",
                    "scalar");
                JSON_RETURN_IF_ON_ERROR_HANDLED(CT_ERROR, json_ass, attr, result);
            }
            break;

        case JSON_FUNC_ATT_WITH_WRAPPER:
            jv_result = jv_result_array;
            break;

        case JSON_FUNC_ATT_WITH_CON_WRAPPER:
            if ((jv_result_array->array->count == 1) && (!JSON_VAL_IS_SCALAR(jv_result))) {
                break;
            }
            jv_result = jv_result_array;
            break;

        default:
            // Never reached here.
            CM_ASSERT(0);
            break;
    }

    // 5. handle returning clause
    JSON_RETURN_IF_ON_ERROR_HANDLED(handle_returning_clause(json_ass, jv_result, attr, result, CT_FALSE),
                                    json_ass, attr, result);
    return CT_SUCCESS;
}

status_t sql_get_json_exists_result(variant_t *result, json_value_t *jv_result_array)
{
    result->is_null = CT_FALSE;
    result->type = CT_TYPE_BOOLEAN;
    result->v_bool = (jv_result_array->array->count == 0) ? CT_FALSE : CT_TRUE;
    return CT_SUCCESS;
}

status_t sql_get_json_value_result(json_assist_t *json_ass, variant_t *result, json_func_attr_t attr,
    json_value_t *jv_result_array)
{
    JSON_RETURN_IF_ON_EMPTY_HANDLED(jv_result_array->array->count > 0, json_ass, attr, result);
    if (jv_result_array->array->count > 1) {
        CT_THROW_ERROR(ERR_JSON_VALUE_MISMATCHED, json_ass->is_json_retrieve ? "JSON_VALUE" : "JSONB_VALUE", "multiple");
        JSON_RETURN_IF_ON_ERROR_HANDLED(CT_ERROR, json_ass, attr, result);
    }

    json_value_t *jv_result = (json_value_t *)cm_galist_get(jv_result_array->array, 0);
    if (!JSON_VAL_IS_SCALAR(jv_result)) {
        CT_THROW_ERROR(ERR_JSON_VALUE_MISMATCHED, json_ass->is_json_retrieve ? "JSON_VALUE" : "JSONB_VALUE", "non-scalar");
        JSON_RETURN_IF_ON_ERROR_HANDLED(CT_ERROR, json_ass, attr, result);
    }

    // treat JSON_VAL_NULL as NULL
    if (jv_result->type == JSON_VAL_NULL) {
        result->is_null = CT_TRUE;
        result->type = CT_TYPE_STRING;
        return CT_SUCCESS;
    }

    // handle returning clause
    JSON_RETURN_IF_ON_ERROR_HANDLED(handle_returning_clause(json_ass, jv_result, attr, result, CT_TRUE),
                                    json_ass, attr, result);
    return CT_SUCCESS;
}

status_t sql_get_json_query_result(json_assist_t *json_ass, variant_t *result, json_func_attr_t attr,
    json_value_t *jv_result_array)
{
    JSON_RETURN_IF_ON_EMPTY_HANDLED(jv_result_array->array->count > 0, json_ass, attr, result);
    return handle_wrapper_clause(json_ass, attr, jv_result_array, result);
}

status_t json_func_get_result(json_assist_t *json_ass, expr_node_t *func, variant_t *result, json_path_t *path,
    json_value_t *json_val)
{
    json_value_t jv_result_array;
    json_ass->is_json_retrieve = CT_TRUE;
    CT_RETURN_IFERR(json_item_array_init(json_ass, &jv_result_array.array, JSON_MEM_VMC));
    CT_RETURN_IFERR(json_path_extract(json_val, path, &jv_result_array));

    CT_RETURN_IFERR(json_path_do_filter(json_ass, path->cond, &jv_result_array));

    // execute the inner func
    CT_RETURN_IFERR(json_path_execute_func(json_ass, path->func, &jv_result_array));

    switch (func->value.v_func.func_id) {
        case ID_FUNC_ITEM_JSON_QUERY:
            return sql_get_json_query_result(json_ass, result, func->json_func_attr, &jv_result_array);
        case ID_FUNC_ITEM_JSON_EXISTS:
            return sql_get_json_exists_result(result, &jv_result_array);
        case ID_FUNC_ITEM_JSON_VALUE:
            return sql_get_json_value_result(json_ass, result, func->json_func_attr, &jv_result_array);
        default:
            CT_SRC_THROW_ERROR(func->loc, ERR_ASSERT_ERROR, "invalid func type");
            return CT_ERROR;
    }
}

status_t json_retrieve_core(json_assist_t *json_ass, expr_node_t *func, variant_t *result)
{
    variant_t var_expr;
    variant_t var_path;
    json_path_t path;
    json_value_t json_val;
    json_func_attr_t attr = func->json_func_attr;

    // 1. eval path expr, then compile
    CT_RETURN_IFERR(sql_exec_json_func_arg(json_ass, func->argument->next, &var_path, result));
    CT_RETSUC_IFTRUE(result->type == CT_TYPE_COLUMN);
    if (result->is_null) {
        CT_THROW_ERROR(ERR_JSON_PATH_SYNTAX_ERROR, "missing expression");
        return CT_ERROR;
    }
    path.count = 0;
    CT_RETURN_IFERR(json_path_compile(json_ass, &var_path.v_text, &path, func->argument->next->loc));

    if (path.func != NULL && func->value.v_func.func_id == ID_FUNC_ITEM_JSON_EXISTS) {
        CT_THROW_ERROR(ERR_JSON_PATH_SYNTAX_ERROR, "missing expression");
        return CT_ERROR;
    }

    // 2. eval json text
    CT_RETURN_IFERR(sql_exec_json_func_arg(json_ass, func->argument, &var_expr, result));
    CT_RETSUC_IFTRUE(result->is_null || result->type == CT_TYPE_COLUMN);

    // 3. parse json text to json_value_t
    cm_trim_text(&var_expr.v_text);
    if (var_expr.v_text.len == 0 || (var_expr.v_text.str[0] != '{' && var_expr.v_text.str[0] != '[')) {
        CT_THROW_ERROR(ERR_JSON_SYNTAX_ERROR, "expect non-scalar");
        JSON_RETURN_IF_ON_ERROR_HANDLED(CT_ERROR, json_ass, attr, result);
    }
    json_ass->filter_path = ((path.count == 0) ? NULL : &path);
    JSON_RETURN_IF_ON_ERROR_HANDLED(json_parse(json_ass, &var_expr.v_text, &json_val, func->argument->loc),
                                    json_ass, attr, result);

    // 4. extract scalar from json_value_t according to path
    return json_func_get_result(json_ass, func, result, &path, &json_val);
}

status_t json_set_iteration_find(json_assist_t *json_ass, json_value_t *json_val, json_path_t *path, uint32 level);

// match indexes for step which json type  if array
status_t json_set_iteration_find_indexs_array(json_assist_t *json_ass, json_value_t *json_val,
                                              json_path_t *path, uint32 level)
{
    uint32 loop = 0;
    uint32 from_index = 0;
    uint32 to_index = 0;
    uint32 nestloop = 0;
    bool32 found = CT_FALSE;

    json_path_step_t *step = &path->steps[level];

    if (step->index_pairs_count > 0) {
        for (; loop < step->index_pairs_count; loop++) {
            from_index = step->index_pairs_list[loop].from_index;
            to_index = step->index_pairs_list[loop].to_index;

            nestloop = (nestloop <= from_index) ? from_index : nestloop;
            if (nestloop >= JSON_ARRAY_SIZE(json_val)) {
                break;
            }

            for (; (nestloop < JSON_ARRAY_SIZE(json_val)) && (nestloop <= to_index); nestloop++) {
                found = CT_TRUE;
                CT_RETURN_IFERR(json_set_iteration_find(json_ass, JSON_ARRAY_ITEM(json_val, nestloop), path, level + 1));
            }
        }
    } else {
        // when reach the end, and it is array, it will return this array when it has no any index or * flag ,
        // XXX at the end node
        if (((level + 1) == JSON_PATH_SIZE(path)) && ((step->index_flag & JSON_PATH_INDEX_IS_STAR) == 0)) {
            if (json_ass->policy != JEP_DELETE) {
                *json_val = *json_ass->jv_new_val; // if matched, do replace
            } else {
                json_val->type = JSON_VAL_DELETED;
            }
            return CT_SUCCESS;
        }

        // XX or XX[*]
        for (; loop < JSON_ARRAY_SIZE(json_val); loop++) {
            found = CT_TRUE;
            CT_RETURN_IFERR(json_set_iteration_find(json_ass, JSON_ARRAY_ITEM(json_val, loop), path, level + 1));
        }
    }

    // view all
    if ((json_ass->policy == JEP_REPLACE_OR_INSERT) && (!found) && ((level + 1) == JSON_PATH_SIZE(path))) {
        // do insert here when match no value.
        json_value_t *new_jv = NULL;
        CT_RETURN_IFERR(cm_galist_new(json_val->array, sizeof(json_value_t), (pointer_t *)&new_jv));
        *new_jv = *json_ass->jv_new_val;
    } else if (json_ass->policy == JEP_DELETE) {
        // do delete here.
        CM_ASSERT(JSON_ARRAY_SIZE(json_val) - 1 >= 0);
        for (int32 i = JSON_ARRAY_SIZE(json_val) - 1; i >= 0; i--) {
            json_value_t *val = JSON_ARRAY_ITEM(json_val, i);
            if (JSON_VAL_IS_DELETED(val)) {
                cm_galist_delete(json_val->array, (uint32)i);
            }
        }
    }

    return CT_SUCCESS;
}

status_t json_set_iteration_find_indexs(json_assist_t *json_ass, json_value_t *json_val, json_path_t *path, uint32 level)
{
    json_path_step_t *step = &path->steps[level];

    // path has more nodes,  deal the head node first
    switch (json_val->type) {
        // only can be find at 0 index
        case JSON_VAL_NULL:
        case JSON_VAL_BOOL:
        case JSON_VAL_STRING:
        case JSON_VAL_NUMBER:
            if ((step->index_pairs_count > 0) && (step->index_pairs_list[0].from_index != 0)) {
                break;
            }

            if (JSON_PATH_SIZE(path) > (level + 1)) {
                break; // scaler value don't have children
            }

            // stop at the scaler value , $ , $[*], $[0,...]
            if (json_ass->policy != JEP_DELETE) {
                *json_val = *json_ass->jv_new_val; // if matched, do replace
            } else {
                json_val->type = JSON_VAL_DELETED;
            }
            break;

        case JSON_VAL_OBJECT:
            if ((step->index_pairs_count > 0) && (step->index_pairs_list[0].from_index != 0)) {
                break;
            }

            // XX.    , XX[*].   , XX[0,...].
            CT_RETURN_IFERR(json_set_iteration_find(json_ass, json_val, path, level + 1));
            break;

        // support any index
        case JSON_VAL_ARRAY:
            CT_RETURN_IFERR(json_set_iteration_find_indexs_array(json_ass, json_val, path, level));
            break;

        default:
            // set error.
            CT_THROW_ERROR(ERR_JSON_SYNTAX_ERROR, "invalid json type in JSON data");
            return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t json_set_iteration_insert_obj(json_assist_t *json_ass, json_value_t *json_val, json_path_step_t *step)
{
    json_pair_t *new_jv = NULL;
    uint32 nPairs = JSON_OBJECT_SIZE(json_val);
    uint32 loop;

    /* insert this new val */
    CT_RETURN_IFERR(cm_galist_new(json_val->object, sizeof(json_pair_t), (pointer_t *)&new_jv));
    new_jv->key.type = JSON_VAL_STRING;
    new_jv->key.string.str = step->keyname;
    new_jv->key.string.len = step->keyname_length;
    new_jv->val = *json_ass->jv_new_val;

    if (!json_ass->need_sort || nPairs == 0) {
        return CT_SUCCESS; // insert at the last idx
    }

    /* compare && insert */
    /* sort in an Ascending order */
    for (loop = 0; loop < nPairs; loop++) {
        json_pair_t *pair = JSON_OBJECT_ITEM(json_val, loop);
        if (cm_compare_text(&new_jv->key.string, &pair->key.string) <= 0) {
            break;
        }
    }

    if (loop == nPairs) {
        return CT_SUCCESS; // insert at the last idx
    }

    for (int32 i = JSON_OBJECT_SIZE(json_val) - 1; i > loop; i--) {
        cm_galist_set(json_val->object, i, cm_galist_get(json_val->object, i - 1));
    }
    cm_galist_set(json_val->object, loop, new_jv);

    return CT_SUCCESS;
}

status_t json_set_iteration_find(json_assist_t *json_ass, json_value_t *json_val, json_path_t *path, uint32 level)
{
    // reach the end of path, it may be any type
    if (level >= JSON_PATH_SIZE(path)) {
        if (json_ass->policy != JEP_DELETE) {
            *json_val = *json_ass->jv_new_val; // if matched, do replace
        } else {
            json_val->type = JSON_VAL_DELETED;
        }
        return CT_SUCCESS;
    }

    json_path_step_t *step = &path->steps[level];

    // internal node must be object or array
    if (json_val->type != JSON_VAL_OBJECT) {
        if (json_val->type == JSON_VAL_ARRAY && !step->keyname_exists &&
            (step->keyname_length == 0 || (step->keyname_flag & JSON_PATH_KEYNAME_IS_STAR))) {
            CT_RETURN_IFERR(json_set_iteration_find_indexs_array(json_ass, json_val, path, level));
        }
        return CT_SUCCESS;
    }

    json_pair_t *pair = NULL;
    bool32 found = CT_FALSE;

    // foreach every key-value pairs
    for (uint32 loop = 0; loop < JSON_OBJECT_SIZE(json_val); loop++) {
        pair = JSON_OBJECT_ITEM(json_val, loop);
        // * match any name
        if ((step->keyname_flag & JSON_PATH_KEYNAME_IS_STAR) == 0) {
            if (pair->key.string.len != step->keyname_length ||
                cm_compare_text_str(&pair->key.string, step->keyname) != 0) {
                continue; // if not match name
            }
        }
        found = CT_TRUE;
        CT_RETURN_IFERR(json_set_iteration_find_indexs(json_ass, &pair->val, path, level));
    }

    // view all
    if ((json_ass->policy == JEP_REPLACE_OR_INSERT) && (!found) && ((level + 1) == JSON_PATH_SIZE(path))) {
        // do insert here when match no value.
        CT_RETURN_IFERR(json_set_iteration_insert_obj(json_ass, json_val, step));
    } else if (json_ass->policy == JEP_DELETE) {
        // do delete here.
        for (int32 i = JSON_OBJECT_SIZE(json_val) - 1; i >= 0; i--) {
            pair = JSON_OBJECT_ITEM(json_val, i);
            if (JSON_VAL_IS_DELETED(&pair->val)) {
                cm_galist_delete(json_val->object, (uint32)i);
            }
        }
    }

    return CT_SUCCESS;
}

status_t json_set_iteration(json_assist_t *json_ass, json_value_t *jv_target, json_path_t *path)
{
    CM_POINTER2(path, jv_target);

    // the count of path for full tree, just only need one or zero
    uint32 headlevel = 0;

    // DFS , no error, just match or no match
    return json_set_iteration_find_indexs(json_ass, jv_target, path, headlevel);
}

status_t json_set_core(json_assist_t *json_ass, json_value_t *jv_target, json_path_t *path, json_func_attr_t attr,
    variant_t *result)
{
    // extract the json tree, according the path and policy, and ignore the filter path && json_func.
    json_ass->need_sort = CT_FALSE;
    CT_RETURN_IFERR(json_set_iteration(json_ass, jv_target, path));

    if (JSON_VAL_IS_DELETED(jv_target)) {
        result->is_null = CT_TRUE;
        result->type = CT_TYPE_STRING;
        return CT_SUCCESS;
    }

    // handle returning clause
    JSON_RETURN_IF_ON_ERROR_HANDLED(handle_returning_clause(json_ass, jv_target, attr, result, CT_FALSE), json_ass, attr, result);
    return CT_SUCCESS;
}

// ============================================================================
// JSON PATH PARSE, COMPILE, EXTRACT
static inline bool32 json_path_is_last_char(text_t *path_text, uint32 curr_index)
{
    return (curr_index == (path_text->len - 1));
}

static inline bool32 json_path_is_end(text_t *path_text, uint32 curr_index)
{
    return (curr_index >= path_text->len);
}

static bool32 json_path_match_1_word(text_t *path_text, uint32 curr_index, const char *str, uint32 len)
{
    text_t tmp;

    if ((curr_index + len) > path_text->len) {
        return CT_FALSE;
    }

    tmp.str = path_text->str + curr_index;
    tmp.len = len;

    return cm_text_str_equal_ins(&tmp, str);
}

static void json_path_get_prev_char_idx(text_t *path_text, uint32 curr_index, int32 *prev_char_index)
{
    int32 loop;

    *prev_char_index = -1;
    for (loop = (int32)(curr_index - 1); loop >= 0; loop--) {
        if (path_text->str[loop] == JSON_PATH_CHR_SPACE) {
            continue;
        } else {
            *prev_char_index = loop;
            return;
        }
    }

    return;
}

static void json_path_get_next_char_idx(text_t *path_text, uint32 curr_index, uint32 *next_char_index)
{
    uint32 loop;

    *next_char_index = path_text->len;
    for (loop = (curr_index + 1); loop < path_text->len; loop++) {
        if (path_text->str[loop] == JSON_PATH_CHR_SPACE) {
            continue;
        } else {
            *next_char_index = loop;
            return;
        }
    }

    return;
}

#define CHECK_PATH_EXPR_MAX_LEN(count)                                                                               \
    do {                                                                                                             \
        if ((count) > JSON_PATH_MAX_LEN) {                                                                           \
            CT_THROW_ERROR_EX(ERR_JSON_PATH_SYNTAX_ERROR, "exceed max path length(maximum: %u)", JSON_PATH_MAX_LEN); \
            return CT_ERROR;                                                                                         \
        }                                                                                                            \
    } while (0);

#define CHECK_PATH_EXPR_MAX_LEVEL(count)                                                             \
    do {                                                                                             \
        if ((count) > JSON_PATH_MAX_LEVEL) {                                                         \
            CT_THROW_ERROR_EX(ERR_JSON_PATH_SYNTAX_ERROR, "exceed max path nest level(maximum: %u)", \
                JSON_PATH_MAX_LEVEL);                                                                \
            return CT_ERROR;                                                                         \
        }                                                                                            \
    } while (0);

static void json_path_fill_step_keyname_flag(json_path_step_t *step)
{
    if (step->keyname_length == 1 && step->keyname[0] == JSON_PATH_CHR_STAR) {
        step->keyname_flag |= JSON_PATH_KEYNAME_IS_STAR;
        step->keyname_exists = CT_FALSE;
    }

    // add another flag here
    return;
}

#define GET_INDEX_NUMBER_FROM_STR(trim_tmp, num_end, num_start)                                    \
    do {                                                                                          \
        char index_tmp_single_str[32] = {""};                                                     \
        text_t tmp_num_str;                                                                       \
        tmp_num_str.str = (trim_tmp).str + (num_start);                                            \
        tmp_num_str.len = (num_end) - (num_start);                                                \
        cm_trim_text(&tmp_num_str);                                                               \
        if (tmp_num_str.len >= 32) {                                                              \
            CT_THROW_ERROR(ERR_JSON_PATH_SYNTAX_ERROR, "the indexes too long");                   \
            return CT_ERROR;                                                                      \
        }                                                                                         \
        MEMS_RETURN_IFERR(strncpy_s(index_tmp_single_str, 32, tmp_num_str.str, tmp_num_str.len)); \
        index_tmp_single_str[tmp_num_str.len] = '\0';                                             \
        CT_RETURN_IFERR(cm_str2uint32(index_tmp_single_str, &num_val));                         \
    } while (0);

#define CLEAR_ALL_PARAMS_FOR_NEXT_STEP(begin_index, mid_index, end_index, bracket_count, continus_array_flag)    \
    do {                                                                                                        \
        begin_index = -1;                                                                                       \
        mid_index = -1;                                                                                         \
        end_index = -1;                                                                                         \
        bracket_count = 0;                                                                                       \
        continus_array_flag = CT_FALSE;                                                                         \
    } while (0);

static status_t json_path_check_dot_valid(text_t *path_text, json_path_t *path, bool32 continus_array_flag,
    uint32 curr_index)
{
    uint32 next_char_index = 0;

    if (!continus_array_flag) {
        json_path_get_next_char_idx(path_text, curr_index, &next_char_index);
        if (!json_path_is_end(path_text, next_char_index) &&
            (path_text->str[next_char_index] == JSON_PATH_CHR_SQBRACKET_L)) {
            JSON_PATH_RESET(path);
            CT_THROW_ERROR(ERR_JSON_PATH_SYNTAX_ERROR, "step name not specified");
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

#define CHAR_IS_NORMAL_VAR_NAME(c) \
    ((CM_IS_DIGIT(c)) || ((c) >= 'A' && (c) <= 'Z') || ((c) >= 'a' && (c) <= 'z') || ((c) == '_'))

static status_t json_path_check_stepname_valid(json_path_step_t *step)
{
    uint16 loop = 0;
    if (step->keyname_flag & JSON_PATH_KEYNAME_IS_STAR) {
        return CT_SUCCESS;
    }

    for (; loop < step->keyname_length; loop++) {
        if (!CHAR_IS_NORMAL_VAR_NAME(step->keyname[loop])) {
            CT_THROW_ERROR(ERR_JSON_PATH_SYNTAX_ERROR, "unexpected char in step name without \" wrapper");
            return CT_ERROR;
        }
    }

    if (CM_IS_DIGIT(step->keyname[0])) {
        CT_THROW_ERROR(ERR_JSON_PATH_SYNTAX_ERROR, "first char of step name without \" wrapper can't be digit");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t json_path_generate_keyname(text_t *path_text, json_path_step_t *step, int32 begin_index,
    int32 end_index)
{
    text_t trimtmp;
    bool32 has_quto = CT_FALSE;

    trimtmp.str = path_text->str + begin_index;
    trimtmp.len = (uint32)(end_index - begin_index);
    cm_trim_text(&trimtmp);

    if (trimtmp.str[0] == '"' && trimtmp.str[trimtmp.len - 1] == '"') {
        has_quto = CT_TRUE;
        trimtmp.str++;
        trimtmp.len -= 2;
    }

    step->keyname_length = trimtmp.len;
    if (step->keyname_length > JSON_PATH_MAX_STEP_NAME_LEN) {
        CT_THROW_ERROR_EX(ERR_JSON_PATH_SYNTAX_ERROR,
            "the current length(%u) of step name has exceeded maximum length(%u)", step->keyname_length,
            JSON_PATH_MAX_STEP_NAME_LEN);
        return CT_ERROR;
    }

    MEMS_RETURN_IFERR(
        strncpy_s(step->keyname, (int)(JSON_PATH_MAX_STEP_NAME_LEN + 1), trimtmp.str, step->keyname_length));

    step->keyname[step->keyname_length] = '\0';
    step->keyname_exists = CT_TRUE;
    json_path_fill_step_keyname_flag(step);

    if (!has_quto) {
        CT_RETURN_IFERR(json_path_check_stepname_valid(step));
    }

    return CT_SUCCESS;
}

static status_t json_path_generate_indexes(text_t *path_text, json_path_step_t *step, int32 begin_index, int end_index)
{
    int32 loop;
    uint32 num_val;
    uint32 loop_count = 0;
    char loop_char;
    int32 num_start = -1;
    int32 num_end = -1;
    bool32 has_to_chrs = CT_FALSE;
    text_t trim_tmp;

    if (end_index <= begin_index) {
        CT_THROW_ERROR(ERR_JSON_PATH_SYNTAX_ERROR, "array subscript not specified");
        return CT_ERROR;
    }

    trim_tmp.str = path_text->str + begin_index;
    trim_tmp.len = (uint32)(end_index - begin_index);
    cm_trim_text(&trim_tmp);

    // there is only a * char in []
    if (trim_tmp.len == 1 && trim_tmp.str[0] == JSON_PATH_CHR_STAR) {
        step->index_flag |= JSON_PATH_INDEX_IS_STAR;
        return CT_SUCCESS;
    }

    // get indexs pairs
    for (loop = 0; (uint32)loop <= trim_tmp.len;) {
        // reach the end, deal as comma,  it seems like add a , behind of the str
        loop_char = json_path_is_end(&trim_tmp, (uint32)loop) ? JSON_PATH_CHR_COMMA : trim_tmp.str[loop];
        if (loop_count >= JSON_PATH_MAX_ARRAY_IDX_CNT) {
            CT_THROW_ERROR_EX(ERR_JSON_PATH_SYNTAX_ERROR, "exceed max array index pairs(maximum: %u)",
                JSON_PATH_MAX_ARRAY_IDX_CNT);
            return CT_ERROR;
        }

        switch (loop_char) {
            case JSON_PATH_CHR_SPACE:
                loop++;
                break;

            case JSON_PATH_CHR_COMMA:

                num_end = loop;
                if (num_start < 0) {
                    if (!has_to_chrs) {
                        CT_THROW_ERROR(ERR_JSON_PATH_SYNTAX_ERROR, "invalid array index");
                        return CT_ERROR;
                    }

                    // to          ,
                    step->index_pairs_list[loop_count].to_index = step->index_pairs_list[loop_count].from_index;
                } else {
                    // make the str to number
                    GET_INDEX_NUMBER_FROM_STR(trim_tmp, num_end, num_start);

                    // check the index order
                    if (loop_count > 0 && num_val < step->index_pairs_list[loop_count - 1].to_index) {
                        CT_THROW_ERROR(ERR_JSON_PATH_SYNTAX_ERROR, "invalid order of array indexes");
                        return CT_ERROR;
                    }
                    if (!has_to_chrs) {
                        // ,XX,
                        step->index_pairs_list[loop_count].from_index = num_val;
                    }
                    step->index_pairs_list[loop_count].to_index = num_val;

                    // check the index order
                    if (step->index_pairs_list[loop_count].to_index < step->index_pairs_list[loop_count].from_index) {
                        CT_THROW_ERROR(ERR_JSON_PATH_SYNTAX_ERROR, "invalid order of array indexes");
                        return CT_ERROR;
                    }
                }

                loop++;
                loop_count++;
                num_start = -1;
                num_end = -1;
                has_to_chrs = CT_FALSE;
                break;

            case JSON_PATH_CHR_STAR:
                CT_THROW_ERROR(ERR_JSON_PATH_SYNTAX_ERROR, "array wildcard must be used alone");
                return CT_ERROR;

            default:
                // number
                if (CM_IS_DIGIT(loop_char)) {
                    if (num_start < 0) {
                        num_start = loop;
                    }
                    loop++;
                    break;
                }

                // to
                if (json_path_match_1_word(&trim_tmp, (uint32)loop, "TO", 2)) {
                    num_end = loop;
                    has_to_chrs = CT_TRUE;

                    // ,     to
                    if (num_start < 0) {
                        step->index_pairs_list[loop_count].from_index =
                            loop_count > 0 ? step->index_pairs_list[loop_count - 1].to_index : 0;
                        loop += 2;
                        break;
                    }

                    // ,  XX   to ,    make the str to number
                    GET_INDEX_NUMBER_FROM_STR(trim_tmp, num_end, num_start);

                    // check the index order
                    if (loop_count > 0 && num_val < step->index_pairs_list[loop_count - 1].to_index) {
                        CT_THROW_ERROR(ERR_JSON_PATH_SYNTAX_ERROR, "invalid order of array indexes");
                        return CT_ERROR;
                    }
                    step->index_pairs_list[loop_count].from_index = num_val;

                    loop += 2;
                    num_start = -1;
                    num_end = -1;
                    break;
                }

                CT_THROW_ERROR(ERR_JSON_PATH_SYNTAX_ERROR, "invlid array index");
                return CT_ERROR;
        }
    }

    step->index_pairs_count = loop_count;
    return CT_SUCCESS;
}

static status_t json_path_generate_array_step(text_t *path_text, json_path_t *path, uint32 loop_count,
    int32 begin_index, int32 mid_index, int32 end_index)
{
    status_t status;
    json_path_step_t *path_step = NULL;

    // firstly, generate keyname node
    path_step = JSON_PATH_ITEM(path, loop_count);
    path_step->type = JSON_PATH_STEP_ARRAY;

    if (begin_index < mid_index) {
        status = json_path_generate_keyname(path_text, path_step, begin_index, mid_index);
        if (status != CT_SUCCESS) {
            JSON_PATH_RESET(path);
            return status;
        }
    } else {
        // nothing
    }

    // then, get index number //
    status = json_path_generate_indexes(path_text, path_step, mid_index + 1, end_index);
    if (status != CT_SUCCESS) {
        JSON_PATH_RESET(path);
        return status;
    }

    return CT_SUCCESS;
}

static status_t json_path_generate_keyname_step(text_t *path_text, json_path_t *path, uint32 loop_count,
    int32 begin_index, int32 end_index)
{
    status_t status;
    json_path_step_t *path_step = NULL;

    if (begin_index < 0) {
        JSON_PATH_RESET(path);
        CT_THROW_ERROR(ERR_JSON_PATH_SYNTAX_ERROR, "invlid step name");
        return CT_ERROR;
    }

    // generate keyname node only
    path_step = JSON_PATH_ITEM(path, loop_count);
    path_step->type = JSON_PATH_STEP_KEYNAME;
    status = json_path_generate_keyname(path_text, path_step, begin_index, end_index);
    if (status != CT_SUCCESS) {
        JSON_PATH_RESET(path);
        return status;
    }

    return CT_SUCCESS;
}

static status_t json_path_generate_head_step_idxes(text_t *path_text, json_path_t *path, int32 mid_index,
    int32 end_index)
{
    status_t status;
    json_path_step_t *step = JSON_PATH_ITEM(path, 0);

    step->type = JSON_PATH_STEP_HEAD;
    // then, get index number
    status = json_path_generate_indexes(path_text, step, mid_index + 1, end_index);
    if (status != CT_SUCCESS) {
        JSON_PATH_RESET(path);
        return status;
    }

    return CT_SUCCESS;
}

static status_t json_path_generate_head_step(text_t *path_text, json_path_t *path, uint32 *loop_count, uint32 *curr_idx)
{
    json_path_step_t *path_step = NULL;
    uint32 next_char_index = 0;

    if (*curr_idx > 0) {
        JSON_PATH_RESET(path);
        CT_THROW_ERROR(ERR_JSON_PATH_SYNTAX_ERROR, "path must start with $ character");
        return CT_ERROR;
    }

    path_step = JSON_PATH_ITEM(path, (*loop_count));
    path_step->type = JSON_PATH_STEP_HEAD;

    if (json_path_is_last_char(path_text, *curr_idx)) { // $
        *curr_idx = path_text->len + 1;                 // to break outer big loop in json_path_compile_core
        *loop_count = *loop_count + 1;
        return CT_SUCCESS;
    }

    json_path_get_next_char_idx(path_text, *curr_idx, &next_char_index);
    if (path_text->str[next_char_index] == JSON_PATH_CHR_DOT) { // $.
        *curr_idx = next_char_index + 1;
        *loop_count = *loop_count + 1;
    } else if (path_text->str[next_char_index] == JSON_PATH_CHR_SQBRACKET_L) { // $[
        // no end for head node, will parse indexes in [] later
        *curr_idx = next_char_index;
    } else {
        JSON_PATH_RESET(path);
        CT_THROW_ERROR(ERR_JSON_PATH_SYNTAX_ERROR, "path must start with $ character");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t json_path_skip_next_quto_idx(text_t *path_text, uint32 *loop)
{
    bool32 flag = CT_FALSE;
    uint16 loop_tmp = *loop + 1;
    int32 prev_chr_idx = -1;

    json_path_get_prev_char_idx(path_text, *loop, &prev_chr_idx);
    if ((prev_chr_idx == -1) || path_text->str[prev_chr_idx] != '.') {
        CT_THROW_ERROR(ERR_JSON_PATH_SYNTAX_ERROR, "Invalid step name");
        return CT_ERROR;
    }
    for (; loop_tmp < path_text->len; loop_tmp++) {
        if (path_text->str[loop_tmp] == '"' && path_text->str[loop_tmp - 1] != '\\') {
            flag = CT_TRUE;
            *loop = loop_tmp + 1;
            break;
        }
    }

    if (!flag) {
        CT_THROW_ERROR(ERR_JSON_PATH_SYNTAX_ERROR, "Invalid step name");
        return CT_ERROR;
    }

    if (!(json_path_is_end(path_text, *loop) || path_text->str[*loop] == '.' || path_text->str[*loop] == '[' ||
        path_text->str[*loop] == ' ')) {
        CT_THROW_ERROR(ERR_JSON_PATH_SYNTAX_ERROR, "Invalid step name");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t json_path_func_step_skip_brack(text_t *path_text)
{
    int32 prev_chr_idx = -1;
    json_path_get_prev_char_idx(path_text, path_text->len - 1, &prev_chr_idx);
    if ((prev_chr_idx <= 0) || path_text->str[prev_chr_idx] != JSON_PATH_CHR_BRACKET_L) {
        CT_THROW_ERROR(ERR_JSON_PATH_SYNTAX_ERROR, "Invalid json func");
        return CT_ERROR;
    }

    path_text->len = prev_chr_idx;

    cm_trim_text(path_text);
    return CT_SUCCESS;
}

static status_t json_path_func_step_find_name(text_t *path_text, json_path_t *path)
{
    int32 last_dot_idx = path_text->len - 1;
    text_t func;
    for (; last_dot_idx >= 0; last_dot_idx--) {
        if (path_text->str[last_dot_idx] == JSON_PATH_CHR_DOT) {
            break;
        }
    }

    if (last_dot_idx <= 0 || last_dot_idx == (path_text->len - 1)) {
        CT_THROW_ERROR(ERR_JSON_PATH_SYNTAX_ERROR, "Invalid json func");
        return CT_ERROR;
    }

    func.str = path_text->str + (last_dot_idx + 1);
    func.len = path_text->len - 1 - last_dot_idx;
    json_func_step_item_t *item = json_func_step_match_item(&func);
    if (item == NULL) {
        CT_THROW_ERROR(ERR_JSON_PATH_SYNTAX_ERROR, "Invalid json func");
        return CT_ERROR;
    }

    path->func = item;
    path_text->len = last_dot_idx;
    cm_trim_text(path_text);
    return CT_SUCCESS;
}

static status_t json_path_generate_func_step(text_t *path_text, json_path_t *path)
{
    cm_trim_text(path_text);

    // there is no func at the end of path, it wil be ok
    if (path_text->str[path_text->len - 1] != JSON_PATH_CHR_BRACKET_R) {
        return CT_SUCCESS;
    }

    // skip the '(' and ')' chars
    CT_RETURN_IFERR(json_path_func_step_skip_brack(path_text));

    // find the func
    CT_RETURN_IFERR(json_path_func_step_find_name(path_text, path));

    return CT_SUCCESS;
}

// compile the json select path expr , path(func)
static status_t json_path_compile_core(text_t *path_text, json_path_t *path)
{
    int32 loop;
    char loop_char;
    int32 begin_index = -1;
    int32 mid_index = -1;
    int32 end_index = -1;
    uint32 loop_count = 0;
    uint32 bracket_count = 0;
    uint32 next_char_index = 0;
    bool32 continus_array_flag = CT_FALSE;

    // init data set and path str
    JSON_PATH_RESET(path);
    cm_trim_text(path_text);
    CHECK_PATH_EXPR_MAX_LEN(path_text->len);

    // check if the expr is vaild
    if ((path_text->len < JSON_PATH_MIN_LEN) || (path_text->str[0]) != JSON_PATH_CHR_BEGIN) {
        CT_THROW_ERROR(ERR_JSON_PATH_SYNTAX_ERROR, "path must start with $ character");
        return CT_ERROR;
    }

    // try to find the inner func
    CT_RETURN_IFERR(json_path_generate_func_step(path_text, path));
    cm_trim_text(path_text);

    for (loop = 0; (uint32)loop <= path_text->len;) {
        // if there is "" , ignore all special char below
        // followed by [] or . or str_end
        // behind of .
        // check it is not escaped "
        if ((!json_path_is_end(path_text, (uint32)loop)) &&
            (path_text->str[loop] == '"' && path_text->str[loop - 1] != '\\')) {
            begin_index = loop;
            CT_RETURN_IFERR(json_path_skip_next_quto_idx(path_text, (uint32 *)&loop));
        }

        // reach the end or has continues array flag, deal as dot , it seems like add a dot behind of the str
        loop_char = (continus_array_flag || json_path_is_end(path_text, (uint32)loop)) ? JSON_PATH_CHR_DOT :
                                                                                         path_text->str[loop];

        CHECK_PATH_EXPR_MAX_LEVEL(loop_count + 1);
        switch (loop_char) {
            case JSON_PATH_CHR_SPACE:
                loop++;
                break;

            case JSON_PATH_CHR_BEGIN:

                // generate head node
                CT_RETURN_IFERR(json_path_generate_head_step(path_text, path, &loop_count, (uint32 *)&loop));
                break;

            case JSON_PATH_CHR_SQBRACKET_L:

                if (bracket_count > 0) {
                    JSON_PATH_RESET(path);
                    CT_THROW_ERROR(ERR_JSON_PATH_SYNTAX_ERROR, "invlid array index");
                    return CT_ERROR;
                }
                bracket_count++;

                mid_index = loop;
                loop++;
                break;

            case JSON_PATH_CHR_SQBRACKET_R:
                end_index = loop;
                json_path_get_next_char_idx(path_text, (uint32)loop, &next_char_index);
                if (json_path_is_end(path_text, next_char_index) ||
                    (path_text->str[next_char_index] == JSON_PATH_CHR_DOT)) {
                    loop = next_char_index;
                } else if (path_text->str[next_char_index] == JSON_PATH_CHR_SQBRACKET_L) {
                    // assume that there is a '.' char here... , and dont't change the lopp value
                    CHECK_PATH_EXPR_MAX_LEVEL(loop_count + 1);
                    continus_array_flag = CT_TRUE;
                } else {
                    JSON_PATH_RESET(path);
                    CT_THROW_ERROR(ERR_JSON_PATH_SYNTAX_ERROR, "");
                    return CT_ERROR;
                }

                break;

            case JSON_PATH_CHR_DOT:

                // check if this dot is valid...
                CT_RETURN_IFERR(json_path_check_dot_valid(path_text, path, continus_array_flag, (uint32)loop));

                // no [
                if (mid_index < 0) {
                    end_index = loop;

                    // generate keyname node only
                    CT_RETURN_IFERR(
                        json_path_generate_keyname_step(path_text, path, loop_count, begin_index, end_index));
                } else {
                    // has [
                    if (end_index > 0 && loop_count == 0) {
                        // continue to generate the head node
                        CT_RETURN_IFERR(json_path_generate_head_step_idxes(path_text, path, mid_index, end_index));
                    } else if (begin_index < 0 || end_index < 0) {
                        JSON_PATH_RESET(path);
                        CT_THROW_ERROR(ERR_JSON_PATH_SYNTAX_ERROR, "");
                        return CT_ERROR;
                    } else {
                        // generate path array step, medium step , not head step
                        CT_RETURN_IFERR(json_path_generate_array_step(path_text, path, loop_count, begin_index,
                            mid_index, end_index));
                    }
                }

                loop_count++;
                loop++;

                // clear all index for the next node
                CLEAR_ALL_PARAMS_FOR_NEXT_STEP(begin_index, mid_index, end_index, bracket_count, continus_array_flag);
                break;

            default:
                if (begin_index < 0) {
                    begin_index = loop;
                }
                loop++;
                break;
        }
    }

    path->count = loop_count;
    return CT_SUCCESS;
}

// expr equals path(func) plus '?' plus filter
status_t json_path_compile(json_assist_t *json_ass, text_t *path_text, json_path_t *path, source_location_t loc)
{
    uint32 loop = 0;
    bool32 find = CT_FALSE;
    bool32 quotation = CT_FALSE;
    int32 char_index = -1;
    text_t temp_expr = *path_text;

    // find the index of ?
    for (; loop < temp_expr.len; loop++) {
        if (temp_expr.str[loop] == '"') {
            if (loop == 0 || temp_expr.str[loop - 1] == '\\') {
                continue;
            }
            quotation = !quotation;
        }
        if (!quotation && (temp_expr.str[loop] == JSON_PATH_CHR_QUESTION)) {
            if (find) {
                CT_THROW_ERROR(ERR_JSON_PATH_SYNTAX_ERROR, "? must followed by parenthetical expression");
                return CT_ERROR;
            }
            find = CT_TRUE;
            char_index = (int32)loop;
        }
    }

    if (!find) {
        // only main path without filter...
        return json_path_compile_core(path_text, path);
    }

    // path(func)
    if (char_index <= 0) {
        CT_THROW_ERROR(ERR_JSON_PATH_SYNTAX_ERROR, "missing expression");
        return CT_ERROR;
    }

    temp_expr.len = (uint32)char_index;
    CT_RETURN_IFERR(json_path_compile_core(&temp_expr, path));

    // filter clause reserved
    if (find && ((uint32)(char_index + 1) >= path_text->len)) {
        CT_THROW_ERROR(ERR_JSON_PATH_SYNTAX_ERROR, "missing expression");
        return CT_ERROR;
    }

    temp_expr.str = path_text->str + char_index + 1;
    temp_expr.len = path_text->len - char_index - 1;

    CT_RETURN_IFERR(json_pf_create_cond_from_text(json_ass, &temp_expr, &path->cond, loc));

    return CT_SUCCESS;
}

static status_t json_path_extract_find(json_value_t *json_val, json_path_t *path, uint32 level,
    json_value_t *jv_result_array);
// match indexes for step which json type  if array
static status_t json_path_extract_find_indexs_array(json_value_t *json_val, json_path_t *path, uint32 level,
    json_value_t *jv_result_array)
{
    uint32 loop = 0;
    uint32 from_index = 0;
    uint32 to_index = 0;
    uint32 nest_loop = 0;

    json_path_step_t *step = &path->steps[level];

    if (step->index_pairs_count > 0) {
        for (; loop < step->index_pairs_count; loop++) {
            from_index = step->index_pairs_list[loop].from_index;
            to_index = step->index_pairs_list[loop].to_index;

            nest_loop = (nest_loop <= from_index) ? from_index : nest_loop;
            if (nest_loop >= JSON_ARRAY_SIZE(json_val)) {
                break;
            }

            for (; (nest_loop < JSON_ARRAY_SIZE(json_val)) && (nest_loop <= to_index); nest_loop++) {
                CT_RETURN_IFERR(
                    json_path_extract_find(JSON_ARRAY_ITEM(json_val, nest_loop), path, level + 1, jv_result_array));
            }
        }
    } else {
        // when reach the end, and it is array, it will return this array when it has no any index or * flag ,
        // XXX at the end node
        if (((level + 1) == JSON_PATH_SIZE(path)) && ((step->index_flag & JSON_PATH_INDEX_IS_STAR) == 0)) {
            json_value_t *new_jv = NULL;
            CT_RETURN_IFERR(cm_galist_new(jv_result_array->array, sizeof(json_value_t), (pointer_t *)&new_jv));
            *new_jv = *json_val;
            return CT_SUCCESS;
        }

        // XX or XX[*]
        for (; loop < JSON_ARRAY_SIZE(json_val); loop++) {
            CT_RETURN_IFERR(json_path_extract_find(JSON_ARRAY_ITEM(json_val, loop), path, level + 1, jv_result_array));
        }
    }

    return CT_SUCCESS;
}

static status_t json_path_extract_find_indexs(json_value_t *json_val, json_path_t *path, uint32 level,
    json_value_t *jv_result_array)
{
    json_path_step_t *step = &path->steps[level];

    // path has more nodes,  deal the head node first
    switch (json_val->type) {
        // only can be find at 0 index
        case JSON_VAL_NULL:
        case JSON_VAL_BOOL:
        case JSON_VAL_STRING:
        case JSON_VAL_NUMBER:
            if ((step->index_pairs_count > 0) && (step->index_pairs_list[0].from_index != 0)) {
                break;
            }

            if (JSON_PATH_SIZE(path) > (level + 1)) {
                break; // scaler value don't have children
            }

            // stop at the scaler value , $ , $[*], $[0,...]
            json_value_t *new_jv = NULL;
            CT_RETURN_IFERR(cm_galist_new(jv_result_array->array, sizeof(json_value_t), (pointer_t *)&new_jv));
            *new_jv = *json_val;
            break;

        case JSON_VAL_OBJECT:
            if ((step->index_pairs_count > 0) && (step->index_pairs_list[0].from_index != 0)) {
                break;
            }

            // XX.    , XX[*].   , XX[0,...].
            CT_RETURN_IFERR(json_path_extract_find(json_val, path, level + 1, jv_result_array));
            break;

        // support any index
        case JSON_VAL_ARRAY:
            CT_RETURN_IFERR(json_path_extract_find_indexs_array(json_val, path, level, jv_result_array));
            break;

        default:
            cm_galist_reset(jv_result_array->array);
            break;
    }

    return CT_SUCCESS;
}

static status_t json_path_extract_find(json_value_t *json_val, json_path_t *path, uint32 level, json_value_t *jv_result_array)
{
    // reach the end of path, it may be any type
    if (level >= JSON_PATH_SIZE(path)) {
        json_value_t *new_jv = NULL;
        CT_RETURN_IFERR(cm_galist_new(jv_result_array->array, sizeof(json_value_t), (pointer_t *)&new_jv));
        *new_jv = *json_val;
        return CT_SUCCESS;
    }

    json_path_step_t *step = &path->steps[level];
    json_pair_t *pair = NULL;

    // internal node must be object or array
    if (json_val->type != JSON_VAL_OBJECT) {
        if (json_val->type == JSON_VAL_ARRAY && !step->keyname_exists &&
            (step->keyname_length == 0 || (step->keyname_flag & JSON_PATH_KEYNAME_IS_STAR))) {
            CT_RETURN_IFERR(json_path_extract_find_indexs_array(json_val, path, level, jv_result_array));
        }
        return CT_SUCCESS;
    }
    // foreach every key-value pairs
    for (uint32 loop = 0; loop < JSON_OBJECT_SIZE(json_val); loop++) {
        pair = JSON_OBJECT_ITEM(json_val, loop);
        // * match any name
        if ((step->keyname_flag & JSON_PATH_KEYNAME_IS_STAR) == 0) {
            if (pair->key.string.len != step->keyname_length ||
                cm_compare_text_str(&pair->key.string, step->keyname) != 0) {
                continue; // if not match name
            }
        }
        CT_RETURN_IFERR(json_path_extract_find_indexs(&pair->val, path, level, jv_result_array));
    }
    return CT_SUCCESS;
}

// this extract return NULL, scaler, vector
// if it has mutipul pathes, return error, otherwise, just match or no match
// start withlevel 0
// deal head node first
// finally, extract no value means not matched if jv_result is still null
status_t json_path_extract(json_value_t *json_val, json_path_t *path, json_value_t *jv_result_array)
{
    CM_POINTER2(path, json_val);

    // the count of path for full tree, just only need one or zero
    uint32 headlevel = 0;

    jv_result_array->type = JSON_VAL_ARRAY;

    // DFS , no error, just match or no match
    return json_path_extract_find_indexs(json_val, path, headlevel, jv_result_array);
}

int json_object_item_idx(json_value_t *json_val, text_t *key)
{
    uint32 j;
    json_pair_t *pair = NULL;
    for (j = 0; j < JSON_OBJECT_SIZE(json_val); j++) {
        pair = JSON_OBJECT_ITEM(json_val, j);
        if (cm_text_equal(&pair->key.string, key)) {
            break;
        }
    }

    // found
    if (j < JSON_OBJECT_SIZE(json_val)) {
        return (int)j;
    }

    return -1;
}

status_t json_merge_patch(json_assist_t *json_ass, json_value_t *jv_target, json_value_t *jv_patch,
                          json_value_t **jv_result)
{
    json_pair_t *pair = NULL;

    // 1.  if the patch is an object, do following actions.
    if (JSON_VAL_IS_OBJECT(jv_patch)) {
        uint32 i;

        // 2.1  If the source is not an object then act as if it were the empty object ({}).
        if (!JSON_VAL_IS_OBJECT(jv_target)) {
            jv_target->type = JSON_VAL_OBJECT;
            CT_RETURN_IFERR(json_item_array_init(json_ass, &jv_target->object, JSON_MEM_LARGE_POOL));
        }

        // 2.2  Iterate over the (p-field:  v-value) members of the patch object.
        for (i = 0; i < JSON_OBJECT_SIZE(jv_patch); i++) {
            pair = JSON_OBJECT_ITEM(jv_patch, i);

            int idx = json_object_item_idx(jv_target, &pair->key.string);
            if (pair->val.type == JSON_VAL_NULL) {
                if (idx >= 0) { // found
                    // jv_patch value is null and , its field exists in jv_target, do action delete
                    cm_galist_delete(jv_target->object, (uint32)idx);
                }
            } else {
                if (idx >= 0) { // found
                    // jv_patch value is not null and , its field exists in jv_target, do action replace
                    json_value_t *jv_tmp = NULL;
                    CT_RETURN_IFERR(
                        json_merge_patch(json_ass, &(JSON_OBJECT_ITEM(jv_target, (uint32)idx))->val, &pair->val, &jv_tmp));
                    JSON_OBJECT_ITEM(jv_target, (uint32)idx)->val = *jv_tmp;
                } else {
                    // jv_patch value is not null and , its field doesn't  exist in jv_target, do action add
                    json_pair_t *new_pair = NULL;
                    CT_RETURN_IFERR(cm_galist_new(jv_target->object, sizeof(json_pair_t), (pointer_t *)&new_pair));
                    *new_pair = *pair;
                }
            }
        }

        *jv_result = jv_target;
        return CT_SUCCESS;
    }

    // 1. If the patch is not a JSON object then replace the source by the patch.
    *jv_result = jv_patch;
    return CT_SUCCESS;
}

// ============================================================================
// JSON PATH FILTER:
//     - PARSE
//     - EVAL
#define JSON_PF_RETURN_TXT2DEC_ERR(text, dec)                                           \
    do {                                                                                \
        if (cm_text_to_dec((text), (dec)) != CT_SUCCESS) {                              \
            cm_reset_error();                                                           \
            CT_THROW_ERROR(ERR_JSON_PATH_SYNTAX_ERROR, "path filter - invalid number"); \
            return CT_ERROR;                                                            \
        }                                                                               \
    } while (0)

status_t json_pf_op_and(json_value_t *left, json_value_t *right, bool32 *result)
{
    *result = CT_FALSE;
    if (left->boolean && right->boolean) {
        *result = CT_TRUE;
    }
    return CT_SUCCESS;
}

status_t json_pf_op_or(json_value_t *left, json_value_t *right, bool32 *result)
{
    *result = CT_FALSE;
    if (left->boolean || right->boolean) {
        *result = CT_TRUE;
    }
    return CT_SUCCESS;
}

status_t json_pf_op_not(json_value_t *left, json_value_t *right, bool32 *result)
{
    *result = CT_FALSE;
    if (!right->boolean) {
        *result = CT_TRUE;
    }
    return CT_SUCCESS;
}

status_t json_pf_op_eq(json_value_t *left, json_value_t *right, bool32 *result)
{
    variant_t v_left;
    variant_t v_right;

    switch (left->type) {
        case JSON_VAL_NULL:
            *result = CT_TRUE;
            break;

        case JSON_VAL_BOOL:
            *result = (left->boolean == right->boolean);
            break;

        case JSON_VAL_STRING:
            *result = (cm_compare_text(&left->string, &right->string) == 0);
            break;

        case JSON_VAL_NUMBER:
            JSON_PF_RETURN_TXT2DEC_ERR(&left->number, &v_left.v_dec);
            JSON_PF_RETURN_TXT2DEC_ERR(&right->number, &v_right.v_dec);
            *result = (cm_dec_cmp(&(v_left.v_dec), &(v_right.v_dec)) == 0);
            break;

        default:
            CT_THROW_ERROR_EX(ERR_JSON_PATH_SYNTAX_ERROR, "path filter - unexpected type %u", left->type);
            return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t json_pf_op_neq(json_value_t *left, json_value_t *right, bool32 *result)
{
    variant_t v_left;
    variant_t v_right;

    switch (left->type) {
        case JSON_VAL_NULL:
            *result = CT_FALSE;
            break;

        case JSON_VAL_BOOL:
            *result = left->boolean != right->boolean;
            break;

        case JSON_VAL_STRING:
            *result = cm_compare_text(&left->string, &right->string) != 0;
            break;

        case JSON_VAL_NUMBER:
            JSON_PF_RETURN_TXT2DEC_ERR(&left->number, &v_left.v_dec);
            JSON_PF_RETURN_TXT2DEC_ERR(&right->number, &v_right.v_dec);
            *result = (cm_dec_cmp(&(v_left.v_dec), &(v_right.v_dec)) != 0);
            break;

        default:
            CT_THROW_ERROR_EX(ERR_JSON_PATH_SYNTAX_ERROR, "path filter - unexpected type %u", left->type);
            return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t json_pf_op_lt(json_value_t *left, json_value_t *right, bool32 *result)
{
    variant_t v_left;
    variant_t v_right;

    switch (left->type) {
        case JSON_VAL_NULL:
        case JSON_VAL_BOOL:
            *result = CT_FALSE;
            break;

        case JSON_VAL_STRING:
            *result = cm_compare_text(&left->string, &right->string) < 0;
            break;

        case JSON_VAL_NUMBER:
            JSON_PF_RETURN_TXT2DEC_ERR(&left->number, &v_left.v_dec);
            JSON_PF_RETURN_TXT2DEC_ERR(&right->number, &v_right.v_dec);
            *result = cm_dec_cmp(&(v_left.v_dec), &(v_right.v_dec)) < 0;
            break;

        default:
            CT_THROW_ERROR_EX(ERR_JSON_PATH_SYNTAX_ERROR, "path filter - unexpected type %u", left->type);
            return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t json_pf_op_leq(json_value_t *left, json_value_t *right, bool32 *result)
{
    variant_t v_left;
    variant_t v_right;

    switch (left->type) {
        case JSON_VAL_NULL:
        case JSON_VAL_BOOL:
            *result = CT_FALSE;
            break;

        case JSON_VAL_STRING:
            *result = cm_compare_text(&left->string, &right->string) <= 0;
            break;

        case JSON_VAL_NUMBER:
            JSON_PF_RETURN_TXT2DEC_ERR(&left->number, &v_left.v_dec);
            JSON_PF_RETURN_TXT2DEC_ERR(&right->number, &v_right.v_dec);
            *result = cm_dec_cmp(&(v_left.v_dec), &(v_right.v_dec)) <= 0;
            break;

        default:
            CT_THROW_ERROR_EX(ERR_JSON_PATH_SYNTAX_ERROR, "path filter - unexpected type %u", left->type);
            return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t json_pf_op_gt(json_value_t *left, json_value_t *right, bool32 *result)
{
    variant_t v_left;
    variant_t v_right;

    switch (left->type) {
        case JSON_VAL_NULL:
        case JSON_VAL_BOOL:
            *result = CT_FALSE;
            break;

        case JSON_VAL_STRING:
            *result = cm_compare_text(&left->string, &right->string) > 0;
            break;

        case JSON_VAL_NUMBER:
            JSON_PF_RETURN_TXT2DEC_ERR(&left->number, &v_left.v_dec);
            JSON_PF_RETURN_TXT2DEC_ERR(&right->number, &v_right.v_dec);
            *result = cm_dec_cmp(&(v_left.v_dec), &(v_right.v_dec)) > 0;
            break;

        default:
            CT_THROW_ERROR_EX(ERR_JSON_PATH_SYNTAX_ERROR, "path filter - unexpected type %u", left->type);
            return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t json_pf_op_geq(json_value_t *left, json_value_t *right, bool32 *result)
{
    variant_t v_left;
    variant_t v_right;

    switch (left->type) {
        case JSON_VAL_NULL:
        case JSON_VAL_BOOL:
            *result = CT_FALSE;
            break;

        case JSON_VAL_STRING:
            *result = cm_compare_text(&left->string, &right->string) >= 0;
            return CT_SUCCESS;

        case JSON_VAL_NUMBER:
            JSON_PF_RETURN_TXT2DEC_ERR(&left->number, &v_left.v_dec);
            JSON_PF_RETURN_TXT2DEC_ERR(&right->number, &v_right.v_dec);
            *result = cm_dec_cmp(&(v_left.v_dec), &(v_right.v_dec)) >= 0;
            break;
        default:
            CT_THROW_ERROR_EX(ERR_JSON_PATH_SYNTAX_ERROR, "path filter - unexpected type %u", left->type);
            return CT_ERROR;
    }

    return CT_SUCCESS;
}

typedef status_t (*json_op_func_t)(json_value_t *left, json_value_t *right, bool32 *result);
typedef struct st_json_pf_op {
    char *name;
    int len;
    json_pf_op_type_t type;
    json_op_func_t func;
} json_pf_op_t;
json_pf_op_t g_json_pf_ops[] = {
    { NULL, 0, JSON_PF_OP_INVLID,       NULL },

    { "&&", 2, JSON_PF_OP_AND,          json_pf_op_and },
    { "||", 2, JSON_PF_OP_OR,           json_pf_op_or },
    { "!",  1, JSON_PF_OP_NOT,          json_pf_op_not },

    { "==", 2, JSON_PF_OP_EQ,           json_pf_op_eq },
    { "!=", 2, JSON_PF_OP_NEQ,          json_pf_op_neq },
    { "<",  1, JSON_PF_OP_LT,           json_pf_op_lt },
    { "<=", 2, JSON_PF_OP_LEQ,          json_pf_op_leq },
    { ">",  1, JSON_PF_OP_GT,           json_pf_op_gt },
    { ">=", 2, JSON_PF_OP_GEQ,          json_pf_op_geq },
    { NULL, 0, JSON_PF_OP_EXISTS,       NULL },
    { NULL, 0, JSON_PF_OP_HAS_SUBSTR,   NULL },
    { NULL, 0, JSON_PF_OP_STARTS_WITH,  NULL },
    { NULL, 0, JSON_PF_OP_LIKE,         NULL },
    { NULL, 0, JSON_PF_OP_LIKE_REGEX,   NULL },
    { NULL, 0, JSON_PF_OP_EQ_REGEX,     NULL },
    { NULL, 0, JSON_PF_OP_IN,           NULL },
};

static json_pf_op_t *json_pf_op_find(text_t *src)
{
    uint32 i;

    cm_trim_text(src);
    for (i = 0; i < sizeof(g_json_pf_ops) / sizeof(json_pf_op_t); i++) {
        if (src->len == g_json_pf_ops[i].len && g_json_pf_ops[i].name != NULL &&
            strncmp(g_json_pf_ops[i].name, src->str, g_json_pf_ops[i].len) == 0) {
            return &g_json_pf_ops[i];
        }
    }

    return NULL;
}

int32 json_pf_get_back_bracket_index(text_t *curr_text)
{
    uint32 bracket_count;
    uint32 loop = 0;
    bool32 flag = CT_FALSE;

    // to find the relative ) index
    bracket_count = 1;
    for (loop = 1; loop < curr_text->len; loop++) {
        if (curr_text->str[loop] == '"' && curr_text->str[loop - 1] != '\\') {
            flag = !flag;
        } else if (curr_text->str[loop] == '(') {
            if (!flag) {
                bracket_count++;
            }
        } else if (curr_text->str[loop] == ')') {
            if (!flag) {
                bracket_count--;
            }
            if (bracket_count == 0) {
                break;
            }
        }
    }

    if (bracket_count != 0) {
        return -1;
    }

    return (int32)loop;
}

void json_pf_remove_outer_bracket(text_t *curr_text)
{
    while ((curr_text->len >= 2) && ((curr_text->str[0] == '('))) {
        uint32 index = json_pf_get_back_bracket_index(curr_text);
        if (index != (curr_text->len - 1)) {
            break;
        }

        CM_REMOVE_FIRST(curr_text);
        CM_REMOVE_LAST(curr_text);
        cm_trim_text(curr_text);
    }

    return;
}

status_t json_pf_create_cond_func(json_assist_t *json_ass, lex_t *lex, json_pf_cond_tree_t *cond)
{
    json_pf_cond_t *cond_op_not = NULL;

    // only  not op now, there will be other op
    json_lex_trim(lex->curr_text);
    if (LEX_CURR(lex) != '!') {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(sql_push(json_ass->stmt, sizeof(json_pf_cond_t), (void **)&cond_op_not));
    MEMS_RETURN_IFERR(memset_sp(cond_op_not, sizeof(json_pf_cond_t), 0, sizeof(json_pf_cond_t)));
    cond_op_not->type = JSON_PF_OP_NOT;

    APPEND_CHAIN(&cond->chain, cond_op_not);
    (void)json_lex(lex);

    return CT_SUCCESS;
}

status_t json_pf_create_cond_bracket(json_assist_t *json_ass, lex_t *lex, json_pf_cond_tree_t *cond,
                                     bool32 *has_bracket,
    source_location_t loc)
{
    int32 loop;
    text_t text_inner;
    json_pf_cond_t *cond_inner = NULL;

    json_lex_trim(lex->curr_text);
    if (LEX_CURR(lex) != '(') {
        *has_bracket = CT_FALSE;
        return CT_SUCCESS;
    }

    loop = json_pf_get_back_bracket_index(&lex->curr_text->value);
    if (loop < 0) {
        CT_THROW_ERROR(ERR_JSON_PATH_SYNTAX_ERROR, "path filter - uncompleted bracket operator");
        return CT_ERROR;
    }

    *has_bracket = CT_TRUE;
    CT_RETURN_IFERR(sql_push(json_ass->stmt, sizeof(json_pf_cond_t), (void **)&cond_inner));
    MEMS_RETURN_IFERR(memset_sp(cond_inner, sizeof(json_pf_cond_t), 0, sizeof(json_pf_cond_t)));

    // create inner cond tree
    text_inner.str = lex->curr_text->str;
    text_inner.len = (uint32)(loop + 1);
    CT_RETURN_IFERR(json_pf_create_cond_from_text(json_ass, &text_inner, &cond_inner, loc));

    APPEND_CHAIN(&cond->chain, cond_inner);

    (void)json_lex_move_n(lex, loop);
    (void)json_lex(lex);

    return CT_SUCCESS;
}


#define JSON_PF_IS_OP_CHAR(ch) \
    (((ch) == '>') || ((ch) == '<') || ((ch) == '=') || ((ch) == '&') || ((ch) == '|') || ((ch) == '!'))
static inline uint32 json_lex_rpath_len(lex_t *lex)
{
    char *str = NULL;

    for (str = lex->curr_text->str; str < lex->curr_text->str + lex->curr_text->len; str++) {
        if (JSON_PF_IS_OP_CHAR(*str) || *str == ' ' || *str == '(' || *str == ')') {
            break;
        }
    }

    return (uint32)(str - lex->curr_text->str);
}

static status_t json_pf_parse_rpath(lex_t *lex, json_path_t *json_path)
{
    text_t rpath_text;
    status_t status;

    rpath_text.str = lex->curr_text->str;
    rpath_text.len = json_lex_rpath_len(lex);

    rpath_text.str[0] = '$';
    status = json_path_compile_core(&rpath_text, json_path);
    rpath_text.str[0] = '@';
    CT_RETURN_IFERR(status);

    (void)json_lex_move_n(lex, (int)(rpath_text.len - 1));
    (void)json_lex(lex);

    return CT_SUCCESS;
}

static status_t json_pf_create_expr(json_assist_t *json_ass, lex_t *lex, json_pf_expr_t **expr)
{
    CT_RETURN_IFERR(sql_push(json_ass->stmt, sizeof(json_pf_expr_t), (void **)expr));

    switch (LEX_CURR(lex)) {
        case '@':
            (*expr)->type1 = JSON_PF_EXPR_RPATH;
            CT_RETURN_IFERR(json_pf_parse_rpath(lex, &(*expr)->rpath));
            break;

        default:
            (*expr)->type1 = JSON_PF_EXPR_CONST;
            CT_RETURN_IFERR(json_parse_scalar(lex, &((*expr)->constant), json_ass));
            break;
    }

    return CT_SUCCESS;
}

static inline uint32 json_lex_op_len(lex_t *lex)
{
    char *str = NULL;

    for (str = lex->curr_text->str; str < lex->curr_text->str + lex->curr_text->len; str++) {
        if (!JSON_PF_IS_OP_CHAR(*str) || *str == ' ' || *str == '(' || *str == ')') {
            break;
        }
    }

    return (uint32)(str - lex->curr_text->str);
}

static status_t json_pf_create_cmp_op(json_assist_t *json_ass, lex_t *lex, json_pf_op_type_t *type)
{
    text_t op_text;
    json_pf_op_t *op = NULL;

    op_text.str = lex->curr_text->str;
    op_text.len = json_lex_op_len(lex);

    op = json_pf_op_find(&op_text);
    if (op == NULL || !JSON_PF_OP_IS_CMP(op->type)) {
        CT_THROW_ERROR(ERR_JSON_PATH_SYNTAX_ERROR, "path filter - unexpected comparison operator");
        return CT_ERROR;
    }

    *type = op->type;

    (void)json_lex_move_n(lex, (int)(op_text.len - 1));
    (void)json_lex(lex);

    return CT_SUCCESS;
}

static status_t json_pf_verify_cmp(json_pf_cond_t *cond)
{
    if (JSON_PF_OP_IS_CMP(cond->type)) {
        json_pf_expr_t *left = cond->l_expr;
        json_pf_expr_t *right = cond->r_expr;

        if (JSON_PF_EXPR_TYPE(left) != JSON_PF_EXPR_RPATH) {
            SWAP(json_pf_expr_t *, left, right);
        }

        if (JSON_PF_EXPR_TYPE(left) != JSON_PF_EXPR_RPATH || JSON_PF_EXPR_TYPE(right) == JSON_PF_EXPR_RPATH) {
            CT_THROW_ERROR(ERR_JSON_PATH_SYNTAX_ERROR, "path filter - invalid comparison");
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t json_pf_create_cond_cmp(json_assist_t *json_ass, lex_t *lex, json_pf_cond_tree_t *cond)
{
    json_pf_cond_t *cmp = NULL;

    CT_RETURN_IFERR(sql_push(json_ass->stmt, sizeof(json_pf_cond_t), (void **)&cmp));
    MEMS_RETURN_IFERR(memset_sp(cmp, sizeof(json_pf_cond_t), 0, sizeof(json_pf_cond_t)));

    CT_RETURN_IFERR(json_pf_create_expr(json_ass, lex, &cmp->l_expr));

    CT_RETURN_IFERR(json_pf_create_cmp_op(json_ass, lex, &cmp->type));

    CT_RETURN_IFERR(json_pf_create_expr(json_ass, lex, &cmp->r_expr));

    CT_RETURN_IFERR(json_pf_verify_cmp(cmp));

    APPEND_CHAIN(&cond->chain, cmp);

    return CT_SUCCESS;
}

static status_t json_pf_create_cond_logic(json_assist_t *json_ass, lex_t *lex, json_pf_cond_tree_t *cond)
{
    text_t op_text;
    json_pf_op_t *op = NULL;
    json_pf_cond_t *logic_op = NULL;

    CT_RETURN_IFERR(sql_push(json_ass->stmt, sizeof(json_pf_cond_t), (void **)&logic_op));
    MEMS_RETURN_IFERR(memset_sp(logic_op, sizeof(json_pf_cond_t), 0, sizeof(json_pf_cond_t)));
    json_lex_trim(lex->curr_text);

    op_text.str = lex->curr_text->str;
    op_text.len = json_lex_op_len(lex);

    op = json_pf_op_find(&op_text);
    if (op == NULL || !JSON_PF_OP_IS_LOGIC(op->type) || op->type == JSON_PF_OP_NOT) {
        CT_THROW_ERROR(ERR_JSON_PATH_SYNTAX_ERROR, "path filter - unexpected comparison operator");
        return CT_ERROR;
    }

    logic_op->type = op->type;
    APPEND_CHAIN(&cond->chain, logic_op);

    (void)json_lex_move_n(lex, (int32)op_text.len - 1);
    (void)json_lex(lex);

    return CT_SUCCESS;
}

#define PF_COND_NODE_IS_CMP_BOOL(cond) (((cond) != NULL) && ((cond)->l_expr != NULL || ((cond)->r_expr != NULL)))
#define PF_COND_NODE_IS_LOGIC_NOT_OP(cond) \
    (((cond) != NULL) && (!PF_COND_NODE_IS_CMP_BOOL(cond)) && ((cond)->type == JSON_PF_OP_NOT))
#define PF_COND_NODE_IS_LOGIC_AND_OP(cond) \
    (((cond) != NULL) && (!PF_COND_NODE_IS_CMP_BOOL(cond)) && ((cond)->type == JSON_PF_OP_AND))
#define PF_COND_NODE_IS_LOGIC_OR_OP(cond) \
    (((cond) != NULL) && (!PF_COND_NODE_IS_CMP_BOOL(cond)) && ((cond)->type == JSON_PF_OP_OR))

static status_t json_pf_form_cond_with_not(json_pf_cond_tree_t *cond_tree)
{
    json_pf_cond_t *json_node = cond_tree->chain.first;

    do {
        if (json_node == NULL) {
            break;
        }

        if (!PF_COND_NODE_IS_LOGIC_NOT_OP(json_node)) {
            json_node = json_node->next;
            continue;
        }

        /* if is not a correct condition */
        if (json_node->next == NULL) {
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "condition parsing error");
            return CT_ERROR;
        }

        // not not cmp_node    ==    cmp_node
        if (PF_COND_NODE_IS_LOGIC_NOT_OP(json_node->next)) { // do remove this two nodes
            if (json_node->prev != NULL) {
                json_node->prev->next = json_node->next->next;
            } else {
                cond_tree->chain.first = json_node->next->next;
            }

            json_node->next->next->prev = json_node->prev;

            cond_tree->chain.count -= 2;
            json_node = json_node->next->next;
        } else { // do down next json_node
            json_node->r_cond = json_node->next;
            json_node->next = json_node->next->next;
            if (json_node->next != NULL) {
                json_node->next->prev = json_node;
            }
            cond_tree->chain.count -= 1;
            json_node = json_node->next;
        }
    } while (json_node != NULL);

    return CT_SUCCESS;
}

static status_t json_pf_form_cond_with_logic(json_pf_cond_tree_t *cond_tree, json_pf_op_type_t type)
{
    json_pf_cond_t *json_node = NULL;
    if (cond_tree->chain.count < 2) {
        return CT_SUCCESS;
    }

    json_node = cond_tree->chain.first->next;
    while (json_node != NULL) {
        if (PF_COND_NODE_IS_CMP_BOOL(json_node) || (json_node->type != type)) {
            json_node = json_node->next;
            continue;
        }

        /* if is not a correct condition */
        if (!PF_COND_NODE_IS_CMP_BOOL(json_node->prev) || !PF_COND_NODE_IS_CMP_BOOL(json_node->next)) {
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "condition parsing error");
            return CT_ERROR;
        }

        json_node->l_cond = json_node->prev;
        json_node->r_cond = json_node->next;

        json_node->prev = json_node->prev->prev;
        json_node->next = json_node->next->next;

        if (json_node->prev != NULL) {
            json_node->prev->next = json_node;
        } else {
            cond_tree->chain.first = json_node;
        }
        if (json_node->next != NULL) {
            json_node->next->prev = json_node;
        }

        cond_tree->chain.count -= 2;
        json_node = json_node->next;
    }

    return CT_SUCCESS;
}

static status_t json_pf_generate_cond(json_assist_t *json_ass, json_pf_cond_tree_t *cond_tree)
{
    // generate condition tree according to operator priority
    if (json_pf_form_cond_with_not(cond_tree) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (json_pf_form_cond_with_logic(cond_tree, JSON_PF_OP_AND) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (json_pf_form_cond_with_logic(cond_tree, JSON_PF_OP_OR) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cond_tree->chain.count != 1) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "condition error");
        return CT_ERROR;
    }

    cond_tree->root = cond_tree->chain.first;
    return CT_SUCCESS;
}

static status_t json_pf_create_cond(json_assist_t *json_ass, lex_t *lex, json_pf_cond_tree_t **cond,
                                    source_location_t loc)
{
    bool32 has_bracket = CT_FALSE;
    CT_RETURN_IFERR(sql_push(json_ass->stmt, sizeof(json_pf_cond_tree_t), (void **)cond));
    JSON_PF_COND_TREE_INIT(*cond);

    for (;;) {
        CT_RETURN_IFERR(json_pf_create_cond_func(json_ass, lex, *cond));

        CT_RETURN_IFERR(json_pf_create_cond_bracket(json_ass, lex, *cond, &has_bracket, loc));

        if (!has_bracket) {
            CT_RETURN_IFERR(json_pf_create_cond_cmp(json_ass, lex, *cond));
        }

        CT_BREAK_IF_TRUE(LEX_CURR_EX(lex) == LEX_END);

        CT_RETURN_IFERR(json_pf_create_cond_logic(json_ass, lex, *cond));
    }

    CT_RETURN_IFERR(json_pf_generate_cond(json_ass, *cond));

    return CT_SUCCESS;
}

status_t json_pf_create_cond_from_text(json_assist_t *json_ass, text_t *text, json_pf_cond_t **cond,
                                       source_location_t src_loc)
{
    sql_text_t sql_text;
    lex_t lex;
    json_pf_cond_tree_t *cond_tree = NULL;

    // json_lex_remove_brackets
    cm_trim_text(text);
    json_pf_remove_outer_bracket(text);

    sql_text.value = *text;
    sql_text.loc = src_loc;

    lex_init(&lex, &sql_text);
    lex.loc = src_loc;
    json_lex_trim(lex.curr_text);

    CT_RETURN_IFERR(json_pf_create_cond(json_ass, &lex, &cond_tree, src_loc));

    *cond = cond_tree->root;

    return CT_SUCCESS;
}


#define JSON_PF_RETURN_CONVERT_ERR(src_type, dst_type)                                              \
    do {                                                                                            \
        cm_reset_error();                                                                           \
        CT_THROW_ERROR_EX(ERR_JSON_PATH_SYNTAX_ERROR, "path filter - invalid conversion: %s to %s", \
            JSON_TYPE_STR(src_type), JSON_TYPE_STR(dst_type));                                      \
        return CT_ERROR;                                                                            \
    } while (0)

status_t json_pf_convert_to_string(json_value_t *json_val)
{
    switch (json_val->type) {
        case JSON_VAL_BOOL:
            if (json_val->boolean == CT_TRUE) {
                json_val->string.str = "true";
                json_val->string.len = 4;
            } else {
                json_val->string.str = "false";
                json_val->string.len = 5;
            }
            json_val->type = JSON_VAL_STRING;
            break;

        case JSON_VAL_NUMBER:
            json_val->type = JSON_VAL_STRING;
            break;

        case JSON_VAL_STRING:
            break;

        default:
            JSON_PF_RETURN_CONVERT_ERR((int)json_val->type, JSON_VAL_STRING);
    }

    return CT_SUCCESS;
}

status_t json_pf_convert_to_number(json_value_t *json_val)
{
    dec8_t dec;

    switch (json_val->type) {
        case JSON_VAL_NUMBER:
            break;

        case JSON_VAL_STRING:
            if (cm_text_to_dec(&json_val->string, &dec) != CT_SUCCESS) {
                JSON_PF_RETURN_CONVERT_ERR((int)json_val->type, JSON_VAL_NUMBER);
            }
            json_val->type = JSON_VAL_NUMBER;
            break;

        default:
            JSON_PF_RETURN_CONVERT_ERR((int)json_val->type, JSON_VAL_NUMBER);
            return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t json_pf_convert_to_bool(json_value_t *json_val)
{
    switch (json_val->type) {
        case JSON_VAL_BOOL:
            break;

        case JSON_VAL_STRING:
            if (cm_text_str_equal_ins(&json_val->string, "true")) {
                json_val->boolean = CT_TRUE;
            } else if (cm_text_str_equal_ins(&json_val->string, "false")) {
                json_val->boolean = CT_FALSE;
            } else {
                JSON_PF_RETURN_CONVERT_ERR((int)json_val->type, JSON_VAL_BOOL);
            }

            json_val->type = JSON_VAL_BOOL;
            break;

        default:
            JSON_PF_RETURN_CONVERT_ERR((int)json_val->type, JSON_VAL_BOOL);
    }

    return CT_SUCCESS;
}

status_t json_pf_convert_to_null(json_value_t *json_val)
{
    if (json_val->type != JSON_VAL_NULL) {
        JSON_PF_RETURN_CONVERT_ERR((int)json_val->type, JSON_VAL_NULL);
    }

    return CT_SUCCESS;
}

status_t json_pf_convert(json_value_t *json_val, jv_type_t type)
{
    switch (type) {
        case JSON_VAL_NULL:
            CT_RETURN_IFERR(json_pf_convert_to_null(json_val));
            break;
        case JSON_VAL_BOOL:
            CT_RETURN_IFERR(json_pf_convert_to_bool(json_val));
            break;
        case JSON_VAL_NUMBER:
            CT_RETURN_IFERR(json_pf_convert_to_number(json_val));
            break;
        case JSON_VAL_STRING:
            CT_RETURN_IFERR(json_pf_convert_to_string(json_val));
            break;
        default:
            JSON_PF_RETURN_CONVERT_ERR((int)json_val->type, type);
    }

    return CT_SUCCESS;
}

#define JSON_PF_RETURN_MATCH_ERR(hint)                                                                              \
    do {                                                                                                            \
        CT_THROW_ERROR_EX(ERR_JSON_PATH_SYNTAX_ERROR, "path filter - relative path reference to %s value", (hint)); \
        return CT_ERROR;                                                                                            \
    } while (0)

status_t json_pf_eval_expr(json_assist_t *json_ass, json_pf_expr_t *expr, json_value_t *result)
{
    switch (JSON_PF_EXPR_TYPE(expr)) {
        case JSON_PF_EXPR_CONST:
            *result = expr->constant;
            break;

        case JSON_PF_EXPR_RPATH: {
            json_value_t jv_result_array;
            json_value_t *jv_tmp = NULL;

            // RP_expr doesn't support func step() and nested filter expr
            CT_RETURN_IFERR(json_item_array_init(json_ass, &jv_result_array.array, JSON_MEM_LARGE_POOL));
            CT_RETURN_IFERR(json_path_extract(json_ass->jv, &expr->rpath, &jv_result_array));
            if (jv_result_array.array->count == 0) {
                JSON_PF_RETURN_MATCH_ERR("no");
            } else if (jv_result_array.array->count > 1) {
                JSON_PF_RETURN_MATCH_ERR("multiple");
            } else {
                jv_tmp = (json_value_t *)cm_galist_get(jv_result_array.array, 0);
                if (!JSON_VAL_IS_SCALAR(jv_tmp)) {
                    JSON_PF_RETURN_MATCH_ERR("non-scalar");
                }
                *result = *jv_tmp;
            }
            break;
        }

        default:
            CT_THROW_ERROR_EX(ERR_JSON_PATH_SYNTAX_ERROR, "path filter - unknown type: %u", JSON_PF_EXPR_TYPE(expr));
            return CT_ERROR;
    }

    return CT_SUCCESS;
}


status_t json_pf_eval_cond(json_assist_t *json_ass, json_pf_cond_t *cond, bool32 *result)
{
    json_value_t left;
    json_value_t right;

    if (cond == NULL) {
        *result = CT_FALSE;
        return CT_SUCCESS;
    }

    // 1. eval left & right
    if (JSON_PF_OP_IS_LOGIC(cond->type)) {
        left.type = JSON_VAL_BOOL;
        right.type = JSON_VAL_BOOL;
        if (cond->type != JSON_PF_OP_NOT) {
            CT_RETURN_IFERR(json_pf_eval_cond(json_ass, cond->l_cond, &left.boolean));
        }
        CT_RETURN_IFERR(json_pf_eval_cond(json_ass, cond->r_cond, &right.boolean));
    } else {
        json_value_t *json_val = NULL;
        jv_type_t type;

        CM_ASSERT(JSON_PF_OP_IS_CMP(cond->type));

        CT_RETURN_IFERR(json_pf_eval_expr(json_ass, cond->l_expr, &left));
        CT_RETURN_IFERR(json_pf_eval_expr(json_ass, cond->r_expr, &right));

        // The default type for a comparison is defined at compile time,
        // based on the type(s) for the non-variable side(s).
        json_val = JSON_PF_EXPR_TYPE(cond->l_expr) == JSON_PF_EXPR_RPATH ? &left : &right;
        type = JSON_PF_EXPR_TYPE(cond->l_expr) == JSON_PF_EXPR_RPATH ? right.type : left.type;
        CT_RETURN_IFERR(json_pf_convert(json_val, type));
    }

    // 2. eval op
    CT_RETURN_IFERR(g_json_pf_ops[cond->type].func(&left, &right, result));

    return CT_SUCCESS;
}

status_t json_path_do_filter(json_assist_t *json_ass, json_pf_cond_t *cond, json_value_t *jv_array)
{
    bool32 result;
    int i;

    CT_RETSUC_IFTRUE(cond == NULL);

    CM_ASSERT(jv_array->array->count - 1 >= 0);
    for (i = jv_array->array->count - 1; i >= 0; i--) {
        json_ass->jv = (json_value_t *)cm_galist_get(jv_array->array, (uint32)i);
        if (json_pf_eval_cond(json_ass, cond, &result) != CT_SUCCESS) {
            int32 err_code;
            const char *err_msg = NULL;

            cm_get_error(&err_code, &err_msg, NULL);
            if (IS_JSON_ERR(err_code)) {
                CT_LOG_DEBUG_INF("[JSON] CT-%05d, %s", err_code, err_msg);
                cm_reset_error();
                cm_galist_delete(jv_array->array, (uint32)i);
                continue;
            } else {
                return CT_ERROR;
            }
        }

        if (!result) {
            cm_galist_delete(jv_array->array, (uint32)i);
        }
    }

    return CT_SUCCESS;
}

status_t json_path_execute_func(json_assist_t *json_ass, json_func_step_item_t *func, json_value_t *jv_array)
{
    json_value_t *json_val = NULL;
    int i;

    CT_RETSUC_IFTRUE(func == NULL);

    CM_ASSERT(jv_array->array->count - 1 >= 0);
    for (i = jv_array->array->count - 1; i >= 0; i--) {
        json_val = (json_value_t *)cm_galist_get(jv_array->array, (uint32)i);
        // SUCCESS : convert  / calculate ok,    otherwise : filter fail, remove this.
        if (func->invoke(json_ass->stmt, json_val) != CT_SUCCESS) {
            cm_galist_delete(jv_array->array, (uint32)i);
        }
    }
    return CT_SUCCESS;
}

/* sort in an Ascending order */
uint32 json_object_key_sort_part(galist_t *object, uint32 left, uint32 right)
{
    uint32 i = left;
    uint32 j = right;
    json_pair_t *pivot_pair = (json_pair_t *)cm_galist_get(object, i);

    json_pair_t *obj_left_pair = NULL;
    json_pair_t *obj_right_pair = NULL;

    while (i < j) {
        /* from right to left */
        obj_right_pair = (json_pair_t *)cm_galist_get(object, j);
        while ((i < j) && (cm_compare_text(&obj_right_pair->key.string, &pivot_pair->key.string) >= 0)) {
            j--;
            obj_right_pair = (json_pair_t *)cm_galist_get(object, j);
        }
        // swap
        if (i < j) {
            cm_galist_set(object, i, obj_right_pair);
        }

        /* from left to right */
        obj_left_pair = (json_pair_t *)cm_galist_get(object, i);
        while ((i < j) && (cm_compare_text(&obj_left_pair->key.string, &pivot_pair->key.string) <= 0)) {
            i++;
            obj_left_pair = (json_pair_t *)cm_galist_get(object, i);
        }
        // swap
        if (i < j) {
            cm_galist_set(object, j, obj_left_pair);
        }
    }

    /* in the end, i is equals j, set the fixed value */
    cm_galist_set(object, i, pivot_pair);

    return i;
}

status_t json_object_key_sort(json_assist_t *json_ass, json_value_t *json_val)
{
    galist_t *root = NULL;
    CT_RETURN_IFERR(json_item_array_init(json_ass, &root, JSON_MEM_LARGE_POOL_SORT));

    json_quick_sort_t *node_init = NULL;
    CT_RETURN_IFERR(cm_galist_new(root, sizeof(json_quick_sort_t), (pointer_t *)&node_init));
    node_init->left = 0;
    node_init->right = JSON_OBJECT_SIZE(json_val) - 1;

    while (root->count != 0) {
        json_quick_sort_t *node_parent = (json_quick_sort_t *)cm_galist_get(root, root->count - 1);
        cm_galist_delete(root, root->count - 1);

        uint32 pivot = json_object_key_sort_part(json_val->object, node_parent->left, node_parent->right);
        if (node_parent->left != pivot) {
            json_quick_sort_t *node_child_left = NULL;
            CT_RETURN_IFERR(cm_galist_new(root, sizeof(json_quick_sort_t), (pointer_t *)&node_child_left));
            node_child_left->left = node_parent->left;
            node_child_left->right = pivot - 1;
        }

        if (pivot != node_parent->right) {
            json_quick_sort_t *node_child_right = NULL;
            CT_RETURN_IFERR(cm_galist_new(root, sizeof(json_quick_sort_t), (pointer_t *)&node_child_right));
            node_child_right->left = pivot + 1;
            node_child_right->right = node_parent->right;
        }
    }

    JSON_FREE_LARGE(&json_ass->jsa);
    return CT_SUCCESS;
}

status_t json_analyse(json_assist_t *json_ass, json_value_t *json_val, json_analyse_t *analyse)
{
    switch (json_val->type) {
        case JSON_VAL_ARRAY:
            if (analyse != NULL) {
                analyse->array_count++;
                analyse->array_elems_count += JSON_ARRAY_SIZE(json_val);
                analyse->max_elems_count =
                    (JSON_ARRAY_SIZE(json_val) > analyse->max_elems_count)
                        ? JSON_ARRAY_SIZE(json_val) : analyse->max_elems_count;
                analyse->odd_elems_count += JSON_ARRAY_SIZE(json_val) % 2;
            }
            for (uint32 i = 0; i < JSON_ARRAY_SIZE(json_val); i++) {
                CT_RETURN_IFERR(json_analyse(json_ass, JSON_ARRAY_ITEM(json_val, i), analyse));
            }
            break;

        case JSON_VAL_OBJECT:
            if (analyse != NULL) {
                analyse->object_count++;
                analyse->object_elems_count += JSON_OBJECT_SIZE(json_val);
                analyse->max_elems_count =
                    (JSON_OBJECT_SIZE(json_val) > analyse->max_elems_count) ? JSON_OBJECT_SIZE(json_val) : analyse->max_elems_count;
                analyse->odd_elems_count += JSON_OBJECT_SIZE(json_val) % 2;
            }

            // quick sort
            if (JSON_OBJECT_SIZE(json_val) > 1) {
                CT_RETURN_IFERR(json_object_key_sort(json_ass, json_val));
            }

            for (uint32 i = 0; i < JSON_OBJECT_SIZE(json_val); i++) {
                CT_RETURN_IFERR(json_analyse(json_ass, &JSON_OBJECT_ITEM(json_val, i)->key, analyse));
            }
            for (uint32 i = 0; i < JSON_OBJECT_SIZE(json_val); i++) {
                CT_RETURN_IFERR(json_analyse(json_ass, &JSON_OBJECT_ITEM(json_val, i)->val, analyse));
            }
            break;

        case JSON_VAL_STRING:
        case JSON_VAL_NUMBER:
            if (analyse != NULL) {
                analyse->last_elem_len = json_val->string.len;
                analyse->string_number_len += json_val->string.len;
            }
            break;

        case JSON_VAL_BOOL:
        case JSON_VAL_NULL:
            break;

        default:
            break;
    }

    return CT_SUCCESS;
}

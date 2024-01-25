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
 * cm_lex.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_lex.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_LEX_H__
#define __CM_LEX_H__

#include "cm_defs.h"
#include "cm_text.h"
#include "cm_word.h"
#include "cm_decimal.h"

#define MAX_LEX_STACK_DEPTH 800  // ENSURE sizeof(lex_t) < 16K

#ifdef __cplusplus
extern "C" {
#endif

/*
* CAUTION!!!: don't change the value of cmp_type;
*/
typedef enum en_cmp_type {
    CMP_TYPE_UNKNOWN         = 0,
    // cmp_type definition cannot be less than CMP_TYPE_EQUAL
    CMP_TYPE_EQUAL           = 300,
    CMP_TYPE_GREAT_EQUAL     = 301,
    CMP_TYPE_GREAT           = 302,
    CMP_TYPE_LESS            = 303,
    CMP_TYPE_LESS_EQUAL      = 304,
    CMP_TYPE_NOT_EQUAL       = 305,
    CMP_TYPE_EQUAL_ANY       = 306,
    CMP_TYPE_NOT_EQUAL_ANY   = 307,
    CMP_TYPE_IN              = 308,
    CMP_TYPE_NOT_IN          = 309,  // EXIST THE CONDITION OF 'TYPE > CMP_TYPE_NOT_IN'
    CMP_TYPE_IS_NULL         = 310,
    CMP_TYPE_IS_NOT_NULL     = 311,
    CMP_TYPE_LIKE            = 312,
    CMP_TYPE_NOT_LIKE        = 313,
    CMP_TYPE_REGEXP          = 314,
    CMP_TYPE_NOT_REGEXP      = 315,
    CMP_TYPE_BETWEEN         = 316,
    CMP_TYPE_NOT_BETWEEN     = 317,
    CMP_TYPE_EXISTS          = 318,
    CMP_TYPE_NOT_EXISTS      = 319,
    CMP_TYPE_REGEXP_LIKE     = 320,
    CMP_TYPE_NOT_REGEXP_LIKE = 321,
    CMP_TYPE_GREAT_EQUAL_ANY = 322,
    CMP_TYPE_GREAT_ANY       = 323,
    CMP_TYPE_LESS_ANY        = 324,
    CMP_TYPE_LESS_EQUAL_ANY  = 325,
    CMP_TYPE_EQUAL_ALL       = 326,
    CMP_TYPE_NOT_EQUAL_ALL   = 327,
    CMP_TYPE_GREAT_EQUAL_ALL = 328,
    CMP_TYPE_GREAT_ALL       = 329,
    CMP_TYPE_LESS_ALL        = 330,
    CMP_TYPE_LESS_EQUAL_ALL  = 331,
    CMP_TYPE_IS_JSON         = 332,
    CMP_TYPE_IS_NOT_JSON     = 333,
} cmp_type_t;

/* The word type of numeric type */
typedef enum en_numeric_type {
    NUM_TYPE_INT = CT_TYPE_INTEGER,
    NUM_TYPE_BIGINT = CT_TYPE_BIGINT,
    NUM_TYPE_REAL = CT_TYPE_REAL,
    NUM_TYPE_NUMERIC = CT_TYPE_NUMBER,
} numeric_type_t;

typedef enum en_comment_type {
    COMMENT_TYPE_LINE = 500,
    COMMENT_TYPE_SECTION,
} comment_type_t;

#pragma pack(4)
typedef struct st_lex_stack_item {
    sql_text_t text;
} lex_stack_item_t;
#pragma pack()

typedef struct st_lex_stack {
    uint32 depth;
    lex_stack_item_t items[MAX_LEX_STACK_DEPTH];
} lex_stack_t;

#define LEX_MATCH_FIRST_WORD    0
#define LEX_MATCH_SECOND_WORD   1
#define LEX_MATCH_THIRD_WORD    2

#define LEX_SINGLE_WORD 0x00000000  //
#define LEX_WITH_OWNER 0x00000001   // for user.table.column
#define LEX_WITH_ARG 0x00000002     // for user.function
#define LEX_IN_COND 0x00000004      // for user.split num in condition
#define LEX_PL_DECLARE 0x00000008   // for loop up declare in pl declare section, don't look up names
#define LEX_PL_NORMAL 0x00000010    // normal processing of var names
#define LEX_IN_FUNCTION 0x00000020

typedef struct st_lex {
    uint32 flags;           // user.table.column, or user.function(args)
    uint32 key_word_count;  // external key words
    key_word_t *key_words;  // external key words
    uint32      ext_flags;  // user.table.column, or user.function(args)
    sql_text_t text;
    sql_text_t *curr_text;
    source_location_t loc;
    char *begin_addr;  // for the last fetched word
    /* Whether to infer the datatype a number word, if the infer_numtype is FALSE,
     * all number word is used as DECIMAL/NUMBER datatype; else the datatype of
     * number word is inferred by cm_decide_numtype */
    bool32 infer_numtype;
    text_t *curr_user;
    uint8 call_version; /* client and server negotiate version */

    /* note!!!! stack must be bottom */
    lex_stack_t stack;
} lex_t;

#define LEX_HEAD_SIZE (sizeof(lex_t) - sizeof(lex_stack_t))

#define LEX_CURR(lex) (((lex)->curr_text->len == 0) ? LEX_END : (lex)->curr_text->str[0])
#define LEX_NEXT(lex) (((lex)->curr_text->len <= 1) ? LEX_END : (lex)->curr_text->str[1])
#define LEX_END  ((char)'\0')
#define LEX_LOC  (lex->loc)

/**
 * LOAD DATA INFILE 'File Name' INTO TABLE 'Table name' COLUMNS TERMINATED BY  'Terminated String'
 * define the size of space to store Terminated String.
*/
#define TERMINATED_STR_ARRAY_SIZE 11

status_t lex_extract_first(sql_text_t *text, word_t *word);
status_t lex_fetch(lex_t *lex, word_t *word);
status_t lex_fetch_in_hint(lex_t *lex, word_t *word);
status_t lex_fetch_string(lex_t *lex, word_t *word);
status_t lex_expected_fetch(lex_t *lex, word_t *word);
status_t lex_expected_fetch_word(lex_t *lex, const char *word);
status_t lex_expected_fetch_word2(lex_t *lex, const char *word1, const char *word2);
status_t lex_expected_fetch_word3(lex_t *lex, const char *word1, const char *word2, const char *word3);
status_t lex_try_fetch_1of2(lex_t *lex, const char *word1, const char *word2, uint32 *matched_id);
status_t lex_try_fetch_1of3(lex_t *lex, const char *word1, const char *word2, const char *word3,
                            uint32 *matched_id);
status_t lex_try_fetch_1ofn(lex_t *lex, uint32 *matched_id, int num, ...);
status_t lex_expected_fetch_1of2(lex_t *lex, const char *word1, const char *word2, uint32 *matched_id);
status_t lex_expected_fetch_1of3(lex_t *lex, const char *word1, const char *word2, const char *word3,
                                 uint32 *matched_id);
status_t lex_expected_fetch_int32(lex_t *lex, int32 *size);
status_t lex_expected_fetch_uint32(lex_t *lex, uint32 *num);
status_t lex_expected_fetch_uint64(lex_t *lex, uint64 *size);
status_t lex_expected_fetch_dec(lex_t *lex, dec8_t *dec);
status_t lex_expected_fetch_seqval(lex_t *lex, int64 *val);
status_t lex_expected_fetch_size(lex_t *lex, int64 *size, int64 min_size, int64 max_size);
status_t lex_check_asciichar(text_t *text, source_location_t *loc, char *c, bool32 allow_empty_char);
status_t lex_expected_fetch_asciichar(lex_t *lex, char *c, bool32 allow_empty_char);
status_t lex_expected_fetch_str(lex_t *lex, char *str, uint32 str_max_length, char *key_word_info);
status_t lex_expected_fetch_string(lex_t *lex, word_t *word);
status_t lex_expected_fetch_dqstring(lex_t *lex, word_t *word);
status_t lex_expected_fetch_enclosed_string(lex_t *lex, word_t *word);
status_t lex_expected_fetch_tblname(lex_t *lex, word_t *word, text_buf_t *tbl_textbuf);
status_t lex_expected_fetch_variant(lex_t *lex, word_t *word);
status_t lex_expected_fetch_bracket(lex_t *lex, word_t *word);
status_t lex_expected_fetch_comp(lex_t *lex, word_t *word, bool32 fetch_pwd);
status_t lex_expected_end(lex_t *lex);
status_t lex_try_fetch(lex_t *lex, const char *word, bool32 *result);
status_t lex_try_fetch2(lex_t *lex, const char *word1, const char *word2, bool32 *result);
status_t lex_try_fetch3(lex_t *lex, const char *word1, const char *word2, const char *word3, bool32 *result);
status_t lex_try_fetch4(lex_t *lex, const char *word1, const char *word2, const char *word3, const char *word4,
                        bool32 *result);
status_t lex_try_fetch_n(lex_t *lex, uint32 n, const char **words, bool32 *result);
status_t lex_try_fetch_anyone(lex_t *lex, uint32 n, const char **words, bool32 *result);
status_t lex_try_match_records(lex_t *lex, const word_record_t *records, uint32 num, uint32 *matched_id);
status_t lex_try_fetch_char(lex_t *lex, char c, bool32 *result);
status_t lex_try_fetch_bracket(lex_t *lex, word_t *word, bool32 *result);
status_t lex_try_fetch_comment(lex_t *lex, word_t *word, bool32 *result);
status_t lex_try_fetch_hint_comment(lex_t *lex, word_t *word, bool32 *result);
status_t lex_try_fetch_variant(lex_t *lex, word_t *word, bool32 *result);
status_t lex_try_fetch_variant_excl(lex_t *lex, word_t *word, uint32 excl, bool32 *result);
status_t lex_try_fetch_database_link(lex_t *lex, word_t *word, bool32 *result);
status_t lex_skip_comments(lex_t *lex, word_t *word);
status_t lex_try_fetch_datatype(lex_t *lex, word_t *typword, bool32 *is_found);
bool32 lex_match_head(sql_text_t *text, const char *word, uint32 *len);
status_t lex_expected_fetch_1ofn(lex_t *lex, uint32 *matched_id, int num, ...);
status_t lex_fetch_to_char(lex_t *lex, word_t *word, char c);
status_t lex_inc_special_word(lex_t *lex, const char *word, bool32 *result);
bool32 is_splitter(char c);
bool32 is_nameble(char c);
bool32 is_variant_head(char c);

static inline char lex_skip(lex_t *lex, uint32 step_input)
{
    uint32 step = step_input;
    if (lex->curr_text->len < step) {
        CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "lex->curr_text->len(%u) >= step(%u)", lex->curr_text->len, step);
        step = lex->curr_text->len;
    }
    lex->curr_text->str += step;
    lex->curr_text->len -= step;
    lex->curr_text->loc.column += step;
    return LEX_CURR(lex);
}

static inline char lex_skip_line_breaks(lex_t *lex)
{
    const uint32 step = 1;
    if (lex->curr_text->len < step) {
        CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "lex->curr_text->len(%u) >= step(%u)", lex->curr_text->len, step);
        return LEX_CURR(lex);
    }
    lex->curr_text->str += step;
    lex->curr_text->len -= step;
    lex->curr_text->loc.line += step;
    lex->curr_text->loc.column = 1;
    return LEX_CURR(lex);
}

static inline void lex_skip_line(lex_t *lex)
{
    uchar c;
    sql_text_t *text = lex->curr_text;

    while (text->len > 0) {
        c = (uchar)CM_TEXT_BEGIN(text);
        if (c == '\n') {
            lex_skip(lex, 1);
            break;
        }

        text->str++;
        text->len--;
    }
}

static inline bool32 lex_eof(lex_t *lex)
{
    return lex->curr_text->len == 0;
}

static inline status_t lex_push(lex_t *lex, sql_text_t *text)
{
    lex_stack_item_t *item = NULL;

    if (lex->stack.depth >= MAX_LEX_STACK_DEPTH) {
        CT_SRC_THROW_ERROR(text->loc, ERR_SQL_SYNTAX_ERROR, "text is too complex");
        return CT_ERROR;
    }

    if (lex->stack.depth == 0) {
        lex->text = *text;
    }

    item = &lex->stack.items[lex->stack.depth];
    item->text = *text;
    lex->curr_text = &item->text;
    lex->stack.depth++;
    return CT_SUCCESS;
}

static inline void lex_pop(lex_t *lex)
{
    lex_stack_item_t *item = NULL;

    if (lex->stack.depth == 0) {
        return;
    }

    lex->stack.depth--;
    if (lex->stack.depth > 0) {
        item = &lex->stack.items[lex->stack.depth - 1];
        lex->curr_text = &item->text;
    } else {
        lex->curr_text = &lex->text;
    }
}

static inline void lex_init(lex_t *lex, const sql_text_t *sql)
{
    lex->flags = LEX_SINGLE_WORD;
    lex->stack.depth = 0;
    lex->text = *sql;
    lex->key_word_count = 0;
    lex->key_words = NULL;
    lex->infer_numtype = CT_TRUE;
    (void)lex_push(lex, &lex->text);
}

static inline void lex_reset(lex_t *lex)
{
    lex->text.len = 0;
    lex->stack.depth = 0;
}

static inline bool8 lex_is_empty(lex_t *lex)
{
    return (lex->text.len == 0);
}

static inline void lex_init_for_native_type(lex_t *lex, const sql_text_t *sql, text_t *curr_user,
                                            uint8 call_version, bool32 using_native_datatype)
{
    lex_init(lex, sql);
    lex->infer_numtype = using_native_datatype;
    lex->call_version = call_version;
    lex->curr_user = curr_user;
}

static inline void lex_init_ex(lex_t *lex, const sql_text_t *sql, uint32 key_word_count, key_word_t *key_words)
{
    lex_init(lex, sql);
    lex->key_word_count = key_word_count;
    lex->key_words = key_words;
}

static inline void lex_check_location(sql_text_t *text)
{
    if (CM_TEXT_BEGIN(text) == '\n') {
        text->loc.line++;
        text->loc.column = 1;
    } else {
        text->loc.column++;
    }
}

static inline void lex_trim(sql_text_t *text)
{
    uchar c;

    while (text->len > 0) {
        c = (uchar)CM_TEXT_BEGIN(text);
        if (c > ' ') {
            break;
        }

        lex_check_location(text);
        text->str++;
        text->len--;
    }
}

static inline void lex_remove_brackets(sql_text_t *text)
{
    // the first level brackets pair is normal
    if (text->len >= 2 && CM_TEXT_BEGIN(text) == '(' && CM_TEXT_END(text) == ')') {
        text->str++;
        text->len -= 2;
        text->loc.column++;
        lex_trim(text);
    }
}

static inline void lex_remove_all_brackets(sql_text_t *text)
{
    while (text->len >= 2 && CM_TEXT_BEGIN(text) == '(' && CM_TEXT_END(text) == ')') {
        text->str++;
        text->len -= 2;
        text->loc.column++;
        lex_trim(text);
    }
}

static inline bool32 is_variant(word_t *word)
{
    if (word->type == WORD_TYPE_VARIANT || word->type == WORD_TYPE_PL_NEW_COL ||
        word->type == WORD_TYPE_PL_OLD_COL || word->type == WORD_TYPE_PL_ATTR ||
        word->type == WORD_TYPE_DQ_STRING) {
        return CT_TRUE;
    }

    if (word->type == WORD_TYPE_KEYWORD || word->type == WORD_TYPE_DATATYPE || word->type == WORD_TYPE_RESERVED) {
        return word->namable;
    }

    return CT_FALSE;
}

static inline bool32 is_unamable_keyword(word_t *word)
{
    if (word->type == WORD_TYPE_KEYWORD) {
        return !word->namable;
    }

    return CT_FALSE;
}

#define LEX_ADD_WRAP(text)    \
    do {                      \
        (text)->str--;        \
        (text)->len += 2;     \
        (text)->loc.column++; \
    } while (0)
#define LEX_REMOVE_WRAP(word)  \
    do {                       \
        (word)->text.str++;    \
        (word)->text.len -= 2; \
    } while (0)
#define LEX_OFFSET(lex, word)      (uint32)((word)->text.str - (lex)->text.str)
#define IS_SPEC_CHAR(word, c)      ((word)->text.len == 1 && *(word)->text.str == (c) && (word)->type != WORD_TYPE_DQ_STRING)
#define IS_UNNAMABLE_KEYWORD(word) is_unamable_keyword(word)
#define  IS_KEY_WORD(word, key_word_id) ((word)->id == (key_word_id) && (word)->type == WORD_TYPE_KEYWORD)
#define IS_VARIANT(word)           is_variant(word)

/* return the origin string */
#define W2S(word) (T2S(&(word)->text.value))

/* return the string in upper mode when it is dq string, otherwise return the original string */
#define W2S_EX(word) (T2S_CASE((&(word)->text.value), IS_DQ_STRING((word)->type)))

#define IS_DQ_STRING(type) (((type) & WORD_TYPE_DQ_STRING) == WORD_TYPE_DQ_STRING)

static inline void lex_back(lex_t *lex, word_t *word)
{
    if (word->type != WORD_TYPE_EOF) {
        lex->curr_text->len += (uint32)(lex->curr_text->str - word->begin_addr);
        lex->curr_text->str = word->begin_addr;
        lex->curr_text->loc = word->loc;
    }
}

static inline void lex_back_text(lex_t *lex, sql_text_t *text)
{
    if (text->len != 0) {
        lex->curr_text->len += text->len;
        lex->curr_text->str = text->str;
        lex->curr_text->loc = text->loc;
    }
}

#define LEX_SAVE(lex)    sql_text_t __text__ = *(lex)->curr_text;
#define LEX_RESTORE(lex) *(lex)->curr_text = __text__;

/**
* Try to fetch tuple with n continuous words.
* @note the comments are allowed among in these words

*/
static inline status_t lex_try_fetch_tuple(lex_t *lex, const word_tuple_t *tuple, bool32 *result)
{
    return lex_try_fetch_n(lex, tuple->size, (const char **)tuple->words, result);
}

status_t lex_fetch_pl_label(lex_t *lex, word_t *word);
status_t lex_fetch_array(lex_t *lex, word_t *word);
status_t lex_try_match_array(lex_t *lex, uint8 *is_array, ct_type_t datatype);
status_t lex_try_fetch_subscript(lex_t *lex, int32 *ss_start, int32 *ss_end);
status_t lex_fetch_in_outline(lex_t *lex, word_t *word);

#define SET_LEX_KEY_WORD(lex, words, count) \
    do {                                    \
        (lex)->key_words = (words);         \
        (lex)->key_word_count = (count);    \
    } while (0)

#define SAVE_LEX_KEY_WORD(lex, words, count) \
    do {                                     \
        (words) = (lex)->key_words;          \
        (count) = (lex)->key_word_count;     \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif

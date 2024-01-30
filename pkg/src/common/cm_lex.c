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
 * cm_lex.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_lex.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_lex.h"
#include "cm_defs.h"
#include "string.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SPILTTER_CHAR     (char)1
#define NAMABLE_CHAR      (char)2
#define VARIANT_HEAD_CHAR (char)3
#define VERSION_10        (uint8)10      // must equals to CS_VERSION_10 = 10

static const char g_char_map[] = {
    0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x00, 0x02, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00,
    0x00, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x01, 0x01, 0x01, 0x01, 0x03,
    0x00, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00,
    /* unicode , GBK all zero; Chinese all 0x3 except 255p. */
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x00
};

#define IS_SPLITTER(c) (g_char_map[(uint8)(c)] == SPILTTER_CHAR)
#define IS_NAMABLE(c) (g_char_map[(uint8)(c)] >= NAMABLE_CHAR)
#define IS_NUM(c) (g_char_map[(uint8)(c)] == NAMABLE_CHAR)
/** [int|bigint]size_indicator */
#define IS_SIZE_INDICATOR(c) \
    ((c) == 'B' || (c) == 'K' || (c) == 'M' || (c) == 'G' || (c) == 'T' || (c) == 'P' || (c) == 'E' || (c) == 'S')
#define IS_MICROSECOND(c) ((c) == 'M')
#define IS_VARIANT_HEAD(c) (g_char_map[(uint8)(c)] == VARIANT_HEAD_CHAR)

bool32 is_splitter(char c)
{
    return IS_SPLITTER(c);
}

bool32 is_nameble(char c)
{
    return IS_NAMABLE(c);
}

bool32 is_variant_head(char c)
{
    return IS_VARIANT_HEAD(c);
}

static inline char lex_move(lex_t *lex)
{
    if (lex->curr_text->len == 0) {
        return LEX_END;
    }

    lex_check_location(lex->curr_text);
    lex->curr_text->str++;
    lex->curr_text->len--;
    return LEX_CURR(lex);
}

static inline void lex_begin_fetch(lex_t *lex, word_t *word)
{
    lex_trim(lex->curr_text);
    lex->loc = lex->curr_text->loc;
    lex->begin_addr = lex->curr_text->str;

    if (word != NULL) {
        word->text.str = lex->begin_addr;
        word->text.len = 0;
        word->text.loc = lex->loc;
        word->begin_addr = lex->begin_addr;
        word->loc = lex->loc;
    }
}

static word_type_t lex_diagnose_word_type_by_colon(lex_t *lex)
{
    bool32 result = CT_FALSE;
    char c2 = LEX_NEXT(lex);
    if (c2 == ':') {
        return WORD_TYPE_ANCHOR;
    }

    if (c2 == '=') {
        return WORD_TYPE_PL_SETVAL;
    }

    if (lex_try_fetch(lex, ":NEW.", &result) != CT_SUCCESS) {
        return WORD_TYPE_ERROR;
    }

    if (result) {
        return WORD_TYPE_PL_NEW_COL;
    }

    if (lex_try_fetch(lex, ":OLD.", &result) != CT_SUCCESS) {
        return WORD_TYPE_ERROR;
    }

    if (result) {
        return WORD_TYPE_PL_OLD_COL;
    }

    return WORD_TYPE_PARAM;
}

static word_type_t lex_diagnose_word_type(lex_t *lex)
{
    char c1 = LEX_CURR(lex);
    char c2 = LEX_NEXT(lex);

    if (g_char_map[(uint8)c1] == VARIANT_HEAD_CHAR) {
        if (c1 == 'X' && c2 == '\'') {
            return WORD_TYPE_HEXADECIMAL;
        }

        if ((c1 == 'C' || c1 == 'c') &&
            (c2 == 'O' || c2 == 'o') &&
            lex->curr_text->len >= sizeof("CONNECT_BY_ROOT") - 1 &&
            cm_strcmpni(lex->curr_text->str, "CONNECT_BY_ROOT", sizeof("CONNECT_BY_ROOT") - 1) == 0) {
            return WORD_TYPE_OPERATOR;
        }

        if (lex->call_version >= VERSION_10 && lex->curr_text->len >= sizeof("ARRAY[]") - 1 &&
            cm_strcmpni(lex->curr_text->str, "ARRAY[", sizeof("ARRAY[") - 1) == 0) {
            return WORD_TYPE_ARRAY;
        }

        return WORD_TYPE_VARIANT;
    }

    if (c1 >= '0' && c1 <= '9') {
        if (c1 == '0' && c2 == 'x') {
            return WORD_TYPE_HEXADECIMAL;
        }
        return WORD_TYPE_NUMBER;
    }

    switch (c1) {
        case '(':
            return WORD_TYPE_BRACKET;

        case '.':
            return (c2 >= '0' && c2 <= '9') ? WORD_TYPE_NUMBER : ((c2 == '.') ?
                WORD_TYPE_PL_RANGE : WORD_TYPE_SPEC_CHAR);

        case ',':
            return WORD_TYPE_SPEC_CHAR;

        case '\'':
            return WORD_TYPE_STRING;

        case '*':
        case '+':
            return WORD_TYPE_OPERATOR;

        case '/':
            return c2 == '*' ? WORD_TYPE_COMMENT : WORD_TYPE_OPERATOR;

        case '%':
            return WORD_TYPE_OPERATOR;

        case '-':
            return c2 == '-' ? WORD_TYPE_COMMENT : WORD_TYPE_OPERATOR;
        case '!':
            return c2 == '=' ? WORD_TYPE_COMPARE : WORD_TYPE_ERROR;

        case '<':
            return c2 == '<' ? WORD_TYPE_OPERATOR : WORD_TYPE_COMPARE;

        case '>':
            return c2 == '>' ? WORD_TYPE_OPERATOR : WORD_TYPE_COMPARE;

        case '=':
            return WORD_TYPE_COMPARE;

        case '?':
        case '$':
            return WORD_TYPE_PARAM;

        case ':':
            return lex_diagnose_word_type_by_colon(lex);

        case '|':
        case '&':
        case '^':
            return WORD_TYPE_OPERATOR;

        case '`':
        case '\"':
            return WORD_TYPE_DQ_STRING;

        case ';':
            return WORD_TYPE_PL_TERM;

        case '#':
            return WORD_TYPE_VARIANT;

        case '~':
            return WORD_TYPE_ALPHA_PARAM;

        default:
            break;
    }

    return WORD_TYPE_ERROR;
}

/** diagnosis whether a word is a NUMBER type or a SIZE type */
static inline bool32 lex_diag_num_word(word_t *word, text_t *text, num_part_t *np)
{
    char c = CM_TEXT_END(&word->text);
    char second2last;
    second2last = CM_TEXT_SECONDTOLAST(&word->text);

    if (CM_IS_DIGIT(c) || CM_IS_DOT(c)) {
        word->type = WORD_TYPE_NUMBER;
        text->str = word->text.str;
        text->len = word->text.len;
    } else {
        c = UPPER(c);
        second2last = UPPER(second2last);

        if (IS_SIZE_INDICATOR(c)) {
            if (np->is_neg || np->has_dot || np->has_expn ||
                word->text.len < 2) {  // the SIZE must be positive, no dot and its length GEQ 2
                return CT_FALSE;
            }
            
            word->type = WORD_TYPE_SIZE;
            text->str = word->text.str;
            if (IS_MICROSECOND(second2last)) {
                text->len = word->text.len - 2;
                // size must be non-negative, has no dot and expn
                np->excl_flag |= (NF_NEGATIVE_SIGN | NF_DOT | NF_EXPN);
                np->sz_indicator = second2last;
            } else {
                text->len = word->text.len - 1;
                // size must be non-negative, has no dot and expn
                np->excl_flag |= (NF_NEGATIVE_SIGN | NF_DOT | NF_EXPN);
                np->sz_indicator = c;
            }
        } else {  // unexpected character
            return CT_FALSE;
        }
    }

    return CT_TRUE;
}

/**
* To fetch a number without deciding its datatype. The number can be an
* integer, bigint, uint32, uint64, real and decimal;
* This function can also fetch a SIZE WORD with format "[+][int|bigint]size_indicator"
* The definition of excl_flag can refer to the definition of *num_flag_t*
* @see lex_fetch_num
* */
static num_errno_t lex_fetch_numpart(lex_t *lex, word_t *word)
{
    text_t text;
    uint32 i = 0;
    num_part_t *np = &word->np;

    np->is_neg = np->has_dot = np->has_expn = CT_FALSE;

    // Step 1. simple scan
    CT_RETVALUE_IFTRUE((lex->curr_text->len == 0), NERR_ERROR);

    char c = lex->curr_text->str[i];
    if (c == '-') {
        // if negative sign not allowed
        CT_RETVALUE_IFTRUE((np->excl_flag & NF_NEGATIVE_SIGN), NERR_UNALLOWED_NEG);
        np->is_neg = CT_TRUE;
        i++;
    } else if (c == '+') {
        i++;
    }
    /* check again */
    CT_RETVALUE_IFTRUE((i >= lex->curr_text->len), NERR_ERROR);

    for (; i < lex->curr_text->len; i++) {
        c = lex->curr_text->str[i];
        if (CM_IS_DOT(c)) {
            // dot not allowed or more than one dot
            CT_RETVALUE_IFTRUE((np->excl_flag & NF_DOT), NERR_UNALLOWED_DOT);
            CT_RETVALUE_IFTRUE((np->has_dot), NERR_MULTIPLE_DOTS);

            char n = ((i + 1) < lex->curr_text->len) ? lex->curr_text->str[i + 1] : '\0';
            // when meet two dot, back and return.
            CT_BREAK_IF_TRUE(CM_IS_DOT(n));
            np->has_dot = CT_TRUE;
            continue;
        }
        if (IS_SPLITTER(c)) {
            // +/- are two splitter chars
            // handle scientific 21321E+3213 or 2132E-2323
            if (CM_IS_SIGN_CHAR(c) && CM_IS_EXPN_CHAR(lex->curr_text->str[i - 1])) {
                // expn 'E' or 'e' not allowed
                CT_RETVALUE_IFTRUE((np->has_expn), NERR_EXPN_WITH_NCHAR);
                CT_RETVALUE_IFTRUE((np->excl_flag & NF_EXPN), NERR_UNALLOWED_EXPN);
                np->has_expn = CT_TRUE;
                continue;
            }
            break;
        }

        if (word->type == WORD_TYPE_NUMBER && IS_VARIANT_HEAD(c) && (lex->flags & LEX_IN_COND)) {
            if (CM_IS_EXPN_CHAR(c) && ((i + 1) < lex->curr_text->len) &&
                (CM_IS_SIGN_CHAR(lex->curr_text->str[i + 1]) || IS_NUM(lex->curr_text->str[i + 1]))) {
                continue;
            }
            break;
        }
    }
    // check again
    CT_RETVALUE_IFTRUE((i == 0), NERR_NO_DIGIT);
    word->text.len = i;
    CT_RETVALUE_IFTRUE((!lex_diag_num_word(word, &text, np)), NERR_ERROR);
    CM_CHECK_NUM_ERRNO(cm_split_num_text(&text, np));

    (void)lex_skip(lex, word->text.len);
    return NERR_SUCCESS;
}

/**
 * To fetch a number. The number can be an integer, bigint, real and decimal;
 * This function can also fetch a SIZE WORD with format "[int|bigint]size_indicator"
 * in which the size_indicator can be (capital and lowercase) 'B' (bytes), 'K'(kilobyte)
 * 'M', 'G', 'T', 'P', and 'E' (Exabyte);
 * To allow this function to parse a real/decimal number with scientific format also with
 * the indicator 'E' or 'e'. Obviously, this conflicts with the size indicator 'E',
 * therefore we the indicator E must be specially handled.
 *
 * + If 'E' in the middle of the word, then the word is a number word;
 * + If 'E' is at the end of the word, the word is a size word;
 * + If two or more indicators are found, an error will be returned.
 *

 */
static status_t lex_fetch_num(lex_t *lex, word_t *word)
{
    num_errno_t err_no;
    word->np.excl_flag = NF_NONE;

    err_no = lex_fetch_numpart(lex, word);
    if (err_no != NERR_SUCCESS) {
        CT_SRC_THROW_ERROR(word->loc, ERR_INVALID_NUMBER, cm_get_num_errinfo(err_no));
        return CT_ERROR;
    }

    // process the fetched numeric word, and decide its type
    if (lex->infer_numtype) {
        err_no = cm_decide_numtype(&word->np, (ct_type_t *)&word->id);
        if (err_no != NERR_SUCCESS) {
            CT_SRC_THROW_ERROR(word->loc, ERR_SQL_SYNTAX_ERROR, "invalid number");
            return CT_ERROR;
        }
    } else {
        word->id = CT_TYPE_NUMBER;
    }

    return CT_SUCCESS;
}

static void lex_cmp2any_type(word_t *word)
{
    switch (word->id) {
        case CMP_TYPE_EQUAL:
            word->id = CMP_TYPE_EQUAL_ANY;
            break;
        case CMP_TYPE_NOT_EQUAL:
            // As long as there is a difference, return true, Instead equals all returns false
            word->id = CMP_TYPE_NOT_EQUAL_ANY;
            break;
        case CMP_TYPE_GREAT_EQUAL:
            word->id = CMP_TYPE_GREAT_EQUAL_ANY;
            break;
        case CMP_TYPE_GREAT:
            word->id = CMP_TYPE_GREAT_ANY;
            break;
        case CMP_TYPE_LESS:
            word->id = CMP_TYPE_LESS_ANY;
            break;
        case CMP_TYPE_LESS_EQUAL:
            word->id = CMP_TYPE_LESS_EQUAL_ANY;
            break;
        default:
            break;
    }
}

static void lex_cmp2all_type(word_t *word)
{
    switch (word->id) {
        case CMP_TYPE_EQUAL:
            word->id = CMP_TYPE_EQUAL_ALL;
            break;
        case CMP_TYPE_NOT_EQUAL:
            // As long as one is the same, it returns false, and the other is true.
            word->id = CMP_TYPE_NOT_EQUAL_ALL;
            break;
        case CMP_TYPE_GREAT_EQUAL:
            word->id = CMP_TYPE_GREAT_EQUAL_ALL;
            break;
        case CMP_TYPE_GREAT:
            word->id = CMP_TYPE_GREAT_ALL;
            break;
        case CMP_TYPE_LESS:
            word->id = CMP_TYPE_LESS_ALL;
            break;
        case CMP_TYPE_LESS_EQUAL:
            word->id = CMP_TYPE_LESS_EQUAL_ALL;
            break;
        default:
            break;
    }
}

static status_t lex_fetch_cmp(lex_t *lex, word_t *word)
{
    char curr, next;
    uint32 match_id;

    curr = CM_TEXT_BEGIN(lex->curr_text);
    next = lex_skip(lex, 1);

    if (curr == '<') {
        word->id = (uint32)CMP_TYPE_LESS;
        if (next == '=') {
            (void)lex_skip(lex, 1);
            word->id = (uint32)CMP_TYPE_LESS_EQUAL;
        } else if (next == '>') {
            (void)lex_skip(lex, 1);
            word->id = (uint32)CMP_TYPE_NOT_EQUAL;
        }
    } else if (curr == '>') {
        word->id = CMP_TYPE_GREAT;
        if (next == '=') {
            (void)lex_skip(lex, 1);
            word->id = (uint32)CMP_TYPE_GREAT_EQUAL;
        }
    } else if (curr == '!') {
        if (next != '=') {
            CT_THROW_ERROR(ERR_ASSERT_ERROR, "next == '='");
            return CT_ERROR;
        }
        (void)lex_skip(lex, 1);
        word->id = (uint32)CMP_TYPE_NOT_EQUAL;
    } else {
        word->id = (uint32)CMP_TYPE_EQUAL;
    }

    word->text.len = (uint32)(lex->curr_text->str - word->text.str);

    if (lex_try_fetch_1of3(lex, "ANY", "ALL", "SOME", &match_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (match_id == 0 || match_id == 2) {
        lex_cmp2any_type(word);
    } else if (match_id == 1) {
        lex_cmp2all_type(word);
    }

    return CT_SUCCESS;
}

static void lex_fetch_anchor(lex_t *lex, word_t *word)
{
    char c, next;

    c = CM_TEXT_BEGIN(lex->curr_text);
    next = lex_skip(lex, 1);

    switch (c) {
        case ':':
            if (next == ':') {
                (void)lex_skip(lex, 1);
            }
            break;
        default:
            break;
    }
    word->text.len = (uint32)(lex->curr_text->str - word->text.str);
}

static void lex_fetch_oper(lex_t *lex, word_t *word)
{
    char c, next;

    c = CM_TEXT_BEGIN(lex->curr_text);
    next = lex_skip(lex, 1);

    switch (c) {
        case 'c':
        case 'C':
            (void)lex_skip(lex, (uint32)strlen("CONNECT_BY_ROOT") - 1);
            word->id = (uint32)OPER_TYPE_ROOT;
            break;
        case '|':
            if (next == '|') {
                (void)lex_skip(lex, 1);
                word->id = (uint32)OPER_TYPE_CAT;
            } else {
                word->id = (uint32)OPER_TYPE_BITOR;
            }
            break;

        case '+':
            word->id = (uint32)OPER_TYPE_ADD;
            break;

        case '-':
            word->id = (uint32)OPER_TYPE_SUB;
            break;

        case '*':
            word->id = (uint32)OPER_TYPE_MUL;
            break;

        case '/':
            word->id = (uint32)OPER_TYPE_DIV;
            break;

        case '%':
            word->id = (uint32)OPER_TYPE_MOD;
            break;

        case '&':
            word->id = (uint32)OPER_TYPE_BITAND;
            break;
        case '^':
            word->id = (uint32)OPER_TYPE_BITXOR;
            break;
        case '<':
            if (next == '<') {
                (void)lex_skip(lex, 1);
                word->id = (uint32)OPER_TYPE_LSHIFT;
            }
            break;
        case '>':
            if (next == '>') {
                (void)lex_skip(lex, 1);
                word->id = (uint32)OPER_TYPE_RSHIFT;
            }
            break;
        default:
            break;
    }

    word->text.len = (uint32)(lex->curr_text->str - word->text.str);
}

static status_t lex_fetch_comment(lex_t *lex, word_t *word)
{
    char curr, next;
    bool32 finished = CT_FALSE;

    curr = CM_TEXT_BEGIN(lex->curr_text);
    (void)lex_skip(lex, 2);

    if (curr == '-') {       // parse COMMENT LINE
        if (word != NULL) {  // word is not null
            word->id = (uint32)COMMENT_TYPE_LINE;
        }
        curr = LEX_CURR(lex);
        while (curr != '\n' && curr != LEX_END) {
            curr = lex_skip(lex, 1);
        }

        finished = CT_TRUE;
    } else {                 // parse COMMENT SECTION
        if (word != NULL) {  // word is not null
            word->id = (uint32)COMMENT_TYPE_SECTION;
        }
        for (;;) {
            curr = LEX_CURR(lex);
            next = LEX_NEXT(lex);
            if (curr == LEX_END || next == LEX_END) {
                break;
            }

            if (curr == '*' && next == '/') {
                (void)lex_skip(lex, 2);
                finished = CT_TRUE;
                break;
            }

            if (curr == '\n') {
                (void)lex_skip_line_breaks(lex);
            } else {
                (void)lex_skip(lex, 1);
            }
        }
    }

    if (!finished) {
        CT_SRC_THROW_ERROR(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "text is not completed");
        return CT_ERROR;
    }

    if (word != NULL) {  // word is not null
        word->text.len = (uint32)(lex->curr_text->str - word->text.str);
    }

    return CT_SUCCESS;
}

static void lex_fetch_special_char(lex_t *lex, word_t *word)
{
    (void)lex_skip(lex, 1);
    word->text.len = 1;
}

static status_t lex_fetch_name(lex_t *lex, word_t *word)
{
    char c = lex_skip(lex, 1);

    while (c != LEX_END && c != '@') {
        if (IS_SPLITTER(c)) {
            break;
        }

        if (!IS_NAMABLE(c)) {
            CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "namable char expected but %c found", c);
            return CT_ERROR;
        }

        c = lex_skip(lex, 1);
    }

    word->text.len = (uint32)(lex->curr_text->str - word->text.str);

    if (word->text.len > CT_MAX_NAME_LEN) {
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "object is too long or varaint name");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t lex_fetch_param(lex_t *lex, word_t *word)
{
    if (CM_TEXT_BEGIN(lex->curr_text) == '?') {
        lex_fetch_special_char(lex, word);
        return CT_SUCCESS;
    } else {
        return lex_fetch_name(lex, word);
    }
}

static status_t lex_fetch_alpha_param(lex_t *lex, word_t *word)
{
    char c;
    c = lex_skip(lex, 1);
    if (c == LEX_END || IS_SPLITTER(c)) {
        word->text.len = 1;
        word->namable = CT_FALSE;
        return CT_SUCCESS;
    }

    CT_SRC_THROW_ERROR(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "text is incorrect");
    return CT_ERROR;
}

static status_t lex_expected_fetch_extra(lex_t *lex, word_t *ex_word)
{
    bool32 result = CT_FALSE;
    uint32 flags = lex->flags;

    lex->flags = LEX_SINGLE_WORD;

    if (lex_fetch(lex, ex_word) != CT_SUCCESS) {
        lex->flags = flags;
        return CT_ERROR;
    }

    lex->flags = flags;

    result = IS_VARIANT(ex_word) || (ex_word->type == WORD_TYPE_RESERVED && (ex_word->namable ||
        ex_word->id == RES_WORD_ROWID || ex_word->id == RES_WORD_ROWSCN || ex_word->id == RES_WORD_ROWNODEID));
    if (!result) {
        CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "expression expected but '%s' found", W2S(ex_word));
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t lex_try_fetch_onedot(lex_t *lex, bool32 *result)
{
    sql_text_t *text = lex->curr_text;
    if (lex_skip_comments(lex, NULL) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (text->len == 0 || *text->str != '.') {
        *result = CT_FALSE;
        return CT_SUCCESS;
    }

    if ((LEX_CURR(lex) == '.') && (LEX_NEXT(lex) == '.')) {
        *result = CT_FALSE;
        return CT_SUCCESS;
    }

    (void)lex_skip(lex, 1);
    *result = CT_TRUE;
    return CT_SUCCESS;
}

static status_t lex_try_fetch_owner(lex_t *lex, word_t *word)
{
    word_t ex_word;
    bool32 result = CT_FALSE;
    key_word_t *save_key_words = NULL;
    uint32 save_key_word_count;
    for (;;) {
        CT_RETURN_IFERR(lex_try_fetch_onedot(lex, &result));

        if (!result) {
            break;
        }

        if (word->ex_count >= MAX_EXTRA_TEXTS - 1) {
            CT_SRC_THROW_ERROR(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "too many '.' found");
            return CT_ERROR;
        }

        CT_RETURN_IFERR(lex_try_fetch(lex, "*", &result));

        if (result) {
            word->ori_type = word->type;
            word->type = WORD_TYPE_STAR;
            word->ex_words[word->ex_count].text.len = 1;
            word->ex_words[word->ex_count].text.str = lex->begin_addr;
            word->ex_words[word->ex_count].text.loc = lex->loc;
            word->ex_count++;
            return CT_SUCCESS;
        }

        SAVE_LEX_KEY_WORD(lex, save_key_words, save_key_word_count);
        SET_LEX_KEY_WORD(lex, (key_word_t *)g_method_key_words, METHOD_KEY_WORDS_COUNT);
        if (lex_expected_fetch_extra(lex, &ex_word) != CT_SUCCESS) {
            SET_LEX_KEY_WORD(lex, save_key_words, save_key_word_count);
            return CT_ERROR;
        }
        SET_LEX_KEY_WORD(lex, save_key_words, save_key_word_count);
        
        if (word->ex_count + ex_word.ex_count + 1 > MAX_EXTRA_TEXTS) {
            CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "complex extra texts more than %u level",
                (int32)MAX_EXTRA_TEXTS);
            return CT_ERROR;
        }
        for (uint32 i = 0; i <= ex_word.ex_count; i++) {
            word->ex_words[word->ex_count].text = (i == 0) ? ex_word.text : ex_word.ex_words[i - 1].text;
            word->ex_words[word->ex_count].type = (i == 0) ? ex_word.type : ex_word.ex_words[i - 1].type;
            word->ex_count++;
        }
        if (ex_word.type == WORD_TYPE_PL_ATTR) {
            word->type = WORD_TYPE_PL_ATTR;
            word->id = ex_word.id;
        }
    }

    return CT_SUCCESS;
}

static status_t lex_try_fetch_pl_attr(lex_t *lex, word_t *word, bool32 *result)
{
    word_t ex_word;

    LEX_SAVE(lex);

    if (lex_try_fetch_char(lex, '%', result) != CT_SUCCESS) {  // result = true, PL ATTR
        LEX_RESTORE(lex);
        return CT_SUCCESS;
    }

    if (!(*result)) {
        LEX_RESTORE(lex);
        return CT_SUCCESS;
    }

    lex_begin_fetch(lex, &ex_word);

    if (lex->stack.depth == 0 || CM_IS_EMPTY(&lex->curr_text->value)) {
        LEX_RESTORE(lex);
        return CT_SUCCESS;
    }

    if (lex_fetch_name(lex, &ex_word) != CT_SUCCESS) {
        LEX_RESTORE(lex);
        return CT_SUCCESS;
    }

    if (lex_match_subset((key_word_t *)g_pl_attr_words, PL_ATTR_WORDS_COUNT, &ex_word)) {
        word->id = ex_word.id;
        word->ex_words[word->ex_count].text = ex_word.text;
        word->type = WORD_TYPE_PL_ATTR;
        word->ex_count++;
    } else {
        LEX_RESTORE(lex);
    }
    return CT_SUCCESS;
}

status_t lex_try_fetch_database_link(lex_t *lex, word_t *word, bool32 *result)
{
    LEX_SAVE(lex);

    if (lex_try_fetch_char(lex, '@', result) != CT_SUCCESS) {  // result = true, PL ATTR
        LEX_RESTORE(lex);
        return CT_SUCCESS;
    }

    if (!(*result)) {
        LEX_RESTORE(lex);
        return CT_SUCCESS;
    }

    lex_begin_fetch(lex, word);
    if (lex->stack.depth == 0 || CM_IS_EMPTY(lex->curr_text)) {
        CT_SRC_THROW_ERROR(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "database link name cannot be null.");
        return CT_ERROR;
    }
    CT_RETURN_IFERR(lex_fetch_name(lex, word));

    return CT_SUCCESS;
}

static bool32 lex_is_unnamable_function(word_t *word)
{
    return (word->type == WORD_TYPE_DATATYPE && cm_strcmpni(word->text.str, "char", strlen("char")) == 0) ||
           (word->type == WORD_TYPE_KEYWORD && cm_strcmpni(word->text.str, "insert", strlen("insert")) == 0) ||
           (word->type == WORD_TYPE_KEYWORD && cm_strcmpni(word->text.str, "values", strlen("values")) == 0);
}

static status_t lex_fetch_variant(lex_t *lex, word_t *word, bool32 in_hint)
{
    uint32 flags = lex->flags;
    word_t ex_word;
    bool32 result = CT_FALSE;

    CT_RETURN_IFERR(lex_fetch_name(lex, word));

    if (SECUREC_UNLIKELY(in_hint)) {
        return lex_match_hint_keyword(lex, word);
    }

    CT_RETURN_IFERR(lex_try_fetch_pl_attr(lex, word, &result));

    word->namable = CT_TRUE;
    if (word->type != WORD_TYPE_PL_ATTR) {
        CT_RETURN_IFERR(lex_match_keyword(lex, word));
    }
    
    if (!word->namable && !lex_is_unnamable_function(word)) {
        return CT_SUCCESS;
    }

    if (lex->ext_flags != 0) {
        flags = lex->ext_flags;
    }

    if (flags & LEX_WITH_OWNER) {
        CT_RETURN_IFERR(lex_try_fetch_owner(lex, word));
        if (word->ex_count > 0 && word->type != WORD_TYPE_PL_ATTR) {
            word->id = CT_INVALID_ID32;
        }
    }

    // If word is prior, don't need fetch arg.
    if ((flags & LEX_WITH_ARG) && (word->id != OPER_TYPE_PRIOR)) {
        CT_RETURN_IFERR(lex_try_fetch_bracket(lex, &ex_word, &result));

        if (result) {
            cm_trim_text(&ex_word.text.value);

            if (ex_word.text.len == 1 && ex_word.text.str[0] == '+') {
                word->type = WORD_TYPE_JOIN_COL;
            } else {
                word->ex_words[word->ex_count].type = ex_word.type;
                word->ex_words[word->ex_count].text = ex_word.text;
                word->ex_count++;
                word->type = WORD_TYPE_FUNCTION;
            }
        }
    }
    lex->ext_flags = 0;

    return CT_SUCCESS;
}

static status_t lex_fetch_quote(lex_t *lex, word_t *word, char quote)
{
    bool32 finished = CT_FALSE;
    char curr, next;

    curr = lex_move(lex);

    char charcurr = LEX_CURR(lex);
    char charnext = LEX_NEXT(lex);
    if (charcurr == '0' && charnext == 'x') {
        word->id = CT_TYPE_BINARY;
    }

    while (curr != LEX_END) {
        if (curr == quote) {
            next = LEX_NEXT(lex);
            if (next == quote) {  // a''b => a'b
                curr = lex_skip(lex, 2);
                continue;
            }

            (void)lex_skip(lex, 1);
            finished = CT_TRUE;
            break;
        }

        curr = lex_move(lex);
    }

    if (!finished) {
        CT_SRC_THROW_ERROR(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "text is not completed");
        return CT_ERROR;
    }

    word->text.len = (uint32)(lex->curr_text->str - word->text.str);

    return CT_SUCCESS;
}

static status_t lex_fetch_dquote(lex_t *lex, word_t *word, char quote)
{
    word_t ex_word;
    bool32 result = CT_FALSE;

    if (lex_fetch_quote(lex, word, quote) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word->text.len <= 2) {
        CT_SRC_THROW_ERROR(word->loc, ERR_SQL_SYNTAX_ERROR, "invalid identifier, length 0");
        return CT_ERROR;
    }

    CM_REMOVE_ENCLOSED_CHAR(&word->text);

    if (word->text.len > CT_MAX_NAME_LEN) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "text is too long, max is %u",
                              CT_MAX_NAME_LEN);
        return CT_ERROR;
    }

    if (lex->flags & LEX_WITH_OWNER) {
        if (lex_try_fetch_owner(lex, word) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (lex->flags & LEX_WITH_ARG) {
        if (lex_try_fetch_bracket(lex, &ex_word, &result) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (result) {
            word->ex_words[word->ex_count].text = ex_word.text;
            word->ex_count++;
            word->ori_type = word->type;
            word->type = WORD_TYPE_FUNCTION;
        }
    }

    return CT_SUCCESS;
}

status_t lex_fetch_string(lex_t *lex, word_t *word)
{
    return lex_fetch_quote(lex, word, '\'');
}

static status_t lex_fetch_bracket(lex_t *lex, word_t *word)
{
    bool32 in_string = CT_FALSE;
    bool32 in_quot = CT_FALSE;
    uint32 depth = 1;
    char c = lex_move(lex);

    while (c != LEX_END) {
        if (c == '\'') {
            in_string = !in_string;
            c = lex_move(lex);
            continue;
        }
        if (in_string) {
            c = lex_move(lex);
            continue;
        }

        if (c == '\"') {
            in_quot = !in_quot;
            c = lex_move(lex);
            continue;
        }

        if (in_quot) {
            c = lex_move(lex);
            continue;
        }
        if ((c == '/' && LEX_NEXT(lex) == '*') || (c == '-' && LEX_NEXT(lex) == '-')) {
            CT_RETURN_IFERR(lex_fetch_comment(lex, NULL));
            c = LEX_CURR(lex);
            continue;
        }
        if (c == '(') {
            depth++;
        } else if (c == ')') {
            depth--;
            if (depth == 0) {
                (void)lex_skip(lex, 1);
                break;
            }
        }

        c = lex_move(lex);
    }

    if (in_quot || in_string || depth != 0) {
        CT_SRC_THROW_ERROR(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "text is not completed");
        return CT_ERROR;
    }

    word->text.len = (uint32)(lex->curr_text->str - word->text.str);
    lex_remove_brackets(&word->text);
    return CT_SUCCESS;
}

static status_t lex_fetch_pl_setval(lex_t *lex, word_t *word)
{
    word->text.str = lex->curr_text->str;
    word->text.len = 2;
    (void)lex_move(lex);
    (void)lex_move(lex);
    return CT_SUCCESS;
}

status_t lex_fetch_pl_label(lex_t *lex, word_t *word)
{
    bool32 finished = CT_FALSE;
    char curr, next;

    curr = *lex->curr_text->str;
    word->text.str = lex->curr_text->str;
    LEX_SAVE(lex);

    do {
        next = LEX_NEXT(lex);
        if ((curr == '>') && (next == '>')) {  // a''b => a'b
            (void)lex_move(lex);
            (void)lex_move(lex);
            finished = CT_TRUE;
            break;
        }
        curr = lex_move(lex);
    } while (next != LEX_END);

    if (!finished) {
        CT_SRC_THROW_ERROR(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "text is not completed");
        return CT_ERROR;
    }

    LEX_RESTORE(lex);

    if (lex_expected_fetch(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t lex_fetch_new_or_old_col(lex_t *lex, word_t *word)
{
    word_t ex_word;

    if (lex_expected_fetch_extra(lex, &ex_word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (ex_word.ex_count > 0) {
        CT_SRC_THROW_ERROR(word->loc, ERR_SQL_SYNTAX_ERROR, "invalid column");
        return CT_ERROR;
    }

    word->ex_words[0].text = ex_word.text;
    word->ex_words[0].type = ex_word.type;
    word->ex_count = 1;
    word->text.len = (uint32)(lex->curr_text->str - word->text.str);
    cm_rtrim_text(&word->text.value);
    return CT_SUCCESS;
}

static status_t lex_fetch_hexadecimal_val(lex_t *lex, word_t *word)
{
    char curr = LEX_CURR(lex);
    char next = LEX_NEXT(lex);
    if ((curr == 'X' && next == '\'') || (curr == '0' && next == 'x')) {
        (void)lex_skip(lex, 2);

        for (;;) {
            curr = LEX_CURR(lex);
            if (curr == LEX_END) {
                break;
            }

            if (!((curr >= '0' && curr <= '9') || (curr >= 'a' && curr <= 'f') || (curr >= 'A' && curr <= 'F') ||
                  curr == '\'')) {
                break;
            }

            (void)lex_skip(lex, 1);
        }

        word->text.len = (uint32)(lex->curr_text->str - word->text.str);
        word->id = CT_TYPE_BINARY;
    }
    return CT_SUCCESS;
}

status_t lex_try_match_array(lex_t *lex, uint8 *is_array, ct_type_t datatype)
{
    uint32 num;
    bool32 result = CT_FALSE;

    if (lex->call_version < VERSION_10) {
        *is_array = CT_FALSE;
        return CT_SUCCESS;
    }

    LEX_SAVE(lex);
    *is_array = CT_FALSE;

    if (lex_try_fetch(lex, "[", &result) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (result) {
        if (lex_try_fetch(lex, "]", &result) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (result) {
            *is_array = CT_TRUE;
        } else {
            if (lex_expected_fetch_uint32(lex, &num) != CT_SUCCESS) {
                LEX_RESTORE(lex);
                return CT_ERROR;
            }

            if (lex_expected_fetch_word(lex, "]") != CT_SUCCESS) {
                LEX_RESTORE(lex);
                return CT_ERROR;
            }

            *is_array = CT_TRUE;
        }
    } else {
        LEX_RESTORE(lex);
        return CT_SUCCESS;
    }

    if (*is_array == CT_TRUE) {
        if (!cm_datatype_arrayable(datatype)) {
            CT_THROW_ERROR(ERR_DATATYPE_NOT_SUPPORT_ARRAY, get_datatype_name_str(datatype));
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t lex_try_fetch_subscript(lex_t *lex, int32 *ss_start, int32 *ss_end)
{
    int32 start;
    int32 end;
    bool32 result;
    LEX_SAVE(lex);

    if (lex_try_fetch(lex, "[", &result) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (result) {
        do {
            if (lex_expected_fetch_int32(lex, &start) != CT_SUCCESS) {
                break;
            }
            if (start <= 0) {
                CT_SRC_THROW_ERROR(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "invalid array subscript");
                return CT_ERROR;
            }
            if (lex_try_fetch(lex, "]", &result) != CT_SUCCESS) {
                return CT_ERROR;
            }

            /* f1[m] */
            if (result) {
                *ss_start = start;
                *ss_end = CT_INVALID_ID32;
                return CT_SUCCESS;
            }

            /* f1[m:n] */
            if (lex_expected_fetch_word(lex, ":") != CT_SUCCESS) {
                break;
            }

            if (lex_expected_fetch_int32(lex, &end) != CT_SUCCESS) {
                break;
            }

            if (end <= 0) {
                CT_SRC_THROW_ERROR(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "invalid array subscript");
                return CT_ERROR;
            }

            if (lex_expected_fetch_word(lex, "]") != CT_SUCCESS) {
                break;
            }

            *ss_start = start;
            *ss_end = end;
            return CT_SUCCESS;
        } while (0);
        LEX_RESTORE(lex);
        cm_reset_error();
    }

    *ss_start = (int32)CT_INVALID_ID32;
    *ss_end = (int32)CT_INVALID_ID32;
    return CT_SUCCESS;
}

status_t lex_fetch_array(lex_t *lex, word_t *word)
{
    char curr;
    word_t tmp_word;
    word->ex_count = 0;

    (void)lex_skip(lex, sizeof("[") - 1);

    /* fetch the array content inside the [] */
    lex_begin_fetch(lex, word);
    curr = LEX_CURR(lex);
    while (curr != LEX_END && curr != ']') {
        if (curr == '\'' || curr == '"') {
            if (lex_fetch_quote(lex, &tmp_word, curr) != CT_SUCCESS) {
                return CT_ERROR;
            }
            curr = LEX_CURR(lex);
        } else {
            curr = lex_move(lex);
        }
    }

    if (curr != ']') {
        CT_SRC_THROW_ERROR(LEX_LOC, ERR_INVALID_ARRAY_FORMAT);
        return CT_ERROR;
    } else {
        word->text.len = (uint32)(lex->curr_text->str - word->text.str);
        word->id = CT_TYPE_ARRAY;
        (void)lex_skip(lex, 1); // skip ]
    }

    return CT_SUCCESS;
}

static void lex_fetch_range_char(lex_t *lex, word_t *word)
{
    (void)lex_skip(lex, 2);
    word->text.len = 2;
}

static status_t lex_fetch_word(lex_t *lex, word_t *word, bool32 in_hint)
{
    status_t status;

    word->namable = CT_TRUE;
    word->id = CT_INVALID_ID32;
    word->ex_count = 0;
    word->ori_type = WORD_TYPE_UNKNOWN;
    word->flag_type = 0;
    lex_begin_fetch(lex, word);

    if (lex->curr_text->len == 0 || lex->stack.depth == 0) {
        word->type = WORD_TYPE_EOF;
        return CT_SUCCESS;
    }

    /* diagnose the word type preliminarily */
    word->type = lex_diagnose_word_type(lex);
    status = CT_SUCCESS;

    switch (word->type) {
        case WORD_TYPE_NUMBER:
            status = lex_fetch_num(lex, word);
            word->namable = CT_FALSE;
            break;

        case WORD_TYPE_COMPARE:
            status = lex_fetch_cmp(lex, word);
            word->namable = CT_FALSE;
            break;

        case WORD_TYPE_OPERATOR:
            lex_fetch_oper(lex, word);
            word->namable = CT_FALSE;
            break;

        case WORD_TYPE_COMMENT:
            status = lex_fetch_comment(lex, word);
            word->namable = CT_FALSE;
            break;

        case WORD_TYPE_PARAM:
            status = lex_fetch_param(lex, word);
            word->namable = CT_FALSE;
            break;

        case WORD_TYPE_PL_RANGE:
            lex_fetch_range_char(lex, word);
            word->namable = CT_FALSE;
            break;

        case WORD_TYPE_PL_TERM:
        case WORD_TYPE_SPEC_CHAR:
            lex_fetch_special_char(lex, word);
            word->namable = CT_FALSE;
            break;

        case WORD_TYPE_STRING:
            status = lex_fetch_string(lex, word);
            break;

        case WORD_TYPE_BRACKET:
            status = lex_fetch_bracket(lex, word);
            word->namable = CT_FALSE;
            break;

        case WORD_TYPE_VARIANT:
            status = lex_fetch_variant(lex, word, in_hint);
            break;

        case WORD_TYPE_ANCHOR:
            lex_fetch_anchor(lex, word);
            word->namable = CT_FALSE;
            break;

        case WORD_TYPE_DQ_STRING:
            status = lex_fetch_dquote(lex, word, LEX_CURR(lex));
            break;

        case WORD_TYPE_PL_SETVAL:
            status = lex_fetch_pl_setval(lex, word);
            break;

        case WORD_TYPE_PL_NEW_COL:
        case WORD_TYPE_PL_OLD_COL:
            status = lex_fetch_new_or_old_col(lex, word);
            break;

        case WORD_TYPE_HEXADECIMAL:
            status = lex_fetch_hexadecimal_val(lex, word);
            word->namable = CT_FALSE;
            break;

        case WORD_TYPE_ARRAY:
            lex_skip(lex, sizeof("array") - 1);
            word->text.len = sizeof("array") - 1;
            status = CT_SUCCESS;
            break;

        case WORD_TYPE_ALPHA_PARAM:
            status = lex_fetch_alpha_param(lex, word);
            break;

        default:
            CT_SRC_THROW_ERROR(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "text is incorrect");
            return CT_ERROR;
    }

    return status;
}

status_t lex_fetch(lex_t *lex, word_t *word)
{
    do {
        if (lex_fetch_word(lex, word, CT_FALSE) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } while (word->type == WORD_TYPE_COMMENT);

    return CT_SUCCESS;
}

status_t lex_fetch_in_hint(lex_t *lex, word_t *word)
{
    do {
        if (lex_fetch_word(lex, word, CT_TRUE) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } while (word->type == WORD_TYPE_COMMENT);

    return CT_SUCCESS;
}

bool32 lex_match_head(sql_text_t *text, const char *word, uint32 *len)
{
    uint32 i;
    for (i = 0; i < text->len; i++) {
        if (word[i] == '\0') {
            *len = i;
            return (bool32)(IS_SPLITTER(text->str[i]) || IS_SPLITTER(word[i - 1]));
        }

        if (UPPER(word[i]) != UPPER(text->str[i])) {
            return CT_FALSE;
        }
    }

    *len = text->len;
    return (bool32)(word[i] == '\0');
}

status_t lex_extract_first(sql_text_t *text, word_t *word)
{
    sql_text_t ex_text = *text;
    lex_t lex;

    while (ex_text.len > 0 && CM_TEXT_BEGIN(&ex_text) == '(') {
        ex_text.str++;
        ex_text.len--;
        lex_trim(&ex_text);
    }

    lex_init(&lex, &ex_text);
    return lex_expected_fetch(&lex, word);
}

status_t lex_expected_fetch(lex_t *lex, word_t *word)
{
    word->ex_count = 0;

    if (lex_fetch(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word->type == WORD_TYPE_EOF) {
        CT_SRC_THROW_ERROR(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "more text expected but terminated");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t lex_expected_fetch_word(lex_t *lex, const char *word)
{
    bool32 result = CT_FALSE;

    if (lex_try_fetch(lex, word, &result) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!result) {
        CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "%s expected", word);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

/**
* Expect to fetch two continuous words.
* @note the comments are allowed among in these words

*/
status_t lex_expected_fetch_word2(lex_t *lex, const char *word1, const char *word2)
{
    bool32 result = CT_FALSE;

    if (lex_try_fetch2(lex, word1, word2, &result) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!result) {
        CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "'%s %s' expected", word1, word2);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

/**
* Expect to fetch three continuous words.
* @note the comments are allowed among in these words

*/
status_t lex_expected_fetch_word3(lex_t *lex, const char *word1, const char *word2, const char *word3)
{
    bool32 result = CT_FALSE;
    if (lex_try_fetch3(lex, word1, word2, word3, &result) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!result) {
        CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "'%s %s %s' expected", word1, word2, word3);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t lex_try_fetch_1of2(lex_t *lex, const char *word1, const char *word2, uint32 *matched_id)
{
    bool32 result = CT_FALSE;

    if (lex_try_fetch(lex, word1, &result) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (result) {
        *matched_id = 0;
        return CT_SUCCESS;
    }

    if (lex_try_fetch(lex, word2, &result) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (result) {
        *matched_id = 1;
        return CT_SUCCESS;
    }

    *matched_id = CT_INVALID_ID32;
    return CT_SUCCESS;
}

status_t lex_try_fetch_1of3(lex_t *lex, const char *word1, const char *word2, const char *word3,
                            uint32 *matched_id)
{
    bool32 result = CT_FALSE;

    if (lex_try_fetch_1of2(lex, word1, word2, matched_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (*matched_id != CT_INVALID_ID32) {
        return CT_SUCCESS;
    }

    if (lex_try_fetch(lex, word3, &result) != CT_SUCCESS) {
        return CT_ERROR;
    }

    *matched_id = result ? 2 : CT_INVALID_ID32;
    return CT_SUCCESS;
}

status_t lex_try_fetch_1ofn(lex_t *lex, uint32 *matched_id, int num, ...)
{
    bool32 result = CT_FALSE;
    va_list ap;
    int i = num;
    uint32 j = 0;

    va_start(ap, num);
    while (i > 0) {
        const char *word = (const char *)va_arg(ap, const char *);

        if (lex_try_fetch(lex, word, &result) != CT_SUCCESS) {
            va_end(ap);
            return CT_ERROR;
        }

        if (result) {
            *matched_id = j;
            va_end(ap);
            return CT_SUCCESS;
        }

        j++;
        i--;
    }
    va_end(ap);

    *matched_id = CT_INVALID_ID32;
    return CT_SUCCESS;
}

status_t lex_expected_fetch_1of2(lex_t *lex, const char *word1, const char *word2, uint32 *matched_id)
{
    if (lex_try_fetch_1of2(lex, word1, word2, matched_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (*matched_id == CT_INVALID_ID32) {
        CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "%s or %s expected", word1, word2);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t lex_expected_fetch_1of3(lex_t *lex, const char *word1, const char *word2, const char *word3,
                                 uint32 *matched_id)
{
    if (lex_try_fetch_1of3(lex, word1, word2, word3, matched_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (*matched_id == CT_INVALID_ID32) {
        CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "%s or %s or %s expected", word1, word2, word3);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t lex_expected_fetch_1ofn(lex_t *lex, uint32 *matched_id, int num, ...)
{
    int iret_snprintf;
    va_list ap;
    bool32 result = CT_FALSE;
    uint32 msg_len, remain_msg_len;
    int i = num;
    uint32 j = 0;
    char message[CT_MESSAGE_BUFFER_SIZE] = { 0 };

    va_start(ap, num);
    while (i > 0) {
        const char *word = (const char *)va_arg(ap, const char *);

        if (lex_try_fetch(lex, word, &result) != CT_SUCCESS) {
            va_end(ap);
            return CT_ERROR;
        }

        if (result) {
            *matched_id = j;
            va_end(ap);
            return CT_SUCCESS;
        }

        msg_len = (uint32)strlen(message);
        remain_msg_len = CT_MESSAGE_BUFFER_SIZE - msg_len;
        if (i != 1) {
            iret_snprintf = snprintf_s(message + msg_len, remain_msg_len, remain_msg_len - 1, "%s or ", word);
        } else {
            iret_snprintf = snprintf_s(message + msg_len, remain_msg_len, remain_msg_len - 1, "%s", word);
        }
        if (iret_snprintf == -1) {
            va_end(ap);
            CT_THROW_ERROR(ERR_SYSTEM_CALL, iret_snprintf);
            return CT_ERROR;
        }

        j++;
        i--;
    }
    va_end(ap);

    *matched_id = CT_INVALID_ID32;
    CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "%s expected", message);
    return CT_ERROR;
}

static inline num_errno_t lex_parse_size(lex_t *lex, word_t *word, int64 *size)
{
    num_errno_t err_no;

    word->np.excl_flag = NF_DOT | NF_EXPN | NF_NEGATIVE_SIGN;
    word->type = WORD_TYPE_EOF;
    err_no = lex_fetch_numpart(lex, word);
    CM_CHECK_NUM_ERRNO(err_no);

    err_no = cm_decide_numtype(&word->np, (ct_type_t *)&word->id);
    CM_CHECK_NUM_ERRNO(err_no);

    if (!CT_IS_INTEGER_TYPE(word->id)) {
        return NERR_EXPECTED_INTEGER;
    }

    if (word->type == WORD_TYPE_NUMBER) {
        return cm_numpart2bigint(&word->np, size);
    } else if (word->type == WORD_TYPE_SIZE) {
        return cm_numpart2size(&word->np, size);
    }

    return NERR_ERROR;
}

status_t lex_expected_fetch_size(lex_t *lex, int64 *size, int64 min_size, int64 max_size)
{
    word_t word;
    num_errno_t err_no;

    if (CT_INVALID_INT64 != min_size && CT_INVALID_INT64 != max_size) {
        if (min_size > max_size) {
            return CT_ERROR;
        }
    }

    if (lex_skip_comments(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    err_no = lex_parse_size(lex, &word, size);
    if (err_no != NERR_SUCCESS) {
        CT_SRC_THROW_ERROR(word.loc, ERR_SQL_SYNTAX_ERROR, "size must be a positive long integer");
        return CT_ERROR;
    }

    if (CT_INVALID_INT64 != min_size && *size < min_size) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "size value is smaller "
                              "than minimum(" PRINT_FMT_INT64 ") required",
                              min_size);
        return CT_ERROR;
    }

    if (CT_INVALID_INT64 != max_size && *size > max_size) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "size value is bigger "
                              "than maximum(" PRINT_FMT_INT64 ") required",
                              max_size);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t lex_expected_fetch_int32(lex_t *lex, int32 *size)
{
    word_t word;
    num_errno_t err_no;

    if (lex_skip_comments(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    // for an integer dot, expn, size are not allowed
    word.np.excl_flag = NF_DOT | NF_EXPN | NF_SZ_INDICATOR;
    word.type = WORD_TYPE_EOF;
    err_no = lex_fetch_numpart(lex, &word);
    if (err_no != NERR_SUCCESS) {
        CT_SRC_THROW_ERROR(word.loc, ERR_SQL_SYNTAX_ERROR, "invalid integer");
        return CT_ERROR;
    }

    if (word.type != WORD_TYPE_NUMBER) {
        CT_SRC_THROW_ERROR(word.loc, ERR_SQL_SYNTAX_ERROR, "invalid integer");
        return CT_ERROR;
    }

    err_no = cm_numpart2int(&word.np, size);
    if (err_no != NERR_SUCCESS) {
        CT_SRC_THROW_ERROR(word.loc, ERR_SQL_SYNTAX_ERROR, "invalid integer");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t lex_expected_fetch_uint32(lex_t *lex, uint32 *num)
{
    word_t word;
    num_errno_t err_no;

    if (lex_skip_comments(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    // for an integer dot, expn, size are not allowed
    word.np.excl_flag = NF_DOT | NF_EXPN | NF_SZ_INDICATOR | NF_NEGATIVE_SIGN;
    word.type = WORD_TYPE_EOF;
    err_no = lex_fetch_numpart(lex, &word);
    if (err_no != NERR_SUCCESS) {
        CT_SRC_THROW_ERROR(word.loc, ERR_SQL_SYNTAX_ERROR, "unsigned integer expected");
        return CT_ERROR;
    }

    if (word.type != WORD_TYPE_NUMBER) {
        CT_SRC_THROW_ERROR(word.loc, ERR_SQL_SYNTAX_ERROR, "unsigned integer expected");
        return CT_ERROR;
    }

    err_no = cm_numpart2uint32(&word.np, num);
    if (err_no != NERR_SUCCESS) {
        CT_SRC_THROW_ERROR(word.loc, ERR_SQL_SYNTAX_ERROR, "unsigned integer expected");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t lex_expected_fetch_uint64(lex_t *lex, uint64 *size)
{
    word_t word;
    num_errno_t err_no;

    if (lex_skip_comments(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    // for an uint64, dot, negative, expn, size are not allowed
    word.np.excl_flag = NF_DOT | NF_NEGATIVE_SIGN | NF_EXPN | NF_SZ_INDICATOR;
    word.type = WORD_TYPE_EOF;
    err_no = lex_fetch_numpart(lex, &word);
    if (err_no != NERR_SUCCESS) {
        CT_SRC_THROW_ERROR(word.loc, ERR_SQL_SYNTAX_ERROR, "invalid uint64");
        return CT_ERROR;
    }

    if (word.type != WORD_TYPE_NUMBER) {
        CT_SRC_THROW_ERROR(word.loc, ERR_SQL_SYNTAX_ERROR, "invalid uint64");
        return CT_ERROR;
    }

    err_no = cm_numpart2uint64(&word.np, size);
    if (err_no != NERR_SUCCESS) {
        CT_SRC_THROW_ERROR(word.loc, ERR_SQL_SYNTAX_ERROR, "invalid uint64");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

/**
 * To fetch a decimal

 */
status_t lex_expected_fetch_dec(lex_t *lex, dec8_t *dec)
{
    word_t word;
    num_errno_t err_no;

    if (lex_skip_comments(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    word.np.excl_flag = NF_NONE;

    do {
        word.type = WORD_TYPE_EOF;
        err_no = lex_fetch_numpart(lex, &word);
        if (err_no != NERR_SUCCESS) {
            break;
        }
        if (word.type != WORD_TYPE_NUMBER) {
            err_no = NERR_UNEXPECTED_CHAR;
            break;
        }
        err_no = cm_numpart_to_dec8(&word.np, dec);
        if (err_no != NERR_SUCCESS) {
            break;
        }
        return CT_SUCCESS;
    } while (0);

    CT_SRC_THROW_ERROR_EX(word.loc, ERR_SQL_SYNTAX_ERROR, "invalid number text %s", cm_get_num_errinfo(err_no));
    return CT_ERROR;
}

/**
* To fetch a sequence value, The currently implementation require the
* value of a sequence to be between in CT_MIN_INT64 and CT_MAX_INT64.
* For the values that out of the range is a TODO word in future.

*/
status_t lex_expected_fetch_seqval(lex_t *lex, int64 *val)
{
    dec8_t dec;
    if (lex_expected_fetch_dec(lex, &dec) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!cm_dec_is_integer(&dec)) {
        return CT_ERROR;
    }

    (void)cm_dec8_to_int64_range(&dec, val, ROUND_TRUNC);
    return CT_SUCCESS;
}

/**
 * convert 0x00 ~ 0x7F to an ASCII char
 */
static inline status_t lex_text2hexchar(text_t *text, source_location_t *loc, char *c)
{
    uint32 val;
    do {
        if (text->len != 4) {
            break;
        }
        if (!CM_IS_HEX(text->str[2]) || !CM_IS_HEX(text->str[3])) {
            break;
        }
        val = cm_hex2int8(text->str[2]);
        val <<= 4;
        val += cm_hex2int8(text->str[3]);
        if (val > 127) {
            break;
        }
        *c = (char)val;
        return CT_SUCCESS;
    } while (0);

    CT_SRC_THROW_ERROR(*loc, ERR_SQL_SYNTAX_ERROR, "invalid hexdecimal character format, \\x00 ~ \\x7F is ok");
    return CT_ERROR;
}

/**
 * conver string 0x00 ~ 0x7F to an ASCII char
 *
 */
static inline status_t lex_str2hexchar(const char *str, char *c)
{
    uint32 val;
    do {
        if (strlen(str) != 4) {
            break;
        }
        if (!CM_IS_HEX(str[2]) || !CM_IS_HEX(str[3])) {
            break;
        }
        val = cm_hex2int8(str[2]);
        val <<= 4;
        val += cm_hex2int8(str[3]);
        if (val > 127) {
            break;
        }
        *c = (char)val;
        return CT_SUCCESS;
    } while (0);

    return CT_ERROR;
}

typedef struct {
    char *key;
    char value;
} char_map_t;

#define CT_MAX_KEY_STR_LEN  6  // "\\\""

static const char_map_t g_supported_escape_char[] = {
    { "\\a",  '\a' },
    { "\\t",  '\t' },
    { "\\n",  '\n' },
    { "\\r",  '\r' },
    { "\\?",  '?' },
    { "\\\"", '\"' },
    { "\\o",  '\0' },
    { "\\0",  '\0' },
    { "\\v",  '\v' },
    { "\\f",  '\f' },
};

status_t lex_check_asciichar(text_t *text, source_location_t *loc, char *c, bool32 allow_empty_char)
{
    bool32 cond = CT_FALSE;

    do {
        if (CM_IS_EMPTY(text)) {
            CT_BREAK_IF_TRUE(!allow_empty_char);
            *c = CT_INVALID_INT8;
            return CT_SUCCESS;
        }

        if (text->len == 1) {
            CT_BREAK_IF_TRUE(!CM_IS_ASCII(text->str[0]));
            *c = text->str[0];
            return CT_SUCCESS;
        }

        // escaped char = '
        cond = (text->len == 2) && CM_TEXT_BEGIN(text) == '\'' && CM_TEXT_SECOND(text) == '\'';
        if (cond) {
            *c = '\'';
            return CT_SUCCESS;
        }

        // handing escaped char \0x
        cond = CM_TEXT_BEGIN(text) == '\\' && CM_TEXT_SECOND(text) == 'x';
        if (cond) {
            return lex_text2hexchar(text, loc, c);
        }

        // handing escaped char  \,  ascii_char = g_supported_escape_char
        cond = CM_TEXT_BEGIN(text) == '\\' && text->len < CT_MAX_KEY_STR_LEN;
        if (cond) {
            for (uint32 i = 0; i < sizeof(g_supported_escape_char) / sizeof(char_map_t); i++) {
                if (cm_compare_text_str_ins(text, g_supported_escape_char[i].key) == 0) {
                    *c = g_supported_escape_char[i].value;
                    return CT_SUCCESS;
                }
            }
        }
    } while (0);

    return CT_ERROR;
}

/**
* Parsing string into one character
*/
status_t lex_expected_fetch_asciichar(lex_t *lex, char *c, bool32 allow_empty_char)
{
    word_t word;

    if (lex_expected_fetch_string(lex, &word) != CT_SUCCESS ||
        lex_check_asciichar(&word.text.value, &word.loc, c, allow_empty_char) != CT_SUCCESS) {
        CT_SRC_THROW_ERROR(word.loc, ERR_SQL_SYNTAX_ERROR, "single ASCII character expected");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

/**
 * Parsing string, Specially hex (\x00 ~ \x7F), escape characters(like \a \t)
 */
status_t lex_expected_fetch_str(lex_t *lex, char *str, uint32 str_max_length, char *key_word_info)
{
    word_t word;
    uint32 j = 0;
    do {
        CT_BREAK_IF_TRUE(lex_expected_fetch_string(lex, &word) != CT_SUCCESS);
        CT_BREAK_IF_TRUE(CM_IS_EMPTY(&word.text.value));

        if (word.text.len > str_max_length) {
            CT_SRC_THROW_ERROR_EX(word.loc, ERR_SQL_SYNTAX_ERROR, "%s is too long, max length is %u", key_word_info,
                                  str_max_length);
            return CT_ERROR;
        }

        for (uint32 i = 0; i < word.text.len; i++) {
            // Process hex characters
            // Note: \x00 ~ \x7F will be resolved to a char, others (like \x80~\xFF  \xGG) will not be changed.
            if (word.text.str[i] == '\\' && i + 3 < word.text.len && word.text.str[i + 1] == 'x') {
                char hex_str[5] = { '\\', 'x', word.text.str[i + 2], word.text.str[i + 3], '\0' };
                char ret_c;

                // if resolve hex to char successfully, skip 3 characters.
                // otherwise, these four characters will be resolved as common characters
                if (CT_SUCCESS == lex_str2hexchar(hex_str, &ret_c)) {
                    str[j++] = ret_c;

                    i += 3;
                    continue;
                }
            }
            // Note:others (like \x80~\xFF  \xGG) will not be changed, so there is no else
            // Process escape characters
            if (word.text.str[i] == '\\' && i + 1 < word.text.len) {
                char key[3] = { '\\', word.text.str[i + 1], '\0' };
                text_t key_text;
                key_text.str = key;
                key_text.len = (uint32)strlen(key);

                bool32 key_in_map = 0;

                for (uint32 temp = 0; temp < sizeof(g_supported_escape_char) / sizeof(char_map_t); temp++) {
                    if (cm_compare_text_str_ins(&key_text, g_supported_escape_char[temp].key) == 0) {
                        str[j++] = g_supported_escape_char[temp].value;

                        // Notice: One character must be skipped, because it has been handled.
                        i++;
                        key_in_map = 1;
                        break;
                    }
                }

                if (!key_in_map) {
                    str[j++] = word.text.str[i];
                }
            } else {
                // Process common characters
                str[j++] = word.text.str[i];
            }
        }
        str[j] = '\0';

        return CT_SUCCESS;
    } while (0);

    CT_SRC_THROW_ERROR_EX(word.loc, ERR_SQL_SYNTAX_ERROR, "fetch %s failed.", key_word_info);
    return CT_ERROR;
}

status_t lex_expected_fetch_string(lex_t *lex, word_t *word)
{
    if (lex_expected_fetch(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word->type != WORD_TYPE_STRING) {
        CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "'...' expected but %s found", W2S(word));
        return CT_ERROR;
    }

    LEX_REMOVE_WRAP(word);
    return CT_SUCCESS;
}

status_t lex_expected_fetch_dqstring(lex_t *lex, word_t *word)
{
    lex_begin_fetch(lex, word);

    if (lex_fetch_quote(lex, word, '\"') != CT_SUCCESS) {
        return CT_ERROR;
    }
    CM_REMOVE_ENCLOSED_CHAR(&word->text);
    return CT_SUCCESS;
}

/* Fetch a string that enclosed by ("), ('), (`) */
status_t lex_expected_fetch_enclosed_string(lex_t *lex, word_t *word)
{
    lex_begin_fetch(lex, word);

    char qchar = LEX_CURR(lex);
    if (qchar != '\"' && qchar != '\'' && qchar != '`') {
        CT_SRC_THROW_ERROR(lex->loc, ERR_SQL_SYNTAX_ERROR, "expected an enclosed char: (\"), (\'), (`)");
        return CT_ERROR;
    }

    if (lex_fetch_quote(lex, word, qchar) != CT_SUCCESS) {
        return CT_ERROR;
    }

    CM_REMOVE_ENCLOSED_CHAR(&word->text);
    return CT_SUCCESS;
}

/**
 * fetch   schema.table
 * + word  The word representation of schema.table
 */
status_t lex_expected_fetch_tblname(lex_t *lex, word_t *word, text_buf_t *tbl_textbuf)
{
    bool32 result = CT_FALSE;
    word_t ex_word = { 0 };

    word->ex_count = 0;
    CT_RETURN_IFERR(lex_expected_fetch_variant(lex, word));
    CT_RETURN_IFERR(lex_try_fetch_char(lex, '.', &result));

    if (result) {  // dot is found
        if (lex_expected_fetch_extra(lex, &ex_word) != CT_SUCCESS) {
            return CT_ERROR;
        }
        word->ex_words[word->ex_count].text = ex_word.text;
        word->ex_words[word->ex_count].type = ex_word.type;
        word->ex_count++;
    }

    // if textbuf is not null, set the buf with user.tbl_name
    if (tbl_textbuf == NULL) {
        return CT_SUCCESS;
    }

    do {
        if (word->type == WORD_TYPE_DQ_STRING) {
            CT_BREAK_IF_TRUE(!cm_buf_append_char(tbl_textbuf, *word->begin_addr));
        }
        CT_BREAK_IF_TRUE(!cm_buf_append_text(tbl_textbuf, &word->text.value));
        if (word->type == WORD_TYPE_DQ_STRING) {
            CT_BREAK_IF_TRUE(!cm_buf_append_char(tbl_textbuf, *word->begin_addr));
        }
        if (result) {
            CT_BREAK_IF_TRUE(!cm_buf_append_str(tbl_textbuf, "."));
            if (ex_word.type == WORD_TYPE_DQ_STRING) {
                CT_BREAK_IF_TRUE(!cm_buf_append_char(tbl_textbuf, *ex_word.begin_addr));
            }
            CT_BREAK_IF_TRUE(!cm_buf_append_text(tbl_textbuf, &ex_word.text.value));
            if (ex_word.type == WORD_TYPE_DQ_STRING) {
                CT_BREAK_IF_TRUE(!cm_buf_append_char(tbl_textbuf, *ex_word.begin_addr));
            }
        }
        return CT_SUCCESS;
    } while (0);

    CT_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "object name is too long");
    return CT_ERROR;
}

status_t lex_expected_fetch_variant(lex_t *lex, word_t *word)
{
    if (lex_expected_fetch(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!IS_VARIANT(word)) {
        CT_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid variant/object name was found");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t lex_try_fetch_datatype(lex_t *lex, word_t *typword, bool32 *is_found)
{
    if (lex->stack.depth == 0 || CM_IS_EMPTY(lex->curr_text)) {
        CT_SRC_THROW_ERROR(lex->loc, ERR_SQL_SYNTAX_ERROR, "missing datatype");
        return CT_ERROR;
    }

    if (lex_skip_comments(lex, typword) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (CM_IS_EMPTY(lex->curr_text)) {  // check again
        CT_SRC_THROW_ERROR(lex->loc, ERR_SQL_SYNTAX_ERROR, "missing datatype");
        return CT_ERROR;
    }

    typword->namable = CT_TRUE;
    typword->id = CT_INVALID_ID32;

    if (lex_fetch_name(lex, typword) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_try_match_datatype(lex, typword, is_found) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t lex_expected_fetch_bracket(lex_t *lex, word_t *word)
{
    if (lex_fetch(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word->type != WORD_TYPE_BRACKET) {
        CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "(...) expected but %s found", W2S(word));
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t lex_expected_fetch_comp(lex_t *lex, word_t *word, bool32 fetch_pwd)
{
    if (lex_expected_fetch(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word->type != WORD_TYPE_COMPARE) {
        if (fetch_pwd) {
            CT_SRC_THROW_ERROR(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "= expected after PASSWORD");
        } else {
            CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "= expected but %s found", W2S(word));
        }
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t lex_expected_end(lex_t *lex)
{
    word_t word;
    if (lex_fetch(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word.type != WORD_TYPE_EOF) {
        CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "expected end but %s found", W2S(&word));
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t lex_try_fetch_comment(lex_t *lex, word_t *word, bool32 *result)
{
    sql_text_t *text = lex->curr_text;
    lex_trim(text);

    *result = CT_FALSE;
    if (text->len < 2) {
        return CT_SUCCESS;
    }

    if ((*text->str == '-' && text->str[1] == '-') || (*text->str == '/' && text->str[1] == '*')) {
        *result = CT_TRUE;
        return lex_fetch_comment(lex, word);
    }

    return CT_SUCCESS;
}

static inline void lex_extract_hint_content(word_t *word)
{
    word->text.len -= 5;  // hint header /* + */
    word->text.str += 3;
    word->text.loc.column += 3;
    lex_trim(&word->text);
}

status_t lex_try_fetch_hint_comment(lex_t *lex, word_t *word, bool32 *result)
{
    sql_text_t *text = lex->curr_text;
    lex_trim(text);

    *result = CT_FALSE;

    // hint format: /* +[space][hint_items][space] */
    if (text->len < 5) {
        return CT_SUCCESS;
    }
    if (*text->str == '/' && text->str[1] == '*' && text->str[2] == '+') {
        *result = CT_TRUE;
        lex_begin_fetch(lex, word);
        if (lex_fetch_comment(lex, word) != CT_SUCCESS) {
            return CT_ERROR;
        }
        lex_extract_hint_content(word);
    }

    return CT_SUCCESS;
}

status_t lex_try_fetch_variant(lex_t *lex, word_t *word, bool32 *result)
{
    if (lex_fetch(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    *result = IS_VARIANT(word);

    if (!(*result)) {
        lex_back(lex, word);
    }

    return CT_SUCCESS;
}

status_t lex_try_fetch_variant_excl(lex_t *lex, word_t *word, uint32 excl, bool32 *result)
{
    if (lex_fetch(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if ((uint32)word->type & excl) {
        lex_back(lex, word);
        *result = CT_FALSE;
        return CT_SUCCESS;
    }

    *result = IS_VARIANT(word);

    if (!(*result)) {
        lex_back(lex, word);
    }

    return CT_SUCCESS;
}

status_t lex_skip_comments(lex_t *lex, word_t *word)
{
    bool32 result = CT_FALSE;

    do {
        if (lex_try_fetch_comment(lex, word, &result) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } while (result);

    lex_begin_fetch(lex, word);
    return CT_SUCCESS;
}


status_t lex_try_fetch_bracket(lex_t *lex, word_t *word, bool32 *result)
{
    sql_text_t *text = lex->curr_text;
    if (lex_skip_comments(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!(text->len > 0 && *text->str == '(')) {
        *result = CT_FALSE;
        return CT_SUCCESS;
    }
    word->type = WORD_TYPE_BRACKET;
    *result = CT_TRUE;
    return lex_fetch_bracket(lex, word);
}

status_t lex_try_fetch_char(lex_t *lex, char c, bool32 *result)
{
    sql_text_t *text = lex->curr_text;
    if (lex_skip_comments(lex, NULL) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (text->len == 0 || *text->str != c) {
        *result = CT_FALSE;
        return CT_SUCCESS;
    }

    if ((c == '.') && (LEX_NEXT(lex) == '.')) {
        *result = CT_FALSE;
        return CT_SUCCESS;
    }

    (void)lex_skip(lex, 1);
    *result = CT_TRUE;
    return CT_SUCCESS;
}

status_t lex_try_fetch(lex_t *lex, const char *word, bool32 *result)
{
    uint32 len;

    if (lex_skip_comments(lex, NULL) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_match_head(lex->curr_text, word, &len)) {
        *result = CT_TRUE;
        (void)lex_skip(lex, len);
    } else {
        *result = CT_FALSE;
    }

    return CT_SUCCESS;
}


/**
* Try to fetch n continuous words.
* @note the comments are allowed among in these words

*/
status_t lex_try_fetch_n(lex_t *lex, uint32 n, const char **words, bool32 *result)
{
    LEX_SAVE(lex);

    for (uint32 i = 0; i < n; i++) {
        if (lex_try_fetch(lex, words[i], result) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (!(*result)) {
            LEX_RESTORE(lex);
            return CT_SUCCESS;
        }
    }

    return CT_SUCCESS;
}

status_t lex_try_fetch_anyone(lex_t *lex, uint32 n, const char **words, bool32 *result)
{
    LEX_SAVE(lex);

    for (uint32 i = 0; i < n; i++) {
        if (lex_try_fetch(lex, words[i], result) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if ((*result)) {
            return CT_SUCCESS;
        }
    }

    LEX_RESTORE(lex);
    return CT_SUCCESS;
}

/**
 * Try to fetch two continuous words.
 * @note the comments are allowed among in these words

 */
status_t lex_try_fetch2(lex_t *lex, const char *word1, const char *word2, bool32 *result)
{
    const char *words[2] = { word1, word2 };
    return lex_try_fetch_n(lex, 2, (const char **)words, result);
}

/**
* Try to fetch three continuous words.
* @note the comments are allowed among in these words

*/
status_t lex_try_fetch3(lex_t *lex, const char *word1, const char *word2, const char *word3, bool32 *result)
{
    const char *words[3] = { word1, word2, word3 };
    return lex_try_fetch_n(lex, 3, (const char **)words, result);
}
/**
* Try to fetch four continuous words.
* @note the comments are allowed among in these words

*/
status_t lex_try_fetch4(lex_t *lex, const char *word1, const char *word2, const char *word3, const char *word4,
                        bool32 *result)
{
    const char *words[4] = { word1, word2, word3, word4 };
    return lex_try_fetch_n(lex, 4, (const char **)words, result);
}

status_t lex_try_match_records(lex_t *lex, const word_record_t *records, uint32 num, uint32 *matched_id)
{
    bool32 result = CT_FALSE;

    for (uint32 i = 0; i < num; i++) {
        if (lex_try_fetch_tuple(lex, &records[i].tuple, &result) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (result) {
            *matched_id = records[i].id;
            return CT_SUCCESS;
        }
    }

    *matched_id = CT_INVALID_ID32;
    return CT_SUCCESS;
}

status_t lex_fetch_to_char(lex_t *lex, word_t *word, char c)
{
    do {
        if (lex_fetch_word(lex, word, CT_FALSE) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } while (!(word->type == WORD_TYPE_EOF || IS_SPEC_CHAR(word, c)));

    return CT_SUCCESS;
}

status_t lex_inc_special_word(lex_t *lex, const char *word, bool32 *result)
{
    word_t tmp_word;

    LEX_SAVE(lex);
    *result = CT_FALSE;

    do {
        if (lex_fetch(lex, &tmp_word) != CT_SUCCESS) {
            LEX_RESTORE(lex);
            return CT_ERROR;
        }

        if (cm_text_str_equal_ins(&tmp_word.text.value, word)) {
            LEX_RESTORE(lex);
            *result = CT_TRUE;
            return CT_SUCCESS;
        }
    } while (!(tmp_word.type == WORD_TYPE_EOF));

    LEX_RESTORE(lex);
    return CT_SUCCESS;
}

static status_t lex_fetch_outline_name(lex_t *lex, word_t *word)
{
    char c = lex_skip(lex, 1);

    while (c != LEX_END && c != '@') {
        if (IS_SPLITTER(c)) {
            break;
        }
        c = lex_skip(lex, 1);
    }

    word->text.len = (uint32)(lex->curr_text->str - word->text.str);

    return CT_SUCCESS;
}

static status_t lex_fetch_outline_word(lex_t *lex, word_t *word)
{
    if (lex->curr_text->len == 0 || lex->stack.depth == 0) {
        word->type = WORD_TYPE_EOF;
        return CT_SUCCESS;
    }

    char curr = LEX_CURR(lex);
    if (curr == '(') {
        word->type = WORD_TYPE_BRACKET;
        CT_RETURN_IFERR(lex_fetch_bracket(lex, word));
    } else if (curr == '"') {
        word->type = WORD_TYPE_DQ_STRING;
        CT_RETURN_IFERR(lex_fetch_dquote(lex, word, LEX_CURR(lex)));
    } else if (curr == '\'') {
        word->type = WORD_TYPE_STRING;
        CT_RETURN_IFERR(lex_fetch_string(lex, word));
        CM_REMOVE_ENCLOSED_CHAR(&word->text);
    } else {
        word->type = WORD_TYPE_VARIANT;
        CT_RETURN_IFERR(lex_fetch_outline_name(lex, word));
        return lex_match_hint_keyword(lex, word);
    }

    return CT_SUCCESS;
}

status_t lex_fetch_in_outline(lex_t *lex, word_t *word)
{
    if (lex_fetch_outline_word(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

#ifdef __cplusplus
}
#endif

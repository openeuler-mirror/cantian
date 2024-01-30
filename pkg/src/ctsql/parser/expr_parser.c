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
 * expr_parser.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser/expr_parser.c
 *
 * -------------------------------------------------------------------------
 */
#include "expr_parser.h"
#include "cond_parser.h"
#include "func_parser.h"
#include "srv_instance.h"
#include "pl_executor.h"
#include "ctsql_type_map.h"
#include "dml_cl.h"
#include "decl_cl.h"
#include "param_decl_cl.h"
#include "ctsql_select_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline void sql_var2entype(word_t *word, expr_node_type_t *node_type)
{
    switch (word->type) {
        case WORD_TYPE_PARAM:
            *node_type = EXPR_NODE_PARAM;
            break;
        case WORD_TYPE_FUNCTION:
            *node_type = EXPR_NODE_FUNC;
            break;
        case WORD_TYPE_VARIANT:
        case WORD_TYPE_DQ_STRING:
        case WORD_TYPE_JOIN_COL:
            *node_type = EXPR_NODE_COLUMN;
            break;
        case WORD_TYPE_BRACKET:
            *node_type = EXPR_NODE_UNKNOWN;
            break;
        case WORD_TYPE_RESERVED:
            *node_type = EXPR_NODE_RESERVED;
            break;
        case WORD_TYPE_KEYWORD:
        case WORD_TYPE_DATATYPE:
            if (word->id == KEY_WORD_CASE) {
                *node_type = EXPR_NODE_CASE;
            } else {
                *node_type = (word->namable) ? EXPR_NODE_COLUMN : EXPR_NODE_UNKNOWN;
            }
            break;
        case WORD_TYPE_PL_NEW_COL:
            *node_type = EXPR_NODE_NEW_COL;
            break;
        case WORD_TYPE_PL_OLD_COL:
            *node_type = EXPR_NODE_OLD_COL;
            break;
        case WORD_TYPE_PL_ATTR:
            *node_type = EXPR_NODE_PL_ATTR;
            break;
        case WORD_TYPE_ARRAY:
            *node_type = EXPR_NODE_ARRAY;
            break;
        default:
            *node_type = EXPR_NODE_CONST;
            break;
    }
}

static inline void sql_oper2entype(word_t *word, expr_node_type_t *node_type)
{
    switch ((operator_type_t)word->id) {
        case OPER_TYPE_ADD:
            *node_type = EXPR_NODE_ADD;
            break;

        case OPER_TYPE_SUB:
            *node_type = EXPR_NODE_SUB;
            break;

        case OPER_TYPE_MUL:
            *node_type = EXPR_NODE_MUL;
            break;

        case OPER_TYPE_DIV:
            *node_type = EXPR_NODE_DIV;
            break;

        case OPER_TYPE_MOD:
            *node_type = EXPR_NODE_MOD;
            break;

        case OPER_TYPE_CAT:
            *node_type = EXPR_NODE_CAT;
            break;
        case OPER_TYPE_BITAND:
            *node_type = EXPR_NODE_BITAND;
            break;
        case OPER_TYPE_BITOR:
            *node_type = EXPR_NODE_BITOR;
            break;
        case OPER_TYPE_BITXOR:
            *node_type = EXPR_NODE_BITXOR;
            break;
        case OPER_TYPE_LSHIFT:
            *node_type = EXPR_NODE_LSHIFT;
            break;
        case OPER_TYPE_RSHIFT:
            *node_type = EXPR_NODE_RSHIFT;
            break;
        default:
            *node_type = EXPR_NODE_UNKNOWN;
            break;
    }
}

static bool32 sql_match_expected(expr_tree_t *expr, word_t *word, expr_node_type_t *node_type)
{
    if (expr->expecting == EXPR_EXPECT_UNARY) {
        expr->expecting = EXPR_EXPECT_VAR;
        if (word->id == OPER_TYPE_PRIOR) {
            *node_type = (expr_node_type_t)EXPR_NODE_PRIOR;
        } else {
            *node_type = (expr_node_type_t)EXPR_NODE_NEGATIVE;
        }
        return CT_TRUE;
    }

    if ((expr->expecting & EXPR_EXPECT_ALPHA) && word->type == WORD_TYPE_ALPHA_PARAM) {
        expr->expecting = EXPR_EXPECT_ALPHA;
        *node_type = (expr_node_type_t)EXPR_NODE_CSR_PARAM;
        return CT_TRUE;
    }

    /* BEGIN for the parse of count(*) branch */
    if (((expr)->expecting & EXPR_EXPECT_STAR) != 0 && EXPR_IS_STAR(word)) {
        expr->expecting = 0;
        *node_type = (expr_node_type_t)EXPR_NODE_STAR;
        return CT_TRUE;
    }

    /* END for the parse of count(*) branch */
    if ((expr->expecting & EXPR_EXPECT_VAR) && ((uint32)word->type & EXPR_VAR_WORDS)) {
        expr->expecting = EXPR_EXPECT_OPER;
        sql_var2entype(word, node_type);
        return CT_TRUE;
    }

    if ((expr->expecting & EXPR_EXPECT_OPER) != 0 && EXPR_IS_OPER(word)) {
        sql_oper2entype(word, node_type);
        expr->expecting = EXPR_EXPECT_VAR | EXPR_EXPECT_UNARY_OP;
        return CT_TRUE;
    }
    return CT_FALSE;
}

static status_t sql_parse_size(lex_t *lex, uint16 max_size, bool32 is_requred, typmode_t *type,
                               datatype_wid_t datatype_id)
{
    bool32 result = CT_FALSE;
    word_t word;
    int32 size;
    text_t text_size, text_char;

    CT_RETURN_IFERR(lex_try_fetch_bracket(lex, &word, &result));

    if (!result) {        // if no bracket found, i.e., the size is not specified
        if (is_requred) { // but the size must be specified, then throw an error
            CT_SRC_THROW_ERROR(word.text.loc, ERR_SQL_SYNTAX_ERROR, "the column size must be specified");
            return CT_ERROR;
        }
        type->size = 1;
        return CT_SUCCESS;
    }

    lex_remove_brackets(&word.text);
    text_size = *(text_t *)&word.text;

    // try get char or byte attr
    if (type->datatype == CT_TYPE_CHAR || type->datatype == CT_TYPE_VARCHAR) {
        cm_trim_text((text_t *)&word.text);
        cm_split_text((text_t *)&word.text, ' ', '\0', &text_size, &text_char);

        if (text_char.len > 0) {
            if (datatype_id == DTYP_NCHAR || datatype_id == DTYP_NVARCHAR) {
                source_location_t loc;
                loc.line = word.text.loc.line;
                loc.column = word.text.loc.column + text_size.len;
                CT_SRC_THROW_ERROR(loc, ERR_SQL_SYNTAX_ERROR, "missing right parenthesis");
                return CT_ERROR;
            }
            cm_trim_text(&text_char);
            if (cm_text_str_equal_ins(&text_char, "CHAR")) {
                type->is_char = CT_TRUE;
            } else if (!cm_text_str_equal_ins(&text_char, "BYTE")) {
                CT_SRC_THROW_ERROR(word.text.loc, ERR_SQL_SYNTAX_ERROR, "the column char type must be CHAR or BYTE");
                return CT_ERROR;
            }
        }
    }

    if (!cm_is_int(&text_size)) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "integer size value expected but %s found",
            W2S(&word));
        return CT_ERROR;
    }

    CT_RETURN_IFERR(cm_text2int(&text_size, &size));

    if (size <= 0 || size > (int32)max_size) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "size value must between 1 and %u", max_size);
        return CT_ERROR;
    }

    type->size = (uint16)size;

    return CT_SUCCESS;
}

static status_t sql_parse_precision(lex_t *lex, typmode_t *type)
{
    bool32 result = CT_FALSE;
    text_t text_prec, text_scale;
    word_t word;
    int32 precision, scale; // to avoid overflow

    CT_RETURN_IFERR(lex_try_fetch_bracket(lex, &word, &result));

    if (!result) {                                 // both precision and scale are not specified
        type->precision = CT_UNSPECIFIED_NUM_PREC; /* *< 0 stands for precision is not defined when create table */
        type->scale = CT_UNSPECIFIED_NUM_SCALE;
        type->size = CT_IS_NUMBER2_TYPE(type->datatype) ? (uint16)MAX_DEC2_BYTE_SZ : (uint16)MAX_DEC_BYTE_SZ;
        return CT_SUCCESS;
    }

    lex_remove_brackets(&word.text);
    cm_split_text((text_t *)&word.text, ',', '\0', &text_prec, &text_scale);

    if (!cm_is_int(&text_prec)) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "precision expected but %s found", W2S(&word));
        return CT_ERROR;
    }

    // type->precision
    CT_RETURN_IFERR(cm_text2int(&text_prec, &precision));

    if (precision < CT_MIN_NUM_PRECISION || precision > CT_MAX_NUM_PRECISION) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "precision must between %d and %d",
            CT_MIN_NUM_PRECISION, CT_MAX_NUM_PRECISION);
        return CT_ERROR;
    }
    type->precision = (uint8)precision;
    type->size = CT_IS_NUMBER2_TYPE(type->datatype) ? (uint16)MAX_DEC2_BYTE_BY_PREC(type->precision) :
                                                      (uint16)MAX_DEC_BYTE_BY_PREC(type->precision);

    cm_trim_text(&text_scale);
    if (text_scale.len == 0) { // Only the precision is specified and the scale is not specified
        type->scale = 0;       // then the scale is 0
        return CT_SUCCESS;
    }

    if (!cm_is_int(&text_scale)) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "scale expected but %s found", W2S(&word));
        return CT_ERROR;
    }

    CT_RETURN_IFERR(cm_text2int(&text_scale, &scale));

    int32 min_scale = CT_MIN_NUM_SCALE;
    int32 max_scale = CT_MAX_NUM_SCALE;
    if (scale > max_scale || scale < min_scale) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "numeric scale specifier is out of range (%d to %d)",
            min_scale, max_scale);
        return CT_ERROR;
    }
    type->scale = (int8)scale;
    return CT_SUCCESS;
}

static status_t sql_parse_real_mode(lex_t *lex, pmode_t pmod, typmode_t *type)
{
    bool32 result = CT_FALSE;
    text_t text_prec, text_scale;
    word_t word;
    int32 precision, scale; // to avoid overflow

    type->size = sizeof(double);
    do {
        if (pmod == PM_PL_ARG) {
            result = CT_FALSE;
            break;
        }
        CT_RETURN_IFERR(lex_try_fetch_bracket(lex, &word, &result));
    } while (0);

    if (!result) {                                  // both precision and scale are not specified
        type->precision = CT_UNSPECIFIED_REAL_PREC; /* *< 0 stands for precision is not defined when create table */
        type->scale = CT_UNSPECIFIED_REAL_SCALE;
        return CT_SUCCESS;
    }

    lex_remove_brackets(&word.text);
    cm_split_text((text_t *)&word.text, ',', '\0', &text_prec, &text_scale);

    if (cm_text2int_ex(&text_prec, &precision) != NERR_SUCCESS) {
        CT_SRC_THROW_ERROR(word.text.loc, ERR_SQL_SYNTAX_ERROR, "precision must be an integer");
        return CT_ERROR;
    }

    if (precision < CT_MIN_REAL_PRECISION || precision > CT_MAX_REAL_PRECISION) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "precision must between %d and %d",
            CT_MIN_NUM_PRECISION, CT_MAX_NUM_PRECISION);
        return CT_ERROR;
    }
    type->precision = (uint8)precision;

    cm_trim_text(&text_scale);
    if (text_scale.len == 0) { // Only the precision is specified and the scale is not specified
        type->scale = 0;       // then the scale is 0
        return CT_SUCCESS;
    }

    if (cm_text2int_ex(&text_scale, &scale) != NERR_SUCCESS) {
        CT_SRC_THROW_ERROR(word.text.loc, ERR_SQL_SYNTAX_ERROR, "scale must be an integer");
        return CT_ERROR;
    }

    if (scale > CT_MAX_REAL_SCALE || scale < CT_MIN_REAL_SCALE) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "scale must between %d and %d", CT_MIN_REAL_SCALE,
            CT_MAX_REAL_SCALE);
        return CT_ERROR;
    }
    type->scale = (int8)scale;
    return CT_SUCCESS;
}

/* used for parsing a number/decimal type in PL argument
 * e.g. the type of t_column, the precison and scale of NUMBER are not allowed here.
 * CREATE OR REPLACE PROCEDURE select_item ( *   t_column in NUMBER,
 * )
 * IS
 * temp1 VARCHAR2(10);
 * BEGIN
 * temp1 := t_column;
 * DBE_OUTPUT.PRINT_LINE ('No Data found for SELECT on ' || temp1);
 * END;
 * /
 *
 * @see sql_parse_rough_interval_attr
 *  */
static inline status_t sql_parse_rough_precision(lex_t *lex, typmode_t *type)
{
    type->precision = CT_UNSPECIFIED_NUM_PREC; /* *< 0 stands for precision is not defined when create table */
    type->scale = CT_UNSPECIFIED_NUM_SCALE;
    type->size = CT_IS_NUMBER2_TYPE(type->datatype) ? MAX_DEC2_BYTE_SZ : MAX_DEC_BYTE_SZ;
    return CT_SUCCESS;
}

/**
 * Parse the precision of a DATATIME or INTERVAL datatype
 * The specified precision must be between *min_prec* and *max_prec*.
 * If it not specified, then the default value is used
 */
static status_t sql_parse_datetime_precision(lex_t *lex, int32 *val_int32, int32 def_prec, int32 min_prec,
    int32 max_prec, const char *field_name)
{
    bool32 result = CT_FALSE;
    word_t word;

    CT_RETURN_IFERR(lex_try_fetch_bracket(lex, &word, &result));

    if (!result) {
        *val_int32 = def_prec;
        return CT_SUCCESS;
    }

    lex_remove_brackets(&word.text);

    if (cm_text2int_ex((text_t *)&word.text, val_int32) != NERR_SUCCESS) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "invalid %s precision, expected integer",
            field_name);
        return CT_ERROR;
    }

    if (*val_int32 < min_prec || *val_int32 > max_prec) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "%s precision must be between %d and %d", field_name,
            min_prec, max_prec);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

/**
 * Parse the leading precision and fractional_seconds_precsion of SECOND
 *
 */
static status_t sql_parse_second_precision(lex_t *lex, int32 *lead_prec, int32 *frac_prec)
{
    bool32 result = CT_FALSE;
    word_t word;
    status_t status;

    CT_RETURN_IFERR(lex_try_fetch_bracket(lex, &word, &result));

    if (!result) {
        *lead_prec = ITVL_DEFAULT_DAY_PREC;
        *frac_prec = ITVL_DEFAULT_SECOND_PREC;
        return CT_SUCCESS;
    }

    lex_remove_brackets(&word.text);
    CT_RETURN_IFERR(lex_push(lex, &word.text));

    do {
        status = CT_ERROR;
        CT_BREAK_IF_ERROR(lex_fetch(lex, &word));

        if (cm_text2int_ex((text_t *)&word.text, lead_prec) != NERR_SUCCESS) {
            CT_SRC_THROW_ERROR(word.text.loc, ERR_SQL_SYNTAX_ERROR, "invalid precision, expected integer");
            break;
        }

        if (*lead_prec > ITVL_MAX_DAY_PREC || *lead_prec < ITVL_MIN_DAY_PREC) {
            CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "DAY precision must be between %d and %d",
                ITVL_MIN_DAY_PREC, ITVL_MAX_DAY_PREC);
            break;
        }

        CT_BREAK_IF_ERROR(lex_try_fetch_char(lex, ',', &result));
        if (!result) {
            *frac_prec = ITVL_DEFAULT_SECOND_PREC;
            status = CT_SUCCESS;
            break;
        }

        CT_BREAK_IF_ERROR(lex_fetch(lex, &word));
        if (cm_text2int_ex((text_t *)&word.text, frac_prec) != NERR_SUCCESS) {
            CT_SRC_THROW_ERROR(word.text.loc, ERR_SQL_SYNTAX_ERROR, "invalid precision, expected integer");
            break;
        }

        if (*frac_prec > ITVL_MAX_SECOND_PREC || *frac_prec < ITVL_MIN_SECOND_PREC) {
            CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR,
                "fractional second precision must be between %d and %d", ITVL_MIN_SECOND_PREC, ITVL_MAX_SECOND_PREC);
            break;
        }
        status = CT_SUCCESS;
    } while (0);

    lex_pop(lex);
    return status;
}

static inline status_t sql_parse_timestamp_mod(lex_t *lex, typmode_t *type, pmode_t pmod, word_t *word)
{
    uint32 match_id;
    bool32 is_local = CT_FALSE;
    int32 prec_val = CT_MAX_DATETIME_PRECISION;

    type->datatype = CT_TYPE_TIMESTAMP;

    if (pmod != PM_PL_ARG) {
        if (sql_parse_datetime_precision(lex, &prec_val, CT_DEFAULT_DATETIME_PRECISION, CT_MIN_DATETIME_PRECISION,
            CT_MAX_DATETIME_PRECISION, "timestamp") != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    type->precision = (uint8)prec_val;
    type->scale = 0;
    type->size = sizeof(timestamp_t);

    if (lex_try_fetch_1of2(lex, "WITH", "WITHOUT", &match_id) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (match_id == CT_INVALID_ID32) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(lex_try_fetch(lex, "LOCAL", &is_local));

    CT_RETURN_IFERR(lex_expected_fetch_word2(lex, "TIME", "ZONE"));

    if (match_id == 1) {
        /* timestamp without time zone : do the same as timestamp. */
        return CT_SUCCESS;
    }

    if (is_local) {
        type->datatype = CT_TYPE_TIMESTAMP_LTZ;
        word->id = DTYP_TIMESTAMP_LTZ;
    } else {
        if (lex->call_version >= CS_VERSION_8) {
            type->datatype = CT_TYPE_TIMESTAMP_TZ;
            type->size = sizeof(timestamp_tz_t);
        } else {
            /* CT_TYPE_TIMESTAMP_TZ_FAKE is same with timestamp */
            type->datatype = CT_TYPE_TIMESTAMP_TZ_FAKE;
            type->size = sizeof(timestamp_t);
        }
        word->id = DTYP_TIMESTAMP_TZ;
    }

    return CT_SUCCESS;
}

static status_t sql_parse_interval_ds(lex_t *lex, typmode_t *type, uint32 *pfmt, uint32 match_id, uint32 *itvl_fmt)
{
    int32 prec, frac;
    bool32 result = CT_FALSE;
    uint32 match_id2;
    const interval_unit_t itvl_uints[] = { IU_YEAR, IU_MONTH, IU_DAY, IU_HOUR, IU_MINUTE, IU_SECOND };

    type->datatype = CT_TYPE_INTERVAL_DS;
    type->size = sizeof(interval_ds_t);

    if (match_id < 5) {
        // parse leading precision
        CT_RETURN_IFERR(sql_parse_datetime_precision(lex, &prec, ITVL_DEFAULT_DAY_PREC, ITVL_MIN_DAY_PREC,
            ITVL_MAX_DAY_PREC, "DAY"));
        type->day_prec = (uint8)prec;
        type->frac_prec = 0;

        CT_RETURN_IFERR(lex_try_fetch(lex, "TO", &result));
        if (!result) {
            if (pfmt != NULL) {
                (*pfmt) = *itvl_fmt;
            }
            return CT_SUCCESS;
        }
        CT_RETURN_IFERR(lex_expected_fetch_1ofn(lex, &match_id2, 4, "DAY", "HOUR", "MINUTE", "SECOND"));
        match_id2 += 2;

        if (match_id2 < match_id) {
            CT_SRC_THROW_ERROR(LEX_LOC, ERR_INVALID_INTERVAL_TEXT, "-- invalid field name");
            return CT_ERROR;
        }
        for (uint32 i = match_id + 1; i <= match_id2; ++i) {
            *itvl_fmt |= itvl_uints[i];
        }
        if (match_id2 == 5) {
            // parse second frac_precision
            CT_RETURN_IFERR(sql_parse_datetime_precision(lex, &frac, ITVL_DEFAULT_SECOND_PREC, ITVL_MIN_SECOND_PREC,
                ITVL_MAX_SECOND_PREC, "fractional second"));
            type->frac_prec = (uint8)frac;
        }
    } else {
        // parse leading and fractional precision
        CT_RETURN_IFERR(sql_parse_second_precision(lex, &prec, &frac));
        type->day_prec = (uint8)prec;
        type->frac_prec = (uint8)frac;
    }
    return CT_SUCCESS;
}

/* parsing an interval literal in a SQL expression
 * e.g., INTERVAL '123-2' YEAR(3) TO MONTH, INTERVAL '4 5:12' DAY TO MINUTE */
static inline status_t sql_parse_interval_literal(lex_t *lex, typmode_t *type, uint32 *pfmt)
{
    uint32 match_id, match_id2;
    int32 prec;
    bool32 result = CT_FALSE;
    uint32 itvl_fmt;

    const interval_unit_t itvl_uints[] = { IU_YEAR, IU_MONTH, IU_DAY, IU_HOUR, IU_MINUTE, IU_SECOND };

    CT_RETURN_IFERR(lex_expected_fetch_1ofn(lex, &match_id, 6, "YEAR", "MONTH", "DAY", "HOUR", "MINUTE", "SECOND"));

    itvl_fmt = itvl_uints[match_id];

    if (match_id < 2) {
        type->datatype = CT_TYPE_INTERVAL_YM;
        type->size = sizeof(interval_ym_t);
        // parse leading precision
        CT_RETURN_IFERR(sql_parse_datetime_precision(lex, &prec, ITVL_DEFAULT_YEAR_PREC, ITVL_MIN_YEAR_PREC,
            ITVL_MAX_YEAR_PREC, "YEAR"));
        type->year_prec = (uint8)prec;
        type->reserved = 0;

        if (match_id == 0) {
            CT_RETURN_IFERR(lex_try_fetch(lex, "TO", &result));
            if (result) {
                CT_RETURN_IFERR(lex_expected_fetch_1of2(lex, "YEAR", "MONTH", &match_id2));
                itvl_fmt |= itvl_uints[match_id2];
            }
        }
    } else {
        CT_RETURN_IFERR(sql_parse_interval_ds(lex, type, pfmt, match_id, &itvl_fmt));
    }

    if (pfmt != NULL) {
        (*pfmt) = itvl_fmt;
    }
    return CT_SUCCESS;
}

/**
 * Further distinguish two INTERVAL datatypes, with syntax:
 * INTERVAL  YEAR [( year_precision)]  TO  MONTH
 * INTERVAL  DAY [( day_precision)]  TO  SECOND[( fractional_seconds_precision)]
 */
static inline status_t sql_parse_interval_attr(lex_t *lex, typmode_t *type, word_t *word)
{
    uint32 match_id;
    int32 prec;

    CT_RETURN_IFERR(lex_expected_fetch_1of2(lex, "YEAR", "DAY", &match_id));

    if (match_id == 0) {
        // parse year_precision
        if (sql_parse_datetime_precision(lex, &prec, ITVL_DEFAULT_YEAR_PREC, ITVL_MIN_YEAR_PREC, ITVL_MAX_YEAR_PREC,
            "YEAR") != CT_SUCCESS) {
            return CT_ERROR;
        }
        type->year_prec = (uint8)prec;
        type->reserved = 0;
        CT_RETURN_IFERR(lex_expected_fetch_word2(lex, "TO", "MONTH"));

        type->datatype = CT_TYPE_INTERVAL_YM;
        type->size = sizeof(interval_ym_t);
        word->id = DTYP_INTERVAL_YM;
    } else {
        // parse day_precision
        if (sql_parse_datetime_precision(lex, &prec, ITVL_DEFAULT_DAY_PREC, ITVL_MIN_DAY_PREC, ITVL_MAX_DAY_PREC,
            "DAY") != CT_SUCCESS) {
            return CT_ERROR;
        }
        type->day_prec = (uint8)prec;

        CT_RETURN_IFERR(lex_expected_fetch_word2(lex, "TO", "SECOND"));

        // parse fractional_seconds_precision
        if (sql_parse_datetime_precision(lex, &prec, ITVL_DEFAULT_SECOND_PREC, ITVL_MIN_SECOND_PREC,
            ITVL_MAX_SECOND_PREC, "SECOND") != CT_SUCCESS) {
            return CT_ERROR;
        }
        type->frac_prec = (uint8)prec;

        type->datatype = CT_TYPE_INTERVAL_DS;
        type->size = sizeof(interval_ds_t);
        word->id = DTYP_INTERVAL_DS;
    }

    return CT_SUCCESS;
}

/**
 * Further distinguish two INTERVAL datatypes, with syntax:
 * INTERVAL  YEAR TO  MONTH
 * INTERVAL  DAY TO  SECOND
 *
 * @see sql_parse_rough_precision
 */
static inline status_t sql_parse_rough_interval_attr(lex_t *lex, typmode_t *type, word_t *word)
{
    uint32 match_id;

    CT_RETURN_IFERR(lex_expected_fetch_1of2(lex, "YEAR", "DAY", &match_id));

    if (match_id == 0) {
        CT_RETURN_IFERR(lex_expected_fetch_word2(lex, "TO", "MONTH"));

        // set year_precision
        type->year_prec = (uint8)ITVL_MAX_YEAR_PREC;
        type->reserved = 0;
        type->datatype = CT_TYPE_INTERVAL_YM;
        type->size = sizeof(interval_ym_t);
        word->id = DTYP_INTERVAL_YM;
    } else {
        CT_RETURN_IFERR(lex_expected_fetch_word2(lex, "TO", "SECOND"));

        // set day_precision
        type->day_prec = (uint8)ITVL_MAX_DAY_PREC;
        // set fractional_seconds_precision
        type->frac_prec = (uint8)ITVL_MAX_SECOND_PREC;
        type->datatype = CT_TYPE_INTERVAL_DS;
        type->size = sizeof(interval_ds_t);
        word->id = DTYP_INTERVAL_DS;
    }

    return CT_SUCCESS;
}

static status_t sql_parse_datatype_charset(lex_t *lex, uint8 *charset)
{
    word_t word;
    bool32 result = CT_FALSE;
    uint16 charset_id;

    if (lex_try_fetch(lex, "CHARACTER", &result) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!result) {
        return CT_SUCCESS;
    }

    if (lex_expected_fetch_word(lex, "SET") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_fetch(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word.type == WORD_TYPE_STRING) {
        LEX_REMOVE_WRAP(&word);
    }

    charset_id = cm_get_charset_id_ex(&word.text.value);
    if (charset_id == CT_INVALID_ID16) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "unknown charset option %s", T2S(&word.text.value));
        return CT_ERROR;
    }

    *charset = (uint8)charset_id;

    return CT_SUCCESS;
}

static status_t sql_parse_datatype_collate(lex_t *lex, uint8 *collate)
{
    word_t word;
    bool32 result = CT_FALSE;
    uint16 collate_id;

    if (lex_try_fetch(lex, "COLLATE", &result) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!result) {
        return CT_SUCCESS;
    }

    if (lex_fetch(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word.type == WORD_TYPE_STRING) {
        LEX_REMOVE_WRAP(&word);
    }

    collate_id = cm_get_collation_id(&word.text.value);
    if (collate_id == CT_INVALID_ID16) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "unknown collation option %s",
            T2S(&word.text.value));
        return CT_ERROR;
    }

    *collate = (uint8)collate_id;
    return CT_SUCCESS;
}

#define sql_set_default_typmod(typmod, typsz) ((typmod)->size = (uint16)(typsz), CT_SUCCESS)

static inline status_t sql_parse_varchar_mode(lex_t *lex, pmode_t pmod, typmode_t *typmod, datatype_wid_t dword_id)
{
    if (pmod == PM_PL_ARG) {
        return sql_set_default_typmod(typmod, CT_MAX_STRING_LEN);
    }
    return sql_parse_size(lex, (pmod == PM_NORMAL) ? CT_MAX_COLUMN_SIZE : CT_MAX_STRING_LEN, CT_TRUE, typmod, dword_id);
}

static status_t sql_parse_orcl_typmod(lex_t *lex, pmode_t pmod, typmode_t *typmode, word_t *typword)
{
    datatype_wid_t dword_id = (datatype_wid_t)typword->id;
    switch (dword_id) {
        case DTYP_BIGINT:
        case DTYP_UBIGINT:
        case DTYP_INTEGER:
        case DTYP_UINTEGER:
        case DTYP_SMALLINT:
        case DTYP_USMALLINT:
        case DTYP_TINYINT:
        case DTYP_UTINYINT:
            typmode->datatype = CT_TYPE_NUMBER;
            typmode->precision = CT_MAX_NUM_PRECISION;
            typmode->scale = 0;
            typmode->size = MAX_DEC_BYTE_BY_PREC(CT_MAX_NUM_PRECISION);
            return CT_SUCCESS;

        case DTYP_BOOLEAN:
            typmode->datatype = CT_TYPE_BOOLEAN;
            typmode->size = sizeof(bool32);
            return CT_SUCCESS;

        case DTYP_DOUBLE:
        case DTYP_FLOAT:
        case DTYP_NUMBER:
        case DTYP_DECIMAL:
            typmode->datatype = CT_TYPE_NUMBER;
            return (pmod != PM_PL_ARG) ? sql_parse_precision(lex, typmode) : sql_parse_rough_precision(lex, typmode);
        case DTYP_NUMBER2:
            typmode->datatype = CT_TYPE_NUMBER2;
            return (pmod != PM_PL_ARG) ? sql_parse_precision(lex, typmode) : sql_parse_rough_precision(lex, typmode);

        case DTYP_BINARY:
            typmode->datatype = g_instance->sql.string_as_hex_binary ? CT_TYPE_RAW : CT_TYPE_BINARY;
            return (pmod != PM_PL_ARG) ? sql_parse_size(lex, (uint16)CT_MAX_COLUMN_SIZE, CT_FALSE, typmode, dword_id) :
                                         sql_set_default_typmod(typmode, CT_MAX_COLUMN_SIZE);

        case DTYP_VARBINARY:
            typmode->datatype = g_instance->sql.string_as_hex_binary ? CT_TYPE_RAW : CT_TYPE_VARBINARY;
            return (pmod != PM_PL_ARG) ? sql_parse_size(lex, (uint16)CT_MAX_COLUMN_SIZE, CT_TRUE, typmode, dword_id) :
                                         sql_set_default_typmod(typmode, CT_MAX_COLUMN_SIZE);

        case DTYP_RAW:
            typmode->datatype = CT_TYPE_RAW;
            return (pmod != PM_PL_ARG) ? sql_parse_size(lex, (uint16)CT_MAX_COLUMN_SIZE, CT_FALSE, typmode, dword_id) :
                                         sql_set_default_typmod(typmode, CT_MAX_COLUMN_SIZE);

        case DTYP_CHAR:
            typmode->datatype = CT_TYPE_CHAR;
            return (pmod != PM_PL_ARG) ? sql_parse_size(lex, (uint16)CT_MAX_COLUMN_SIZE, CT_FALSE, typmode, dword_id) :
                                         sql_set_default_typmod(typmode, CT_MAX_COLUMN_SIZE);

        case DTYP_VARCHAR:
            typmode->datatype = CT_TYPE_VARCHAR;
            return sql_parse_varchar_mode(lex, pmod, typmode, dword_id);

        case DTYP_DATE:
            typmode->datatype = CT_TYPE_DATE;
            typmode->size = sizeof(date_t);
            return CT_SUCCESS;

        case DTYP_TIMESTAMP:
            return sql_parse_timestamp_mod(lex, typmode, pmod, typword);

        case DTYP_INTERVAL:
            return (pmod != PM_PL_ARG) ? sql_parse_interval_attr(lex, typmode, typword) :
                                         sql_parse_rough_interval_attr(lex, typmode, typword);

        case DTYP_BINARY_DOUBLE:
        case DTYP_BINARY_FLOAT:
            typmode->datatype = CT_TYPE_REAL;
            typmode->size = sizeof(double);
            return CT_SUCCESS;

        case DTYP_BINARY_UINTEGER:
            typmode->datatype = CT_TYPE_UINT32;
            typmode->size = sizeof(uint32);
            return CT_SUCCESS;
        case DTYP_BINARY_INTEGER:
            typmode->datatype = CT_TYPE_INTEGER;
            typmode->size = sizeof(int32);
            return CT_SUCCESS;

        case DTYP_SERIAL:
        case DTYP_BINARY_BIGINT:
            typmode->datatype = CT_TYPE_BIGINT;
            typmode->size = sizeof(int64);
            return CT_SUCCESS;

        case DTYP_BLOB: {
            typmode->datatype = CT_TYPE_BLOB;
            return sql_set_default_typmod(typmode, CT_MAX_COLUMN_SIZE);
        }

        case DTYP_CLOB: {
            typmode->datatype = CT_TYPE_CLOB;
            return sql_set_default_typmod(typmode, CT_MAX_COLUMN_SIZE);
        }

        case DTYP_IMAGE:
#ifdef Z_SHARDING
            if (IS_COORDINATOR) {
                CT_SRC_THROW_ERROR(typword->loc, ERR_CAPABILITY_NOT_SUPPORT,
                    "IMAGE Type(includes IMAGE and LONGBLOB and MEDIUMBLOB)");
                return CT_ERROR;
            }
#endif
            typmode->datatype = CT_TYPE_IMAGE;
            return sql_set_default_typmod(typmode, CT_MAX_COLUMN_SIZE);

        case DTYP_NVARCHAR:
            typmode->datatype = CT_TYPE_VARCHAR;
            CT_RETURN_IFERR(sql_parse_varchar_mode(lex, pmod, typmode, dword_id));
            typmode->is_char = CT_TRUE;
            return CT_SUCCESS;

        case DTYP_NCHAR:
            typmode->datatype = CT_TYPE_CHAR;
            if (pmod != PM_PL_ARG) {
                CT_RETURN_IFERR(sql_parse_size(lex, (uint16)CT_MAX_COLUMN_SIZE, CT_FALSE, typmode, dword_id));
            } else {
                CT_RETURN_IFERR(sql_set_default_typmod(typmode, CT_MAX_COLUMN_SIZE));
            }

            typmode->is_char = CT_TRUE;
            return CT_SUCCESS;

        case DTYP_BINARY_UBIGINT:
            CT_SRC_THROW_ERROR(typword->loc, ERR_CAPABILITY_NOT_SUPPORT, "datatype");
            return CT_ERROR;

        default:
            CT_SRC_THROW_ERROR_EX(typword->loc, ERR_SQL_SYNTAX_ERROR, "unrecognized datatype word: %s",
                T2S(&typword->text.value));
            return CT_ERROR;
    }
}

static status_t sql_parse_native_typmod(lex_t *lex, pmode_t pmod, typmode_t *typmode, word_t *typword)
{
    status_t status;
    datatype_wid_t dword_id = (datatype_wid_t)typword->id;
    switch (dword_id) {
        /* now we map smallint/tinyint unsigned into uint */
        case DTYP_UINTEGER:
        case DTYP_BINARY_UINTEGER:
        case DTYP_USMALLINT:
        case DTYP_UTINYINT:
            typmode->datatype = CT_TYPE_UINT32;
            typmode->size = sizeof(uint32);
            return CT_SUCCESS;
        /* now we map smallint/tinyint signed into int */
        case DTYP_SMALLINT:
        case DTYP_TINYINT:
        case DTYP_INTEGER:
        case DTYP_PLS_INTEGER:
        case DTYP_BINARY_INTEGER:
            typmode->datatype = CT_TYPE_INTEGER;
            typmode->size = sizeof(int32);
            return CT_SUCCESS;

        case DTYP_BOOLEAN:
            typmode->datatype = CT_TYPE_BOOLEAN;
            typmode->size = sizeof(bool32);
            return CT_SUCCESS;

        case DTYP_NUMBER:
            typmode->datatype = CT_TYPE_NUMBER;
            status = (pmod != PM_PL_ARG) ? sql_parse_precision(lex, typmode) : sql_parse_rough_precision(lex, typmode);
            CT_RETURN_IFERR(status);
            sql_try_match_type_map(lex->curr_user, typmode);
            return status;

        case DTYP_NUMBER2:
            typmode->datatype = CT_TYPE_NUMBER2;
            return (pmod != PM_PL_ARG) ? sql_parse_precision(lex, typmode) : sql_parse_rough_precision(lex, typmode);

        case DTYP_DECIMAL:
            typmode->datatype = CT_TYPE_NUMBER;
            return (pmod != PM_PL_ARG) ? sql_parse_precision(lex, typmode) : sql_parse_rough_precision(lex, typmode);

        case DTYP_BINARY:
            typmode->datatype = g_instance->sql.string_as_hex_binary ? CT_TYPE_RAW : CT_TYPE_BINARY;
            return (pmod != PM_PL_ARG) ? sql_parse_size(lex, (uint16)CT_MAX_COLUMN_SIZE, CT_TRUE, typmode, dword_id) :
                                         sql_set_default_typmod(typmode, CT_MAX_COLUMN_SIZE);

        case DTYP_VARBINARY:
            typmode->datatype = g_instance->sql.string_as_hex_binary ? CT_TYPE_RAW : CT_TYPE_VARBINARY;
            return (pmod != PM_PL_ARG) ? sql_parse_size(lex, (uint16)CT_MAX_COLUMN_SIZE, CT_TRUE, typmode, dword_id) :
                                         sql_set_default_typmod(typmode, CT_MAX_COLUMN_SIZE);

        case DTYP_RAW:
            typmode->datatype = CT_TYPE_RAW;
            return (pmod != PM_PL_ARG) ? sql_parse_size(lex, (uint16)CT_MAX_COLUMN_SIZE, CT_TRUE, typmode, dword_id) :
                                         sql_set_default_typmod(typmode, CT_MAX_COLUMN_SIZE);

        case DTYP_CHAR:
            typmode->datatype = CT_TYPE_CHAR;
            return (pmod != PM_PL_ARG) ? sql_parse_size(lex, (uint16)CT_MAX_COLUMN_SIZE, CT_FALSE, typmode, dword_id) :
                                         sql_set_default_typmod(typmode, CT_MAX_COLUMN_SIZE);

        case DTYP_VARCHAR:
        case DTYP_STRING:
            typmode->datatype = CT_TYPE_VARCHAR;
            return sql_parse_varchar_mode(lex, pmod, typmode, dword_id);

        case DTYP_DATE:
            typmode->datatype = CT_TYPE_DATE;
            typmode->size = sizeof(date_t);
            return CT_SUCCESS;

        case DTYP_TIMESTAMP:
            return sql_parse_timestamp_mod(lex, typmode, pmod, typword);

        case DTYP_INTERVAL:
            return (pmod != PM_PL_ARG) ? sql_parse_interval_attr(lex, typmode, typword) :
                                         sql_parse_rough_interval_attr(lex, typmode, typword);

        case DTYP_DOUBLE:
        case DTYP_FLOAT:
            typmode->datatype = CT_TYPE_REAL;
            return sql_parse_real_mode(lex, pmod, typmode);

        case DTYP_BINARY_DOUBLE:
        case DTYP_BINARY_FLOAT:
            typmode->datatype = CT_TYPE_REAL;
            typmode->size = sizeof(double);
            typmode->precision = CT_UNSPECIFIED_REAL_PREC;
            typmode->scale = CT_UNSPECIFIED_REAL_SCALE;
            return CT_SUCCESS;

        case DTYP_SERIAL:
        case DTYP_BIGINT:
        case DTYP_BINARY_BIGINT:
            typmode->datatype = CT_TYPE_BIGINT;
            typmode->size = sizeof(int64);
            return CT_SUCCESS;

        case DTYP_JSONB:
        case DTYP_BLOB: {
            typmode->datatype = CT_TYPE_BLOB;
            return sql_set_default_typmod(typmode, CT_MAX_COLUMN_SIZE);
        }

        case DTYP_CLOB: {
            typmode->datatype = CT_TYPE_CLOB;
            return sql_set_default_typmod(typmode, CT_MAX_COLUMN_SIZE);
        }

        case DTYP_IMAGE:
            typmode->datatype = CT_TYPE_IMAGE;
            return sql_set_default_typmod(typmode, CT_MAX_COLUMN_SIZE);

        case DTYP_NVARCHAR:
            typmode->datatype = CT_TYPE_VARCHAR;
            CT_RETURN_IFERR(sql_parse_varchar_mode(lex, pmod, typmode, dword_id));
            typmode->is_char = CT_TRUE;
            return CT_SUCCESS;

        case DTYP_NCHAR:
            typmode->datatype = CT_TYPE_CHAR;
            if (pmod != PM_PL_ARG) {
                CT_RETURN_IFERR(sql_parse_size(lex, (uint16)CT_MAX_COLUMN_SIZE, CT_FALSE, typmode, dword_id));
            } else {
                CT_RETURN_IFERR(sql_set_default_typmod(typmode, CT_MAX_COLUMN_SIZE));
            }

            typmode->is_char = CT_TRUE;
            return CT_SUCCESS;

        case DTYP_UBIGINT:
        case DTYP_BINARY_UBIGINT:
            CT_SRC_THROW_ERROR(typword->loc, ERR_CAPABILITY_NOT_SUPPORT, "datatype");
            return CT_ERROR;

        default:
            CT_SRC_THROW_ERROR_EX(typword->loc, ERR_SQL_SYNTAX_ERROR, "unrecognized datatype word: %s",
                T2S(&typword->text.value));
            return CT_ERROR;
    }
}

status_t sql_parse_typmode(lex_t *lex, pmode_t pmod, typmode_t *typmod, word_t *typword)
{
    status_t status;
    typmode_t tmode = { 0 };
    uint8 charset = 0;
    uint8 collate = 0;

    if (USE_NATIVE_DATATYPE) {
        status = sql_parse_native_typmod(lex, pmod, &tmode, typword);
        CT_RETURN_IFERR(status);
    } else {
        status = sql_parse_orcl_typmod(lex, pmod, &tmode, typword);
        CT_RETURN_IFERR(status);
    }

    if (CT_IS_STRING_TYPE(tmode.datatype)) {
        status = sql_parse_datatype_charset(lex, &charset);
        CT_RETURN_IFERR(status);
        tmode.charset = charset;

        status = sql_parse_datatype_collate(lex, &collate);
        CT_RETURN_IFERR(status);
        tmode.collate = collate;
    }

    if (typmod != NULL) {
        *typmod = tmode;
    }

    return CT_SUCCESS;
}

status_t sql_parse_datatype_typemode(lex_t *lex, pmode_t pmod, typmode_t *typmod, word_t *typword, word_t *tword)
{
    CT_RETURN_IFERR(sql_parse_typmode(lex, pmod, typmod, tword));

    if (typword != NULL) {
        *typword = *tword;
    }

    if (lex_try_match_array(lex, &typmod->is_array, typmod->datatype) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

/**
 * An important interface to parse a datatype starting from the current LEX,
 * Argument description:
 * + pmod    : see definition of @pmode_t
 * + typmode : The typemode of the parsing datatype. If it is NULL, the output typmode is ignored.
 * + typword : The word of a datatype. It includes type location in SQL, type ID. If it is NULL, it is ignored.

 */
status_t sql_parse_datatype(lex_t *lex, pmode_t pmod, typmode_t *typmod, word_t *typword)
{
    bool32 is_found = CT_FALSE;
    word_t tword;
    if (lex_try_fetch_datatype(lex, &tword, &is_found) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!is_found) {
        CT_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR, "datatype expected, but got '%s'", W2S(&tword));
        return CT_ERROR;
    }

    if (sql_parse_datatype_typemode(lex, pmod, typmod, typword, &tword) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

/*
    INTERVAL 'integer [-integer]' {YEAR|MONTH}[(prec)] [TO {YEAR|MONTH}]
    OR
    INTERVAL '{integer|integer time_expr|time_expr}'
        {DAY|HOUR|MINUTE|SECOND}[(prec)] [TO {DAY|HOUR|MINUTE|SECOND[(sec_prec)]}]
*/
static status_t sql_try_parse_interval_expr(sql_stmt_t *stmt, expr_node_t *node, bool32 *result)
{
    lex_t *lex = stmt->session->lex;
    text_t itvl_text;
    typmode_t type = { 0 };
    uint32 itvl_fmt = 0;
    interval_detail_t interval_detail;
    word_t word;

    CT_RETURN_IFERR(lex_fetch(lex, &word));
    if (word.type != WORD_TYPE_STRING) {
        (*result) = CT_FALSE;
        lex_back(lex, &word);
        return CT_SUCCESS;
    }
    (*result) = CT_TRUE;
    itvl_text = word.text.value;
    itvl_text.str += 1;
    itvl_text.len -= 2;

    CT_RETURN_IFERR(sql_parse_interval_literal(lex, &type, &itvl_fmt));

    node->type = EXPR_NODE_CONST;
    node->datatype = type.datatype;
    node->value.type = (int16)type.datatype;
    node->value.is_null = CT_FALSE;
    node->typmod = type;

    CT_RETURN_IFERR(cm_text2intvl_detail(&itvl_text, type.datatype, &interval_detail, itvl_fmt));

    if (type.datatype == CT_TYPE_INTERVAL_YM) {
        CT_RETURN_IFERR(cm_encode_yminterval(&interval_detail, &node->value.v_itvl_ym));
        CT_RETURN_IFERR(cm_adjust_yminterval(&node->value.v_itvl_ym, type.year_prec));
    } else {
        CT_RETURN_IFERR(cm_encode_dsinterval(&interval_detail, &node->value.v_itvl_ds));
        CT_RETURN_IFERR(cm_adjust_dsinterval(&node->value.v_itvl_ds, type.day_prec, type.frac_prec));
    }

    return CT_SUCCESS;
}

/*
  DATE '1995-01-01' OR TIMESTAMP '1995-01-01 11:22:33.456'
*/
static status_t sql_try_parse_date_expr(sql_stmt_t *stmt, word_t *word, expr_node_t *node, bool32 *result)
{
    lex_t *lex = stmt->session->lex;
    uint32 type_id = word->id;
    word_t next_word;

    if (!cm_text_str_equal_ins(&word->text.value, "DATE") && !cm_text_str_equal_ins(&word->text.value, "TIMESTAMP")) {
        (*result) = CT_FALSE;
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(lex_fetch(lex, &next_word));
    if (next_word.type != WORD_TYPE_STRING) {
        (*result) = CT_FALSE;
        lex_back(lex, &next_word);
        return CT_SUCCESS;
    }
    (*result) = CT_TRUE;
    CM_REMOVE_ENCLOSED_CHAR(&next_word.text.value);

    if (type_id == DTYP_DATE) {
        node->datatype = CT_TYPE_DATE;
        node->typmod.precision = 0;
        CT_RETURN_IFERR(cm_text2date_def(&next_word.text.value, &node->value.v_date));
    } else if (type_id == DTYP_TIMESTAMP) {
        node->datatype = CT_TYPE_TIMESTAMP;
        node->typmod.precision = CT_DEFAULT_DATETIME_PRECISION;
        CT_RETURN_IFERR(cm_text2timestamp_def(&next_word.text.value, &node->value.v_date));
    } else {
        CT_SRC_THROW_ERROR_EX(next_word.text.loc, ERR_SQL_SYNTAX_ERROR, "invalid datatype word id: %u", type_id);
        return CT_ERROR;
    }

    node->type = EXPR_NODE_CONST;
    node->value.type = node->datatype;
    node->value.is_null = CT_FALSE;
    node->typmod.size = sizeof(date_t);

    return CT_SUCCESS;
}

status_t sql_copy_text_remove_quotes(sql_context_t *context, text_t *src, text_t *dst)
{
    if (sql_alloc_mem(context, src->len, (void **)&dst->str) != CT_SUCCESS) {
        return CT_ERROR;
    }
    dst->len = 0;
    for (uint32 i = 0; i < src->len; i++) {
        CM_TEXT_APPEND(dst, CM_GET_CHAR(src, i));
        // if existing two continuous '
        if (CM_GET_CHAR(src, i) == '\'') {
            ++i;
            if (i >= src->len) {
                break;
            }
            if (CM_GET_CHAR(src, i) != '\'') {
                CM_TEXT_APPEND(dst, CM_GET_CHAR(src, i));
            }
        }
    }
    return CT_SUCCESS;
}

status_t sql_word2text(sql_stmt_t *stmt, word_t *word, expr_node_t *node)
{
    text_t const_text;
    text_t *val_text = NULL;

    const_text = word->text.value;
    CM_REMOVE_ENCLOSED_CHAR(&const_text);

    /*
     * The max size of text in sql is CT_MAX_COLUMN_SIZE.
     * The max size of text in plsql is CT_SHARED_PAGE_SIZE.
     */
    if (SQL_TYPE(stmt) <= CTSQL_TYPE_DDL_CEIL && const_text.len > CT_MAX_COLUMN_SIZE) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_VALUE_ERROR, "constant string in SQL is too long, can not exceed %u",
            CT_MAX_COLUMN_SIZE);
        return CT_ERROR;
    }
    if (SQL_TYPE(stmt) >= CTSQL_TYPE_CREATE_PROC && SQL_TYPE(stmt) < CTSQL_TYPE_PL_CEIL_END &&
        const_text.len > sql_pool->memory->page_size) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_VALUE_ERROR,
            "constant string in PL/SQL is too long, can not exceed %u", sql_pool->memory->page_size);
        return CT_ERROR;
    }

    val_text = VALUE_PTR(text_t, &node->value);
    node->value.type = CT_TYPE_CHAR;

    if (const_text.len == 0) {
        if (g_instance->sql.enable_empty_string_null) {
            // empty text is used as NULL like oracle
            val_text->str = NULL;
            val_text->len = 0;
            node->value.is_null = CT_TRUE;
            return CT_SUCCESS;
        }
    }

    return sql_copy_text_remove_quotes(stmt->context, &const_text, val_text);
}

status_t word_to_variant_number(word_t *word, variant_t *var)
{
    num_errno_t err_num = NERR_ERROR;
    var->is_null = CT_FALSE;
    var->type = (ct_type_t)word->id;

    switch (var->type) {
        case CT_TYPE_UINT32:
            err_num = cm_numpart2uint32(&word->np, &var->v_uint32);
            break;
        case CT_TYPE_INTEGER:
            err_num = cm_numpart2int(&word->np, &var->v_int);
            break;

        case CT_TYPE_BIGINT:
            err_num = cm_numpart2bigint(&word->np, &var->v_bigint);
            if (var->v_bigint == (int64)(CT_MIN_INT32)) {
                var->type = CT_TYPE_INTEGER;
                var->v_int = CT_MIN_INT32;
            }
            break;
        case CT_TYPE_UINT64:
            err_num = cm_numpart2uint64(&word->np, &var->v_ubigint);
            break;
        case CT_TYPE_REAL:
            err_num = cm_numpart2real(&word->np, &var->v_real);
            break;

        case CT_TYPE_NUMBER:
        case CT_TYPE_NUMBER2:
        case CT_TYPE_DECIMAL: {
            err_num = cm_numpart_to_dec8(&word->np, &var->v_dec);
            if (NUMPART_IS_ZERO(&word->np) && word->np.has_dot) {
                var->type = CT_TYPE_INTEGER;
                var->v_int = 0;
            }
            break;
        }

        default:
            CM_NEVER;
            break;
    }

    if (err_num != NERR_SUCCESS) {
        if (err_num == NERR_OVERFLOW) {
            CT_THROW_ERROR(ERR_NUM_OVERFLOW);
        } else {
            CT_SRC_THROW_ERROR(word->loc, ERR_INVALID_NUMBER, cm_get_num_errinfo(err_num));
        }
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_word2number(word_t *word, expr_node_t *node)
{
    if (UNARY_INCLUDE_NEGATIVE(node)) {
        word->np.is_neg = !word->np.is_neg;
    }

    CT_RETURN_IFERR(word_to_variant_number(word, &node->value));

    if (UNARY_INCLUDE_ROOT(node)) {
        node->unary = UNARY_OPER_ROOT;
    } else {
        node->unary = UNARY_OPER_NONE;
    }

    return CT_SUCCESS;
}

#define CHECK_PARAM_NAME_NEEDED(stmt) \
    ((stmt)->context->type == CTSQL_TYPE_ANONYMOUS_BLOCK || (stmt)->plsql_mode == PLSQL_DYNSQL)

status_t sql_add_param_mark(sql_stmt_t *stmt, word_t *word, bool32 *is_repeated, uint32 *pnid)
{
    sql_param_mark_t *param_mark = NULL;
    text_t name;
    uint32 i, num;
    text_t num_text;

    *is_repeated = CT_FALSE;

    if (word->text.len >= 2 && word->text.str[0] == '$') { // $parameter minimum length2
        /* using '$' as param identifier can only be followed with number */
        num_text.str = word->text.str + 1;
        num_text.len = word->text.len - 1;
        CT_RETURN_IFERR(cm_text2uint32(&num_text, &num)); /* here just checking whether it can be tranform */
    }
    if (word->text.len >= 2 && CHECK_PARAM_NAME_NEEDED(stmt)) { // $parameter minimum length2
        *pnid = stmt->context->pname_count;                     // paramter name id
        for (i = 0; i < stmt->context->params->count; i++) {
            param_mark = (sql_param_mark_t *)cm_galist_get(stmt->context->params, i);
            name.len = param_mark->len;
            name.str = stmt->session->lex->text.str + param_mark->offset - stmt->text_shift;

            if (cm_text_equal_ins(&name, &word->text.value)) {
                // parameter name is found
                *is_repeated = CT_TRUE;
                *pnid = param_mark->pnid;
                break;
            }
        }

        // not found
        if (!(*is_repeated)) {
            stmt->context->pname_count++;
        }
    } else {
        *is_repeated = CT_FALSE;
        *pnid = stmt->context->pname_count;
        stmt->context->pname_count++;
    }

    if (cm_galist_new(stmt->context->params, sizeof(sql_param_mark_t), (void **)&param_mark) != CT_SUCCESS) {
        return CT_ERROR;
    }

    param_mark->offset = LEX_OFFSET(stmt->session->lex, word) + stmt->text_shift;
    param_mark->len = word->text.len;
    param_mark->pnid = *pnid;
    return CT_SUCCESS;
}

static status_t sql_word2csrparam(sql_stmt_t *stmt, word_t *word, expr_node_t *node)
{
    if (!(stmt->context->type < CTSQL_TYPE_DML_CEIL)) {
        CT_SRC_THROW_ERROR(word->loc, ERR_SQL_SYNTAX_ERROR, "cursor sharing param only allowed in dml");
        return CT_ERROR;
    }

    node->value.is_null = CT_FALSE;
    node->value.type = CT_TYPE_INTEGER;
    VALUE(uint32, &node->value) = stmt->context->csr_params->count;
    CT_RETURN_IFERR(cm_galist_insert(stmt->context->csr_params, node));
    return CT_SUCCESS;
}

static status_t sql_word2param(sql_stmt_t *stmt, word_t *word, expr_node_t *node)
{
    uint32 param_id;
    bool32 is_repeated = CT_FALSE;
    if (IS_DDL(stmt) || IS_DCL(stmt)) {
        CT_SRC_THROW_ERROR(word->loc, ERR_SQL_SYNTAX_ERROR, "param only allowed in dml or anonymous block or call");
        return CT_ERROR;
    }
    if (stmt->context->params == NULL) {
        CT_SRC_THROW_ERROR(word->loc, ERR_SQL_SYNTAX_ERROR, "Current position cannot use params");
        return CT_ERROR;
    }

    node->value.is_null = CT_FALSE;
    node->value.type = CT_TYPE_INTEGER;
    VALUE(uint32, &node->value) = stmt->context->params->count;

    CT_RETURN_IFERR(sql_add_param_mark(stmt, word, &is_repeated, &param_id));

    if (stmt->context->type == CTSQL_TYPE_ANONYMOUS_BLOCK) {
        return plc_convert_param_node(stmt, node, is_repeated, param_id);
    }

    return CT_SUCCESS;
}

static status_t sql_word2plattr_type(word_t *word, uint16 *attr_type)
{
    switch (word->id) {
        case PL_ATTR_WORD_ISOPEN:
            *attr_type = PLV_ATTR_ISOPEN;
            break;
        case PL_ATTR_WORD_FOUND:
            *attr_type = PLV_ATTR_FOUND;
            break;
        case PL_ATTR_WORD_NOTFOUND:
            *attr_type = PLV_ATTR_NOTFOUND;
            break;
        case PL_ATTR_WORD_ROWCOUNT:
            *attr_type = PLV_ATTR_ROWCOUNT;
            break;
        default:
            CT_THROW_ERROR(ERR_PL_INVALID_ATTR_FMT);
            return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t sql_word2plattr(sql_stmt_t *stmt, expr_tree_t *expr, word_t *word, expr_node_t *node)
{
    plv_decl_t *plv_decl = NULL;
    if (!cm_text_str_equal_ins(&word->text.value, "SQL")) {
        pl_compiler_t *compiler = (pl_compiler_t *)stmt->pl_compiler;
        if (compiler != NULL) {
            plc_find_decl_ex(compiler, word, PLV_CUR, NULL, &plv_decl);
            if (plv_decl == NULL) {
                CT_SRC_THROW_ERROR(node->loc, ERR_UNDEFINED_SYMBOL_FMT, W2S(word));
                return CT_ERROR;
            }
        }
    }
    node->value.type = CT_TYPE_INTEGER;
    if (plv_decl != NULL) {
        node->value.v_plattr.id = plv_decl->vid;
        node->value.v_plattr.is_implicit = (bool8)CT_FALSE;
    } else {
        node->value.v_plattr.is_implicit = (bool8)CT_TRUE;
    }
    return sql_word2plattr_type(word, &node->value.v_plattr.type);
}

static status_t sql_word2column(sql_stmt_t *stmt, expr_tree_t *expr, word_t *word, expr_node_t *node)
{
    lex_t *lex = stmt->session->lex;

    node->value.type = CT_TYPE_COLUMN;
    if (sql_word_as_column(stmt, word, &node->word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return lex_try_fetch_subscript(lex, &node->word.column.ss_start, &node->word.column.ss_end);
}

static status_t sql_word2reserved(expr_tree_t *expr, word_t *word, expr_node_t *node)
{
    node->value.type = CT_TYPE_INTEGER;
    node->value.v_res.res_id = word->id;
    node->value.v_res.namable = word->namable;
    return CT_SUCCESS;
}

static inline bool32 is_for_each_row_trigger(sql_stmt_t *stmt)
{
    pl_compiler_t *compiler = (pl_compiler_t *)stmt->pl_compiler;
    trig_desc_t *trig = NULL;

    if (compiler == NULL || compiler->type != PL_TRIGGER) {
        return CT_FALSE;
    }

    trig = &((pl_entity_t *)compiler->entity)->trigger->desc;

    if ((trig->type != TRIG_AFTER_EACH_ROW && trig->type != TRIG_BEFORE_EACH_ROW && trig->type != TRIG_INSTEAD_OF)) {
        return CT_FALSE;
    }

    return CT_TRUE;
}

status_t hex2assic(const text_t *text, bool32 hex_prefix, binary_t *bin)
{
    uint32 i, pos;
    uint8 half_byte;

    CM_POINTER2(text, bin);

    if (hex_prefix) {
        if (text->len < 3) { // min hex string is 0x0
            CT_THROW_ERROR(ERR_TEXT_FORMAT_ERROR, "hex");
            return CT_ERROR;
        }
    }

    // set the starting position
    i = hex_prefix ? sizeof("0x") - 1 : 0;
    uint32 len = text->len;
    bool32 is_quotes = (text->str[0] == 'X') && (text->str[1] == '\'');
    if (is_quotes) {
        len = text->len - 1;
        if (len % 2 == 1) {
            CT_THROW_ERROR(ERR_TEXT_FORMAT_ERROR, "hex");
            return CT_ERROR;
        }
    }
    uint32 val;
    pos = 0;
    if (len % 2 == 1) { // handle odd length hex string
        val = 0;
        val <<= 4;

        val += cm_hex2int8(text->str[i]);
        bin->bytes[pos] = (uint8)val;
        pos++;
        i++;
    }

    for (; i < len; i += 2) {
        half_byte = cm_hex2int8((uint8)text->str[i]);
        if (half_byte == 0xFF) {
            CT_THROW_ERROR(ERR_TEXT_FORMAT_ERROR, "hex");
            return CT_ERROR;
        }

        bin->bytes[pos] = (uint8)(half_byte << 4);

        half_byte = cm_hex2int8((uint8)text->str[i + 1]);
        if (half_byte == 0xFF) {
            CT_THROW_ERROR(ERR_TEXT_FORMAT_ERROR, "hex");
            return CT_ERROR;
        }

        bin->bytes[pos] += half_byte;
        pos++;
    }

    bin->size = pos;

    return CT_SUCCESS;
}

status_t sql_word2hexadecimal(sql_stmt_t *stmt, word_t *word, expr_node_t *node)
{
    bool32 has_prefix = CT_FALSE;
    binary_t bin;
    char *str = NULL;
    text_t const_text = word->text.value;

    if (word->text.len > CT_MAX_COLUMN_SIZE * 2) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_VALUE_ERROR, "hexadecimal string is too long, can not exceed %u",
            2 * CT_MAX_COLUMN_SIZE);
        return CT_ERROR;
    }

    if (sql_alloc_mem(stmt->context, (const_text.len + 1) / 2, (void **)&str) != CT_SUCCESS) {
        return CT_ERROR;
    }

    uint32 len = word->text.len;
    has_prefix = (word->text.len >= 2) &&
        ((word->text.str[0] == 'X' && word->text.str[1] == '\'' && word->text.str[len - 1] == '\'') ||
        (word->text.str[0] == '0' && word->text.str[1] == 'x'));
    bin.bytes = (uint8 *)str;
    bin.size = 0;
    if (hex2assic(&word->text.value, has_prefix, &bin) != CT_SUCCESS) {
        return CT_ERROR;
    }

    node->value.is_null = CT_FALSE;
    node->value.v_bin = bin;
    node->value.v_bin.is_hex_const = CT_TRUE;
    node->value.type = CT_TYPE_BINARY;
    return CT_SUCCESS;
}

static status_t sql_convert_expr_word(sql_stmt_t *stmt, expr_tree_t *expr, word_t *word, expr_node_t *node)
{
    switch (word->type) {
        case WORD_TYPE_STRING:
            return sql_word2text(stmt, word, node);
        case WORD_TYPE_NUMBER:
            return sql_word2number(word, node);
        case WORD_TYPE_PARAM:
            return sql_word2param(stmt, word, node);
        case WORD_TYPE_ALPHA_PARAM:
            return sql_word2csrparam(stmt, word, node);
        case WORD_TYPE_RESERVED:
            CT_RETURN_IFERR(sql_word2reserved(expr, word, node));
            return word->namable ? sql_word2column(stmt, expr, word, node) : CT_SUCCESS;
        case WORD_TYPE_VARIANT:
        case WORD_TYPE_DQ_STRING:
        case WORD_TYPE_JOIN_COL:
            if (stmt->context->type >= CTSQL_TYPE_CREATE_PROC && stmt->context->type < CTSQL_TYPE_PL_CEIL_END) {
                return plc_word2var(stmt, word, node);
            }
            return sql_word2column(stmt, expr, word, node);
        case WORD_TYPE_KEYWORD:
        case WORD_TYPE_DATATYPE:
            /* when used as variant */
            if (stmt->context->type >= CTSQL_TYPE_CREATE_PROC && stmt->context->type < CTSQL_TYPE_PL_CEIL_END &&
                word->namable == CT_TRUE) {
                return plc_word2var(stmt, word, node);
            }
            return sql_word2column(stmt, expr, word, node);
        case WORD_TYPE_PL_ATTR:
            return sql_word2plattr(stmt, expr, word, node);
        case WORD_TYPE_PL_NEW_COL:
        case WORD_TYPE_PL_OLD_COL: {
            if (!is_for_each_row_trigger(stmt)) {
                CT_SRC_THROW_ERROR_EX(word->loc, ERR_SQL_SYNTAX_ERROR,
                    "':new.' or ':old.' can only appear in row trigger. word = %s", W2S(word));
                return CT_ERROR;
            }
            return plc_word2var(stmt, word, node);
        }
        case WORD_TYPE_HEXADECIMAL:
            return sql_word2hexadecimal(stmt, word, node);
        default:
            CT_SRC_THROW_ERROR_EX(word->loc, ERR_SQL_SYNTAX_ERROR, "unexpected word %s found", W2S(word));
            return CT_ERROR;
    }
}

static inline status_t sql_parse_one_case_pair(sql_stmt_t *stmt, word_t *word, galist_t *case_pairs, bool32 is_cond)
{
    status_t status;
    case_pair_t *pair = NULL;

    if (cm_galist_new(case_pairs, sizeof(case_pair_t), (void **)&pair) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (is_cond) {
        status = sql_create_cond_until(stmt, &pair->when_cond, word);
    } else {
        status = sql_create_expr_until(stmt, &pair->when_expr, word);
    }

    if (status != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word->id != KEY_WORD_THEN) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "THEN expected but %s found", W2S(word));
        return CT_ERROR;
    }

    if (sql_create_expr_until(stmt, &pair->value, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static inline status_t sql_parse_case_pairs(sql_stmt_t *stmt, word_t *word, galist_t *case_pairs, bool32 is_cond)
{
    for (;;) {
        if (sql_parse_one_case_pair(stmt, word, case_pairs, is_cond) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (!(word->id == KEY_WORD_WHEN || word->id == KEY_WORD_ELSE || word->id == KEY_WORD_END)) {
            CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "WHEN/ELSE/END expected but %s found",
                W2S(word));
            return CT_ERROR;
        }

        if (word->id == KEY_WORD_ELSE || word->id == KEY_WORD_END) {
            break;
        }
    }
    return CT_SUCCESS;
}

static inline status_t sql_parse_case_default_expr(sql_stmt_t *stmt, word_t *word, expr_tree_t **default_expr)
{
    if (word->id == KEY_WORD_ELSE) {
        if (sql_create_expr_until(stmt, default_expr, word) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (word->id != KEY_WORD_END) {
            CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "THEN expected but %s found", W2S(word));
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t sql_parse_case_expr(sql_stmt_t *stmt, word_t *word, expr_node_t *node)
{
    lex_t *lex = stmt->session->lex;
    key_word_t *save_key_words = lex->key_words;
    uint32 save_key_word_count = lex->key_word_count;
    bool32 is_cond = CT_FALSE;
    case_expr_t *case_expr = NULL;
    key_word_t key_words[] = { { (uint32)KEY_WORD_END, CT_FALSE, { (char *)"end", 3 } },
                               { (uint32)KEY_WORD_WHEN, CT_FALSE, { (char *)"when", 4 } }
                             };

    node->type = EXPR_NODE_CASE;
    if (sql_alloc_mem(stmt->context, sizeof(case_expr_t), (void **)&case_expr) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_try_fetch(stmt->session->lex, "WHEN", &is_cond) != CT_SUCCESS) {
        return CT_SUCCESS;
    }

    cm_galist_init(&case_expr->pairs, (void *)stmt->context, (ga_alloc_func_t)sql_alloc_mem);
    case_expr->is_cond = is_cond;

    lex->key_words = key_words;
    lex->key_word_count = ELEMENT_COUNT(key_words);

    if (!is_cond) {
        if (sql_create_expr_until(stmt, &case_expr->expr, word) != CT_SUCCESS) {
            lex->key_words = save_key_words;
            lex->key_word_count = save_key_word_count;
            return CT_ERROR;
        }

        if (word->id != KEY_WORD_WHEN) {
            lex->key_words = save_key_words;
            lex->key_word_count = save_key_word_count;
            CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "WHEN expected but %s found", W2S(word));
            return CT_ERROR;
        }
    }

    if (sql_parse_case_pairs(stmt, word, &case_expr->pairs, is_cond) != CT_SUCCESS) {
        lex->key_words = save_key_words;
        lex->key_word_count = save_key_word_count;
        return CT_ERROR;
    }

    if (sql_parse_case_default_expr(stmt, word, &case_expr->default_expr) != CT_SUCCESS) {
        lex->key_words = save_key_words;
        lex->key_word_count = save_key_word_count;
        return CT_ERROR;
    }

    VALUE(pointer_t, &node->value) = case_expr;
    lex->key_words = save_key_words;
    lex->key_word_count = save_key_word_count;

    return CT_SUCCESS;
}

static status_t sql_parse_array_element_expr(sql_stmt_t *stmt, lex_t *lex, expr_node_t *node)
{
    uint32 subscript = 1;
    word_t next_word;
    expr_tree_t **expr = NULL;
    bool32 expect_expr = CT_FALSE;
    var_array_t *val = &node->value.v_array;

    expr = &node->argument;
    val->count = 0;

    while (lex->curr_text->len > 0) {
        if (sql_create_expr_until(stmt, expr, &next_word) != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }

        val->count++;
        (*expr)->subscript = subscript;
        subscript++;

        if (next_word.type == WORD_TYPE_SPEC_CHAR && IS_SPEC_CHAR(&next_word, ',')) {
            expr = &(*expr)->next;
            expect_expr = CT_TRUE;
            lex_trim(lex->curr_text);
        } else if (next_word.type == WORD_TYPE_EOF) {
            /* end of the array elements */
            expect_expr = CT_FALSE;
            break;
        } else {
            CT_SRC_THROW_ERROR(LEX_LOC, ERR_INVALID_ARRAY_FORMAT);
            return CT_ERROR;
        }
    }

    if (expect_expr) {
        CT_SRC_THROW_ERROR(LEX_LOC, ERR_INVALID_ARRAY_FORMAT);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t sql_parse_array_expr(sql_stmt_t *stmt, word_t *word, expr_node_t *node)
{
    lex_t *lex = stmt->session->lex;

    if (lex_fetch_array(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_push(lex, &word->text)) {
        return CT_ERROR;
    }

    if (sql_parse_array_element_expr(stmt, lex, node) != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }

    lex_pop(lex);
    return CT_SUCCESS;
}

static status_t sql_create_expr_node(sql_stmt_t *stmt, expr_tree_t *expr, word_t *word, expr_node_type_t node_type,
    expr_node_t **node)
{
    CT_RETURN_IFERR(sql_stack_safe(stmt));

    if (sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)node) != CT_SUCCESS) {
        return CT_ERROR;
    }

    (*node)->owner = expr;
    (*node)->type = (word->type == WORD_TYPE_JOIN_COL) ? EXPR_NODE_JOIN : node_type;
    (*node)->unary = expr->unary;
    (*node)->loc = word->text.loc;
    (*node)->dis_info.need_distinct = CT_FALSE;
    (*node)->dis_info.idx = CT_INVALID_ID32;
    (*node)->optmz_info = (expr_optmz_info_t) { OPTIMIZE_NONE, 0 };
    (*node)->format_json = CT_FALSE;
    (*node)->json_func_attr = (json_func_attr_t) { 0, 0 };
    (*node)->typmod.is_array = 0;
    (*node)->value.v_col.ss_start = CT_INVALID_ID32;
    (*node)->value.v_col.ss_end = CT_INVALID_ID32;

    if (word->type == WORD_TYPE_DATATYPE && (word->id == DTYP_DATE || word->id == DTYP_TIMESTAMP)) {
        bool32 result = CT_FALSE;
        CT_RETURN_IFERR(sql_try_parse_date_expr(stmt, word, *node, &result));
        CT_RETSUC_IFTRUE(result);
    }

    if (node_type <= EXPR_NODE_OPCEIL) {
        return CT_SUCCESS;
    }

    if (node_type == EXPR_NODE_NEGATIVE) {
        word->flag_type = (uint32)word->flag_type ^ (uint32)WORD_FLAG_NEGATIVE;
        return CT_SUCCESS;
    }

    if (node_type == EXPR_NODE_FUNC) {
        CT_RETURN_IFERR(sql_build_func_node(stmt, word, *node));
        // to support analytic function
        CT_RETURN_IFERR(sql_build_func_over(stmt, expr, word, node));

        return CT_SUCCESS;
    }

    if (node_type == EXPR_NODE_CASE) {
        return sql_parse_case_expr(stmt, word, *node);
    }

    if (node_type == EXPR_NODE_ARRAY) {
        return sql_parse_array_expr(stmt, word, *node);
    }

    if (word->type == WORD_TYPE_DATATYPE && word->id == DTYP_INTERVAL) {
        bool32 result = CT_FALSE;
        CT_RETURN_IFERR(sql_try_parse_interval_expr(stmt, *node, &result));
        CT_RETSUC_IFTRUE(result);
    }

    return sql_convert_expr_word(stmt, expr, word, *node);
}

status_t sql_add_expr_word_inside(sql_stmt_t *stmt, expr_tree_t *expr, word_t *word, expr_node_type_t node_type)
{
    expr_node_t *node = NULL;
    expr_tree_t *sub_expr = NULL;

    if (word->type == (uint32)WORD_TYPE_BRACKET) {
        if (sql_create_expr_from_text(stmt, &word->text, &sub_expr, word->flag_type) != CT_SUCCESS) {
            return CT_ERROR;
        }

        node = sub_expr->root;

        if (expr->chain.count > 0 &&
            (expr->chain.last->type == EXPR_NODE_NEGATIVE || expr->chain.last->type == EXPR_NODE_PRIOR) &&
            word->type != WORD_TYPE_OPERATOR) {
            expr->chain.last->right = node;
        } else {
            APPEND_CHAIN(&expr->chain, node);
            UNARY_REDUCE_NEST(expr, node);
        }
    } else {
        if (sql_create_expr_node(stmt, expr, word, node_type, &node) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (expr->chain.count > 0 &&
            (expr->chain.last->type == EXPR_NODE_NEGATIVE || expr->chain.last->type == EXPR_NODE_PRIOR) &&
            word->type != WORD_TYPE_OPERATOR) {
            expr->chain.last->right = node;
        } else {
            APPEND_CHAIN(&expr->chain, node);
        }
    }
    return CT_SUCCESS;
}

static status_t inline oper2unary(sql_stmt_t *stmt, word_t *word, unary_oper_t *unary_oper)
{
    switch (word->id) {
        case OPER_TYPE_SUB:
            *unary_oper = UNARY_OPER_NEGATIVE;
            break;
        case OPER_TYPE_ADD:
            *unary_oper = UNARY_OPER_POSITIVE;
            break;
        case OPER_TYPE_ROOT: {
            if (!stmt->in_parse_query) {
                CT_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR,
                    "CONNECT BY clause required in this query block");
                return CT_ERROR;
            }
            *unary_oper = UNARY_OPER_ROOT;
            break;
        }
        default:
            CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "Unknown unary operator id \"%u\"", word->id);
            return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_add_expr_word(sql_stmt_t *stmt, expr_tree_t *expr, word_t *word)
{
    expr_node_type_t node_type;

    if (word->type == WORD_TYPE_ANCHOR) {
        return sql_convert_to_cast(stmt, expr, word);
    }

    if ((expr->expecting & EXPR_EXPECT_UNARY_OP) && EXPR_IS_UNARY_OP_ROOT(word)) {
        expr->expecting = EXPR_EXPECT_VAR;
        CT_RETURN_IFERR(oper2unary(stmt, word, &expr->unary));
        return CT_SUCCESS;
    }

    if ((expr->expecting & EXPR_EXPECT_UNARY_OP) && EXPR_IS_UNARY_OP(word)) {
        if (word->id == (uint32)OPER_TYPE_ADD) {
            expr->expecting = EXPR_EXPECT_VAR;
            return CT_SUCCESS;
        }
        expr->expecting = EXPR_EXPECT_UNARY;
    }

    if (!sql_match_expected(expr, word, &node_type)) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "the word \"%s\" is not correct", W2S(word));
        return CT_ERROR;
    }

    if (sql_add_expr_word_inside(stmt, expr, word, node_type) != CT_SUCCESS) {
        return CT_ERROR;
    }

    expr->unary = UNARY_OPER_NONE;
    return CT_SUCCESS;
}

status_t sql_create_expr(sql_stmt_t *stmt, expr_tree_t **expr)
{
    if (sql_alloc_mem(stmt->context, sizeof(expr_tree_t), (void **)expr) != CT_SUCCESS) {
        return CT_ERROR;
    }

    (*expr)->owner = stmt->context;
    (*expr)->expecting = (EXPR_EXPECT_UNARY_OP | EXPR_EXPECT_VAR | EXPR_EXPECT_STAR);
    (*expr)->next = NULL;

    return CT_SUCCESS;
}

static status_t sql_build_star_expr(sql_stmt_t *stmt, expr_tree_t *expr, word_t *word)
{
    lex_t *lex = stmt->session->lex;

    if (expr->chain.count > 0) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "expression expected but %s found", W2S(word));
        return CT_ERROR;
    }

    if (sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&expr->root) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_word_as_column(stmt, word, &expr->root->word) != CT_SUCCESS) {
        return CT_ERROR;
    }
    expr->root->type = EXPR_NODE_STAR;
    expr->root->loc = word->text.loc;
    expr->star_loc.begin = word->ori_type == WORD_TYPE_DQ_STRING ? LEX_OFFSET(lex, word) - 1 : LEX_OFFSET(lex, word);
    return lex_fetch(lex, word);
}

status_t sql_create_expr_until(sql_stmt_t *stmt, expr_tree_t **expr, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    word_type_t word_type;
    uint32 save_flags = stmt->session->lex->flags;

    word->flag_type = WORD_FLAG_NONE;
    word_type = WORD_TYPE_OPERATOR;

    CT_RETURN_IFERR(sql_create_expr(stmt, expr));

    CT_RETURN_IFERR(lex_skip_comments(lex, NULL));

    (*expr)->loc = LEX_LOC;

    for (;;) {
        if ((*expr)->expecting == EXPR_EXPECT_OPER) {
            stmt->session->lex->flags &= (~LEX_WITH_ARG);
        } else {
            stmt->session->lex->flags = save_flags;
        }

        CT_RETURN_IFERR(lex_fetch(stmt->session->lex, word));
        CT_BREAK_IF_TRUE(word->type == WORD_TYPE_EOF);

        if ((IS_SPEC_CHAR(word, '*') && word_type == WORD_TYPE_OPERATOR) || word->type == WORD_TYPE_STAR) {
            return sql_build_star_expr(stmt, *expr, word);
        }

        CT_BREAK_IF_TRUE((IS_UNNAMABLE_KEYWORD(word) && word->id != KEY_WORD_CASE) || IS_SPEC_CHAR(word, ',') ||
            (word->type == WORD_TYPE_COMPARE) || (word->type == WORD_TYPE_PL_TERM) ||
            (word->type == WORD_TYPE_PL_RANGE));

        CT_BREAK_IF_TRUE((word->type == WORD_TYPE_VARIANT || word->type == WORD_TYPE_JOIN_COL ||
            word->type == WORD_TYPE_STRING || word->type == WORD_TYPE_KEYWORD || word->type == WORD_TYPE_DATATYPE ||
            word->type == WORD_TYPE_DQ_STRING || word->type == WORD_TYPE_FUNCTION ||
            word->type == WORD_TYPE_RESERVED) &&
            word_type != WORD_TYPE_OPERATOR);

        if (word->id == KEY_WORD_PRIMARY) {
            bool32 ret;
            CT_RETURN_IFERR(lex_try_fetch(lex, "KEY", &ret));

            // KEY WORD NOT VARIANT.
            CT_BREAK_IF_TRUE(ret);
        }
        word_type = word->type;
        CT_RETURN_IFERR(sql_add_expr_word(stmt, *expr, word));
    }
    CT_RETURN_IFERR(sql_generate_expr(*expr));
    stmt->session->lex->flags = save_flags;
    return CT_SUCCESS;
}

static status_t sql_parse_select_expr(sql_stmt_t *stmt, expr_tree_t *expr, sql_text_t *sql)
{
    sql_select_t *select_ctx = NULL;

    if (stmt->ssa_stack.depth == 0) {
        CT_SRC_THROW_ERROR(stmt->session->lex->loc, ERR_UNEXPECTED_KEY, "SUBSELECT");
        return CT_ERROR;
    }

    if (sql_create_select_context(stmt, sql, SELECT_AS_VARIANT, &select_ctx) != CT_SUCCESS) {
        return CT_ERROR;
    }

    expr->generated = CT_TRUE;
    if (sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&expr->root) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_array_put(CTSQL_CURR_SSA(stmt), select_ctx) != CT_SUCCESS) {
        return CT_ERROR;
    }

    select_ctx->parent = CTSQL_CURR_NODE(stmt);
    expr->root->type = EXPR_NODE_SELECT;
    expr->root->value.type = CT_TYPE_INTEGER;
    expr->root->value.v_obj.id = CTSQL_CURR_SSA(stmt)->count - 1;
    expr->root->value.v_obj.ptr = select_ctx;
    CT_RETURN_IFERR(sql_slct_add_ref_node(stmt->context, expr->root, sql_alloc_mem));
    return CT_SUCCESS;
}

static status_t sql_parse_normal_expr(sql_stmt_t *stmt, expr_tree_t *expr, word_t *word)
{
    while (word->type != WORD_TYPE_EOF) {
        if (sql_add_expr_word(stmt, expr, word) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (lex_fetch(stmt->session->lex, word) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (sql_generate_expr(expr) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_create_expr_list(sql_stmt_t *stmt, sql_text_t *text, expr_tree_t **expr)
{
    word_t word;
    expr_tree_t *last_expr = NULL;
    expr_tree_t *curr_expr = NULL;
    lex_t *lex = stmt->session->lex;
    last_expr = NULL;

    CT_RETURN_IFERR(lex_push(lex, text));

    for (;;) {
        /* Here, curr_expr->next is set by NULL at initializing phase.
         * See function sql_create_expr. */
        if (sql_create_expr_until(stmt, &curr_expr, &word) != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }

        if (last_expr == NULL) {
            *expr = curr_expr;
        } else {
            last_expr->next = curr_expr;
        }
        last_expr = curr_expr;

        if (word.type == WORD_TYPE_EOF) {
            break;
        }

        if (!IS_SPEC_CHAR(&word, ',')) {
            lex_pop(lex);
            CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, ", expected but '%s' found", W2S(&word));
            return CT_ERROR;
        }
    }

    lex_pop(lex);
    return CT_SUCCESS;
}

status_t sql_create_expr_from_text(sql_stmt_t *stmt, sql_text_t *text, expr_tree_t **expr, word_flag_t word_flag)
{
    word_t word;
    lex_t *lex = stmt->session->lex;
    status_t status;
    const char *words[] = { "UNION", "MINUS", "EXCEPT", "INTERSECT" };
    const uint32 words_cnt = sizeof(words) / sizeof(char *);
    bool32 result = CT_FALSE;

    word.flag_type = word_flag;
    *expr = NULL;

    CT_RETURN_IFERR(sql_stack_safe(stmt));

    CT_RETURN_IFERR(lex_push(lex, text));

    if (sql_create_expr(stmt, expr) != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }

    if (lex_fetch(lex, &word) != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }

    LEX_SAVE(lex);
    // Judge whether the next word is UNION/MINUS/EXCEPT/INTERSECT.
    if (lex_try_fetch_anyone(lex, words_cnt, words, &result) != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }
    LEX_RESTORE(lex);

    if (result || word.id == KEY_WORD_SELECT || word.id == KEY_WORD_WITH) {
        word.text = *text;
        status = sql_parse_select_expr(stmt, *expr, &word.text);
    } else {
        status = sql_parse_normal_expr(stmt, *expr, &word);
    }
    lex_pop(lex);
    return status;
}

status_t sql_create_expr_from_word(sql_stmt_t *stmt, word_t *word, expr_tree_t **expr)
{
    if (sql_create_expr(stmt, expr) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return sql_add_expr_word(stmt, *expr, word);
}

static void sql_down_expr_node(expr_tree_t *expr, expr_node_t *root)
{
    root->left = root->prev;
    root->right = root->next;
    root->next = root->next->next;
    root->prev = root->prev->prev;
    if (root->prev != NULL) {
        root->prev->next = root;
    } else {
        expr->chain.first = root;
    }
    if (root->next != NULL) {
        root->next->prev = root;
    } else {
        expr->chain.last = root;
    }
    root->left->prev = NULL;
    root->left->next = NULL;
    root->right->prev = NULL;
    root->right->next = NULL;
    expr->chain.count -= 2;
}

static status_t sql_form_expr_with_opers(expr_tree_t *expr, uint32 opers)
{
    expr_node_t *prev = NULL;
    expr_node_t *next = NULL;
    expr_node_t *head;

    /* get next expr node ,merge node is needed at least two node */
    head = expr->chain.first->next;

    while (head != NULL) {
        if (head->type >= EXPR_NODE_CONST || head->left != NULL ||
            (IS_OPER_NODE(head) && g_opr_priority[head->type] != g_opr_priority[opers])) {
            head = head->next;
            continue;
        }

        prev = head->prev;
        next = head->next;

        /* if is not a correct expression */
        if (prev == NULL || next == NULL) {
            CT_SRC_THROW_ERROR(head->loc, ERR_SQL_SYNTAX_ERROR, "expression error");
            return CT_ERROR;
        }

        sql_down_expr_node(expr, head);

        head = head->next;
    }

    return CT_SUCCESS;
}

status_t sql_generate_expr(expr_tree_t *expr)
{
    if (expr->chain.count == 0) {
        CT_SRC_THROW_ERROR(expr->loc, ERR_SQL_SYNTAX_ERROR, "invalid expression");
        return CT_ERROR;
    }

    for (uint32 oper_mode = OPER_TYPE_MUL; oper_mode <= OPER_TYPE_CAT; ++oper_mode) {
        if (sql_form_expr_with_opers(expr, oper_mode) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (expr->chain.count != 1) {
        CT_SRC_THROW_ERROR(expr->loc, ERR_SQL_SYNTAX_ERROR, "expression error");
        return CT_ERROR;
    }

    expr->generated = CT_TRUE;
    expr->root = expr->chain.first;
    return CT_SUCCESS;
}

status_t sql_build_column_expr(sql_stmt_t *stmt, knl_column_t *column, expr_tree_t **r_result)
{
    expr_node_t *col_node = NULL;
    expr_tree_t *column_expr = NULL;

    if (sql_create_expr(stmt, &column_expr) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&col_node) != CT_SUCCESS) {
        return CT_ERROR;
    }

    col_node->owner = column_expr;
    col_node->type = EXPR_NODE_COLUMN;

    col_node->value.is_null = CT_FALSE;
    col_node->value.type = CT_TYPE_COLUMN;
    col_node->value.v_col.ancestor = 0;
    col_node->value.v_col.datatype = column->datatype;
    col_node->value.v_col.tab = column->table_id;
    col_node->value.v_col.col = column->id;

    APPEND_CHAIN(&(column_expr->chain), col_node);

    *r_result = column_expr;
    return sql_generate_expr(*r_result);
}

status_t sql_build_default_reserved_expr(sql_stmt_t *stmt, expr_tree_t **r_result)
{
    expr_node_t *reserved_node = NULL;
    expr_tree_t *reserved_expr = NULL;

    if (sql_create_expr(stmt, &reserved_expr) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&reserved_node) != CT_SUCCESS) {
        return CT_ERROR;
    }

    reserved_node->owner = reserved_expr;
    reserved_node->type = EXPR_NODE_RESERVED;
    reserved_node->datatype = CT_TYPE_UNKNOWN;

    reserved_node->value.is_null = CT_FALSE;
    reserved_node->value.type = CT_TYPE_INTEGER;

    reserved_node->value.v_rid.res_id = RES_WORD_DEFAULT;
    APPEND_CHAIN(&(reserved_expr->chain), reserved_node);

    *r_result = reserved_expr;
    return sql_generate_expr(*r_result);
}

#ifdef __cplusplus
}
#endif

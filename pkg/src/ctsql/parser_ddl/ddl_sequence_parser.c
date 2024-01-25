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
 * ddl_sequence_parser.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser_ddl/ddl_sequence_parser.c
 *
 * -------------------------------------------------------------------------
 */

#include "ddl_sequence_parser.h"
#include "ddl_parser_common.h"
#include "ddl_parser.h"
#include "dtc_dls.h"

static void sql_init_create_sequence(sql_stmt_t *stmt, knl_sequence_def_t *seq_def)
{
    CM_POINTER(seq_def);
    seq_def->name.len = 0;
    seq_def->start = 1;
    seq_def->step = DDL_SEQUENCE_DEFAULT_INCREMENT;
    seq_def->min_value = 1;
    seq_def->max_value = DDL_ASC_SEQUENCE_DEFAULT_MAX_VALUE;
    seq_def->cache = DDL_SEQUENCE_DEFAULT_CACHE;
    seq_def->is_cycle = CT_FALSE; // default is no cycle
    seq_def->nocache = CT_FALSE;  // no_cache is not specified
    seq_def->nominval = CT_TRUE;  // no_min_value is not specified
    seq_def->nomaxval = CT_TRUE;  // no_max_value is not specified
    seq_def->is_order = CT_FALSE; // order is not specified
    seq_def->is_option_set = (uint32)0;
}

/* ****************************************************************************
Description  : check sequence max/min value is valid or not according to the
grammar
Input        : knl_sequence_def_t * stmt
Output       : None
Modification : Create function
Date         : 2017-02-23
**************************************************************************** */
static status_t sql_check_sequence_scop_value_valid(knl_sequence_def_t *sequence_def)
{
    if (sequence_def->max_value <= sequence_def->min_value) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "MINVALUE must less than MAXVALUE");
        return CT_ERROR;
    }

    int64 next;
    if (sequence_def->step > 0) {
        if ((opr_int64add_overflow(sequence_def->min_value, sequence_def->step, &next)) ||
            (sequence_def->max_value < next)) {
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "INCREMENT must be less than MAX value minus MIN value");
            return CT_ERROR;
        }
    }

    if (sequence_def->step < 0) {
        if ((opr_int64add_overflow(sequence_def->max_value, sequence_def->step, &next)) ||
            (sequence_def->min_value > next)) {
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "INCREMENT must be less than MAX value minus MIN value");
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}
/* ****************************************************************************
Description  : format sequence max/min value according to the grammar
Input        : knl_sequence_def_t * stmt
Output       : None
Modification : Create function
Date         : 2017-02-23
**************************************************************************** */
static status_t sql_format_sequence_scop_value(knl_sequence_def_t *sequence_def)
{
    sequence_def->nominval = sequence_def->is_minval_set ? CT_FALSE : CT_TRUE;
    sequence_def->nomaxval = sequence_def->is_maxval_set ? CT_FALSE : CT_TRUE;

    /* if minvalue is not specified, then depending on the increment value,
    assign the ascending or descending sequence's default min value */
    if (sequence_def->nominval) {
        sequence_def->min_value =
            sequence_def->step < 0 ? DDL_DESC_SEQUENCE_DEFAULT_MIN_VALUE : DDL_ASC_SEQUENCE_DEFAULT_MIN_VALUE;
        sequence_def->is_minval_set = sequence_def->is_nominval_set ? 1 : 0; /* specify the 'nominvalue' */
    }

    /* if maxvalue is not specified, then depending on the increment value,
    assign the ascending or descending sequence's default max value */
    if (sequence_def->nomaxval) {
        sequence_def->max_value =
            sequence_def->step < 0 ? DDL_DESC_SEQUENCE_DEFAULT_MAX_VALUE : DDL_ASC_SEQUENCE_DEFAULT_MAX_VALUE;
        sequence_def->is_maxval_set = sequence_def->is_nomaxval_set ? 1 : 0; /* specify the 'nomaxvalue' */
    }

    return sql_check_sequence_scop_value_valid(sequence_def);
}
/* ****************************************************************************
Description  : check sequence start with value is valid or not according to
the grammar
Input        : knl_sequence_def_t * stmt
Output       : None
Modification : Create function
Date         : 2017-02-23
**************************************************************************** */
static status_t sql_check_sequence_start_value(knl_sequence_def_t *sequence_def)
{
    if (sequence_def->step > 0) {
        if (sequence_def->start - sequence_def->step > sequence_def->max_value) {
            CT_THROW_ERROR(ERR_SEQ_INVALID, "start value cannot be greater than max value plus increment");
            return CT_ERROR;
        }

        if (sequence_def->start < sequence_def->min_value) {
            CT_THROW_ERROR(ERR_SEQ_INVALID, "start value cannot be less than min value");
            return CT_ERROR;
        }
    } else {
        if (sequence_def->start - sequence_def->step < sequence_def->min_value) {
            CT_THROW_ERROR(ERR_SEQ_INVALID, "start value cannot be less than min value plus increment");
            return CT_ERROR;
        }

        if (sequence_def->start > sequence_def->max_value) {
            CT_THROW_ERROR(ERR_SEQ_INVALID, "start value cannot be greater than max value");
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

/* ****************************************************************************
Description  : format sequence start with value according to the grammar
Input        : knl_sequence_def_t * stmt
Output       : None
Modification : Create function
Date         : 2017-02-23
**************************************************************************** */
static status_t sql_format_sequence_start_value(knl_sequence_def_t *sequence_def)
{
    /* if no start value is specified, then min value would be the start value */
    if (!sequence_def->is_start_set) {
        sequence_def->start = sequence_def->step > 0 ? sequence_def->min_value : sequence_def->max_value;
    }

    return sql_check_sequence_start_value(sequence_def);
}

static status_t sql_check_sequence_cache_value(knl_sequence_def_t *sequence_def)
{
    int64 step = cm_abs64(sequence_def->step);
    if (sequence_def->cache <= 1) {
        CT_THROW_ERROR(ERR_SEQ_INVALID, "CACHE value must be larger than 1");
        return CT_ERROR;
    }

    if (sequence_def->is_nocache_set) {
        sequence_def->cache = 0;
        sequence_def->is_cache_set = 1;
    }

    if (!sequence_def->nocache && sequence_def->cache < 2) {
        CT_THROW_ERROR(ERR_SEQ_INVALID, "number to CACHE must be more than 1");
        return CT_ERROR;
    }

    if (sequence_def->is_cycle && ((uint64)sequence_def->cache >
        ceil((double)((uint64)sequence_def->max_value - sequence_def->min_value) / step))) {
        CT_THROW_ERROR(ERR_SEQ_INVALID, "number to CACHE must be less than one cycle");
        return CT_ERROR;
    }

    if (sequence_def->step >= 1 &&
        (sequence_def->cache > (DDL_ASC_SEQUENCE_DEFAULT_MAX_VALUE / cm_abs64(sequence_def->step)))) {
        CT_THROW_ERROR(ERR_SEQ_INVALID, "CACHE multiply abs of STEP must be less than DEFAULT MAXVALUE");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t sql_format_sequence(sql_stmt_t *stmt, knl_sequence_def_t *sequence_def)
{
    if (sql_format_sequence_scop_value(sequence_def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_format_sequence_start_value(sequence_def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_check_sequence_cache_value(sequence_def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t sql_parse_increment(lex_t *lex, knl_sequence_def_t *sequence_def)
{
    int64 increment = 0;

    if (lex_expected_fetch_word(lex, "BY") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch_seqval(lex, &increment) != CT_SUCCESS) {
        CT_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR, "sequence INCREMENT must be a bigint");
        return CT_ERROR;
    }

    if (increment == 0) {
        CT_SRC_THROW_ERROR(lex->loc, ERR_SEQ_INVALID, "sequence INCREMENT must be a non-zero integer");
        return CT_ERROR;
    }

    sequence_def->step = increment;

    return CT_SUCCESS;
}

static status_t sql_parse_start_with(lex_t *lex, knl_sequence_def_t *sequence_def)
{
    if (lex_expected_fetch_word(lex, "WITH") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch_seqval(lex, &sequence_def->start) != CT_SUCCESS) {
        CT_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR, "sequence START WITH must be a bigint");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t sql_parse_sequence_parameters(sql_stmt_t *stmt, knl_sequence_def_t *seq_def, word_t *word,
    bool32 allow_groupid)
{
    status_t status;
    lex_t *lex = stmt->session->lex;

    for (;;) {
        status = lex_fetch(stmt->session->lex, word);
        CT_RETURN_IFERR(status);

        if (word->type == WORD_TYPE_EOF) {
            break;
        }

        switch (word->id) {
            case (uint32)KEY_WORD_INCREMENT:
                if (seq_def->is_step_set == CT_TRUE) {
                    CT_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR, "duplicate INCREMENT specifications");
                    return CT_ERROR;
                }
                status = sql_parse_increment(lex, seq_def);
                CT_RETURN_IFERR(status);
                seq_def->is_step_set = 1;
                break;

            case (uint32)KEY_WORD_MINVALUE:
                if (seq_def->is_minval_set == CT_TRUE) {
                    CT_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR, "duplicate MINVALUE specifications");
                    return CT_ERROR;
                }
                if (lex_expected_fetch_seqval(lex, &seq_def->min_value) != CT_SUCCESS) {
                    CT_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR, "sequence MINVALUE must be a bigint");
                    return CT_ERROR;
                }
                seq_def->nominval = CT_FALSE;
                seq_def->is_minval_set = 1;
                break;

            case (uint32)KEY_WORD_NO_MINVALUE:
                if (seq_def->is_nominval_set == CT_TRUE) {
                    CT_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR, "duplicate NO_MINVALUE specifications");
                    return CT_ERROR;
                }
                seq_def->nominval = CT_TRUE;
                seq_def->is_nominval_set = 1;
                break;

            case (uint32)KEY_WORD_MAXVALUE:
                if (seq_def->is_maxval_set == CT_TRUE) {
                    CT_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR, "duplicate MAXVALUE specifications");
                    return CT_ERROR;
                }
                if (lex_expected_fetch_seqval(lex, &seq_def->max_value) != CT_SUCCESS) {
                    CT_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR, "sequence MAXVALUE must be a bigint");
                    return CT_ERROR;
                }
                seq_def->nomaxval = CT_FALSE;
                seq_def->is_maxval_set = 1;
                break;

            case (uint32)KEY_WORD_NO_MAXVALUE:
                if (seq_def->is_nomaxval_set == CT_TRUE) {
                    CT_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR, "duplicate NO_MAXVALUE specifications");
                    return CT_ERROR;
                }
                seq_def->nomaxval = CT_TRUE;
                seq_def->is_nomaxval_set = 1;
                break;

            case (uint32)KEY_WORD_START:
                if (seq_def->is_start_set == CT_TRUE) {
                    CT_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR, "duplicate START specifications");
                    return CT_ERROR;
                }
                status = sql_parse_start_with(lex, seq_def);
                CT_RETURN_IFERR(status);
                seq_def->is_start_set = CT_TRUE;
                break;

            case (uint32)KEY_WORD_CACHE:
                if (seq_def->is_cache_set == CT_TRUE) {
                    CT_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR, "duplicate CACHE specifications");
                    return CT_ERROR;
                }
                if (lex_expected_fetch_seqval(lex, &seq_def->cache) != CT_SUCCESS) {
                    CT_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR, "sequence CACHE must be a bigint");
                    return CT_ERROR;
                }
                seq_def->is_cache_set = 1;
                break;

            case (uint32)KEY_WORD_NO_CACHE:
                if (seq_def->is_nocache_set == CT_TRUE) {
                    CT_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR, "duplicate NO_CACHE specifications");
                    return CT_ERROR;
                }
                seq_def->nocache = CT_TRUE;
                seq_def->is_nocache_set = 1;
                break;

            case (uint32)KEY_WORD_CYCLE:
                if (seq_def->is_cycle_set == CT_TRUE) {
                    CT_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR,
                        "duplicate or conflicting CYCLE/NOCYCLE specifications");
                    return CT_ERROR;
                }
                seq_def->is_cycle = CT_TRUE;
                seq_def->is_cycle_set = 1;
                break;

            case (uint32)KEY_WORD_NO_CYCLE:
                if (seq_def->is_cycle_set == CT_TRUE) {
                    CT_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR,
                        "duplicate or conflicting CYCLE/NOCYCLE specifications");
                    return CT_ERROR;
                }
                seq_def->is_cycle = CT_FALSE;
                seq_def->is_cycle_set = 1;
                break;

            case (uint32)KEY_WORD_ORDER:
                if (seq_def->is_order_set == CT_TRUE) {
                    CT_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR,
                        "duplicate or conflicting ORDER/NOORDER specifications");
                    return CT_ERROR;
                }
                seq_def->is_order = CT_TRUE;
                seq_def->is_order_set = 1;
                break;

            case (uint32)KEY_WORD_NO_ORDER:
                if (seq_def->is_order_set == CT_TRUE) {
                    CT_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR,
                        "duplicate or conflicting ORDER/NOORDER specifications");
                    return CT_ERROR;
                }
                seq_def->is_order = CT_FALSE;
                seq_def->is_order_set = 1;
                break;
            default:
                CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "syntax error in sequence statement");
                return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t sql_check_sequence_conflict_parameters(sql_stmt_t *stmt, knl_sequence_def_t *def)
{
    bool32 result;

    result = (def->is_minval_set && def->is_nominval_set);
    if (result) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "duplicate or conflicting MINVAL/NOMINVAL specifications");
        return CT_ERROR;
    }
    result = (def->is_maxval_set && def->is_nomaxval_set);
    if (result) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "duplicate or conflicting MAX/NOMAXVAL specifications");
        return CT_ERROR;
    }

    result = (def->is_cache_set && def->is_nocache_set);
    if (result) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "duplicate or conflicting CACHE/NOCACHE specifications");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_check_sequence_parameters_relation(sql_stmt_t *stmt, knl_sequence_def_t *def)
{
    bool32 result;

    CT_RETURN_IFERR(sql_check_sequence_conflict_parameters(stmt, def));

    result = (!def->is_maxval_set && def->is_cycle && (def->step > 0));
    if (result) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "ascending sequences that CYCLE must specify MAXVALUE");
        return CT_ERROR;
    }

    result = (!def->is_minval_set && def->is_cycle && (def->step < 0));
    if (result) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "descending sequences that CYCLE must specify MINVALUE");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}


status_t sql_parse_create_sequence(sql_stmt_t *stmt)
{
    status_t status;
    knl_sequence_def_t *sequence_def = NULL;
    word_t word;
    lex_t *lex = stmt->session->lex;

    lex->flags |= LEX_WITH_OWNER;

    status = sql_alloc_mem(stmt->context, sizeof(knl_sequence_def_t), (void **)&sequence_def);
    CT_RETURN_IFERR(status);

    sql_init_create_sequence(stmt, sequence_def);
    stmt->context->entry = sequence_def;
    stmt->context->type = CTSQL_TYPE_CREATE_SEQUENCE;
    // parse the sequence name
    status = lex_expected_fetch_variant(stmt->session->lex, &word);
    CT_RETURN_IFERR(status);

    status = sql_convert_object_name(stmt, &word, &sequence_def->user, NULL, &sequence_def->name);
    CT_RETURN_IFERR(status);

    status = sql_parse_sequence_parameters(stmt, sequence_def, &word, CT_TRUE);
    CT_RETURN_IFERR(status);
    status = sql_check_sequence_parameters_relation(stmt, sequence_def);
    CT_RETURN_IFERR(status);

    return sql_format_sequence(stmt, sequence_def);
}

static void sql_parse_alter_sequence_get_param(knl_sequence_def_t *def, dc_sequence_t *seq)
{
    if (def->is_nocache_set) {
        def->cache = 0;
        def->is_cache_set = 1;
    }
    if (def->is_nominval_set) {
        def->min_value = def->step < 0 ? DDL_DESC_SEQUENCE_DEFAULT_MIN_VALUE : DDL_ASC_SEQUENCE_DEFAULT_MIN_VALUE;
        def->is_minval_set = def->is_nominval_set; /* specify the 'nominvalue' */
    }

    if (def->is_nomaxval_set) {
        def->max_value = def->step < 0 ? DDL_DESC_SEQUENCE_DEFAULT_MAX_VALUE : DDL_ASC_SEQUENCE_DEFAULT_MAX_VALUE;
        def->is_maxval_set = def->is_nomaxval_set; /* specify the 'nomaxvalue' */
    }
    return;
}
/*
 * merge param in dc when alter sequence
 * @param[in]   def - sequence defination
 * @param[in]   seq - sequence in dc
 * @return void
 */
static void seq_merge_alter_param(knl_sequence_def_t *seq_def, dc_sequence_t *seq)
{
    seq_def->step = seq_def->is_step_set ? seq_def->step : seq->step;
    seq_def->cache = seq_def->is_cache_set ? seq_def->cache : seq->cache_size;
    seq_def->min_value = seq_def->is_minval_set ? seq_def->min_value : seq->minval;
    seq_def->max_value = seq_def->is_maxval_set ? seq_def->max_value : seq->maxval;
    seq_def->is_cycle = seq_def->is_cycle_set ? seq_def->is_cycle : seq->is_cyclable;
    seq_def->nocache = seq_def->is_nocache_set ? 1 : (seq->is_cache ? 0 : 1);
}
/*
 * check the parameter when alter sequence
 * @param[in]   session - user session
 * @param[in]   def - sequence defination
 * @param[in]   sequence - sequence in dc
 * @return
 * - CT_SUCCESS
 * - CT_ERROR
 */
static status_t seq_check_alter_param(sql_stmt_t *stmt, knl_sequence_def_t *def, dc_sequence_t *sequence)
{
    int64 step = cm_abs64(def->step);
    int64 next;
    if (!def->is_option_set) {
        CT_THROW_ERROR(ERR_SEQ_INVALID, "no options specified for alter sequence");
        return CT_ERROR;
    }
    if (def->is_start_set) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "cannot alter starting sequence number ");
        return CT_ERROR;
    }
    if (def->max_value <= def->min_value) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "MINVALUE must less than MAXVALUE");
        return CT_ERROR;
    }

    if (def->step > 0) {
        if ((opr_int64add_overflow(def->min_value, def->step, &next)) || (def->max_value < next)) {
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "INCREMENT must be less than MAX value minus MIN value");
            return CT_ERROR;
        }
    }
    if (def->step < 0) {
        if ((opr_int64add_overflow(def->max_value, def->step, &next)) || (def->min_value > next)) {
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "INCREMENT must be less than MAX value minus MIN value");
            return CT_ERROR;
        }
    }

    if (!IS_COORDINATOR || (IS_COORDINATOR && IS_APP_CONN(stmt->session))) {
        if (def->min_value > sequence->rsv_nextval) {
            CT_THROW_ERROR(ERR_SEQ_INVALID, "MINVALUE cannot be made to exceed the current value");
            return CT_ERROR;
        }

        if (def->max_value < (sequence->rsv_nextval)) {
            CT_THROW_ERROR(ERR_SEQ_INVALID, "MAXVALUE cannot be made to below the current value");
            return CT_ERROR;
        }
    }

    if (def->is_cycle && def->step > 0 && def->is_nomaxval_set) {
        CT_THROW_ERROR(ERR_SEQ_INVALID, "cycle must specify maxvalue");
        return CT_ERROR;
    }

    if (def->is_cycle && def->step < 0 && def->is_nominval_set) {
        CT_THROW_ERROR(ERR_SEQ_INVALID, "cycle must specify minvalue");
        return CT_ERROR;
    }

    if (def->is_cycle && ((uint64)def->cache > ceil((double)((uint64)def->max_value - def->min_value) / step))) {
        CT_THROW_ERROR(ERR_SEQ_INVALID, "number to CACHE must be less than one cycle");
        return CT_ERROR;
    }

    if ((def->is_nocache_set == 0) && (def->is_cache_set == 1) && (def->cache <= 1)) {
        CT_THROW_ERROR(ERR_SEQ_INVALID, "CACHE value must be larger than 1");
        return CT_ERROR;
    }

    if (def->is_cycle && ((uint64)def->cache > ceil((double)((uint64)def->max_value - def->min_value) / step))) {
        CT_THROW_ERROR(ERR_SEQ_INVALID, "number to CACHE must be less than one cycle");
        return CT_ERROR;
    }

    if (def->step >= 1 && (def->cache > (DDL_ASC_SEQUENCE_DEFAULT_MAX_VALUE / cm_abs64(def->step)))) {
        CT_THROW_ERROR(ERR_SEQ_INVALID, "CACHE multiply abs of STEP must be less than DEFAULT MAXVALUE");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}


status_t sql_parse_check_param(sql_stmt_t *stmt, knl_sequence_def_t *def)
{
    knl_dictionary_t dc_seq;
    dc_sequence_t *sequence = NULL;
    status_t ret;

    if (CT_SUCCESS != dc_seq_open(&stmt->session->knl_session, &def->user, &def->name, &dc_seq)) {
        return CT_ERROR;
    }
    sequence = (dc_sequence_t *)dc_seq.handle;
    dls_spin_lock(&stmt->session->knl_session, &sequence->entry->lock, NULL);

    if (!sequence->valid || sequence->entry->org_scn > DB_CURR_SCN(KNL_SESSION(stmt))) {
        dls_spin_unlock(&stmt->session->knl_session, &sequence->entry->lock);
        dc_seq_close(&dc_seq);
        CT_THROW_ERROR(ERR_SEQ_NOT_EXIST, T2S(&def->user), T2S_EX(&def->name));
        return CT_ERROR;
    }

    def->step = def->is_step_set ? def->step : sequence->step;
    sql_parse_alter_sequence_get_param(def, sequence);
    seq_merge_alter_param(def, sequence);
    ret = seq_check_alter_param(stmt, def, sequence);
    dls_spin_unlock(&stmt->session->knl_session, &sequence->entry->lock);
    dc_seq_close(&dc_seq);
    return ret;
}

status_t sql_parse_alter_sequence(sql_stmt_t *stmt)
{
    word_t word;
    knl_sequence_def_t *def = NULL;
    lex_t *lex = stmt->session->lex;
    status_t status;

    lex->flags |= LEX_WITH_OWNER;

    status = sql_alloc_mem(stmt->context, sizeof(knl_sequence_def_t), (void **)&def);
    CT_RETURN_IFERR(status);

    sql_init_create_sequence(stmt, def);
    stmt->context->entry = def;
    stmt->context->type = CTSQL_TYPE_ALTER_SEQUENCE;

    status = lex_expected_fetch_variant(stmt->session->lex, &word);
    CT_RETURN_IFERR(status);

    if (word.ex_count > 0) {
        status = sql_copy_prefix_tenant(stmt, (text_t *)&word.text, &def->user, sql_copy_name);
        CT_RETURN_IFERR(status);

        status =
            sql_copy_object_name(stmt->context, word.ex_words[0].type, (text_t *)&word.ex_words[0].text, &def->name);
        CT_RETURN_IFERR(status);
    } else {
        cm_str2text(stmt->session->curr_schema, &def->user);
        status = sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &def->name);
        CT_RETURN_IFERR(status);
    }

    status = sql_parse_sequence_parameters(stmt, def, &word, CT_FALSE);
    CT_RETURN_IFERR(status);
    status = sql_check_sequence_conflict_parameters(stmt, def);
    CT_RETURN_IFERR(status);
    if (sql_parse_check_param(stmt, def) != CT_SUCCESS) {
        sql_check_user_priv(stmt, &def->user);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_parse_drop_sequence(sql_stmt_t *stmt)
{
    knl_drop_def_t *def = NULL;
    bool32 is_cascade = CT_FALSE;
    lex_t *lex = stmt->session->lex;

    lex->flags = LEX_WITH_OWNER;

    stmt->context->type = CTSQL_TYPE_DROP_SEQUENCE;

    if (sql_alloc_mem(stmt->context, sizeof(knl_drop_def_t), (void **)&def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_parse_drop_object(stmt, def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    stmt->context->entry = def;
    if (lex_try_fetch(lex, "CASCADE", &is_cascade) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (is_cascade) {
        /* NEED TO PARSE CASCADE INFO. */
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "cascade option no implement.");
        return CT_ERROR;
    }

    return lex_expected_end(lex);
}


static status_t sql_verify_synonym_def(sql_stmt_t *stmt, knl_synonym_def_t *def)
{
    knl_dictionary_t dc;
    pl_entry_t *pl_entry = NULL;
    bool32 is_tab_found = CT_FALSE;
    bool32 found = CT_FALSE;

    if (knl_open_dc_if_exists(KNL_SESSION(stmt), &def->table_owner, &def->table_name, &dc, &is_tab_found) !=
        CT_SUCCESS) {
        return CT_ERROR;
    }
    if (IS_LTT_BY_NAME(def->table_name.str)) {
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "Prevent creating synonyms of local temporary tables");
        return CT_ERROR;
    }
    if (!is_tab_found) {
        if (pl_find_entry(KNL_SESSION(stmt), &def->table_owner, &def->table_name, PL_SYN_LINK_TYPE, &pl_entry,
            &found) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (!found) {
            CT_THROW_ERROR(ERR_USER_OBJECT_NOT_EXISTS, "The object", T2S(&def->table_owner), T2S_EX(&def->table_name));
            return CT_ERROR;
        }
        def->is_knl_syn = CT_FALSE;
    } else {
        if (SYNONYM_EXIST(&dc) || dc.type > DICT_TYPE_GLOBAL_DYNAMIC_VIEW) {
            CT_THROW_ERROR(ERR_INVALID_SYNONYM_OBJ_TYPE, T2S(&def->table_owner), T2S_EX(&def->table_name));
            knl_close_dc(&dc);
            return CT_ERROR;
        }
        def->ref_uid = dc.uid;
        def->ref_oid = dc.oid;
        def->ref_org_scn = dc.org_scn;
        def->ref_chg_scn = dc.chg_scn;
        def->ref_dc_type = dc.type;
        def->is_knl_syn = CT_TRUE;
        knl_close_dc(&dc);
    }
    return CT_SUCCESS;
}

static inline status_t sql_convert_object_name_ex(sql_stmt_t *stmt, word_t *word, bool32 is_public, text_t *owner,
    text_t *name)
{
    status_t status;
    text_t public_user = { PUBLIC_USER, (uint32)strlen(PUBLIC_USER) };

    if (word->ex_count == 1) {
        if (is_public) {
            if (cm_compare_text_str_ins((text_t *)&word->text, PUBLIC_USER) != 0) {
                CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR,
                    "owner of object should be public, but is %s", T2S((text_t *)&word->text));
                return CT_ERROR;
            }
            CT_RETURN_IFERR(sql_copy_name(stmt->context, &public_user, owner));
        } else {
            status = sql_copy_prefix_tenant(stmt, (text_t *)&word->text, owner, sql_copy_name);
            CT_RETURN_IFERR(status);
        }

        status = sql_copy_object_name(stmt->context, word->ex_words[0].type, (text_t *)&word->ex_words[0].text, name);
        CT_RETURN_IFERR(status);
    } else {
        if (is_public) {
            CT_RETURN_IFERR(sql_copy_text(stmt->context, &public_user, owner));
        } else {
            cm_str2text(stmt->session->curr_schema, owner);
        }

        status = sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, name);
        CT_RETURN_IFERR(status);
    }

    return CT_SUCCESS;
}

status_t sql_parse_create_synonym(sql_stmt_t *stmt, uint32 flags)
{
    bool32 is_public = (flags & SYNONYM_IS_PUBLIC) ? CT_TRUE : CT_FALSE;
    word_t word;
    knl_synonym_def_t *def = NULL;
    lex_t *lex = stmt->session->lex;

    if (sql_alloc_mem(stmt->context, sizeof(knl_synonym_def_t), (pointer_t *)&def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    def->flags = flags;
    stmt->context->type = CTSQL_TYPE_CREATE_SYNONYM;

    lex->flags |= LEX_WITH_OWNER;
    if (lex_expected_fetch_variant(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (CT_SUCCESS != sql_convert_object_name_ex(stmt, &word, is_public, &def->owner, &def->name)) {
        return CT_ERROR;
    }

    if (lex_expected_fetch_word(lex, "for") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch_variant(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_convert_object_name(stmt, &word, &def->table_owner, NULL, &def->table_name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (CT_SUCCESS != lex_expected_end(lex)) {
        return CT_ERROR;
    }

    if (sql_verify_synonym_def(stmt, def) != CT_SUCCESS) {
        sql_check_user_priv(stmt, &def->table_owner);
        return CT_ERROR;
    }

    stmt->context->entry = def;

    return CT_SUCCESS;
}

status_t sql_parse_drop_synonym(sql_stmt_t *stmt, uint32 flags)
{
    bool32 result = CT_FALSE;
    bool32 is_public = (flags & SYNONYM_IS_PUBLIC) ? CT_TRUE : CT_FALSE;
    word_t word;
    knl_drop_def_t *def = NULL;
    lex_t *lex = stmt->session->lex;

    if (sql_alloc_mem(stmt->context, sizeof(knl_drop_def_t), (pointer_t *)&def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    stmt->context->type = CTSQL_TYPE_DROP_SYNONYM;

    lex->flags |= LEX_WITH_OWNER;

    if (sql_try_parse_if_exists(lex, &def->options) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch_variant(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_convert_object_name_ex(stmt, &word, is_public, &def->owner, &def->name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_try_fetch(lex, "force", &result) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (result) {
        def->options |= DROP_CASCADE_CONS;
    }

    stmt->context->entry = def;
    return lex_expected_end(lex);
}

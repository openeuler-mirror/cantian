/* -------------------------------------------------------------------------
 *  This file is part of the Cantian project.
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd.
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
 * cm_regexp.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_regexp.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_REGEXP_H__
#define __CM_REGEXP_H__
#define PCRE2_CODE_UNIT_WIDTH 8

#include "cm_text.h"
#include "cm_defs.h"
#include "var_inc.h"
#include "cm_charset.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum en_regexp_arg_type {
    REGEXP_ARG_SOURCE = 0,
    REGEXP_ARG_PATTERN,
    REGEXP_ARG_REPLACE,
    REGEXP_ARG_POSITION,
    REGEXP_ARG_OCCUR,
    REGEXP_ARG_MATCH_PARAM,
    REGEXP_ARG_RETURN_OPT,
    REGEXP_ARG_SUBEXPR,
    REGEXP_ARG_DUMB,
} regexp_arg_type_t;

extern regexp_arg_type_t g_instr_arg_types[];
extern regexp_arg_type_t g_substr_arg_types[];
extern regexp_arg_type_t g_count_arg_types[];
extern regexp_arg_type_t g_replace_arg_types[];

typedef struct st_regexp_args {
    text_t *src;         // subject string which the search is to take place
    text_t *pattern;     // pattern string for the search
    text_t *replace_str; // string for replace
    text_t *match_param; // control aspects of the pattern matching
    int32 offset;        // offset in the subject at which to start matching, default is 1
    int32 occur;         // occurrence of the pattern string within subject string to search for, default is 1
    int32 retopt;        // specifies whether to return start position(0) or end position(1) after the pattern matched, default is 0
    int32 subexpr;       // specifies which capture group of the pattern-expression is used to determine the position within source-string to return, default is 0

    // members below are used for calculating assist
    variant_t var_src;
    variant_t var_pattern;
    variant_t var_replace_str;
    variant_t var_match_param;
    variant_t var_pos;
    variant_t var_occur;
    variant_t var_retopt;
    variant_t var_subexpr;
} regexp_args_t;

typedef void *(*regexp_malloc_t)(size_t);
typedef void (*regexp_free_t)(void *);

typedef struct st_regexp_mem_func {
    regexp_malloc_t allocator;
    regexp_free_t deallocator;
} regexp_mem_func_t;

void cm_regexp_args_init(regexp_args_t *args);

status_t cm_regexp_compile(void **code, const char *regexp, text_t *match_param, charset_type_t charset);
status_t cm_regexp_match(bool32 *matched, const void *code, const text_t *subject);

typedef struct st_regexp_substr_assist {
    const void *code; // compiled regular expression
    text_t subject; // source text
    int32 offset; // match begin from which offset(by character from 0)
    int32 occur; // occurrence of the matched pattern
    int32 subexpr; // specifies which capture group of the pattern-expression
    charset_type_t charset; // charset of source text
} regexp_substr_assist_t;
status_t cm_regexp_instr(int32 *pos, regexp_substr_assist_t *assist, bool32 end);
status_t cm_regexp_substr(text_t *substr, regexp_substr_assist_t *assist);
void cm_regexp_free(void *code);

#ifdef __cplusplus
}
#endif

#endif

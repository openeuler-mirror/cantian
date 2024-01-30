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
 * pragma.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/ast/pragma.c
 *
 * -------------------------------------------------------------------------
 */
#include "pragma.h"

/* NOTICE: this record should be at alphabetical order. */
static key_word_t g_exception_words[] = {
    { (uint32)ACCESS_INTO_NULL,        CT_FALSE, { (char *)"access_into_null" } },
    { (uint32)CASE_NOT_FOUND,          CT_FALSE, { (char *)"case_not_found" } },
    { (uint32)COLLECTION_IS_NULL,      CT_FALSE, { (char *)"collection_is_null" } },
    { (uint32)CURSOR_ALREADY_OPEN,     CT_FALSE, { (char *)"cursor_already_open" } },
    { (uint32)DUP_VAL_ON_INDEX,        CT_FALSE, { (char *)"dup_val_on_index" } },
    { (uint32)INVALID_CURSOR,          CT_FALSE, { (char *)"invalid_cursor" } },
    { (uint32)INVALID_NUMBER,          CT_FALSE, { (char *)"invalid_number" } },
    { (uint32)LOGIN_DENIED,            CT_FALSE, { (char *)"login_denied" } },
    { (uint32)NOT_LOGGED_ON,           CT_FALSE, { (char *)"not_logged_on" } },
    { (uint32)NO_DATA_FOUND,           CT_FALSE, { (char *)"no_data_found" } },
    { (uint32)NO_DATA_NEEDED,          CT_FALSE, { (char *)"no_data_needed" } },
    { (uint32)OTHERS,                  CT_FALSE, { (char *)"others" } },
    { (uint32)PROGRAM_ERROR,           CT_FALSE, { (char *)"program_error" } },
    { (uint32)RETURN_WITHOUT_VALUE,    CT_FALSE, { (char *)"return_without_value" } },
    { (uint32)ROWTYPE_MISMATCH,        CT_FALSE, { (char *)"rowtype_mismatch" } },
    { (uint32)SELF_IS_NULL,            CT_FALSE, { (char *)"self_is_null" } },
    { (uint32)STORAGE_ERROR,           CT_FALSE, { (char *)"storage_error" } },
    { (uint32)SUBSCRIPT_BEYOND_COUNT,  CT_FALSE, { (char *)"subscript_beyond_count" } },
    { (uint32)SUBSCRIPT_OUTSIDE_LIMIT, CT_FALSE, { (char *)"subscript_outside_limit" } },
    { (uint32)SYS_INVALID_ROWID,       CT_FALSE, { (char *)"sys_invalid_rowid" } },
    { (uint32)TIMEOUT_ON_RESOURCE,     CT_FALSE, { (char *)"timeout_on_resource" } },
    { (uint32)TOO_MANY_ROWS,           CT_FALSE, { (char *)"too_many_rows" } },
    { (uint32)VALUE_ERROR,             CT_FALSE, { (char *)"value_error" } },
    { (uint32)ZERO_DIVIDE,             CT_FALSE, { (char *)"zero_divide" } }
};

#define EXCEPTION_WORDS_COUNT (sizeof(g_exception_words) / sizeof(key_word_t)) // divisor is not 0

int32 pl_get_exception_id(word_t *word)
{
    if (lex_match_subset((key_word_t *)g_exception_words, EXCEPTION_WORDS_COUNT, word)) {
        return (int32)word->id;
    }

    return INVALID_EXCEPTION;
}

void pl_init_keywords(void)
{
    uint32 i;

    for (i = 0; i < EXCEPTION_WORDS_COUNT; i++) {
        g_exception_words[i].text.len = (uint32)strlen(g_exception_words[i].text.str);
    }
}

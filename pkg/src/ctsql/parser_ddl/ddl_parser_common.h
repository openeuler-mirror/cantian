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
 * ddl_parser_common.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser_ddl/ddl_parser_common.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DDL_PARSER_COMMON_H__
#define __DDL_PARSER_COMMON_H__

#include "cm_defs.h"
#include "srv_instance.h"
#include "ctsql_stmt.h"
#include "cm_lex.h"

#ifdef __cplusplus
extern "C" {
#endif
status_t sql_try_parse_if_exists(lex_t *lex, uint32 *options);
status_t sql_try_parse_if_not_exists(lex_t *lex, uint32 *options);
status_t sql_parse_drop_object(sql_stmt_t *stmt, knl_drop_def_t *def);
status_t sql_convert_object_name(sql_stmt_t *stmt, word_t *word, text_t *owner, bool32 *owner_explict, text_t *name);
status_t sql_parse_space(sql_stmt_t *stmt, lex_t *lex, word_t *word, text_t *space);
status_t sql_parse_trans(lex_t *lex, word_t *word, uint32 *trans);
status_t sql_parse_crmode(lex_t *lex, word_t *word, uint8 *cr_mode);
status_t sql_parse_pctfree(lex_t *lex, word_t *word, uint32 *pct_free);
status_t sql_parse_storage(lex_t *lex, word_t *word, knl_storage_def_t *storage_def, bool32 alter);
status_t sql_parse_parallelism(lex_t *lex, word_t *word, uint32 *parallelism, int32 max_parallelism);
status_t sql_parse_reverse(word_t *word, bool32 *is_reverse);

#ifdef __cplusplus
}
#endif

#endif

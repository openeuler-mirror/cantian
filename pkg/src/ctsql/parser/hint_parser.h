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
 * hint_parser.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser/hint_parser.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __HINT_PARSER_H__
#define __HINT_PARSER_H__

#include "dml_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t sql_parse_hint(sql_stmt_t *stmt, hint_info_t **hint_info);
status_t sql_alloc_hint(sql_stmt_t *stmt, hint_info_t **hint_info);
bool32 hint_apply_join_method(sql_stmt_t *stmt, sql_join_node_t *join_node, join_cond_t *join_cond, bool32 is_select,
    join_oper_t *jop);

#ifdef __cplusplus
}
#endif

#endif
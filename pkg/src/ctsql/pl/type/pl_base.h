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
 * pl_base.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/type/pl_base.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PL_BASE_H__
#define __PL_BASE_H__

#include "ctsql_verifier.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef status_t (*verify_elemt_t)(sql_verifier_t *, uint32, void *, expr_tree_t *);

status_t udt_verify_method_node(sql_verifier_t *verif, expr_node_t *node, uint32 min_args, uint32 max_args);

status_t udt_verify_construct_base(sql_verifier_t *verif, expr_node_t *node, uint32 min_args, uint32 max_args,
                                   text_t *name, verify_elemt_t verify);

#ifdef __cplusplus
}
#endif

#endif

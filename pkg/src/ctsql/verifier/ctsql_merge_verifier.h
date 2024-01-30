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
 * ctsql_merge_verifier.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/verifier/ctsql_merge_verifier.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_MERGE_VERIFIER_H__
#define __SQL_MERGE_VERIFIER_H__

#include "ctsql_verifier.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t sql_verify_merge(sql_stmt_t *stmt, sql_merge_t *merge_ctx);

#ifdef __cplusplus
}
#endif

#endif
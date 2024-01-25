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
 * ctsql_connect_verifier.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/verifier/ctsql_connect_verifier.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_select_verifier.h"

#ifdef __cplusplus
extern "C" {
#endif


status_t sql_verify_query_connect(sql_verifier_t *verf, sql_query_t *query)
{
    if (query->connect_by_cond == NULL) {
        return CT_SUCCESS;
    }

    verf->curr_query = query;
    verf->excl_flags = SQL_CONNECT_BY_EXCL;
    if (sql_verify_cond(verf, query->connect_by_cond) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (query->start_with_cond == NULL) {
        return CT_SUCCESS;
    }

    verf->excl_flags = SQL_START_WITH_EXCL;
    if (sql_verify_cond(verf, query->start_with_cond) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

#ifdef __cplusplus
}
#endif
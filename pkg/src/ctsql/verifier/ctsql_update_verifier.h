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
 * ctsql_update_verifier.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/verifier/ctsql_update_verifier.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_UPDATE_VERIFIER_H__
#define __SQL_UPDATE_VERIFIER_H__

#include "ctsql_verifier.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t sql_verify_update_pair(knl_handle_t session, sql_verifier_t *verif, column_value_pair_t *pair,
    sql_update_t *update_ctx);
status_t sql_verify_update_pairs(knl_handle_t session, sql_verifier_t *verif, sql_update_t *update_ctx);
status_t sql_verify_upd_object_pairs(sql_verifier_t *verif, sql_update_t *update_ctx);
status_t sql_verify_update(sql_stmt_t *stmt, sql_update_t *update_ctx);

#ifdef __cplusplus
}
#endif

#endif
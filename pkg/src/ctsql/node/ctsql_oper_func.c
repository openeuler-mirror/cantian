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
 * ctsql_oper_func.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/node/ctsql_oper_func.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_date.h"
#include "cm_decimal.h"
#include "ctsql_oper_func.h"
#include "pl_executor.h"
#include "var_inc.h"
#include "ctsql_insert.h"

status_t oprf_column(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    status_t status;
        /* replace into t1 set f1 = f1 ===> replace into t1 set f1 = default(f1) */
        if (SECUREC_UNLIKELY(stmt->default_info.default_on == CT_TRUE &&
            CTSQL_ROOT_CURSOR(stmt) == CTSQL_CURR_CURSOR(stmt))) {
            sql_get_default_value(stmt, VALUE_PTR(var_column_t, &node->value)->col, result);
            status = CT_SUCCESS;
        } else {
            status = sql_get_table_value(stmt, VALUE_PTR(var_column_t, &node->value), result);
        }
    return status;
}

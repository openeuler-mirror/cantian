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
 * ctsql_hint_verifier.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/verifier/ctsql_hint_verifier.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_hint_verifier.h"
#include "dml_parser.h"
#include "hint_parser.h"
#include "srv_instance.h"
#include "ctsql_plan.h"
#include "cbo_base.h"

#ifdef __cplusplus
extern "C" {
#endif

uint32 get_dynamic_sampling_level(sql_stmt_t *stmt)
{
    if (stmt->context->hint_info == NULL || stmt->context->hint_info->opt_params == NULL ||
        stmt->context->hint_info->opt_params->dynamic_sampling == CT_INVALID_ID32) {
        return g_instance->sql.cbo_dyn_sampling;
    }
    return stmt->context->hint_info->opt_params->dynamic_sampling;
}

#ifdef __cplusplus
}
#endif

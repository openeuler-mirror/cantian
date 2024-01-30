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
 * ple_coverage.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/executor/ple_coverage.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __PLE_COVERAGE_H__
#define __PLE_COVERAGE_H__

#include "ctsql_stmt.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_ple_coverage {
    uint8 *hit_count;
    uint32 loc_line_num;
} ple_coverage_t;

#define COVER_ENABLE (g_instance->sql.coverage_enable)
#define PLE_IS_COVER_VALID(exec) \
    ((COVER_ENABLE == CT_TRUE) && ((exec)->coverage != NULL) && ((exec)->entity->def.name.len != 0))

status_t ple_push_coverage_hit_count(sql_stmt_t *stmt);
status_t ple_try_create_coverage_table(knl_handle_t knl_session);
status_t ple_try_insert_coverage_table(sql_stmt_t *stmt, bool32 is_try);
#ifdef __cplusplus
}
#endif

#endif
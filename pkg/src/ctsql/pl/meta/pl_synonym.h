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
 * pl_synonym.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/meta/pl_synonym.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PL_SYNONYM_H__
#define __PL_SYNONYM_H__

#include "knl_dc.h"
#include "ctsql_stmt.h"
#include "obj_defs.h"
#include "pl_meta_common.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t pl_execute_drop_synonym_core(sql_stmt_t *stmt, dc_user_t *dc_user);
status_t pl_write_pl_synonym(knl_session_t *session, knl_synonym_def_t *def, pl_desc_t *desc);
status_t pl_write_syn_dep(knl_session_t *session, knl_synonym_def_t *def, pl_desc_t *desc);
status_t pl_drop_synonym_by_user(knl_handle_t sess, uint32 uid, text_t *syn_name);
status_t pl_load_synonym(knl_handle_t sess, void *desc_in);
#ifdef __cplusplus
}
#endif

#endif

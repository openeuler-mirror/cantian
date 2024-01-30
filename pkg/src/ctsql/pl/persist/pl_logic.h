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
 * pl_logic.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/persist/pl_logic.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __PL_LOGIC_H__
#define __PL_LOGIC_H__

#include "knl_session.h"
#include "pl_defs.h"
#include "pl_logic_persist.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t pl_logic_log_replay(knl_handle_t session, uint32 type, void *data);
void pl_logic_log_put(knl_session_t *session, uint32 type, uint32 uid, uint64 oid, uint32 tid);

#ifdef __cplusplus
}
#endif

#endif
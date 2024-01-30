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
 * pl_upgrade.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/persist/pl_upgrade.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PL_UPGRADE_H__
#define __PL_UPGRADE_H__

#include "knl_dc.h"
#ifdef __cplusplus
extern "C" {
#endif

status_t pl_upgrade_build_object(knl_session_t *session);

#ifdef __cplusplus
}
#endif

#endif

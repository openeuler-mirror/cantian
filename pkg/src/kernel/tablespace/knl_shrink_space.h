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
 * knl_shrink_space.h
 *
 *
 * IDENTIFICATION
 * src/kernel/tablespace/knl_shrink_space.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_SHRINK_SPACE_H__
#define __KNL_SHRINK_SPACE_H__

#include "knl_space_ddl.h"
#include "knl_shrink_space_persist.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t spc_shrink_space(knl_session_t *session, space_t *space, knl_shrink_def_t *shrink);

#ifdef __cplusplus
}
#endif

#endif


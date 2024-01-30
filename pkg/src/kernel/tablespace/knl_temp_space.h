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
 * knl_temp_space.h
 *
 *
 * IDENTIFICATION
 * src/kernel/tablespace/knl_temp_space.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_TEMP_SPACE_H__
#define __KNL_TEMP_SPACE_H__

#include "knl_space_base.h"
#include "knl_db_ctrl.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t spc_alloc_swap_extent(knl_session_t *session, space_t *space, page_id_t *extent);
page_id_t spc_try_get_next_temp_ext(knl_session_t *session, page_id_t extent);
space_t *spc_get_temp_undo(knl_session_t *session);
void spc_free_temp_extent(knl_session_t *session, space_t *space, page_id_t extent);

#ifdef __cplusplus
}
#endif

#endif


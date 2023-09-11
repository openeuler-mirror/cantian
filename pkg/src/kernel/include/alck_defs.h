/* -------------------------------------------------------------------------
 *  This file is part of the Cantian project.
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd.
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
 * alck_defs.h
 *
 *
 * IDENTIFICATION
 * src/kernel/include/alck_defs.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_ALCK_DEFS_H__
#define __KNL_ALCK_DEFS_H__

#include "knl_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/* advisory lock */
bool32   knl_alck_have_se_lock(knl_handle_t sess);
status_t knl_alck_se_lock_ex(knl_handle_t sess, text_t *name, uint32 timeout, bool32 *locked);
status_t knl_alck_se_try_lock_ex(knl_handle_t sess, text_t *name, bool32 *locked);
status_t knl_alck_se_lock_sh(knl_handle_t sess, text_t *name, uint32 timeout, bool32 *locked);
status_t knl_alck_se_try_lock_sh(knl_handle_t sess, text_t *name, bool32 *locked);
status_t knl_alck_se_unlock_ex(knl_handle_t sess, text_t *name, bool32 *unlocked);
status_t knl_alck_se_unlock_sh(knl_handle_t sess, text_t *name, bool32 *unlocked);

status_t knl_alck_tx_lock_ex(knl_handle_t sess, text_t *name, uint32 timeout, bool32 *locked);
status_t knl_alck_tx_try_lock_ex(knl_handle_t sess, text_t *name, bool32 *locked);
status_t knl_alck_tx_lock_sh(knl_handle_t sess, text_t *name, uint32 timeout, bool32 *locked);
status_t knl_alck_tx_try_lock_sh(knl_handle_t sess, text_t *name, bool32 *locked);
void     knl_destroy_se_alcks(knl_handle_t session);
#ifdef __cplusplus
}
#endif

#endif

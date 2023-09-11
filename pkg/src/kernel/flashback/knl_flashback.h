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
 * knl_flashback.h
 *
 *
 * IDENTIFICATION
 * src/kernel/flashback/knl_flashback.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_FLASHBACK_H__
#define __KNL_FLASHBACK_H__

#include "cm_defs.h"
#include "knl_dc.h"
#include "knl_interface.h"
#include "knl_session.h"

#ifdef __cplusplus
extern "C" {
#endif
    
status_t fb_flashback(knl_session_t *session, knl_flashback_def_t *def);
status_t fb_prepare_flashback_table(knl_session_t *session, knl_dictionary_t *dc, knl_scn_t scn);
status_t fb_flashback_table(knl_session_t *session, knl_dictionary_t *dc, knl_scn_t scn);

#ifdef __cplusplus
}
#endif

#endif

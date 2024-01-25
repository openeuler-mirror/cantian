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
 * cms_iofence.h
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_iofence.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CMS_IOFENCE_H
#define CMS_IOFENCE_H

#include "cms_msg_def.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum e_iofence_type {
    IOFENCE_BY_VOTING = 0,
    IOFENCE_BY_DETECT_OFFLINE = 1,
} iofence_type_t;

status_t cms_iofence_list(const char* res_name, uint32 node_id);
status_t cms_iofence_kick(const char* res_name, uint32 node_id);
status_t cms_iofence_wait_reg(const char* res_name, uint32 node_id);
status_t cms_iofence_wait_kick(const char* res_name, uint32 node_id);
void cms_finish_iof_kick(void);
status_t cms_kick_node(const char* name, uint32 node_id, iofence_type_t iofence_type);
status_t cms_send_msg_kick_node(cms_msg_req_iof_kick_t *req, cms_msg_res_iof_kick_t *res, iofence_type_t iofence_type);
void try_cms_kick_node(uint32 node_id, uint32 res_id, iofence_type_t iofence_type);
status_t cms_kick_node_by_ns(const char* name, uint32 node_id, iofence_type_t iofence_type);

#ifdef __cplusplus
}
#endif
#endif

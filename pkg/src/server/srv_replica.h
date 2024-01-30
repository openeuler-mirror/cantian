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
 * srv_replica.h
 *
 *
 * IDENTIFICATION
 * src/server/srv_replica.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SRV_REPLICA_H__
#define __SRV_REPLICA_H__

#include "cm_defs.h"
#include "cm_types.h"
#include "cm_text.h"

#ifdef __cplusplus
extern "C" {
#endif

struct st_cs_pipe;
status_t srv_create_replica_session(struct st_cs_pipe *cs_pipe);
status_t srv_modify_replica(handle_t session, text_t *host, uint16 replica_port, char ip_arr[][CM_MAX_IP_LEN]);
void srv_stop_replica(handle_t session);


#ifdef __cplusplus
}
#endif

#endif

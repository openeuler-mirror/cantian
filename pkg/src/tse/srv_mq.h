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
 * srv_mq.h
 *
 *
 * IDENTIFICATION
 * src/tse/srv_mq.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef SRV_MQ
#define SRV_MQ

#include "tse_srv_util.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

#define REG_RECV_THD_NUM (1)
#define CPU_INFO_STR_SIZE 1280  // 配置的CPU绑核信息，最大取1280

typedef struct tag_mq_cfg_s {
    uint32_t num_msg_recv_thd;
    uint32_t num_msg_queue;
} mq_cfg_s;

int mq_srv_init(void);
int mq_srv_destory(void);

void *get_upstream_shm_inst(void);
mq_cfg_s* get_global_mq_cfg(void);
char *get_global_mq_cpu_info(void);
char *get_global_mq_mysql_cpu_info(void);

int tse_mq_deal_func(void* shm_inst, enum TSE_FUNC_TYPE func_type, void* request);

#ifdef __cplusplus
}
#endif /* __cpluscplus */

#endif

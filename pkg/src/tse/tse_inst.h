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
 * tse_inst.h
 *
 *
 * IDENTIFICATION
 * src/tse/tse_inst.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __TSE_INST_H__
#define __TSE_INST_H__

#include "tse_list.h"
#include "srv_session.h"
#define CTC_CTX_LIST_CNT (1)  // 每个mysql节点1个list，减少锁冲突

typedef struct mysql_inst_info {
    uint32_t inst_id;    // inst_id 高16位为daac的nodeId,低16位为proc_id/mysql_instid
    bool empty;          // 该节点是否未被占用，true未被占用，false被占用
    tse_list_t ctx_lists[CTC_CTX_LIST_CNT];  // 根据指针 % CTC_CTX_LIST_CNT 放到不同的list中去
} mysql_inst_info_s;

#ifdef __cplusplus
extern "C" {
#endif

int init_mysql_inst(void);
int tse_get_inst_id(uint32_t shm_client_id, uint32_t *inst_id);
int add_mysql_inst_ctx_res(uint32_t inst_id, tse_context_t *ptr);
int remove_mysql_inst_ctx_res(uint32_t inst_id, tse_context_t *ptr);
uint32_t *get_ctc_max_inst_num(void);
thread_lock_t *get_g_tse_mes_lock(void);
#ifdef __cplusplus
}
#endif

#endif  //__TSE_INST_H__

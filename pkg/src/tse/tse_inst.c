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
 * tse_inst.c
 *
 *
 * IDENTIFICATION
 * src/tse/tse_inst.c
 *
 * -------------------------------------------------------------------------
 */
#include "tse_module.h"
#include "tse_inst.h"
#include "tse_srv_util.h"
#include "srv_instance.h"
#include "mes_func.h"
#include "rc_reform.h"
#include "dsw_shm.h"

#define GET_MYSQL_INST_POS(inst_id) (((inst_id) & 0xFFFF) - (MYSQL_PROC_START))
static mysql_inst_info_s *g_mysql_inst_infos;
thread_lock_t g_tse_mes_lock;

uint32_t g_ctc_max_inst_num;

thread_lock_t *get_g_tse_mes_lock(void)
{
    return &g_tse_mes_lock;
}

uint32_t *get_ctc_max_inst_num(void)
{
    return &g_ctc_max_inst_num;
}

void my_free_tse_ctx(uint64_t ctx)
{
    tse_context_t *my_ctx = (tse_context_t *)ctx;
    free_tse_ctx(&my_ctx, true);
}


int init_mysql_inst(void)
{
    cm_init_thread_lock(&g_tse_mes_lock);
    g_mysql_inst_infos = malloc(sizeof(mysql_inst_info_s) * g_ctc_max_inst_num);
    if (g_mysql_inst_infos == NULL) {
        CT_LOG_RUN_ERR("init mysql inst info err, can not alloc mem, inst_num(%lu)", g_ctc_max_inst_num);
        return CT_ERROR;
    }
    for (int i = 0; i < g_ctc_max_inst_num; i++) {
        mysql_inst_info_s *inst = &g_mysql_inst_infos[i];
        inst->inst_id = CT_INFINITE32;
        inst->empty = true;
        for (int j = 0; j < CTC_CTX_LIST_CNT; j++) {
            tse_list_init(&inst->ctx_lists[j], my_free_tse_ctx);
        }
    }
    return CT_SUCCESS;
}

uint32_t get_mysql_inst_ctx_list_slot(void *ptr)
{
#if CTC_CTX_LIST_CNT > 1
    uint32_t ret = cm_hash_int64((uint64_t)ptr >> 4);  // 内存地址一般16位对齐，所有后4位为0,需要过滤掉
    return ret % CTC_CTX_LIST_CNT;
#else
    return 0;
#endif
}

int add_mysql_inst_ctx_res(uint32_t inst_id, tse_context_t *ptr)
{
    // inst_id 高16位为daac的nodeId,低16位为proc_id/mysql_instid
    uint32_t mysql_inst_pos = GET_MYSQL_INST_POS(inst_id);
    if (mysql_inst_pos >= g_ctc_max_inst_num) {
        CT_LOG_RUN_ERR("add_mysql_inst_ctx_res error inst id:%x, mysql_inst_pos:%u", inst_id, mysql_inst_pos);
        return CT_ERROR;
    }

    mysql_inst_info_s *inst = &g_mysql_inst_infos[mysql_inst_pos];
    uint32_t slot = get_mysql_inst_ctx_list_slot(ptr);
    CM_ASSERT(slot < CTC_CTX_LIST_CNT);
    tse_list_t *ctx_list = &inst->ctx_lists[slot];
    tse_list_insert(ctx_list, (uint64_t)ptr);
    return CT_SUCCESS;
}

int remove_mysql_inst_ctx_res(uint32_t inst_id, tse_context_t *ptr)
{
    // inst_id 高16位为daac的nodeId,低16位为proc_id/mysql_instid
    uint32_t mysql_inst_pos = GET_MYSQL_INST_POS(inst_id);
    if (mysql_inst_pos >= g_ctc_max_inst_num) {
        CT_LOG_RUN_ERR("remove_mysql_inst_ctx_res error inst id:%x, mysql_inst_pos:%u", inst_id, mysql_inst_pos);
        return CT_ERROR;
    }

    mysql_inst_info_s *inst = &g_mysql_inst_infos[mysql_inst_pos];
    uint32_t slot = get_mysql_inst_ctx_list_slot(ptr);
    CM_ASSERT(slot < CTC_CTX_LIST_CNT);
    tse_list_t *ctx_list = &inst->ctx_lists[slot];
    tse_list_delete(ctx_list, (uint64_t)ptr);
    return CT_SUCCESS;
}

int srv_wait_instance_startuped(void)
{
    CT_LOG_DEBUG_INF("wait for instance_startuped to complete begin.");
    while (!is_instance_startuped()) {
        cm_sleep(1000); /* 1000 ms */
    }
    CT_LOG_DEBUG_INF("wait for instance_startuped to complete end.");
    return CT_SUCCESS;
}

void clean_up_mysql_inst_ctx_list(mysql_inst_info_s *inst)
{
    for (int i = 0; i < CTC_CTX_LIST_CNT; i++) {
        tse_list_t *list = &inst->ctx_lists[i];
        tse_list_clear(list);
    }
}

int tse_release_inst_id(uint32_t inst_id)
{
    // inst_id 高16位为daac的nodeId,低16位为proc_id/mysql_instid
    uint32_t mysql_inst_pos = GET_MYSQL_INST_POS(inst_id);
    if (mysql_inst_pos >= g_ctc_max_inst_num) {
        CT_LOG_RUN_ERR("tse_release_inst_id error inst id:%x, mysql_inst_pos:%u", inst_id, mysql_inst_pos);
        return CT_ERROR;
    }

    mysql_inst_info_s *inst = &g_mysql_inst_infos[mysql_inst_pos];
    if (inst->empty == true || inst->inst_id != inst_id) {
        CT_LOG_RUN_ERR("tse_release_inst_id error inst id:%x %x, empty:%d", inst->inst_id, inst_id, inst->empty);
        return CT_SUCCESS;  // 这个地方可能存在没有调用alloc然后来调用release的情况，检查到状态错误直接返回，做任何操作
    }
    clean_up_mysql_inst_ctx_list(inst);
    inst->empty = true;
    inst->inst_id = CT_INFINITE32;
    CT_LOG_RUN_INF("tse_release_inst_id release inst id:%x", inst_id);
    return CT_SUCCESS;
}

// g_mes.profile.inst_id为nodeId
int tse_alloc_inst_id(uint32_t *inst_id)
{
    /* 集群初始化以及reform期间完成禁止新的Mysqld接入 */
    if ((g_rc_ctx != NULL && g_rc_ctx->status != REFORM_DONE) || !is_instance_startuped()) {
        CT_LOG_RUN_ERR("[TSE_INIT]:Can't alloc tse_inst_id when Reforming. status:%d", g_rc_ctx->status);
        return CT_ERROR;
    }
    // inst_id 高16位为daac的nodeId,低16位为proc_id/mysql_instid
    uint32_t mysql_inst_pos = GET_MYSQL_INST_POS(*inst_id);
    if (mysql_inst_pos >= g_ctc_max_inst_num) {
        CT_LOG_RUN_ERR("tse_alloc_inst_id error inst id:%u, mysql_inst_pos:%u", *inst_id, mysql_inst_pos);
        return CT_ERROR;
    }
    uint32_t alloc_inst_id;
    alloc_inst_id = *inst_id;
    alloc_inst_id |= (g_mes.profile.inst_id << 16);  // 高16位为daac的nodeId,低16位为proc_id
    CM_ASSERT(alloc_inst_id > 0);
    mysql_inst_info_s *inst = &g_mysql_inst_infos[mysql_inst_pos];
    if (inst->empty == false || inst->inst_id != CT_INFINITE32) {
        CT_LOG_RUN_ERR("tse_alloc_inst_id slot in use inst id:%u, empty:%d, mysql_inst_pos:%u", *inst_id, inst->empty,
                       mysql_inst_pos);
        return CT_ERROR;
    }
    inst->inst_id = alloc_inst_id;
    *inst_id = alloc_inst_id;
    inst->empty = false;
    CT_LOG_RUN_INF("tse_alloc_inst_id:%x", alloc_inst_id);
    return CT_SUCCESS;
}

int tse_get_inst_id(uint32_t shm_client_id, uint32_t *inst_id)
{
    uint32_t mysql_inst_pos = GET_MYSQL_INST_POS(shm_client_id); // shm_client_id in 2 to 20 integer
    if (mysql_inst_pos >= g_ctc_max_inst_num) {
        CT_LOG_RUN_ERR("tse_get_inst_id  invaild mysql_inst_pos:%u", mysql_inst_pos);
        return CT_ERROR;
    }
    mysql_inst_info_s *inst = &g_mysql_inst_infos[mysql_inst_pos];
    if (inst->empty == false && inst->inst_id != CT_INFINITE32) {
        *inst_id = inst->inst_id;
        return CT_SUCCESS;
    }
    return CT_ERROR;
}

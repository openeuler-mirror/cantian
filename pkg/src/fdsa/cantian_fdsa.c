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
 * cantian_fdsa.c
 *
 *
 * IDENTIFICATION
 * src/fdsa/cantian_fdsa.c
 *
 * -------------------------------------------------------------------------
 */

#include <dlfcn.h>
#include "cm_log.h"
#include "cm_atomic.h"
#include "cm_thread.h"
#include "cantian_fdsa_interface.h"
#include "cantian_fdsa.h"
#include "dtc_drc.h"

static uint32_t MY_PID = 0;
bool32 g_enable_fdsa;
uint32 g_cantian_time_out_num = 0;
static atomic32_t g_cantian_io_base_no = 0;
static fdsa_interface_t g_fdsa_interface = { .fdsa_handle = NULL};

static status_t fdsa_load_symbol(void *lib_handle, char *symbol, void **sym_lib_handle)
{
    const char *dlsym_err = NULL;

    *sym_lib_handle = dlsym(lib_handle, symbol);
    dlsym_err = dlerror();
    if (dlsym_err != NULL) {
        CT_THROW_ERROR(ERR_LOAD_SYMBOL, symbol, dlsym_err);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t fdsa_init_lib(void)
{
    fdsa_interface_t *intf = &g_fdsa_interface;
    intf->fdsa_handle = dlopen("libfdsa.so", RTLD_LAZY);
    const char *dlopen_err = NULL;
    dlopen_err = dlerror();

    if (intf->fdsa_handle == NULL) {
        CT_LOG_RUN_ERR("failed to load libfdsa.so, maybe lib path error , errno %s", dlopen_err);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(fdsa_load_symbol(intf->fdsa_handle, "HEAL_InitCommon",      (void **)(&intf->HEAL_InitCommon)));
    CT_RETURN_IFERR(fdsa_load_symbol(intf->fdsa_handle, "HEAL_RegisterTask",    (void **)(&intf->HEAL_RegisterTask)));
    CT_RETURN_IFERR(fdsa_load_symbol(intf->fdsa_handle, "HEAL_EnableTask",      (void **)(&intf->HEAL_EnableTask)));
    CT_RETURN_IFERR(fdsa_load_symbol(intf->fdsa_handle, "HEAL_DisableTask",     (void **)(&intf->HEAL_DisableTask)));
    CT_RETURN_IFERR(fdsa_load_symbol(intf->fdsa_handle, "HEAL_UnregisterTask",  (void **)(&intf->HEAL_UnregisterTask)));

    CT_LOG_RUN_INF("load libfdsa.so done");
    return CT_SUCCESS;
}

void fdsa_close_lib(void)
{
    fdsa_interface_t *intf = &g_fdsa_interface;
    if (intf->fdsa_handle != NULL) {
        (void)dlclose(intf->fdsa_handle);
    }
}

uint32 GetFdsaIoNo()
{
    uint32 ioNo = (uint32)cm_atomic32_inc(&g_cantian_io_base_no);
    return ioNo;
}

status_t AddIo2FdsaHashTable(io_id_t io_id)
{
    if (!g_enable_fdsa) {
        return CT_ERROR;
    }
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_res_pool_t *io_pool = &ctx->local_io_map.res_pool;
    if (io_pool->inited == CT_FALSE) {
        return CT_ERROR;
    }
    uint32 idx = drc_res_pool_alloc_item(io_pool);
    if (idx == CT_INVALID_ID32) {
        return CT_ERROR;
    }
    drc_res_bucket_t *bucket = drc_get_buf_map_bucket(&ctx->local_io_map, io_id.fdsa_type, io_id.io_no);
    cm_spin_lock(&bucket->lock, NULL);
    drc_local_io *local_io = (drc_local_io *)DRC_GET_RES_ADDR_BY_ID(io_pool, idx);
    local_io->io_id.io_no = io_id.io_no;
    local_io->io_id.fdsa_type = io_id.fdsa_type;
    local_io->idx = idx;
    local_io->start_time = g_timer()->now;
    drc_res_map_add(bucket, idx, &local_io->next);
    cm_spin_unlock(&bucket->lock);
    CT_LOG_DEBUG_INF("[CANTIAN_FDSA] add io to bucket successed, io_no(%u) fdsa_type(%u).",
        local_io->io_id.io_no, local_io->io_id.fdsa_type);
    return CT_SUCCESS;
}

status_t RemovetIoFromFdsaHashtable(io_id_t io_id)
{
    if (!g_enable_fdsa) {
        return CT_ERROR;
    }
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_res_bucket_t *bucket = drc_get_buf_map_bucket(&ctx->local_io_map, io_id.fdsa_type, io_id.io_no);
    cm_spin_lock(&bucket->lock, NULL);
    drc_local_io *local_io = (drc_local_io *)drc_res_map_lookup(&ctx->local_io_map, bucket, (char*)&io_id);
    if (local_io == NULL) {
        knl_panic(0);
    }
    drc_res_map_remove(&ctx->local_io_map, bucket, (char*)&io_id);
    drc_res_pool_free_item(&ctx->local_io_map.res_pool, local_io->idx);
    cm_spin_unlock(&bucket->lock);
    CT_LOG_DEBUG_INF("[CANTIAN_FDSA] remove io from bucket successed, io_no(%u) fdsa_type(%u).",
        local_io->io_id.io_no, local_io->io_id.fdsa_type);
    return CT_SUCCESS;
}

bool32 CheckIoTimeOut(drc_res_bucket_t *bucket)
{
    cm_spin_lock(&bucket->lock, NULL);
    uint32 idx = bucket->first;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    for (uint32 i = 0; i < bucket->count; i++) {
        drc_local_io *res = DRC_GET_RES_ADDR_BY_ID(&ctx->local_io_map.res_pool, idx);
        uint64 curTime = g_timer()->now;
        if (curTime - res->start_time > CANTIAN_IO_TIME_OUT_ONCE) {
            CT_LOG_RUN_ERR("[CANTIAN_FDSA] Io cost too long, io_id(%u), fdsa_type(%u), start_time(%llu) now_time(%llu)",
                res->io_id.io_no, res->io_id.fdsa_type, res->start_time, curTime);
            cm_spin_unlock(&bucket->lock);
            cm_fync_logfile(); // flush log
            return CT_FALSE;
        }
        if (curTime - res->start_time > CANTIAN_IO_TIME_OUT) {
            CT_LOG_RUN_ERR("[CANTIAN_FDSA] Io cost too long, io_id(%u), fdsa_type(%u), start_time(%llu) now_time(%llu)",
                res->io_id.io_no, res->io_id.fdsa_type, res->start_time, curTime);
            g_cantian_time_out_num++;
        }
        idx = *(uint32*)res;
    }
    cm_spin_unlock(&bucket->lock);
    if (g_cantian_time_out_num >= CANTIAN_IO_TIME_OUT_LIMIT_MAX_NUM) {
        CT_LOG_RUN_ERR("[CANTIAN_FDSA] Time out io num reach (%u), CANTIAN EXIT", g_cantian_time_out_num);
        cm_fync_logfile(); // flush log
        return CT_FALSE;
    }
    return CT_TRUE;
}

void FdsaCheckCallback(HEAL_CBRETURN_S *healCbreturn, void *arg)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    CT_LOG_DEBUG_INF("[CANTIAN_FDSA] FdsaCheckCallback start");

    for (uint32 i = 0; i < ctx->local_io_map.bucket_num; i++) {
        if (CheckIoTimeOut(&ctx->local_io_map.buckets[i]) == CT_FALSE) {
            CT_LOG_RUN_ERR("[CANTIAN_FDSA] CheckIoTimeFun failed");
            healCbreturn->bResult = CT_FALSE;
            g_cantian_time_out_num = 0;
            return;
        }
    }
    healCbreturn->bResult = CT_TRUE;
    g_cantian_time_out_num = 0;
    CT_LOG_DEBUG_INF("[CANTIAN_FDSA] FdsaCheckCallback successed");
    return;
}

status_t InitCantianFdsa(void)
{
    int32_t ret = CT_SUCCESS;
    fdsa_interface_t *intf = &g_fdsa_interface;
    CT_LOG_RUN_INF("[CANTIAN_FDSA] InitFdsa start");

    // 动态加载libfdsa.so
    if (fdsa_init_lib() != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed to init lib.");
        return CT_ERROR;
    }

    // 注册初始化fdsa自愈任务
    HEAL_REGPARAM_S healRegParam = { 0 };
    healRegParam.pCheckCB = FdsaCheckCallback;
    healRegParam.pCollectCB = NULL;
    healRegParam.pHealCB = NULL;

    strcpy_s(healRegParam.szName, FDSA_BUFFER_SIZE_32, CANTIAN_FDSA_HEAL_TASK);
    healRegParam.uiCheckFailTimes = 1;                             // 连续检测失败1次后进行自愈
    healRegParam.uiCheckPeriod = CANTIAN_FDSA_CHECK_CYCLE_TIME;        // 检查周期
    healRegParam.eRecoverLever = HEAL_RECOVER_PROCESS_IMMEDIATELY; // 自愈策略等级

    ret = intf->HEAL_InitCommon(); // 自愈HEAL模块初始化
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CANTIAN_FDSA] Init Fdsa heal task (%d) fail", ret);
        return CT_ERROR;
    }
#ifndef _WIN32
    ret = intf->HEAL_RegisterTask(&healRegParam, (uint16_t)MY_PID, __FUNCTION__, __LINE__); // 自愈任务注册
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CANTIAN_FDSA] Register Fdsa heal task (%d) fail", ret);
        return CT_ERROR;
    }
    ret = intf->HEAL_EnableTask(CANTIAN_FDSA_HEAL_TASK, (uint16_t)MY_PID, __FUNCTION__, __LINE__);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CANTIAN_FDSA] Enable Fdsa heal task (%d) fail", ret);
        return CT_ERROR;
    }
#endif
    CT_LOG_RUN_INF("[CANTIAN_FDSA] InitCLiCsIoFdsa successed");
    return CT_SUCCESS;
}

status_t DeInitCantianFdsa(void)
{
    int32_t ret = CT_SUCCESS;
    fdsa_interface_t *intf = &g_fdsa_interface;
    CT_LOG_RUN_INF("[CANTIAN_FDSA] DeInitCsIoFdsa start");
#ifndef _WIN32
    ret = intf->HEAL_DisableTask(CANTIAN_FDSA_HEAL_TASK, (uint16_t)MY_PID, __FUNCTION__, __LINE__);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CANTIAN_FDSA] Stop Fdsa heal task %d fail", ret);
        return CT_ERROR;
    }

    ret = intf->HEAL_UnregisterTask(CANTIAN_FDSA_HEAL_TASK, NULL, NULL, (uint16_t)MY_PID, __FUNCTION__, __LINE__); // 自愈任务注销
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CANTIAN_FDSA] Cancel Fdsa heal task %d fail", ret);
        return CT_ERROR;
    }
#endif
    fdsa_close_lib();
    CT_LOG_RUN_INF("[CANTIAN_FDSA] DeInitCsIoFdsa successed");
    return CT_SUCCESS;
}
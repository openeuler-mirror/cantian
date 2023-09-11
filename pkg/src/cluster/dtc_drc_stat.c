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
 * dtc_drc_stat.c
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_drc_stat.c
 *
 * -------------------------------------------------------------------------
 */
#include "dtc_drc.h"
#include "dtc_context.h"

char g_master_info_record_name[][GS_DYNVIEW_NORMAL_LEN] = {
    {"R_PO_TOTAL"},
    {"R_PO_CONVETED"},
    {"R_PO_FIRST"},
    {"R_PO_TRY"},
    {"R_PO_CVTING_TOTAL"},
    {"R_PO_CVTING_CURR"},
    {"R_PO_CVTQ_TOTAL"},
    {"R_PO_CVTQ_CURR"},
    {"R_PO_CONFLICT_TOTAL"},

};


status_t drc_master_info_init(drc_res_ctx_t *ctx)
{
    uint32 stat_row_cnt = sizeof(g_master_info_record_name) / sizeof(g_master_info_record_name[0]);
    uint32 stat_info_size = sizeof(drc_master_info_row) * stat_row_cnt;
    ctx->stat.stat_info = (drc_master_info_row *)malloc(stat_info_size);
    if (ctx->stat.stat_info == NULL) {
        return GS_ERROR;
    }

    ctx->stat.master_info_row_cnt = stat_row_cnt;
    int i;
    drc_master_info_row *row = ctx->stat.stat_info;

    for (i = 0; i < stat_row_cnt; i++) {
        row->name = g_master_info_record_name[i];
        row->cnt = 0;
        row++;
    }
    return GS_SUCCESS;
}
status_t drc_stat_init(void)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    ctx->stat.lock = 0;
    ctx->stat.stat_info = NULL;
    (void)cm_atomic_set(&ctx->stat.clean_page_cnt, 0);
    (void)cm_atomic_set(&ctx->stat.clean_lock_cnt, 0);
    (void)cm_atomic_set(&ctx->stat.rcy_page_cnt, 0);
    (void)cm_atomic_set(&ctx->stat.clean_convert_cnt, 0);
    (void)cm_atomic_set(&ctx->stat.rcy_lock_cnt, 0);
    (void)cm_atomic_set(&ctx->stat.mig_buf_cnt, 0);
    (void)cm_atomic_set(&ctx->stat.mig_lock_cnt, 0);
    (void)cm_atomic_set(&ctx->stat.mig_buf_msg_sent_cnt, 0);
    (void)cm_atomic_set(&ctx->stat.mig_lock_msg_sent_cnt, 0);

    if (GS_SUCCESS != drc_master_info_init(ctx)) {
        drc_stat_res_destroy();
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

void drc_stat_res_destroy(void)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_stat_t *stat = &ctx->stat;

    if (stat->stat_info != NULL) {
        free(stat->stat_info);
        stat->stat_info = NULL;
        stat->master_info_row_cnt = 0;
    }

    stat->lock = 0;
    (void)cm_atomic_set(&stat->clean_page_cnt, 0);
    (void)cm_atomic_set(&stat->clean_lock_cnt, 0);
    (void)cm_atomic_set(&stat->clean_convert_cnt, 0);
    (void)cm_atomic_set(&stat->rcy_page_cnt, 0);
    (void)cm_atomic_set(&stat->rcy_lock_cnt, 0);
    (void)cm_atomic_set(&stat->mig_buf_cnt, 0);
    (void)cm_atomic_set(&stat->mig_lock_cnt, 0);
    (void)cm_atomic_set(&stat->mig_buf_msg_sent_cnt, 0);
    (void)cm_atomic_set(&stat->mig_lock_msg_sent_cnt, 0);
}

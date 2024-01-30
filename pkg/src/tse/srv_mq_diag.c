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
 * srv_mq_diag.c
 *
 *
 * IDENTIFICATION
 * src/tse/srv_mq_diag.c
 *
 * -------------------------------------------------------------------------
 */
#include "tse_module.h"
#include "srv_mq_diag.h"
#include "tse_inst.h"
#include "dsw_shm_pri.h"
#include "securec.h"
#include "srv_session.h"

#define CHAR_MAX_SIZE 28000


int get_seg_used_shm_size(int seg_id, int proc_id, char *info)
{
    int mem_lens = 0;
    shm_diag_seg_used_info_t *diag_info = (shm_diag_seg_used_info_t *)malloc(sizeof(shm_diag_seg_used_info_t));
    if (diag_info == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)sizeof(shm_diag_seg_used_info_t), "diag_info");
        return -1;
    }
    int ret = get_seg_used_space_size(seg_id, proc_id, diag_info, &mem_lens);
    if (ret < 0) {
        free(diag_info);
        return -1;
    }

    int j = 0;
    j = sprintf_s(info, CHAR_MAX_SIZE, "seg_id:%d,seg_used_blk_num:%d,seg_used_space_size:%ld\n", diag_info->seg_id,
        diag_info->seg_used_blk_num, diag_info->seg_used_space_size);
    for (int i = 0; i < mem_lens; i++) {
        j += sprintf_s(info + j, CHAR_MAX_SIZE, "mem_list_id:%c,mem_used_blk_num:%d,mem_used_space_size:%ld\n",
            diag_info->diag_mem_used_info[i].mem_list_id, diag_info->diag_mem_used_info[i].mem_used_blk_num,
            diag_info->diag_mem_used_info[i].mem_used_space_size);
    }
    free(diag_info);
    return 0;
}

int get_mysql_used_shm_size(int proc_id, char *info)
{
    int mem_lens = 0;
    int seg_lens = 0;
    shm_diag_used_info_t *diag_info = (shm_diag_used_info_t *)malloc(sizeof(shm_diag_used_info_t));
    if (diag_info == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)sizeof(shm_diag_used_info_t), "diag_info");
        return -1;
    }
    int ret = get_proc_used_space_size(proc_id, diag_info, &seg_lens, &mem_lens);
    if (ret < 0) {
        free(diag_info);
        return -1;
    }

    int k = 0;
    k = sprintf_s(info, CHAR_MAX_SIZE, "proc_id:%d,proc_used_blk_num:%d,proc_used_space_size:%ld\n",
        diag_info->proc_id, diag_info->proc_used_blk_num, diag_info->proc_used_space_size);
    for (int i = 0; i < seg_lens; i++) {
        k += sprintf_s(info + k, CHAR_MAX_SIZE, "seg_id:%d,seg_used_blk_num:%d,seg_used_space_size:%ld\n",
            diag_info->diag_seg_used_info[i].seg_id, diag_info->diag_seg_used_info[i].seg_used_blk_num,
            diag_info->diag_seg_used_info[i].seg_used_space_size);
        for (int j = 0; j < mem_lens; j++) {
            k += sprintf_s(info + k, CHAR_MAX_SIZE, "mem_list_id:%c,mem_used_blk_num:%d,mem_used_space_size:%ld\n",
                diag_info->diag_seg_used_info[i].diag_mem_used_info[j].mem_list_id,
                diag_info->diag_seg_used_info[i].diag_mem_used_info[j].mem_used_blk_num,
                diag_info->diag_seg_used_info[i].diag_mem_used_info[j].mem_used_space_size);
        }
    }
    free(diag_info);
    return 0;
}

int get_mysql_free_shm_size(int proc_id, char *info)
{
    int mem_lens = 0;
    int seg_lens = 0;
    shm_diag_free_info_t *diag_info = (shm_diag_free_info_t *)malloc(sizeof(shm_diag_free_info_t));
    if (diag_info == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)sizeof(shm_diag_free_info_t), "diag_info");
        return -1;
    }
    int ret = get_proc_free_space_size(proc_id, diag_info, &seg_lens, &mem_lens);
    if (ret < 0) {
        free(diag_info);
        return -1;
    }

    int k = 0;
    k = sprintf_s(info, CHAR_MAX_SIZE, "proc_id:%d,proc_free_blk_num:%d,proc_free_space_size:%ld\n",
        diag_info->proc_id, diag_info->proc_free_blk_num, diag_info->proc_free_space_size);
    for (int i = 0; i < seg_lens; i++) {
        k += sprintf_s(info + k, CHAR_MAX_SIZE, "seg_id:%d,seg_free_blk_num:%d,seg_free_space_size:%ld\n",
            diag_info->diag_seg_free_info[i].seg_id, diag_info->diag_seg_free_info[i].seg_free_blk_num,
            diag_info->diag_seg_free_info[i].seg_free_space_size);
        for (int j = 0; j < mem_lens; j++) {
            k += sprintf_s(info + k, CHAR_MAX_SIZE, "mem_list_id:%c,mem_free_blk_num:%d,mem_free_space_size:%ld\n",
                diag_info->diag_seg_free_info[i].diag_mem_free_info[j].mem_list_id,
                diag_info->diag_seg_free_info[i].diag_mem_free_info[j].mem_free_blk_num,
                diag_info->diag_seg_free_info[i].diag_mem_free_info[j].mem_free_space_size);
        }
    }
    free(diag_info);
    return 0;
}

int get_seg_free_shm_size(int seg_id, char *info)
{
    int mem_lens = 0;
    shm_diag_seg_free_info_t *diag_info = (shm_diag_seg_free_info_t *)malloc(sizeof(shm_diag_seg_free_info_t));
    if (diag_info == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)sizeof(shm_diag_seg_free_info_t), "diag_info");
        return -1;
    }
    int ret = get_seg_free_space_size(seg_id, diag_info, &mem_lens);
    if (ret < 0) {
        free(diag_info);
        return -1;
    }

    int j = 0;
    j = sprintf_s(info, CHAR_MAX_SIZE, "seg_id:%d,seg_free_blk_num:%d,seg_free_space_size:%ld\n", diag_info->seg_id,
        diag_info->seg_free_blk_num, diag_info->seg_free_space_size);
    for (int i = 0; i < mem_lens; i++) {
        j += sprintf_s(info + j, CHAR_MAX_SIZE, "mem_list_id:%c,mem_free_blk_num:%d,mem_free_space_size:%ld\n",
            diag_info->diag_mem_free_info[i].mem_list_id, diag_info->diag_mem_free_info[i].mem_free_blk_num,
            diag_info->diag_mem_free_info[i].mem_free_space_size);
    }
    free(diag_info);
    return 0;
}

int get_seg_remaining_message_to_be_processed(int seg_id, char *info)
{
    int msg_count = get_seg_message_in_proc(seg_id);
    int j = sprintf_s(info, CHAR_MAX_SIZE, "seg_remaining_message_to_be_processed:%d\n", msg_count);
    if (j == -1) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, j);
        return -1;
    }
    return 0;
}
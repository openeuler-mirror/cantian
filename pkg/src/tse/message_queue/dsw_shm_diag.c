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
 * dsw_shm_diag.c
 *
 *
 * IDENTIFICATION
 * src/tse/message_queue/dsw_shm_diag.c
 *
 * -------------------------------------------------------------------------
 */

#include "dsw_shm_pri.h"

int get_seg_used_space_size(int seg_id, int proc_id, shm_diag_seg_used_info_t *diag_seg_used_info, int *mem_lens)
{
    int sz;
    struct shm_seg_sysv_s *seg = g_seg_array[seg_id];
    shm_mem_list_t *mem;
    mem_blk_hdr_t *hdr;
    uint32_t ptr;
    int used_blk_num = 0;
    *mem_lens = seg->all_seg_shm->head.nr_mem_class;
    diag_seg_used_info->seg_id = seg->seg_id;
    diag_seg_used_info->seg_used_blk_num = 0;
    diag_seg_used_info->seg_used_space_size = 0;
    for (int i = 0; i < seg->all_seg_shm->head.nr_mem_class; i++) {
        used_blk_num = 0;
        mem = &(seg->all_seg_shm)->mem_list[i];
        if (mem->total == 0) {
            continue;
        }
        sz = (uint32_t)(mem->size + sizeof(mem_blk_hdr_t));
        ptr = mem->start;
        for (int j = 0; j < mem->total; j++) {
            hdr = (mem_blk_hdr_t *)shm2ptr((char *)(seg->all_seg_shm), ptr);
            if (hdr->proc_id == proc_id) {
                used_blk_num++;
                diag_seg_used_info->seg_used_blk_num++;
            }
            ptr += sz;
        }
        diag_seg_used_info->diag_mem_used_info[i].mem_list_id = mem->list_id;
        diag_seg_used_info->diag_mem_used_info[i].mem_used_blk_num = used_blk_num;
        diag_seg_used_info->diag_mem_used_info[i].mem_used_space_size = mem->size * used_blk_num;
        diag_seg_used_info->seg_used_space_size += diag_seg_used_info->diag_mem_used_info[i].mem_used_space_size;
    }
    return 0;
}
int get_proc_used_space_size(int proc_id, shm_diag_used_info_t *diag_used_info, int *seg_lens, int *mem_lens)
{
    if (g_current_seg_num == 0) {
        return -1;
    }
    *seg_lens = g_current_seg_num;
    if (diag_used_info == NULL) {
        return -1;
    }
    diag_used_info->proc_id = proc_id;
    diag_used_info->proc_used_blk_num = 0;
    diag_used_info->proc_used_space_size = 0;
    for (int i = 0; i < g_current_seg_num; i++) {
        get_seg_used_space_size(i, proc_id, &diag_used_info->diag_seg_used_info[i], mem_lens);
        diag_used_info->proc_used_space_size += diag_used_info->diag_seg_used_info[i].seg_used_space_size;
        diag_used_info->proc_used_blk_num += diag_used_info->diag_seg_used_info[i].seg_used_blk_num;
    }
    return 0;
}

int get_proc_free_space_size(int proc_id, shm_diag_free_info_t *diag_free_info, int *seg_lens, int *mem_lens)
{
    if (g_current_seg_num == 0) {
        return -1;
    }
    *seg_lens = g_current_seg_num;
    if (diag_free_info == NULL) {
        return -1;
    }
    diag_free_info->proc_id = proc_id;
    diag_free_info->proc_free_blk_num = 0;
    diag_free_info->proc_free_space_size = 0;
    for (int i = 0; i < g_current_seg_num; i++) {
        get_seg_free_space_size(i, &diag_free_info->diag_seg_free_info[i], mem_lens);
        diag_free_info->proc_free_space_size += diag_free_info->diag_seg_free_info[i].seg_free_space_size;
        diag_free_info->proc_free_blk_num += diag_free_info->diag_seg_free_info[i].seg_free_blk_num;
    }
    return 0;
}

int get_seg_free_space_size(int seg_id, shm_diag_seg_free_info_t *diag_seg_free_info, int *mem_lens)
{
    struct shm_seg_sysv_s *seg = g_seg_array[seg_id];
    shm_mem_list_t *mem;
    mem_blk_hdr_t *hdr;
    uint32_t ptr;
    *mem_lens = seg->all_seg_shm->head.nr_mem_class;
    if (diag_seg_free_info == NULL) {
        return -1;
    }
    diag_seg_free_info->seg_id = seg->seg_id;
    diag_seg_free_info->seg_free_blk_num = 0;
    diag_seg_free_info->seg_free_space_size = 0;
    for (int i = 0; i < seg->all_seg_shm->head.nr_mem_class; i++) {
        int fl_count = 0;
        mem = &(seg->all_seg_shm)->mem_list[i];
        if (mem->total == 0) {
            continue;
        }
        for (ptr = mem->free_list.head; ptr != SHM_NULL; ptr = hdr->next) {
            hdr = (mem_blk_hdr_t *)shm2ptr((char *)(seg->all_seg_shm), ptr);
            fl_count++;
            diag_seg_free_info->seg_free_blk_num++;
        }
        diag_seg_free_info->diag_mem_free_info[i].mem_list_id = mem->list_id;
        diag_seg_free_info->diag_mem_free_info[i].mem_free_blk_num = fl_count;
        diag_seg_free_info->diag_mem_free_info[i].mem_free_space_size = fl_count * mem->size;
        diag_seg_free_info->seg_free_space_size += diag_seg_free_info->diag_mem_free_info[i].mem_free_space_size;
    }
    return 0;
}

int get_seg_message_in_proc(int seg_id)
{
    uint32_t shm_hdr;
    mem_blk_hdr_t *hdr;
    shm_proc_t *p;
    struct shm_seg_sysv_s *seg = g_seg_array[seg_id];
    int msg_count = 0;

    for (int i = 0; i < MAX_SHM_PROC; i++) {
        p = &(seg->all_seg_shm->procs[i]);
        for (shm_hdr = p->rcvq_high.q_head; shm_hdr != SHM_NULL; shm_hdr = hdr->next) {
            hdr = shm2ptr((char *)(seg->all_seg_shm), shm_hdr);
            msg_count++;
        }
    }

    return msg_count;
}
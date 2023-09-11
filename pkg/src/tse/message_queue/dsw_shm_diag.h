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
 * dsw_shm_diag.h
 *
 *
 * IDENTIFICATION
 * src/tse/message_queue/dsw_shm_diag.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef _dsw_shm_diag_pub_h__
#define _dsw_shm_diag_pub_h__

#include "srv_mq_msg.h"
#include "dsw_shm_comm_pri.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

typedef struct shm_diag_mem_used_info {
    uint8_t mem_list_id;
    int mem_used_blk_num;
    int64_t mem_used_space_size;
} shm_diag_mem_used_info_t;

typedef struct shm_diag_seg_used_info {
    int seg_id;
    int seg_used_blk_num;
    int64_t seg_used_space_size;
    shm_diag_mem_used_info_t diag_mem_used_info[MAX_MEM_CLASS];
} shm_diag_seg_used_info_t;

typedef struct shm_diag_used_info {
    int proc_id;
    int proc_used_blk_num;
    int64_t proc_used_space_size;
    shm_diag_seg_used_info_t diag_seg_used_info[SHM_SEG_MAX_NUM];
} shm_diag_used_info_t;

typedef struct shm_diag_mem_free_info {
    uint8_t mem_list_id;
    int mem_free_blk_num;
    int64_t mem_free_space_size;
} shm_diag_mem_free_info_t;

typedef struct shm_diag_seg_free_info {
    int seg_id;
    int seg_free_blk_num;
    int64_t seg_free_space_size;
    shm_diag_mem_free_info_t diag_mem_free_info[MAX_MEM_CLASS];
} shm_diag_seg_free_info_t;

typedef struct shm_diag_free_info {
    int proc_id;
    int proc_free_blk_num;
    int64_t proc_free_space_size;
    shm_diag_seg_free_info_t diag_seg_free_info[SHM_SEG_MAX_NUM];
} shm_diag_free_info_t;

int get_seg_used_space_size(int seg_id, int proc_id, shm_diag_seg_used_info_t *diag_seg_used_info, int *mem_lens);
int get_proc_used_space_size(int proc_id, shm_diag_used_info_t *diag_used_info, int *seg_lens, int *mem_lens);
int get_proc_free_space_size(int proc_id, shm_diag_free_info_t *diag_free_info, int *seg_lens, int *mem_lens);
int get_seg_free_space_size(int seg_id, shm_diag_seg_free_info_t *diag_seg_free_info, int *mem_lens);
int get_seg_message_in_proc(int seg_id);

struct shm_seg_sysv_s *get_seg(int seg_id);

#ifdef __cplusplus
}
#endif /* __cpluscplus */
#endif // __dsw_shm_diag_pub_h__

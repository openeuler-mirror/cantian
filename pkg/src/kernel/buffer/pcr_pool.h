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
 * pcr_pool.h
 *
 *
 * IDENTIFICATION
 * src/kernel/buffer/pcr_pool.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_PCR_POOL_H__
#define __KNL_PCR_POOL_H__

#include "cm_defs.h"
#include "cm_hash.h"
#include "knl_interface.h"
#include "knl_page.h"
#include "knl_session.h"

#ifdef __cplusplus
extern "C" {
#endif
#define CR_POOL_SIZE_THRESHOLD (uint64) SIZE_M(16)  // each CR pool part size should not less than 16M

/* pcr_pool ctrl structure */
typedef struct st_pcrp_ctrl {
    uint32 bucket_id;  // the cache id of the bucket
    uint32 pool_id;
    volatile bool8 recyclable;
    volatile uint8 unused[3];

    page_id_t page_id;
    uint32 rmid;
    uint32 ssn;
    knl_scn_t scn;
    knl_scn_t snap_scn;

    struct st_pcrp_ctrl *prev;
    struct st_pcrp_ctrl *next;
    struct st_pcrp_ctrl *hash_prev;
    struct st_pcrp_ctrl *hash_next;
    page_head_t *page;
} pcrp_ctrl_t;

typedef struct st_pcrp_bucket {
    spinlock_t lock;
    uint32 count;
    pcrp_ctrl_t *first;
} pcrp_bucket_t;

#ifdef WIN32
typedef struct st_pcrp_set {
#else
typedef struct __attribute__((aligned(128))) st_pcrp_set {
#endif
    spinlock_t lock;
    char *addr;
    uint64 size;

    uint32 capacity;
    uint32 hwm;
    uint32 bucket_num;
    uint32 count;

    pcrp_bucket_t *buckets;
    pcrp_ctrl_t *ctrls;
    pcrp_ctrl_t *lru_first;
    pcrp_ctrl_t *lru_last;
    char *page_buf;
} pcrp_set_t;

typedef struct st_pcrp_context {
    pcrp_set_t pcrp_set[CT_MAX_CR_POOL_COUNT];
    uint32 pcrp_set_count;
} pcrp_context_t;

void pcrp_init(knl_session_t *session);
void pcrp_enter_page(knl_session_t *session, page_id_t page_id, knl_scn_t scn, uint32 ssn);
void pcrp_alloc_page(knl_session_t *session, page_id_t page_id, knl_scn_t scn, uint32 ssn);
void pcrp_leave_page(knl_session_t *session, bool32 release);

#ifdef __cplusplus
}
#endif

#endif

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
 * pcr_pool.c
 *
 *
 * IDENTIFICATION
 * src/kernel/buffer/pcr_pool.c
 *
 * -------------------------------------------------------------------------
 */
#include "pcr_pool.h"
#include "knl_context.h"
#include "knl_interface.h"

#define PCRP_BUCKET_TIMES        3  // the times of buckets against PCR pool ctrl
#define PCRP_PAGE_COST          (DEFAULT_PAGE_SIZE(session) + PCRP_BUCKET_TIMES * sizeof(pcrp_bucket_t) + \
                                    sizeof(pcrp_ctrl_t))
#define PCRP_GET_BUCKET(set, id) (&(set)->buckets[(id)])
#define PCRP_RESERVED_PAGE_COUNT 6

static pcrp_ctrl_t g_init_pcrp_ctrl;

/*
 * pcr pool initialize
 * we calculate capacity of each pool by PCRP_PAGE_COST more than basis to decrease collision
 */
void pcrp_init(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    pcrp_set_t *set = NULL;
    uint64 offset;
    uint32 i;
    errno_t ret;

    for (i = 0; i < kernel->pcrp_ctx.pcrp_set_count; i++) {
        set = &kernel->pcrp_ctx.pcrp_set[i];
        set->lock = 0;
        set->size = kernel->attr.cr_pool_part_size;
        set->addr = kernel->attr.cr_buf + i * kernel->attr.cr_pool_part_align_size;
        set->capacity = (uint32)(set->size / PCRP_PAGE_COST);
        set->hwm = 0;
        set->page_buf = set->addr;

        offset = (uint64)DEFAULT_PAGE_SIZE(session) * set->capacity;
        set->ctrls = (pcrp_ctrl_t *)(set->addr + offset);
        offset += set->capacity * sizeof(pcrp_ctrl_t);
        set->buckets = (pcrp_bucket_t *)(set->addr + offset);
        set->bucket_num = PCRP_BUCKET_TIMES * set->capacity;
        ret = memset_sp(set->buckets, sizeof(pcrp_bucket_t) * set->bucket_num, 0,
                        sizeof(pcrp_bucket_t) * set->bucket_num);
        knl_securec_check(ret);

        set->count = 0;
        set->lru_first = NULL;
        set->lru_last = NULL;
        kernel->stat.cr_pool_capacity += set->capacity;
    }

    ret = memset_sp(&g_init_pcrp_ctrl, sizeof(pcrp_ctrl_t), 0, sizeof(pcrp_ctrl_t));
    knl_securec_check(ret);
}

/*
 * add page ctrl to head of pcr pool lru list
 * @param pcr pool context, page ctrl
 */
static inline void pcrp_lru_add_head(pcrp_set_t *ctx, pcrp_ctrl_t *ctrl)
{
    ctrl->prev = NULL;
    ctrl->next = ctx->lru_first;

    if (ctx->lru_first != NULL) {
        ctx->lru_first->prev = ctrl;
    }

    ctx->lru_first = ctrl;
    if (ctx->lru_last == NULL) {
        ctx->lru_last = ctrl;
    }

    ctx->count++;
}

/*
 * add page ctrl to tail of pcr pool lru list
 * @param pcr pool context, page ctrl
 */
static inline void pcrp_lru_add_tail(pcrp_set_t *ctx, pcrp_ctrl_t *ctrl)
{
    ctrl->prev = ctx->lru_last;
    ctrl->next = NULL;

    if (ctx->lru_last != NULL) {
        ctx->lru_last->next = ctrl;
    }

    ctx->lru_last = ctrl;
    if (ctx->lru_first == NULL) {
        ctx->lru_first = ctrl;
    }

    ctx->count++;
}

/*
 * remove page ctrl from pcr pool lru list
 * @param pcr pool context, page ctrl
 */
static inline void pcrp_lru_remove(pcrp_set_t *ctx, pcrp_ctrl_t *ctrl)
{
    if (ctrl->prev != NULL) {
        ctrl->prev->next = ctrl->next;
    }

    if (ctrl->next != NULL) {
        ctrl->next->prev = ctrl->prev;
    }

    if (ctx->lru_last == ctrl) {
        ctx->lru_last = ctrl->prev;
    }

    if (ctx->lru_first == ctrl) {
        ctx->lru_first = ctrl->next;
    }

    ctrl->prev = NULL;
    ctrl->next = NULL;
    ctx->count--;
}

/*
 * shift page ctrl to head of lru list
 * @param pcr pool context, page ctrl
 */
static inline void pcrp_lru_shift(pcrp_set_t *ctx, pcrp_ctrl_t *ctrl)
{
    pcrp_lru_remove(ctx, ctrl);
    pcrp_lru_add_head(ctx, ctrl);
}

/*
 * find page ctrl from bucket with given sid, page id, scn, ssn
 * @param kernel session, pool context, pool bucket, page id, scn , ssn
 */
static pcrp_ctrl_t *pcrp_find_from_bucket(knl_session_t *session, pcrp_set_t *ctx, pcrp_bucket_t *bucket,
    page_id_t page_id, knl_scn_t scn, uint32 ssn)
{
    pcrp_ctrl_t *ctrl = bucket->first;

    while (ctrl != NULL) {
        if (IS_SAME_PAGID(ctrl->page_id, page_id)) {
            break;
        }

        ctrl = ctrl->hash_next;
    }

    if (ctrl == NULL) {
        return NULL;
    }

    while (ctrl != NULL && IS_SAME_PAGID(ctrl->page_id, page_id)) {
        if (ctrl->rmid == session->rmid && ctrl->scn == scn && ctrl->ssn == ssn) {
            return ctrl;
        }

        ctrl = ctrl->hash_next;
    }

    return NULL;
}

/*
 * add page ctrl to pcr pool bucket
 * @param pool bucket, page ctrl
 */
static void pcrp_add_to_bucket(pcrp_bucket_t *bucket, pcrp_ctrl_t *ctrl)
{
    pcrp_ctrl_t *item = bucket->first;

    while (item != NULL) {
        if (IS_SAME_PAGID(item->page_id, ctrl->page_id)) {
            break;
        }

        item = item->hash_next;
    }

    /* add ctrl of a new page to bucket head */
    if (item == NULL) {
        if (bucket->first != NULL) {
            bucket->first->hash_prev = ctrl;
        }

        ctrl->hash_next = bucket->first;
        ctrl->hash_prev = NULL;

        bucket->first = ctrl;
    } else {  // add ctrl to prev of the latest same page
        if (item->hash_prev != NULL) {
            item->hash_prev->hash_next = ctrl;
        }

        ctrl->hash_prev = item->hash_prev;
        ctrl->hash_next = item;
        item->hash_prev = ctrl;

        if (bucket->first == item) {
            bucket->first = ctrl;
        }
    }

    bucket->count++;
}

/*
 * remove page ctrl from pcr pool bucket
 * @param pool bucket, page ctrl
 */
static inline void pcrp_remove_from_bucket(pcrp_bucket_t *bucket, pcrp_ctrl_t *ctrl)
{
    if (ctrl->hash_prev != NULL) {
        ctrl->hash_prev->hash_next = ctrl->hash_next;
    }

    if (ctrl->hash_next != NULL) {
        ctrl->hash_next->hash_prev = ctrl->hash_prev;
    }

    if (bucket->first == ctrl) {
        bucket->first = ctrl->hash_next;
    }

    ctrl->hash_prev = NULL;
    ctrl->hash_next = NULL;
    ctrl->bucket_id = GS_INVALID_ID32;
    bucket->count--;
}

/*
 * recycle page ctrl from pcr pool
 * @param kernel session, pcr pool context
 */
static pcrp_ctrl_t *pcrp_recycle(knl_session_t *session, pcrp_set_t *ctx)
{
    pcrp_ctrl_t *item = NULL;
    pcrp_ctrl_t *shift = NULL;
    pcrp_bucket_t *bucket = NULL;
    uint32 i;

    cm_spin_lock(&ctx->lock, &session->stat->spin_stat.stat_pcr_pool);
    item = ctx->lru_last;

    /*
     * search lru list from last to end to find a page ctrl from
     * ctx that can be recycled. if ctrl was not marked as recyclable,
     * we shift the ctrl to the head.
     */
    for (i = 0; i < ctx->count; i++) {
        if (item->bucket_id == GS_INVALID_ID32) {
            break;
        }

        if (!item->recyclable) {
            shift = item;
            item = item->prev;
            pcrp_lru_shift(ctx, shift);
            continue;
        }

        bucket = PCRP_GET_BUCKET(ctx, item->bucket_id);
        cm_spin_lock(&bucket->lock, &session->stat->spin_stat.stat_pcr_bucket);

        /* ctrl may be used before lock bucket */
        if (!item->recyclable) {
            cm_spin_unlock(&bucket->lock);
            item = item->prev;
            continue;
        }

        pcrp_remove_from_bucket(bucket, item);
        cm_spin_unlock(&bucket->lock);
        break;
    }

    if (i == ctx->count) {
        cm_spin_unlock(&ctx->lock);
        return NULL;
    }

    pcrp_lru_remove(ctx, item);
    cm_spin_unlock(&ctx->lock);
    return item;
}

/*
 * allocate page ctrl from hwm of pcr pool
 * @param kernel session, pcr pool context
 */
static pcrp_ctrl_t *pcrp_alloc_hwm(knl_session_t *session, pcrp_set_t *ctx)
{
    pcrp_ctrl_t *ctrl = NULL;
    uint32 id;

    if (ctx->hwm >= ctx->capacity) {
        return NULL;
    }

    cm_spin_lock(&ctx->lock, NULL);
    if (ctx->hwm >= ctx->capacity) {
        cm_spin_unlock(&ctx->lock);
        return NULL;
    }

    id = ctx->hwm;
    ctx->hwm++;
    ctrl = &ctx->ctrls[id];
    cm_spin_unlock(&ctx->lock);
    session->stat->cr_pool_used++;

    ctrl->page = (page_head_t *)(ctx->page_buf + (uint64)DEFAULT_PAGE_SIZE(session) * id);
    return ctrl;
}

/*
 * allocate page ctrl from pcr pool
 * @param kernel session, pcr pool context
 */
static pcrp_ctrl_t *pcrp_alloc_ctrl(knl_session_t *session, pcrp_set_t *ctx)
{
    pcrp_ctrl_t *item = NULL;
    page_head_t *page = NULL;

    for (;;) {
        item = pcrp_alloc_hwm(session, ctx);
        if (item != NULL) {
            break;
        }

        item = pcrp_recycle(session, ctx);
        if (item != NULL) {
            break;
        }

        knl_wait_for_tick(session);
    }

    page = item->page;
    *item = g_init_pcrp_ctrl;
    item->page = page;

    return item;
}

static inline uint32 pcrp_bucket_hash(page_id_t page_id, uint32 range)
{
    return (HASH_SEED * page_id.page + page_id.file) * HASH_SEED % range;
}

/*
 * enter pcr pool page
 * @param kernel session, page id, scn, ssn
 */
void pcrp_enter_page(knl_session_t *session, page_id_t page_id, knl_scn_t scn, uint32 ssn)
{
    pcrp_set_t *set = NULL;
    pcrp_bucket_t *bucket = NULL;
    pcrp_ctrl_t *ctrl = NULL;
    uint32 pool_id;
    uint32 hash_id;

    pool_id = cm_hash_uint32(session->rmid, session->kernel->pcrp_ctx.pcrp_set_count);
    set = &session->kernel->pcrp_ctx.pcrp_set[pool_id];

    hash_id = pcrp_bucket_hash(page_id, set->bucket_num);
    bucket = PCRP_GET_BUCKET(set, hash_id);

    cm_spin_lock(&bucket->lock, &session->stat->spin_stat.stat_pcr_bucket);
    ctrl = pcrp_find_from_bucket(session, set, bucket, page_id, scn, ssn);
    if (ctrl) {
        ctrl->recyclable = GS_FALSE;
        cm_spin_unlock(&bucket->lock);

        session->curr_cr_page = (char *)ctrl->page;
        session->curr_pcrp_ctrl = ctrl;

        session->stat->cr_gets++;
    } else {
        cm_spin_unlock(&bucket->lock);
        session->curr_cr_page = NULL;
        session->curr_pcrp_ctrl = NULL;
    }
}

/*
 * try to alloc page ctrl from bucket
 * the condition of page ctrl to be reused is that history version count of the page
 * exceed 6 and there exists page recyclable.
 */
static pcrp_ctrl_t *pcrp_try_alloc_ctrl_from_bucket(pcrp_bucket_t *bucket, page_id_t page_id)
{
    pcrp_ctrl_t *item = bucket->first;
    pcrp_ctrl_t *oldest = NULL;
    uint32 page_count = 0;
    knl_scn_t min_scn = GS_INVALID_ID64;
    bool8 has_same_page = GS_FALSE;

    while (item != NULL) {
        /* find the oldest same page on this bucket */
        if (IS_SAME_PAGID(item->page_id, page_id)) {
            if (item->scn < min_scn && item->recyclable) {
                min_scn = item->scn;
                oldest = item;
            }
            page_count++;
            has_same_page = GS_TRUE;
        }

        if (!IS_SAME_PAGID(item->page_id, page_id) && has_same_page) {
            break;
        }

        item = item->hash_next;
    }

    /* if exceed the max page count, resued the page from bucket */
    return page_count >= PCRP_RESERVED_PAGE_COUNT ? oldest :  NULL;
}


/*
 * allocate page from pcr pool for cr page
 * 1.try reused ctrl from current bucket
 * 2.allocate ctrl from pool
 * 3.initialize ctrl info
 * 4.add ctrl to bucket and lru list
 * @param kernel session, page id, scn, ssn
 */
void pcrp_alloc_page(knl_session_t *session, page_id_t page_id, knl_scn_t scn, uint32 ssn)
{
    pcrp_set_t *set = NULL;
    pcrp_bucket_t *bucket = NULL;
    pcrp_ctrl_t *ctrl = NULL;
    bool8 from_bucket = GS_TRUE;
    uint32 pool_id;
    uint32 hash_id;

    pool_id = cm_hash_uint32(session->rmid, session->kernel->pcrp_ctx.pcrp_set_count);
    set = &session->kernel->pcrp_ctx.pcrp_set[pool_id];
    hash_id = pcrp_bucket_hash(page_id, set->bucket_num);
    bucket = PCRP_GET_BUCKET(set, hash_id);

    /*
     * we try to reuse page ctrl that expired on current bucket firstly.
     * otherwise, allocate ctrl from hwm or lru list
     */
    cm_spin_lock(&bucket->lock, &session->stat->spin_stat.stat_pcr_bucket);
    ctrl = pcrp_try_alloc_ctrl_from_bucket(bucket, page_id);
    if (ctrl == NULL) {
        cm_spin_unlock(&bucket->lock);
        ctrl = pcrp_alloc_ctrl(session, set);
        from_bucket = GS_FALSE;
    }

    ctrl->rmid = session->rmid;
    ctrl->page_id = page_id;
    ctrl->scn = scn;
    ctrl->ssn = ssn;
    ctrl->pool_id = pool_id;
    ctrl->bucket_id = hash_id;
    ctrl->recyclable = GS_FALSE;

    /*
     * need to add ctrl from bucket to bucket and lru list
     * or shift reused ctrl to lru head
     */
    if (from_bucket) {
        cm_spin_unlock(&bucket->lock);
        cm_spin_lock(&set->lock, &session->stat->spin_stat.stat_pcr_pool);
        pcrp_lru_shift(set, ctrl);
        cm_spin_unlock(&set->lock);
    } else {
        cm_spin_lock(&bucket->lock, &session->stat->spin_stat.stat_pcr_bucket);
        pcrp_add_to_bucket(bucket, ctrl);
        cm_spin_unlock(&bucket->lock);

        cm_spin_lock(&set->lock, &session->stat->spin_stat.stat_pcr_pool);
        pcrp_lru_add_head(set, ctrl);
        cm_spin_unlock(&set->lock);
    }

    session->curr_cr_page = (char *)ctrl->page;
    session->curr_pcrp_ctrl = ctrl;
}

/*
 * leave page from pcr pool
 * @param kernel session, flag for release
 */
void pcrp_leave_page(knl_session_t *session, bool32 release)
{
    pcrp_set_t *set = NULL;
    pcrp_bucket_t *bucket = NULL;
    pcrp_ctrl_t *ctrl = NULL;

    ctrl = session->curr_pcrp_ctrl;
    if (ctrl != NULL) {
        set = &session->kernel->pcrp_ctx.pcrp_set[ctrl->pool_id];
        bucket = PCRP_GET_BUCKET(set, ctrl->bucket_id);

        if (release) {
            cm_spin_lock(&bucket->lock, &session->stat->spin_stat.stat_pcr_bucket);
            pcrp_remove_from_bucket(bucket, ctrl);
            cm_spin_unlock(&bucket->lock);

            cm_spin_lock(&set->lock, &session->stat->spin_stat.stat_pcr_pool);
            pcrp_lru_remove(set, ctrl);
            pcrp_lru_add_tail(set, ctrl);
            cm_spin_unlock(&set->lock);
        } else {
            cm_spin_lock(&bucket->lock, &session->stat->spin_stat.stat_pcr_bucket);
            ctrl->recyclable = GS_TRUE;
            cm_spin_unlock(&bucket->lock);
        }

        session->curr_cr_page = NULL;
        session->curr_pcrp_ctrl = NULL;
    }
}

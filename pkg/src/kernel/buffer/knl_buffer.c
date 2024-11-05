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
 * knl_buffer.c
 *
 *
 * IDENTIFICATION
 * src/kernel/buffer/knl_buffer.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_buffer_module.h"
#include "knl_buffer.h"
#include "knl_buflatch.h"
#include "pcr_heap.h"
#include "dtc_buffer.h"
#include "dtc_drc.h"
#include "dtc_dcs.h"
#include "dtc_context.h"
#include "dtc_recovery.h"
#include "dtc_database.h"
#include "knl_gbp.h"

#define BUF_PAGE_COST (DEFAULT_PAGE_SIZE(session) + BUCKET_TIMES * sizeof(buf_bucket_t) + sizeof(buf_ctrl_t))
#define BUF_PAGE_COST_WITH_GBP (BUF_PAGE_COST + sizeof(buf_gbp_ctrl_t))

static buf_ctrl_t g_init_buf_ctrl = { .bucket_id = CT_INVALID_ID32 };
uint32 g_cks_level;

static void buf_init_list(buf_set_t *set)
{
    for (uint32 i = 0; i < LRU_LIST_TYPE_COUNT; i++) {
        set->list[i] = g_init_list_t;
        set->list[i].type = i;
    }
}

status_t buf_init(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    buf_context_t *ctx = &kernel->buf_ctx;
    buf_set_t *set = NULL;
    uint64 offset;

    g_cks_level = kernel->attr.db_block_checksum;

    for (uint32 i = 0; i < ctx->buf_set_count; i++) {
        set = &ctx->buf_set[i];
        set->lock = 0;
        set->size = kernel->attr.data_buf_part_size;
        set->addr = kernel->attr.data_buf + i * kernel->attr.data_buf_part_align_size;
        cm_init_cond(&set->set_cond);
        /* set->size <= 32T, BUF_PAGE_COST >= 8360, set->capacity cannot overflow */
        set->capacity = (uint32)(set->size / (KNL_GBP_ENABLE(kernel) ? BUF_PAGE_COST_WITH_GBP : BUF_PAGE_COST));
        set->hwm = 0;
        set->page_buf = set->addr;
        offset = (uint64)DEFAULT_PAGE_SIZE(session) * set->capacity;
        set->ctrls = (buf_ctrl_t *)(set->addr + offset);
        offset += (uint64)set->capacity * sizeof(buf_ctrl_t);
        if (KNL_GBP_ENABLE(kernel)) {
            set->gbp_ctrls = (buf_gbp_ctrl_t *)(set->addr + offset);
            offset += set->capacity * sizeof(buf_gbp_ctrl_t);
        } else {
            set->gbp_ctrls = NULL;
        }
        set->buckets = (buf_bucket_t *)(set->addr + offset);
        set->bucket_num = BUCKET_TIMES * set->capacity;

        knl_reset_large_memory((char *)set->buckets, (uint64)sizeof(buf_bucket_t) * set->bucket_num);
        buf_init_list(set);
    }

    if (kernel->attr.enable_asynch) {
        return buf_aio_init(session);
    }
    
    cm_init_thread_lock(&ctx->buf_mutex);

    return CT_SUCCESS;
}

static inline uint32 buf_lru_get_list_len(buf_ctrl_t *list_start, buf_ctrl_t *list_end, uint8 in_old)
{
    uint32 len = 0;

    buf_ctrl_t *ctrl = list_start;
    while (ctrl != NULL) {
        len++;
        knl_panic_log(ctrl->in_old == in_old, "curr ctrl's in_old status is abnormal in LRU list, panic info: "
                      "page %u-%u type %u ctrl's in_old status %u current in_old status %u",
                      ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type, ctrl->in_old, in_old);
        if (ctrl == list_end) {
            break;
        }
        ctrl = ctrl->next;
    }
    return len;
}

static inline void buf_lru_add_head(buf_lru_list_t *list, buf_ctrl_t *ctrl)
{
    ctrl->prev = NULL;
    ctrl->next = list->lru_first;

    if (list->lru_first != NULL) {
        list->lru_first->prev = ctrl;
    }

    list->lru_first = ctrl;
    if (list->lru_last == NULL) {
        list->lru_last = ctrl;
    }

    if (list->lru_old != NULL) {
        ctrl->in_old = 0;
    } else {
        ctrl->in_old = 1;
    }
    list->count++;
}

static inline void buf_lru_add_tail(buf_lru_list_t *list, buf_ctrl_t *ctrl)
{
    ctrl->in_old = 1;
    ctrl->prev = list->lru_last;
    ctrl->next = NULL;

    if (list->lru_last != NULL) {
        list->lru_last->next = ctrl;
    }

    list->lru_last = ctrl;
    if (list->lru_first == NULL) {
        list->lru_first = ctrl;
    }

    if (list->lru_old != NULL) {
        list->old_count++;
    }
    list->count++;
}

/* adjust the LRU old list head pointer, so that the length of the old blocks list is at the OLD_RATION point */
static void buf_lru_adjust_old_len(buf_lru_list_t *list)
{
    if (list->lru_old == NULL) {
        return;
    }

    uint32 new_len = (uint32)(BUF_LRU_OLD_RATIO * list->count);
    knl_panic_log(list->count >= BUF_LRU_OLD_MIN_LEN,
                  "the buffer count of LRU list is abnormal, panic info: buffer counts %u", list->count);

#ifdef BUF_CHECK_OLD_BUF_LIST_LEN
    buf_assert_old_list_len(list);
#endif

    if (list->old_count + BUF_LRU_OLD_TOLERANCE < new_len) {
        while (list->old_count < new_len) {
            knl_panic_log(list->lru_old->in_old == 1, "the lru_old is not in_old.");
            ++list->old_count;
            list->lru_old = list->lru_old->prev;
            knl_panic_log(list->lru_old->in_old == 0, "the lru_old is in_old.");
            list->lru_old->in_old = 1;
        }
#ifdef BUF_CHECK_OLD_BUF_LIST_LEN
        buf_assert_old_list_len(list);
#endif
        return;
    }

    if (list->old_count > BUF_LRU_OLD_TOLERANCE + new_len) {
        while (list->old_count > new_len) {
            knl_panic_log(list->lru_old->in_old == 1, "the lru_old is not in_old.");
            list->lru_old->in_old = 0;
            list->lru_old = list->lru_old->next;
            knl_panic_log(list->lru_old->in_old == 1, "the lru_old is not in_old.");
            --list->old_count;
        }
#ifdef BUF_CHECK_OLD_BUF_LIST_LEN
        buf_assert_old_list_len(list);
#endif
        return;
    }

    return;
}

/*
 * add a page to the head of the old list
 */
static inline void buf_lru_add_old(buf_lru_list_t *list, buf_ctrl_t *ctrl)
{
    ctrl->in_old = 1;
    ctrl->prev = NULL;
    ctrl->next = list->lru_old;

    knl_panic_log(list->lru_old != NULL, "the lru_old is NULL, panic info: page %u-%u type %u",
                  ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type);

    if (list->lru_old->prev != NULL) {
        list->lru_old->prev->next = ctrl;
    }
    ctrl->prev = list->lru_old->prev;
    list->lru_old->prev = ctrl;

    if (list->lru_first == list->lru_old) {
        list->lru_first = ctrl;
    }

    list->lru_old = ctrl;

    list->old_count++;
    list->count++;
}

void buf_lru_add_ctrl(buf_lru_list_t *list, buf_ctrl_t *ctrl, buf_add_pos_t pos)
{
    knl_panic_log(list->type != LRU_LIST_WRITE, "write list should not be operated with buf_lru_add_ctrl");
    ctrl->list_id = list->type;

    if (pos == BUF_ADD_HOT || ctrl->is_pinned) {
        buf_lru_add_head(list, ctrl);
    } else if (pos == BUF_ADD_COLD || list->lru_old == NULL) {
        buf_lru_add_tail(list, ctrl);
    } else {
        buf_lru_add_old(list, ctrl);
    }

    if (list->count == BUF_LRU_OLD_MIN_LEN) {
        knl_panic_log(list->lru_old == NULL, "the lru_old is not NULL, panic info: page %u-%u type %u, "
                      "lru_old_page %u-%u type %u", ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type,
                      list->lru_old->page_id.file, list->lru_old->page_id.page, list->lru_old->page->type);
        knl_panic_log(list->lru_first->in_old == 1, "the lru_first is not in_old, panic info: page %u-%u type %u",
                      ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type);
        knl_panic_log(list->old_count == 0, "old buffer count in LRU list is abnormal, panic info: page %u-%u type %u "
                      "old_count %u", ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type, list->old_count);
        list->lru_old = list->lru_first;
        list->old_count = list->count;
    }

#ifdef BUF_CHECK_OLD_BUF_LIST_LEN
    if (list->lru_old != NULL) {
        buf_assert_old_list_len(list);
    }
#endif
}

static inline void buf_remove_ctrl(buf_lru_list_t *list, buf_ctrl_t *ctrl)
{
    if (ctrl->prev != NULL) {
        ctrl->prev->next = ctrl->next;
    }

    if (ctrl->next != NULL) {
        ctrl->next->prev = ctrl->prev;
    }

    if (list->lru_last == ctrl) {
        list->lru_last = ctrl->prev;
    }
    if (list->lru_first == ctrl) {
        list->lru_first = ctrl->next;
    }

    knl_panic_log(list->count > 0, "the buffer count of lru_list is abnormal, panic info: page %u-%u type %u count %u",
                  ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type, list->count);
    list->count--;
}

static void buf_lru_remove_ctrl(buf_lru_list_t *list, buf_ctrl_t *ctrl)
{
    knl_panic_log(list->count > 0, "the buffer count of lru_list is abnormal, panic info: page %u-%u type %u count %u",
                  ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type, list->count);
    buf_remove_ctrl(list, ctrl);
    if (list->lru_old == ctrl) {
        knl_panic_log(list->lru_old->in_old == 1, "the lru_old page is not in_old, panic info: page %u-%u type %u",
                      ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type);
        if (ctrl->prev != NULL) {
            list->lru_old = ctrl->prev;
            knl_panic_log(list->lru_old->in_old == 0, "the lru_old page is in_old, panic info: page %u-%u type %u",
                          ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type);
            list->lru_old->in_old = 1;
        } else {
            list->lru_old = ctrl->next;
            list->old_count--;
            knl_panic_log(list->lru_old->in_old == 1, "the lru_old page is not in_old, panic info: page %u-%u type %u",
                          ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type);
        }

        knl_panic_log(list->lru_old != NULL, "the lru_old is NULL, panic info: page %u-%u type %u",
                      ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type);
    } else {
        if (list->lru_old != NULL && ctrl->in_old) {
            list->old_count--;
        }
    }

    ctrl->prev = NULL;
    ctrl->next = NULL;

    if (list->count == BUF_LRU_OLD_MIN_LEN - 1) {
        knl_panic_log(list->lru_old != NULL, "the lru_old is NULL, panic info: page %u-%u type %u",
                      ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type);
        knl_panic_log(list->lru_old->in_old == 1, "the lru_old page is not in_old, panic info: page %u-%u type %u",
                      ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type);
        buf_ctrl_t *tmp = list->lru_first;
        while (tmp != NULL && tmp != list->lru_old) {
            knl_panic_log(tmp->in_old == 0, "curr ctrl is in old, panic info: page %u-%u type %u",
                          ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type);
            tmp->in_old = 1;
            tmp = tmp->next;
        }
        list->lru_old = NULL;
        list->old_count = 0;
    }

    knl_panic_log((list->count < BUF_LRU_OLD_MIN_LEN && list->lru_old == NULL) ||
                  (list->count >= BUF_LRU_OLD_MIN_LEN && list->lru_old != NULL),
                  "panic info: page %u-%u type %u", ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type);

#ifdef BUF_CHECK_OLD_BUF_LIST_LEN
    if (list->lru_old != NULL) {
        buf_assert_old_list_len(list);
    }
#endif
}

/* add source list to tail of target list */
static void buf_lru_append_list(buf_lru_list_t *target, buf_lru_list_t *source)
{
    if (source->count == 0) {
        return;
    }

    cm_spin_lock(&target->lock, NULL);
    source->lru_first->prev = target->lru_last;

    if (target->lru_last != NULL) {
        target->lru_last->next = source->lru_first;
    }

    if (target->lru_first == NULL) {
        target->lru_first = source->lru_first;
    }

    target->lru_last = source->lru_last;
    target->count += source->count;
    cm_spin_unlock(&target->lock);
}

/* move ctrl to hot point of lru list */
static inline void buf_lru_shift_ctrl(buf_lru_list_t *list, buf_ctrl_t *ctrl)
{
    buf_lru_remove_ctrl(list, ctrl);
    buf_lru_add_ctrl(list, ctrl, BUF_ADD_HOT);
}

/*
 * page flushed to disk, but it has not flushed to gbp.
 * it can be reclaimed after it has been flushed to disk.
 * in such case, becuause ctrl is reused and a new page enters,
 * the page will not be flushed to gbp,
 * so, we must notice gbp, it maybe has gap.
 */
static void buf_check_gbp_queue_gap(knl_session_t *session, buf_ctrl_t *item)
{
    if (item->gbp_ctrl->is_gbpdirty) {
        gbp_queue_set_gap(session, item);
        if (item->bucket_id != CT_INVALID_ID32) {
            buf_latch_x(session, item, CT_TRUE);
            /* concurrency with `gbp_knl_write_to_gbp' */
            item->load_status = BUF_NEED_LOAD;
            buf_unlatch(session, item, CT_FALSE);
        }
    }
}

static void buf_init_ctrl(knl_session_t *session, buf_set_t *set, buf_ctrl_t *item, bool32 from_hwm, uint32 options)
{
    page_head_t *page = item->page;

    if (SECUREC_UNLIKELY(KNL_GBP_ENABLE(session->kernel))) {
        buf_ctrl_t init_ctrl_with_gbp = g_init_buf_ctrl;

        init_ctrl_with_gbp.gbp_ctrl = item->gbp_ctrl;
        if (!from_hwm) {
            buf_check_gbp_queue_gap(session, item);
        }
        cm_spin_lock(&item->gbp_ctrl->init_lock, NULL);
        *item = init_ctrl_with_gbp;
        item->page = page;
        /* do not memset is_gbpdirty, gbp_next and gbp_trunc_point */
        item->gbp_ctrl->is_from_gbp = CT_FALSE;
        item->gbp_ctrl->gbp_read_version = 0;
        item->gbp_ctrl->page_status = GBP_PAGE_NONE;
        cm_spin_unlock(&item->gbp_ctrl->init_lock);
    } else {
        *item = g_init_buf_ctrl;
        item->page = page;
    }

    /*
     * strategy to add page to different list with different options:
     * 1. use scan list only if  buffer size is little.
     * 2. otherwise, add page to main list if resident.
     * 3. otherwise, add page to scan list if allocate from hwm or enter page with SEQUENTIAL.
     * 4. otherwise, add page to main list.
     */
    if (set->capacity < BUF_OPTIMIZE_MIN_PAGES) {
        item->list_id = LRU_LIST_SCAN;
        return;
    }

    if (options & ENTER_PAGE_RESIDENT) {
        item->list_id = LRU_LIST_MAIN;
        return;
    }

    if (from_hwm || (options & ENTER_PAGE_SEQUENTIAL)) {
        item->list_id = LRU_LIST_SCAN;
    } else {
        item->list_id = LRU_LIST_MAIN;
    }
}

static inline uint32 buf_bucket_hash(page_id_t page_id, uint32 range)
{
    /* after mod range, the result is less than 0xffffffff */
    return (HASH_SEED * page_id.page + page_id.file) * HASH_SEED % range;
}

static inline uint32 buf_get_pool_id_by_hash(uint32 hash_val, uint32 pool_num)
{
    return hash_val % pool_num;
}

static inline uint32 buf_get_bucket_id_by_hash(uint32 hash_val, uint32 bucket_num)
{
    return hash_val % bucket_num;
}

static inline int32 buf_find_visited(buf_bucket_t **bucket_visited, uint32 bucket_visisted_num,
    buf_bucket_t *cur_bucket)
{
    int i;
    for (i = 0; i < bucket_visisted_num; i++) {
        if (cur_bucket == bucket_visited[i]) {
            return i;
        }
    }
    return -1;
}

static inline bool32 buf_can_expire(buf_ctrl_t *ctrl, buf_expire_type_t expire_type)
{
    if (expire_type == BUF_EVICT) {
        return BUF_CAN_EVICT(ctrl);
    } else if (SECUREC_UNLIKELY(expire_type == BUF_EXPIRE_PAGE)) {
        return BUF_CAN_EXPIRE_PAGE(ctrl);
    } else if (SECUREC_UNLIKELY(expire_type == BUF_EXPIRE_CACHE)) {
        return BUF_CAN_EXPIRE_CACHE(ctrl);
    }
    return CT_FALSE;
}

static inline void buf_expire_compress_remove(buf_bucket_t **bucket_visited, uint32 bucket_visisted_num,
    int32 *map_ctrl_to_bucket, buf_ctrl_t *head, buf_expire_type_t expire_type)
{
    for (int i = 0; i < PAGE_GROUP_COUNT; i++) {
        buf_remove_from_bucket(bucket_visited[map_ctrl_to_bucket[i]], head->compress_group[i]);
        head->compress_group[i]->bucket_id = CT_INVALID_ID32;
        if (SECUREC_UNLIKELY(expire_type == BUF_EXPIRE_PAGE)) {
            head->compress_group[i]->is_resident = 0;
        }
    }

    for (int i = 0; i < bucket_visisted_num; i++) {
        cm_spin_unlock(&bucket_visited[i]->lock);
    }
}

static inline void buf_expire_compress_link_member(knl_session_t *session, buf_set_t *set, buf_lru_list_t *list,
    buf_ctrl_t *head)
{
    buf_lru_list_t *scan_list = &set->scan_list;
    buf_lru_list_t *actual_add_list = list;
    bool32 is_write_list = (list->type == LRU_LIST_WRITE);

    if (SECUREC_UNLIKELY(is_write_list)) {
        // write list can not be linked with usual way. we change to scan list.
        cm_spin_lock(&scan_list->lock, &session->stat->spin_stat.stat_buffer);
        actual_add_list = scan_list;
    }
    
    for (int i = 1; i < PAGE_GROUP_COUNT; i++) {
        buf_ctrl_t *cur_ctrl = head->compress_group[i];
        head->compress_group[i] = NULL; // decouple member from head
        cur_ctrl->compress_group[0] = NULL; // decouple head from member
        buf_lru_add_ctrl(actual_add_list, cur_ctrl, BUF_ADD_COLD);
    }
    head->compress_group[0] = NULL; // clean head to head.

    if (SECUREC_UNLIKELY(is_write_list)) {
        cm_spin_unlock(&scan_list->lock);
    }
}

static void buf_compress_cold_down(knl_session_t *session, buf_ctrl_t *head)
{
    uint32 i;
    buf_ctrl_t *cur_ctrl = NULL;

    for (i = 0; i < PAGE_GROUP_COUNT; i++) {
        cur_ctrl = head->compress_group[i];

        /* after all the members linked later, it can be seen here, so it can not be null */
        knl_panic_log(cur_ctrl != NULL, "A null ctrl appears in compress group, head file:%u, pageid:%u, index:%u",
            head->page_id.file, head->page_id.page, i);

        cur_ctrl->touch_number /= BUF_AGE_DECREASE_FACTOR;
    }
}

static uint32 buf_expire_compress(knl_session_t *session, buf_set_t *set, buf_lru_list_t *list, buf_ctrl_t *head,
                                  buf_expire_type_t expire_type)
{
    uint32 i;
    buf_ctrl_t *cur_ctrl = NULL;
    buf_bucket_t *cur_bucket = NULL;
    buf_bucket_t *bucket_visited[PAGE_GROUP_COUNT];
    int32 map_ctrl_to_bucket[PAGE_GROUP_COUNT];
    uint32 bucket_visisted_num = 0;

    knl_panic(PAGE_IS_COMPRESS_HEAD(head->page_id));

    /*
     * try locking the bucket of the group ctrls and poll the ctrl status,
     * if any trial or poll fails, cancel the locks and return false.
     * only when all the ctrls are locked, we then can evict them.
     */
    for (i = 0; i < PAGE_GROUP_COUNT; i++) {
        cur_ctrl = head->compress_group[i];
        knl_panic_log(cur_ctrl != NULL, "member is not in buffer:%d, page:%d-%d, expire:%d, list:%d",
            i, cur_ctrl->page_id.file, cur_ctrl->page_id.page, expire_type, list->type);

        buf_set_t* cur_set = &session->kernel->buf_ctx.buf_set[cur_ctrl->buf_pool_id];
        cur_bucket = BUF_GET_BUCKET(cur_set, cur_ctrl->bucket_id);

        int visited_id = buf_find_visited(bucket_visited, bucket_visisted_num, cur_bucket);
        if (visited_id != -1) {
            if (buf_can_expire(cur_ctrl, expire_type)) {
                map_ctrl_to_bucket[i] = visited_id;
                continue;
            }
        } else if (cm_spin_timed_lock(&cur_bucket->lock, 100)) {
            if (buf_can_expire(cur_ctrl, expire_type)) {
                map_ctrl_to_bucket[i] = bucket_visisted_num;
                bucket_visited[bucket_visisted_num++] = cur_bucket;
                continue;
            }
            cm_spin_unlock(&cur_bucket->lock);
        }

        break; // to fail the expiration
    }

    /* cancel the bucket locks if not all ctrls are reached */
    if (i < PAGE_GROUP_COUNT) {
        for (i = 0; i < bucket_visisted_num; i++) {
            cm_spin_unlock(&bucket_visited[i]->lock);
        }
        buf_compress_cold_down(session, head);
        return 0; // fail
    }

    /* Now, it is safe to expire the group ctrls
     * Step 1. remove the ctrls from their buckets, exipre the ctrls, and release the locks of the buckets.
     * Step 2. link the member ctrls to list (we now simply choose the current list), and set NULL to all member
               pointers.
    */
    buf_expire_compress_remove(bucket_visited, bucket_visisted_num, map_ctrl_to_bucket, head, expire_type);
    buf_expire_compress_link_member(session, set, list, head);
    return PAGE_GROUP_COUNT; // successful number
}

static uint32 buf_expire_normal(knl_session_t *session, buf_set_t *set, buf_ctrl_t *ctrl, buf_expire_type_t expire_type)
{
    if (!buf_can_expire(ctrl, expire_type)) {
        ctrl->touch_number /= BUF_AGE_DECREASE_FACTOR;
        return 0; // fail
    }

    buf_bucket_t *bucket = BUF_GET_BUCKET(set, ctrl->bucket_id);

    cm_spin_lock(&bucket->lock, &session->stat->spin_stat.stat_bucket);
    if (!buf_can_expire(ctrl, expire_type)) {
        cm_spin_unlock(&bucket->lock);
        return 0; // fail
    }
    buf_remove_from_bucket(bucket, ctrl);
    cm_spin_unlock(&bucket->lock);

    ctrl->bucket_id = CT_INVALID_ID32;
    if (SECUREC_UNLIKELY(expire_type == BUF_EXPIRE_PAGE)) {
        ctrl->is_resident = 0;
    }

    return 1; // successful number
}

uint32 buf_expire_cache(knl_session_t *session, buf_set_t *set)
{
    buf_ctrl_t *item = NULL;
    buf_ctrl_t *shift = NULL;
    uint32 total = 0;
    buf_lru_list_t *list = NULL;

    for (uint32 i = 0; i < LRU_LIST_WRITE; i++) {
        list = &set->list[i];
        cm_spin_lock(&list->lock, &session->stat->spin_stat.stat_buffer);
        item = list->lru_last;
        /* List count will increase since compression members will be added to list tail.
         * On the other way, un-expired will be moved to list head.
         * We snap the list count, and traverse the snaped no matter how the list changes.
         */
        uint32 snap_count = list->count;
        for (uint32 j = 0; j < snap_count; j++) {
            shift = item;
            item = item->prev;

            if (shift->bucket_id == CT_INVALID_ID32) {
                continue;
            }

            uint32 expired_num;
            if (BUF_IS_COMPRESS(shift)) {
                expired_num = buf_expire_compress(session, set, list, shift, BUF_EXPIRE_CACHE);
            } else {
                expired_num = buf_expire_normal(session, set, shift, BUF_EXPIRE_CACHE);
            }
            total += expired_num;

            if (expired_num == 0 && !BUF_CAN_EXPIRE_CACHE(shift)) {
                buf_lru_shift_ctrl(list, shift);
            }
        }
        cm_spin_unlock(&list->lock);
    }
    return total;
}

void buf_expire_page(knl_session_t *session, page_id_t page_id)
{
    buf_ctrl_t *ctrl = NULL;
    buf_bucket_t *bucket = NULL;
    uint8 list_id;
    buf_lru_list_t *list = NULL;

    if (IS_INVALID_PAGID(page_id)) {
        return;
    }

    uint32 hash_val = buf_page_hash_value(page_id);
    uint32 buf_pool_id = buf_get_pool_id_by_hash(hash_val, session->kernel->buf_ctx.buf_set_count);
    buf_set_t *set = &session->kernel->buf_ctx.buf_set[buf_pool_id];
    uint32 hash_id = buf_get_bucket_id_by_hash(hash_val, set->bucket_num);
    bucket = BUF_GET_BUCKET(set, hash_id);

    cm_spin_lock(&bucket->lock, &session->stat->spin_stat.stat_bucket);
    ctrl = buf_find_from_bucket(bucket, page_id);
    if (ctrl == NULL) {
        cm_spin_unlock(&bucket->lock);
        return;
    }

    /* Skip non-head compressed page */
    if (BUF_IS_COMPRESS(ctrl) && !PAGE_IS_COMPRESS_HEAD(page_id)) {
        cm_spin_unlock(&bucket->lock);
        return;
    }

    /* We shoul lock the list to avoid potential bug. If we do not do this, another session may
     * see a ctrl with a valid bucket, but then it's bucket becomes invalid when accessing.
     * To lock the list, the bucket must be released first. We can re-lock it after locking the list
     */
    list_id = ctrl->list_id; // snap the list id before unlocking bucket.
    list = &set->list[list_id];
    cm_spin_unlock(&bucket->lock);

    cm_spin_lock(&list->lock, &session->stat->spin_stat.stat_buffer);
    /* The ctrl may have chaned after we lock the list,
     * if so,  we skip this expireation.
     */
    if (ctrl->bucket_id == CT_INVALID_ID32 || ctrl->list_id != list_id ||
        !IS_SAME_PAGID(ctrl->page_id, page_id)) {
        cm_spin_unlock(&list->lock);
        return;
    }

    if (BUF_IS_COMPRESS(ctrl)) {
        buf_expire_compress(session, set, list, ctrl, BUF_EXPIRE_PAGE);
    } else {
        buf_expire_normal(session, set, ctrl, BUF_EXPIRE_PAGE);
    }

    cm_spin_unlock(&list->lock);
}

static bool32 buf_is_cold_dirty_general(knl_session_t *session, buf_ctrl_t *head)
{
    uint32 i;
    buf_ctrl_t *cur_ctrl = NULL;

    if (head->is_dirty && !BUF_IS_HOT(head)) {
        return CT_TRUE;
    }

    if (!BUF_IS_COMPRESS(head)) {
        return CT_FALSE;
    }

    for (i = 1; i < PAGE_GROUP_COUNT; i++) {
        cur_ctrl = head->compress_group[i];

        /* after all the members linked later, it can be seen here, so it can not be null */
        knl_panic_log(cur_ctrl != NULL, "A null ctrl appears in compress group, head file:%u, pageid:%u, index:%u",
            head->page_id.file, head->page_id.page, i);

        if (cur_ctrl->is_dirty && !BUF_IS_HOT(cur_ctrl)) {
            return CT_TRUE;
        }
    }
    
    return CT_FALSE;
}

static bool32 buf_can_evict_general(knl_session_t *session, buf_ctrl_t *head)
{
    uint32 i;
    buf_ctrl_t *cur_ctrl = NULL;

    if (!buf_can_expire(head, BUF_EVICT)) {
        return CT_FALSE;
    }

    if (!BUF_IS_COMPRESS(head)) {
        return CT_TRUE;
    }

    for (i = 1; i < PAGE_GROUP_COUNT; i++) {
        cur_ctrl = head->compress_group[i];

        /* after all the members linked later, it can be seen here, so it can not be null */
        knl_panic_log(cur_ctrl != NULL, "A null ctrl appears in compress group, head file:%u, pageid:%u, index:%u",
            head->page_id.file, head->page_id.page, i);

        if (!buf_can_expire(cur_ctrl, BUF_EVICT)) {
            return CT_FALSE;
        }
    }

    return CT_TRUE;
}

/*
 * search a single LRU to reclaim a ctrl for use. strategy:
 * 1.if exceed searching threshold, waiting for cleaning up dirty page.
 * 2.move cold dirty page to write list.
 * 3.move hot page to the main list.
 * 4.move page unreclaimable to hot point of current list.
 */
static buf_ctrl_t *buf_recycle(knl_session_t *session, buf_set_t *set, buf_lru_list_t *list)
{
    buf_ctrl_t *shift = NULL;
    uint32 threshold = BUF_LRU_SEARCH_THRESHOLD(set, session);
    uint32 step = 0;
    buf_lru_list_t dirty_list = g_init_list_t;
    uint32 expired_num;

    cm_spin_lock(&list->lock, &session->stat->spin_stat.stat_buffer);
    buf_ctrl_t *item = list->lru_last;

    while (item != NULL) {
        step++;
        /* if exceed threshold, stop and wait for cleaning */
        if (step + set->write_list.count > threshold) {
            item = NULL;
            break;
        }

        if (item->bucket_id == CT_INVALID_ID32) {
            /* The page has been invalided, so directly reuse it */
            break;
        }

        if (BUF_IS_COMPRESS(item)) {
            expired_num = buf_expire_compress(session, set, list, item, BUF_EVICT);
        } else {
            expired_num = buf_expire_normal(session, set, item, BUF_EVICT);
        }
        if (expired_num != 0) {
            break; // We evict a page to reuse.
        }

        /* Doing necessary shifing work for the un-evicted page */
        shift = item;
        item = item->prev;
        if (buf_is_cold_dirty_general(session, shift)) {
            /* move cold dirty page to write list. */
            buf_lru_remove_ctrl(list, shift);
            shift->list_id = LRU_LIST_WRITE;
            buf_lru_add_tail(&dirty_list, shift);
        } else if (!buf_can_evict_general(session, shift)) {
            /* move the currently un-evicted page to the main head,
             * to avoid meet it again for the next try.
             */
            buf_lru_shift_ctrl(list, shift);
        }
    }

    /*
     * Now we either find a page to reuse, or reach the threshold or end of the list.
     * If we reach the threshold or end of the list, the item would point to NULL.
     */
    if (item != NULL) {
        buf_lru_remove_ctrl(list, item);
        item->list_id = list->type;
        session->stat->buffer_recycle_step += step;
    }
    buf_lru_adjust_old_len(list);
    cm_spin_unlock(&list->lock);
    buf_lru_append_list(&set->write_list, &dirty_list);

    if (DB_IS_CLUSTER(session) && (item != NULL) && DCS_BUF_CTRL_IS_OWNER(session, item)) {
        drc_buf_res_try_recycle(session, item->page_id);
    }

    return item;
}

/*
 * allocate buffer ctrl from hwm of buffer set, and added to aux list
 */
static buf_ctrl_t *buf_alloc_hwm(knl_session_t *session, buf_set_t *set)
{
    if (set->hwm >= set->capacity) {
        return NULL;
    }

    cm_spin_lock(&set->lock, &session->stat->spin_stat.stat_buffer);
    if (SECUREC_UNLIKELY(set->hwm >= set->capacity)) {
        cm_spin_unlock(&set->lock);
        return NULL;
    }

    uint32 id = set->hwm;
    set->hwm++;
    buf_ctrl_t *ctrl = &set->ctrls[id];
    cm_spin_unlock(&set->lock);

    *ctrl = g_init_buf_ctrl;
    if (SECUREC_UNLIKELY(KNL_GBP_ENABLE(session->kernel))) {
        ctrl->gbp_ctrl = &set->gbp_ctrls[id];
    } else {
        ctrl->gbp_ctrl = NULL;
    }

    ctrl->page = (page_head_t *)(set->page_buf + (uint64)DEFAULT_PAGE_SIZE(session) * id);
    return ctrl;
}

/*
 * method to alloc ctrl:
 * 1.allocate ctrl from hwm first
 * 2.recycle ctrl from AUX list,if access by sequatial,jump to 4.
 * 3.recycle ctrl from MAIN list.
 * 4.trigger page clean to release dirty page.
 */
static void buf_get_ctrl(knl_session_t *session, buf_set_t *set, uint32 options, buf_ctrl_t **ctrl)
{
    buf_ctrl_t *item = NULL;
    uint32 timeout_ms = session->kernel->attr.page_clean_wait_timeout;

    item = buf_alloc_hwm(session, set);
    if (item != NULL) {
        buf_init_ctrl(session, set, item, CT_TRUE, options);
        *ctrl = item;
        return;
    }

    for (;;) {
        item = buf_recycle(session, set, &set->scan_list);
        if (item == NULL && !(options & ENTER_PAGE_SEQUENTIAL)) {
            item = buf_recycle(session, set, &set->main_list);
        }
        if (item != NULL) {
            session->stat->buffer_recycle_cnt++;
            break;
        }

        ckpt_trigger(session, CT_FALSE, CKPT_TRIGGER_CLEAN);

        if (timeout_ms == 0) {
            knl_wait_for_tick(session);
        } else {
            (void)cm_wait_cond(&set->set_cond, timeout_ms);
        }
        session->stat->buffer_recycle_wait++;
    }

    buf_init_ctrl(session, set, item, CT_FALSE, options);
    *ctrl = item;
}

static void buf_latch_get_latch(knl_session_t *session, buf_bucket_t *bucket, buf_ctrl_t *ctrl, latch_mode_t mode)
{
    uint32 times = 0;
    bool32 lock_needed = CT_FALSE;

    if (mode != LATCH_MODE_X) {
        buf_latch_s(session, ctrl, (mode == LATCH_MODE_FORCE_S), lock_needed);
        return;
    }

    wait_event_t event = ctrl->transfer_status == BUF_TRANS_TRY_REMOTE ? GC_BUFFER_BUSY : BUFFER_BUSY_WAIT;

    for (;;) {
        while (ctrl->is_readonly && ctrl->latch.xsid != session->id) {
            knl_begin_session_wait(session, event, CT_TRUE);
            if (!lock_needed) {
                cm_spin_unlock(&bucket->lock);
                lock_needed = CT_TRUE;
            }

            times++;
            if (SECUREC_UNLIKELY(times > CT_SPIN_COUNT)) {
                times = 0;
                SPIN_STAT_INC(&session->stat_page, r_sleeps);
                cm_spin_sleep();
            }
        }

        buf_latch_x(session, ctrl, lock_needed);
        if (ctrl->is_readonly && ctrl->latch.xsid != session->id) {
            buf_unlatch(session, ctrl, CT_FALSE);
            lock_needed = CT_TRUE; // always need lock after latched on time since bucket is released.
            continue;
        }

        ctrl->latch.xsid = session->id;
        knl_end_session_wait(session, event);
        return;
    }
}

static void buf_latch_ctrl(knl_session_t *session, buf_bucket_t *bucket, buf_ctrl_t *ctrl, latch_mode_t mode)
{
    uint32 times = 0;

    buf_latch_get_latch(session, bucket, ctrl, mode);

    // Wait other session to finish IO read.
    while (ctrl->load_status != (uint8)BUF_IS_LOADED) {
        if (ctrl->load_status == (uint8)BUF_LOAD_FAILED) {
            if (mode == LATCH_MODE_X) {
                // no need for cocurrent contrl with x lock.
                ctrl->load_status = (uint8)BUF_NEED_LOAD;
                break;
            }

            /*
             * For current buffer load, if someone failed to load the page,
             * the current session need to reload again.
             */
            cm_spin_lock(&bucket->lock, &session->stat->spin_stat.stat_bucket);
            if (ctrl->load_status != (uint8)BUF_LOAD_FAILED) {
                cm_spin_unlock(&bucket->lock);
                continue;
            }

            ctrl->load_status = (uint8)BUF_NEED_LOAD;
            cm_spin_unlock(&bucket->lock);
            ctrl->remote_access = 0;
            break;
        }

        knl_begin_session_wait(session, READ_BY_OTHER_SESSION, CT_TRUE);
        times++;
        if (times > CT_SPIN_COUNT) {
            times = 0;
            SPIN_STAT_INC(&session->stat_page, r_sleeps);
            cm_spin_sleep();
        }
    }
    knl_end_session_wait(session, READ_BY_OTHER_SESSION);
}

static inline void buf_init_ctrl_options(knl_session_t *session, buf_ctrl_t *ctrl, uint32 options)
{
    if (options & ENTER_PAGE_RESIDENT) {
        ctrl->is_resident = 1;
    } else if (options & ENTER_PAGE_PINNED) {
        ctrl->is_pinned = 1;
    }
}

static void buf_set_ctrl_options(knl_session_t *session, buf_set_t *set, buf_ctrl_t *ctrl, uint32 options)
{
    if ((options & ENTER_PAGE_RESIDENT) && !ctrl->is_resident) {
        buf_bucket_t *bucket = BUF_GET_BUCKET(set, ctrl->bucket_id);

        cm_spin_lock(&bucket->lock, &session->stat->spin_stat.stat_bucket);
        if (!ctrl->is_resident) {
            ctrl->is_resident = 1;
        }
        cm_spin_unlock(&bucket->lock);
        return;
    }

    if ((options & ENTER_PAGE_PINNED) && !ctrl->is_pinned) {
        ctrl->is_pinned = 1;
    }

    /* we don't need to make accurate statistics */
    if ((options & ENTER_PAGE_FROM_REMOTE) && ctrl->remote_access < CT_REMOTE_ACCESS_LIMIT) {
        ctrl->remote_access++;
    }
}

/* update ctrl touch number when access is outside time window */
static inline void buf_update_ctrl_touch_nr(knl_session_t *session, buf_ctrl_t *item, uint32 options)
{
    date_t systime = KNL_NOW(session);
    if (systime > item->access_time + BUF_ACCESS_WINDOW) {
        item->touch_number++;
        if (options & ENTER_PAGE_HIGH_AGE) {
            item->touch_number += (BUF_TCH_AGE - 1);
        }
        item->access_time = systime;
    }
}

buf_ctrl_t *buf_alloc_ctrl(knl_session_t *session, page_id_t page_id, latch_mode_t mode, uint32 options)
{
    uint32 hash_val = buf_page_hash_value(page_id);
    uint32 buf_pool_id = buf_get_pool_id_by_hash(hash_val, session->kernel->buf_ctx.buf_set_count);
    buf_set_t *set = &session->kernel->buf_ctx.buf_set[buf_pool_id];
    datafile_t *df = DATAFILE_GET(session, page_id.file);
    buf_ctrl_t *item = NULL;

    if (SECUREC_UNLIKELY(df->in_memory)) {
        item = (buf_ctrl_t *)(df->addr + page_id.page * sizeof(buf_ctrl_t));
        if (!item->is_pinned) {
            item->is_pinned = 1;
            item->load_status = (uint8)BUF_NEED_LOAD;
        }
        return NULL;
    }

    uint32 hash_id = buf_get_bucket_id_by_hash(hash_val, set->bucket_num);
    buf_bucket_t *bucket = BUF_GET_BUCKET(set, hash_id);

    /* lock bucket to find page ctrl and release lock after latching */
    cm_spin_lock(&bucket->lock, &session->stat->spin_stat.stat_bucket);
    item = buf_find_from_bucket(bucket, page_id);
    /* nothing to do when page is not in buffer with enter page try */
    if (SECUREC_UNLIKELY((options & ENTER_PAGE_TRY) &&
                         (item == NULL || (!DB_IS_CLUSTER(session) && item->load_status != BUF_IS_LOADED)))) {
        cm_spin_unlock(&bucket->lock);
        return NULL;
    }

    if (item != NULL) {
        item->ref_num++;
        buf_latch_ctrl(session, bucket, item, mode);
        buf_set_ctrl_options(session, set, item, options);
        buf_update_ctrl_touch_nr(session, item, options);

        knl_panic_log(IS_SAME_PAGID(page_id, item->page_id), "the page_id and item's page_id are not same, "
                      "panic info: item page %u-%u type %u curr page %u-%u",
                      item->page_id.file, item->page_id.page, item->page->type, page_id.file, page_id.page);
        knl_panic_log(item->buf_pool_id == buf_pool_id, "item ctrl's buf_pool_id is not equal curr buf_pool_id, "
                      "panic info: page %u-%u type %u item buf_pool_id %u buf_pool_id %u", item->page_id.file,
                      item->page_id.page, item->page->type, item->buf_pool_id, buf_pool_id);
        return item;
    }
    cm_spin_unlock(&bucket->lock);

    knl_begin_session_wait(session, BUFFER_POOL_ALLOC, CT_FALSE);
    buf_get_ctrl(session, set, options, &item);
    knl_end_session_wait(session, BUFFER_POOL_ALLOC);

    /*
     * if the same page ctrl has been added to bucket concurrently,
     * add the ctrl to aux list allocated by self.
     */
    cm_spin_lock(&bucket->lock, &session->stat->spin_stat.stat_bucket);
    buf_ctrl_t *temp = buf_find_from_bucket(bucket, page_id);
    if (SECUREC_UNLIKELY(temp != NULL)) {
        temp->ref_num++;
        buf_latch_ctrl(session, bucket, temp, mode);
        buf_set_ctrl_options(session, set, temp, options);
        knl_panic_log(IS_SAME_PAGID(page_id, temp->page_id), "the page_id and temp's page_id are not same, "
                      "panic info: temp page %u-%u type %u curr page %u-%u",
                      temp->page_id.file, temp->page_id.page, temp->page->type, page_id.file, page_id.page);
        knl_panic_log(temp->buf_pool_id == buf_pool_id, "temp ctrl's buf_pool_id is not equal curr buf_pool_id, "
                      "panic info: page %u-%u type %u temp buf_pool_id %u buf_pool_id %u", temp->page_id.file,
                      temp->page_id.page, temp->page->type, temp->buf_pool_id, buf_pool_id);

        cm_spin_lock(&set->scan_list.lock, &session->stat->spin_stat.stat_buffer);
        buf_lru_add_ctrl(&set->scan_list, item, BUF_ADD_COLD);
        cm_spin_unlock(&set->scan_list.lock);
        return temp;
    }

    item->ref_num = 1;
    item->page_id = page_id;
    item->bucket_id = hash_id;
    item->buf_pool_id = buf_pool_id;
    buf_init_ctrl_options(session, item, options);
    buf_add_to_bucket(bucket, item);

    /* latch the ctrl directly causing no concurrent operations on it */
    if (mode != LATCH_MODE_X) {
        buf_latch_s(session, item, (mode == LATCH_MODE_FORCE_S), CT_FALSE);
    } else {
        buf_latch_x(session, item, CT_FALSE);
        item->latch.xsid = session->id;
    }

    /* add resident page to hot point of main list exclude situatuion with little buffer size */
    if (!page_compress(session, item->page_id)) {
        // compress page is not added here
        buf_add_pos_t add_pos = (options & ENTER_PAGE_RESIDENT) ? BUF_ADD_HOT : BUF_ADD_OLD;
        cm_spin_lock(&set->list[item->list_id].lock, &session->stat->spin_stat.stat_buffer);
        buf_lru_add_ctrl(&set->list[item->list_id], item, add_pos);
        cm_spin_unlock(&set->list[item->list_id].lock);
    }

    if (options & ENTER_PAGE_HIGH_AGE) {
        item->touch_number += (BUF_TCH_AGE - 1);
    }
    item->access_time = KNL_NOW(session);

    return item;
}

/*
 * return NULL if the page is loaded or loading by others at this time,
 * otherwise, latch the page and return
 */
buf_ctrl_t *buf_try_alloc_ctrl(knl_session_t *session, page_id_t page_id, latch_mode_t mode, uint32 options,
                               buf_add_pos_t add_pos)
{
    uint32 hash_val = buf_page_hash_value(page_id);
    uint32 buf_pool_id = buf_get_pool_id_by_hash(hash_val, session->kernel->buf_ctx.buf_set_count);
    buf_set_t *set = &session->kernel->buf_ctx.buf_set[buf_pool_id];
    datafile_t *df = DATAFILE_GET(session, page_id.file);
    buf_ctrl_t *item = NULL;

    if (SECUREC_UNLIKELY(df->in_memory)) {
        item = (buf_ctrl_t *)(df->addr + page_id.page * sizeof(buf_ctrl_t));
        if (!item->is_resident) {
            item->is_resident = 1;
            item->load_status = (uint8)BUF_NEED_LOAD;
        }
        return NULL;
    }

    uint32 hash_id = buf_get_bucket_id_by_hash(hash_val, set->bucket_num);
    buf_bucket_t *bucket = BUF_GET_BUCKET(set, hash_id);

    cm_spin_lock(&bucket->lock, &session->stat->spin_stat.stat_bucket);
    item = buf_find_from_bucket(bucket, page_id);
    if (item != NULL) {
        if ((item->load_status == (uint8)BUF_LOAD_FAILED) && (!DB_IS_CLUSTER(session))) {
            item->ref_num++;
            buf_latch_ctrl(session, bucket, item, mode);
            /* page maybe has been loaded by others after latching */
            if (item->load_status == (uint8)BUF_NEED_LOAD) {
                knl_panic_log(IS_SAME_PAGID(page_id, item->page_id), "the page_id and item's page_id are not same, "
                              "panic info: item page %u-%u type %u curr page %u-%u",
                              item->page_id.file, item->page_id.page, item->page->type, page_id.file, page_id.page);
                knl_panic_log(item->buf_pool_id == buf_pool_id, "item ctrl's buf_pool_id is not equal curr "
                    "buf_pool_id, panic info: page %u-%u type %u item buf_pool_id %u buf_pool_id %u",
                    item->page_id.file, item->page_id.page, item->page->type, item->buf_pool_id, buf_pool_id);
                return item;
            } else {
                buf_unlatch(session, item, CT_TRUE);
                return NULL;
            }
        } else {
            knl_panic_log(IS_SAME_PAGID(page_id, item->page_id), "the page_id and item's page_id are not same, "
                          "panic info: item page %u-%u type %u curr page %u-%u",
                          item->page_id.file, item->page_id.page, item->page->type, page_id.file, page_id.page);
            knl_panic_log(item->buf_pool_id == buf_pool_id, "item ctrl's buf_pool_id is not equal curr buf_pool_id, "
                          "panic info: page %u-%u type %u item buf_pool_id %u buf_pool_id %u", item->page_id.file,
                          item->page_id.page, item->page->type, item->buf_pool_id, buf_pool_id);
            cm_spin_unlock(&bucket->lock);
            return NULL;
        }
    }
    cm_spin_unlock(&bucket->lock);

    knl_begin_session_wait(session, BUFFER_POOL_ALLOC, CT_FALSE);
    buf_get_ctrl(session, set, options, &item);
    knl_end_session_wait(session, BUFFER_POOL_ALLOC);

    /*
     * if anyone has just added the same page ctrl to bucket,
     * release the allocated ctrl to the tail of LRU queue.
     */
    cm_spin_lock(&bucket->lock, &session->stat->spin_stat.stat_bucket);
    buf_ctrl_t *temp = buf_find_from_bucket(bucket, page_id);
    if (SECUREC_UNLIKELY(temp != NULL)) {
        if ((temp->load_status == (uint8)BUF_LOAD_FAILED) && (!DB_IS_CLUSTER(session))) {
            temp->ref_num++;
            buf_latch_ctrl(session, bucket, temp, mode);

            cm_spin_lock(&set->scan_list.lock, &session->stat->spin_stat.stat_buffer);
            buf_lru_add_ctrl(&set->scan_list, item, BUF_ADD_COLD);
            cm_spin_unlock(&set->scan_list.lock);

            /* page maybe has been loaded by others after latching */
            if (temp->load_status == (uint8)BUF_NEED_LOAD) {
                knl_panic_log(IS_SAME_PAGID(page_id, temp->page_id), "the page_id and temp's page_id are not same, "
                              "panic info: temp page %u-%u type %u curr page %u-%u", temp->page_id.file,
                              temp->page_id.page, temp->page->type, page_id.file, page_id.page);
                knl_panic_log(temp->buf_pool_id == buf_pool_id, "temp ctrl's buf_pool_id is not equal curr "
                    "buf_pool_id, panic info: page %u-%u type %u temp buf_pool_id %u buf_pool_id %u",
                    temp->page_id.file, temp->page_id.page, temp->page->type, temp->buf_pool_id, buf_pool_id);
                return temp;
            } else {
                buf_unlatch(session, temp, CT_TRUE);
                return NULL;
            }
        } else {
            knl_panic_log(IS_SAME_PAGID(page_id, temp->page_id),
                "curr page_id and temp's page_id are not same, panic info: temp page %u-%u type %u curr page %u-%u",
                temp->page_id.file, temp->page_id.page, temp->page->type, page_id.file, page_id.page);
            cm_spin_unlock(&bucket->lock);

            cm_spin_lock(&set->scan_list.lock, &session->stat->spin_stat.stat_buffer);
            buf_lru_add_ctrl(&set->scan_list, item, BUF_ADD_COLD);
            cm_spin_unlock(&set->scan_list.lock);
            return NULL;
        }
    }

    item->ref_num = 1;
    item->page_id = page_id;
    item->bucket_id = hash_id;
    item->buf_pool_id = buf_pool_id;
    buf_init_ctrl_options(session, item, options);
    buf_add_to_bucket(bucket, item);

    /* latch the ctrl directly causing no concurrent operations on it */
    if (mode != LATCH_MODE_X) {
        buf_latch_s(session, item, (mode == LATCH_MODE_FORCE_S), CT_FALSE);
    } else {
        buf_latch_x(session, item, CT_FALSE);
        item->latch.xsid = session->id;
    }

    if (!page_compress(session, item->page_id)) {
        cm_spin_lock(&set->list[item->list_id].lock, &session->stat->spin_stat.stat_buffer);
        buf_lru_add_ctrl(&set->list[item->list_id], item, add_pos);
        cm_spin_unlock(&set->list[item->list_id].lock);
    }
    knl_panic_log(IS_SAME_PAGID(page_id, item->page_id), "the page_id and item's page_id are not same, panic info: "
                  "page %u-%u type %u", item->page_id.file, item->page_id.page, item->page->type);
    knl_panic_log(item->buf_pool_id == buf_pool_id, "item's buf_pool_id is not equal curr buf_pool_id, panic info: "
                  "page %u-%u type %u item buf_pool_id %u curr buf_pool_id %u", item->page_id.file,
                  item->page_id.page, item->page->type, item->buf_pool_id, buf_pool_id);

    item->access_time = KNL_NOW(session);
    return item;
}

static inline void buf_alloc_link_head(knl_session_t *session, buf_ctrl_t *head_ctrl, uint32 options,
    buf_add_pos_t add_pos)
{
    uint32 buf_pool_id = buf_get_pool_id(head_ctrl->page_id, session->kernel->buf_ctx.buf_set_count);
    buf_set_t *set = &session->kernel->buf_ctx.buf_set[buf_pool_id];

    /* The head_ctrl->list_id may be changed later (from main to scan) by re-balance function.
     * We use the snapped id to lock/unlock the list, and once we have lock the list, the on-list
     * status polling is guranteed to be correct (wether or not it is on the snapped list).
     * There is case that the head has been on list. We only link it when it is not on.
     */
    uint8 list_id = head_ctrl->list_id;
    cm_spin_lock(&set->list[list_id].lock, &session->stat->spin_stat.stat_buffer);
    if (SECUREC_LIKELY(!BUF_ON_LIST(head_ctrl))) {
        buf_lru_add_ctrl(&set->list[list_id], head_ctrl, add_pos);
    }
    cm_spin_unlock(&set->list[list_id].lock);
}

static void buf_alloc_member(knl_session_t *session, buf_ctrl_t *head_ctrl, page_id_t wanted_page,
    latch_mode_t mode, uint32 options)
{
    page_id_t head_page = head_ctrl->page_id;
    page_id_t member_page = head_page;

    if (SECUREC_UNLIKELY(head_ctrl->compress_group[0] != NULL)) {
        /* Need alloc member, but all the group seems have been in memery
         * and linked together.
         * Such case can heppen if a session loaded failed, while a second session get the
         * head before the group is expired.
         * We do some assersions for such rare event.
         */
        page_id_t test_page = head_page;
        for (int i = 1; i < PAGE_GROUP_COUNT; i++) {
            test_page.page = head_page.page + i;
            knl_panic(head_ctrl->compress_group[i] != NULL);
            knl_panic(IS_SAME_PAGID(head_ctrl->compress_group[i]->page_id, test_page));
            knl_panic(head_ctrl->compress_group[i]->load_status != BUF_IS_LOADED); // may be transient need_load
                // status as another session calls buf_alloc_compress with this page
            knl_panic(head_ctrl->compress_group[i]->compress_group[0] == head_ctrl);
            knl_panic(head_ctrl->compress_group[i]->bucket_id != CT_INVALID_ID32);
        }
    }

    head_ctrl->compress_group[0] = head_ctrl;
    for (int i = 1; i < PAGE_GROUP_COUNT; i++) {
        member_page.page = head_page.page + i;
        latch_mode_t real_mode = LATCH_MODE_S;
        uint32 real_options = ENTER_PAGE_NORMAL;
        if (member_page.page == wanted_page.page || (options & ENTER_PAGE_NO_READ)) {
            real_mode = mode;
            real_options = options;
        }

        buf_ctrl_t *member_ctrl = buf_alloc_ctrl(session, member_page, real_mode, real_options);
        knl_panic(member_ctrl != NULL);
        knl_panic(member_ctrl->load_status == BUF_NEED_LOAD);

        member_ctrl->compress_group[0] = head_ctrl; // so from member we can access head
        head_ctrl->compress_group[i] = member_ctrl; // from head we can access each member
        if (member_page.page != wanted_page.page) {
            buf_unlatch(session, member_ctrl, CT_TRUE);
        }
    }

    if (wanted_page.page != head_page.page) {
        // only keep the wanted ctrl latched finally.
        buf_unlatch(session, head_ctrl, CT_TRUE);
    }
}

/*
 * Head ctrl should be added to list after alloc member. We should do the adding action
 * after the group pointers are set, so that it can access members from head once the head
 * ctrl is exposed on the list.
 */
buf_ctrl_t *buf_alloc_compress(knl_session_t *session, page_id_t wanted_page, latch_mode_t mode, uint32 options)
{
    buf_ctrl_t *ctrl = NULL;
    page_id_t head_page = page_first_group_id(session, wanted_page);
    buf_add_pos_t add_pos = (options & ENTER_PAGE_RESIDENT) ? BUF_ADD_HOT : BUF_ADD_OLD;

    while (CT_TRUE) {
        ctrl = buf_alloc_ctrl(session, wanted_page, mode, options);
        if (ctrl == NULL) {
            // options with ENTER_PAGE_TRY
            return NULL;
        }

        knl_panic(ctrl->load_status == BUF_IS_LOADED || ctrl->load_status == BUF_NEED_LOAD);
        if (ctrl->load_status == BUF_IS_LOADED) {
            return ctrl;
        }

        if (wanted_page.page == head_page.page) {
            break; // Get head with need_load status
        }

        // Member with need_load status, we should unlatch it and compete the head.
        knl_panic_log(!(options & ENTER_PAGE_NO_READ), "First no read must come with a head page:%d-%d",
            wanted_page.file, wanted_page.page);
        ctrl->load_status = (uint8)BUF_LOAD_FAILED; // so it can be latched again.
        buf_unlatch(session, ctrl, CT_TRUE);

        // Use buf_try_alloc_ctrl instead of buf_alloc_member to avoid deadlock.
        ctrl = buf_try_alloc_ctrl(session, head_page, LATCH_MODE_S, ENTER_PAGE_NORMAL, add_pos);
        if (ctrl != NULL) {
            knl_panic(ctrl->load_status == BUF_NEED_LOAD);
            break; // Get head with need_load status
        }

        // Head is loaded or loading by another session, wait a tick to alloc wanted again.
        knl_wait_for_tick(session);
    }

    buf_alloc_member(session, ctrl, wanted_page, mode, options);
    buf_alloc_link_head(session, ctrl, options, add_pos);
    return ctrl->compress_group[wanted_page.page - head_page.page];
}

buf_ctrl_t *buf_try_alloc_compress(knl_session_t *session, page_id_t wanted_page, latch_mode_t mode, uint32 options,
    buf_add_pos_t add_pos)
{
    knl_panic(!(options & ENTER_PAGE_NO_READ)); // pre-read should not come with no read.

    buf_ctrl_t *ctrl = NULL;
    page_id_t head_page = page_first_group_id(session, wanted_page);

    ctrl  = buf_try_alloc_ctrl(session, wanted_page, mode, options, add_pos);
    if (ctrl == NULL) {
        return NULL;
    }

    if (wanted_page.page != head_page.page) {
        ctrl->load_status = (uint8)BUF_LOAD_FAILED; // so it can be latched again.
        buf_unlatch(session, ctrl, CT_TRUE);
        ctrl = buf_try_alloc_ctrl(session, head_page, LATCH_MODE_S, ENTER_PAGE_NORMAL, add_pos);
        if (ctrl == NULL) {
            return NULL;
        }
    }

    knl_panic(ctrl->load_status == BUF_NEED_LOAD);

    buf_alloc_member(session, ctrl, wanted_page, mode, options);
    buf_alloc_link_head(session, ctrl, options, add_pos);
    return ctrl->compress_group[wanted_page.page - head_page.page];
}

buf_ctrl_t *buf_find_by_pageid(knl_session_t *session, page_id_t page_id)
{
    buf_ctrl_t *ctrl = NULL;
    buf_bucket_t *bucket = NULL;

    uint32 hash_val = buf_page_hash_value(page_id);
    uint32 buf_pool_id = buf_get_pool_id_by_hash(hash_val, session->kernel->buf_ctx.buf_set_count);

    buf_set_t *set = &session->kernel->buf_ctx.buf_set[buf_pool_id];
    uint32 hash_id = buf_get_bucket_id_by_hash(hash_val, set->bucket_num);
    bucket = BUF_GET_BUCKET(set, hash_id);

    cm_spin_lock(&bucket->lock, &session->stat->spin_stat.stat_bucket);
    ctrl = buf_find_from_bucket(bucket, page_id);
    cm_spin_unlock(&bucket->lock);

    return ctrl;
}

/*
 * stash page that ckpt marked to list temporary
 */
void buf_stash_marked_page(buf_set_t *set, buf_lru_list_t *list, buf_ctrl_t *ctrl)
{
    cm_spin_lock(&set->write_list.lock, NULL);
    buf_remove_ctrl(&set->write_list, ctrl);
    cm_spin_unlock(&set->write_list.lock);

    buf_lru_add_tail(list, ctrl);
}

/*
 * move page that has been flushed from temporary list to aux list
 */
void buf_reset_cleaned_pages(buf_set_t *set, buf_lru_list_t *list)
{
    buf_ctrl_t *ctrl = list->lru_last;
    buf_ctrl_t *shift = NULL;

    cm_spin_lock(&set->scan_list.lock, NULL);
    while (ctrl != NULL) {
        shift = ctrl;
        ctrl = ctrl->prev;
        buf_add_pos_t pos = shift->is_resident ? BUF_ADD_HOT : BUF_ADD_COLD;
        buf_lru_add_ctrl(&set->scan_list, shift, pos);
    }
    cm_spin_unlock(&set->scan_list.lock);
    cm_release_cond(&set->set_cond);
}

/*
 * move page that has been flushed from temporary list to scan list for all buf set
 */
void buf_reset_cleaned_pages_all_bufset(buf_context_t *buf_ctx, buf_lru_list_t *list)
{
    buf_ctrl_t *ctrl = list->lru_last;
    buf_ctrl_t *shift = NULL;
 
    uint32 pool_id = 0;
    buf_lru_list_t temp_list[CT_MAX_BUF_POOL_NUM] = {0};
    while (ctrl != NULL) {
        pool_id = ctrl->buf_pool_id;
        shift = ctrl;
        ctrl = ctrl->prev;
        buf_lru_add_ctrl(&temp_list[pool_id], shift, BUF_ADD_COLD);
    }
    // Hold lock here, because buf_recycle has more concurrency to get the scan_list lock.
    for (uint32 i = 0; i < buf_ctx->buf_set_count; i++) {
        cm_spin_lock(&buf_ctx->buf_set[i].scan_list.lock, NULL);
        ctrl = temp_list[i].lru_last;
        while (ctrl != NULL) {
            shift = ctrl;
            ctrl = ctrl->prev;
            buf_add_pos_t pos = shift->is_resident ? BUF_ADD_HOT : BUF_ADD_COLD;
            buf_lru_add_ctrl(&buf_ctx->buf_set[i].scan_list, shift, pos);
        }
        cm_spin_unlock(&buf_ctx->buf_set[i].scan_list.lock);
        cm_release_cond(&buf_ctx->buf_set[i].set_cond);
    }
}

/* move ctrls in old list of main list to old point of aux list */
void buf_balance_set_list(buf_set_t *set)
{
    buf_ctrl_t *shift = NULL;
    buf_lru_list_t *list = &set->main_list;
    cm_spin_lock(&list->lock, NULL);
    buf_ctrl_t *item = list->lru_last;

    for (;;) {
        if (item == NULL || item == list->lru_old) {
            break;
        }

        if (!BUF_CAN_EXPIRE_CACHE(item)) {
            item = item->prev;
            continue;
        }

        shift = item;
        item = item->prev;
        buf_lru_remove_ctrl(list, shift);
        cm_spin_lock(&set->scan_list.lock, NULL);
        buf_lru_add_ctrl(&set->scan_list, shift, BUF_ADD_OLD);
        cm_spin_unlock(&set->scan_list.lock);
    }
    cm_spin_unlock(&list->lock);
}

/*
 * Only running when recover or failover with GBP
 * check current page lsn, if curr_lsn is not expect lsn, try pull this page from GBP, and replace as gbp page
 * then update this ctrl's gbp_read_version, make sure same page pull from GBP at most once.
 */
void buf_check_page_version(knl_session_t *session, buf_ctrl_t *ctrl)
{
    knl_instance_t *kernel = session->kernel;
    log_context_t *redo = &kernel->redo_ctx;
    page_id_t page_id = ctrl->page_id;
    gbp_analyse_item_t *item = NULL;

    /* read latest page versioin */
    if (KNL_RECOVERY_WITH_GBP(kernel) && ctrl->gbp_ctrl->gbp_read_version != KNL_GBP_READ_VER(kernel)) {
        uint32 lock_id = page_id.page % CT_GBP_RD_LOCK_COUNT;

        cm_spin_lock(&kernel->gbp_context.buf_read_lock[lock_id], NULL);
        if (!KNL_RECOVERY_WITH_GBP(kernel)) {
            item = NULL; /* check rcy_with_gbp again, if not recover with gbp, do not read gbp */
        } else {
            item = gbp_aly_get_page_item(session, page_id);
        }

        if (item != NULL) {
            if (ctrl->page->lsn < item->lsn) {
                knl_begin_session_wait(session, DB_FILE_GBP_READ, CT_TRUE);
                ctrl->gbp_ctrl->page_status = knl_read_page_from_gbp(session, ctrl);
                knl_end_session_wait(session, DB_FILE_GBP_READ);
            } else {
                /*
                 * page lsn >= expect lsn (item->lsn), we must set item->is_verified here, otherwise
                 * 1. this page is modified by this session and page lsn update to new lsn
                 * 2. this page is flushed to disk and recycled, not in buffer, this page's disk lsn > expect lsn
                 * 3. in gbp_process_batch_read_resp, find this page is not loaded to disk, so curr_page_lsn == 0
                 * 4. in gbp_page_verify, item->is_verified == 0 && gbp_page_lsn == expect_lsn, this page is HIT page
                 * 5. in gbp_process_batch_read_resp, gbp_page_lsn > curr_page_lsn(0) && is HIT page, will be replace
                 * 6. but this page's disk lsn > expect lsn == gbp_page_lsn
                 */
                item->is_verified = 1;
            }
        }
        ctrl->gbp_ctrl->gbp_read_version = KNL_GBP_READ_VER(kernel);
        cm_spin_unlock(&kernel->gbp_context.buf_read_lock[lock_id]);
    }

    /* page should have the latest version */
    if (redo->last_rcy_with_gbp && DB_IS_PRIMARY(&kernel->db) && DB_IS_OPEN(session) && ctrl->page->lsn > 0) {
        uint64 expect_lsn = gbp_aly_get_page_lsn(session, page_id);
        knl_panic_log(ctrl->page->lsn >= expect_lsn, "ctrl page lsn is smaller than expect, panic info: page %u-%u "
                      "type %u ctrl lsn %llu expect_lsn %llu",
                      page_id.file, page_id.page, ctrl->page->type, ctrl->page->lsn, expect_lsn);
    }

    /* after recovery, usable page should be replayed */
    if (ctrl->gbp_ctrl->page_status == GBP_PAGE_USABLE && DB_IS_PRIMARY(&kernel->db) && DB_IS_OPEN(session)) {
        knl_panic_log(0, "[GBP] usable page %u-%u is not replayed after recover", page_id.file, page_id.page);
    }
}

/*
 * After failover with GBP, some local buffer page is old, when use page through buf_enter_page, we can auto update it
 * as new page from GBP. But resident pages is used as memery when read it, not through buf_enter_page.So we should let
 * resident page use buf_check_page_version at least once, to ensure this page can be updated by GBP.
 */
bool32 buf_check_resident_page_version(knl_session_t *session, page_id_t page_id)
{
    /* GBP can't be used in cluster. */
    if (DB_IS_CLUSTER(session)) {
        buf_bucket_t *bucket = buf_find_bucket(session, page_id);

        cm_spin_lock(&bucket->lock, &session->stat->spin_stat.stat_bucket);
        buf_ctrl_t *ctrl = buf_find_from_bucket(bucket, page_id);
        if ((ctrl != NULL) &&
            dcs_local_page_usable(session, (buf_ctrl_t *)ctrl, LATCH_MODE_S) &&
            (ctrl->transfer_status != BUF_TRANS_REL_OWNER)) {
                cm_spin_unlock(&bucket->lock);
                return CT_TRUE;
        }
        cm_spin_unlock(&bucket->lock);

        uint32 depth = session->page_stack.depth;
        while (depth > 0) {
            if (IS_SAME_PAGID(session->page_stack.pages[depth - 1]->page_id, page_id)) {
                return CT_TRUE;
            }
            depth--;
        }

        buf_enter_page(session, page_id, LATCH_MODE_S, ENTER_PAGE_NORMAL);
        buf_leave_page(session, CT_FALSE);
        return CT_TRUE;
    }

    if (SECUREC_LIKELY(!KNL_RECOVERY_WITH_GBP(session->kernel))) {
        return CT_FALSE;
    }

    if (SESSION_IS_LOG_ANALYZE(session) || SESSION_IS_GBP_BG(session)) {
        return CT_TRUE;
    }

    uint32 depth = session->page_stack.depth;
    while (depth > 0) {
        if (IS_SAME_PAGID(session->page_stack.pages[depth - 1]->page_id, page_id)) {
            return CT_TRUE;  // resident page has been enter by self
        }
        depth--;
    }

    buf_bucket_t *bucket = buf_find_bucket(session, page_id);

    cm_spin_lock(&bucket->lock, &session->stat->spin_stat.stat_bucket);
    buf_ctrl_t *ctrl = buf_find_from_bucket(bucket, page_id);
    if (ctrl != NULL) {
        buf_check_page_version(session, ctrl);
    }
    cm_spin_unlock(&bucket->lock);

    return CT_TRUE;
}

bool32 buf_check_resident_page_version_with_ctrl(knl_session_t *session, void *buf_ctrl, page_id_t page_id)
{
    if (DB_IS_CLUSTER(session)) {
        buf_ctrl_t *ctrl = (buf_ctrl_t *)buf_ctrl;
        if (ctrl != NULL && IS_SAME_PAGID(ctrl->page_id, page_id) &&
            dcs_local_page_usable(session, ctrl, LATCH_MODE_S) &&
            (ctrl->transfer_status != BUF_TRANS_REL_OWNER)) {
                if (IS_SAME_PAGID(ctrl->page_id, page_id)) {
                    return CT_TRUE;
                }
        }
    }

    return buf_check_resident_page_version(session, page_id);
}

void buf_expire_datafile_pages(knl_session_t *session, uint32 file_id)
{
    buf_context_t *ctx = &session->kernel->buf_ctx;

    for (uint32 i = 0; i < ctx->buf_set_count; i++) {
        buf_set_t *set = &ctx->buf_set[i];
        for (uint32 j = 0; j < set->hwm; j++) {
            buf_ctrl_t *ctrl = &set->ctrls[j];
            if (ctrl->page_id.file != file_id || ctrl->bucket_id == CT_INVALID_ID32) {
                continue;
            }

            buf_bucket_t *bucket = BUF_GET_BUCKET(set, ctrl->bucket_id);
            cm_spin_lock(&bucket->lock, &session->stat->spin_stat.stat_bucket);
            ctrl->bucket_id = CT_INVALID_ID32;
            ctrl->is_resident = 0;
            buf_remove_from_bucket(bucket, ctrl);
            cm_spin_unlock(&bucket->lock);
        }
    }
}

bool32 pcb_get_buf_from_vm(knl_session_t *session, char **buf, uint32 *buf_id)
{
    pcb_context_t *com_ctx = &session->kernel->compress_buf_ctx;
    compress_buf_ctrl_t *buf_com_ctrl = NULL;
    uint32 i;

    if (!session->kernel->attr.tab_compress_enable_buf) {
        return CT_FALSE;
    }

    cm_spin_lock(&com_ctx->lock, NULL);
    if (com_ctx->opt_count > 0) {
        for (i = 0; i < MAX_PCB_VM_COUNT; i++) {
            if (!com_ctx->com_bufs[i].used) {
                buf_com_ctrl = &com_ctx->com_bufs[i];
                break;
            }
        }

        if (buf_com_ctrl != NULL) {
            buf_com_ctrl->used = CT_TRUE;
            com_ctx->opt_count--;
            *buf = buf_com_ctrl->vm_page->data;
            *buf_id = i;
            cm_spin_unlock(&com_ctx->lock);
            return CT_TRUE;
        }
    }

    cm_spin_unlock(&com_ctx->lock);
    return CT_FALSE;
}
void pcb_assist_init(pcb_assist_t *pcb_assist)
{
    pcb_assist->ori_buf = NULL;
    pcb_assist->aligned_buf = NULL;
    pcb_assist->buf_id = 0;
    pcb_assist->from_vm = CT_TRUE;
}

/*
* Get temporary buffer of group pages from page compress buf context
* if vm pages of page compress buf context are all used currently,we alloc buffer from system.
*/
status_t pcb_get_buf(knl_session_t *session, pcb_assist_t *pcb_assist)
{
    pcb_assist_init(pcb_assist);
    if (!pcb_get_buf_from_vm(session, &pcb_assist->ori_buf, &pcb_assist->buf_id)) {
        pcb_assist->ori_buf = (char *)malloc(DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT + CT_MAX_ALIGN_SIZE_4K);
        pcb_assist->from_vm = CT_FALSE;
    }

    if (pcb_assist->ori_buf == NULL) {
        pcb_assist->aligned_buf = NULL;
        CT_LOG_RUN_ERR("[BUFFER] alloc memory for compress table failed");
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT, "table compress");
        return CT_ERROR;
    }

    pcb_assist->aligned_buf = cm_aligned_buf(pcb_assist->ori_buf);

    return CT_SUCCESS;
}

void pcb_release_buf_from_vm(knl_session_t *session, uint32 buf_id)
{
    pcb_context_t *com_ctx = &session->kernel->compress_buf_ctx;

    cm_spin_lock(&com_ctx->lock, NULL);
    com_ctx->com_bufs[buf_id].used = CT_FALSE;
    com_ctx->opt_count++;
    cm_spin_unlock(&com_ctx->lock);
}

void pcb_release_buf(knl_session_t *session, pcb_assist_t *pcb_assist)
{
    if (!pcb_assist->from_vm) {
        if (pcb_assist->ori_buf != NULL) {
            free(pcb_assist->ori_buf);
            pcb_assist->ori_buf = NULL;
        }
        return;
    }

    pcb_release_buf_from_vm(session, pcb_assist->buf_id);
}

/*
* Initialize page compress buf context,it alloc some vm pages for temporary buffer of page compress
*/
status_t pcb_init_ctx(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    pcb_context_t *com_ctx = &kernel->compress_buf_ctx;
    uint32 vmid;

    if (!kernel->attr.tab_compress_enable_buf) {
        com_ctx->opt_count = 0;
        return CT_SUCCESS;
    }

    uint32 vm_count = kernel->attr.tab_compress_buf_size / CT_VMEM_PAGE_SIZE;

    cm_spin_lock(&com_ctx->lock, NULL);
    for (uint32 i = 0; i < vm_count; i++) {
        vm_page_t *vm_page = NULL;
        if (vm_alloc(session, session->temp_pool, &vmid) != CT_SUCCESS) {
            cm_spin_unlock(&com_ctx->lock);
            return CT_ERROR;
        }

        if (vm_open(session, session->temp_pool, vmid, &vm_page) != CT_SUCCESS) {
            vm_free(session, session->temp_pool, vmid);
            cm_spin_unlock(&com_ctx->lock);
            return CT_ERROR;
        }

        com_ctx->com_bufs[i].used = CT_FALSE;
        com_ctx->com_bufs[i].vm_page = vm_page;
        com_ctx->opt_count++;
    }
    cm_spin_unlock(&com_ctx->lock);
    return CT_SUCCESS;
}

buf_bucket_t *buf_find_bucket(knl_session_t *session, page_id_t page_id)
{
    uint32 hash_val = buf_page_hash_value(page_id);
    uint32 buf_pool_id = buf_get_pool_id_by_hash(hash_val, session->kernel->buf_ctx.buf_set_count);
    buf_set_t *set = &session->kernel->buf_ctx.buf_set[buf_pool_id];
    buf_bucket_t *bucket = NULL;
    uint32 hash_id = buf_get_bucket_id_by_hash(hash_val, set->bucket_num);
    bucket = BUF_GET_BUCKET(set, hash_id);
    return bucket;
}

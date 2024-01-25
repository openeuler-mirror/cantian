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
 * ctsql_vm_hash_table.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_vm_hash_table.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_vm_hash_table.h"

#define MAX_HASH_BUCKET_SIZE (uint32)16777216 // 1<<24
#define MIN_HASH_BUCKET_SIZE (uint32)16384    // 1<<14
#define HASH_FILL_FACTOR (float)0.75

#define HASH_BUCKET_NODE_SIZE (uint32)(sizeof(hash_entry_t))
#define HASH_SEGMENT (seg)
#define HASH_SESSION(seg) ((seg)->sess)
#define HASH_POOL(seg) ((seg)->pool)
#define HASH_PM_POOL(seg) ((seg)->pm_pool)
#define HASH_PAGE_LIST(seg) (&(seg)->vm_list)
#define HASH_LAST_PAGE(seg) ((seg)->last_page)
#define HASH_LAST_PAGE_USED(seg) ((seg)->last_page_used)
#define HASH_BUCKETS_PER_PAGE (CT_VMEM_PAGE_SIZE / HASH_BUCKET_NODE_SIZE)
#define HASH_BUCKETS_LEFT ((CT_VMEM_PAGE_SIZE - HASH_LAST_PAGE_USED(seg)) / HASH_BUCKET_NODE_SIZE)
#define HASH_TABLE_ENTRY_VMID (&hash_table->self.page)
#define HASH_KEY_SCAN_BUF(scan_assit) ((scan_assit)->buf)
#define HASH_KEY_SCAN_SIZE(scan_assit) ((scan_assit)->size)
#define HASH_CALLBACK_CTX(hash_table) ((hash_table)->callback_ctx)

static const page_entry_t g_invalid_page_entry = {
    .page_id = CT_INVALID_INT32,
    .pm_flag = CT_TRUE
};
#define IS_INVALID_PAGE_ENTRY(entry) ((entry)->page_id == CT_INVALID_INT32)

static inline status_t vm_open_page(hash_segment_t *seg, uint32 page_id, char **buf)
{
    vm_page_t *page = NULL;
    if (vm_open(HASH_SESSION(seg), HASH_POOL(seg), page_id, &page) != CT_SUCCESS) {
        return CT_ERROR;
    }
    (*buf) = page->data;
    return CT_SUCCESS;
}

static inline void vm_close_page(hash_segment_t *seg, uint32 page_id)
{
    vm_close(HASH_SESSION(seg), HASH_POOL(seg), page_id, VM_ENQUE_TAIL);
}

static inline status_t pm_open_page(hash_segment_t *seg, uint32 page_id, char **buf)
{
    return pm_open(HASH_PM_POOL(seg), page_id, buf);
}

static inline void pm_close_page(hash_segment_t *seg, uint32 page_id) {}

typedef status_t (*page_open_t)(hash_segment_t *seg, uint32 page_id, char **buf);
typedef void (*page_close_t)(hash_segment_t *seg, uint32 page_id);

typedef struct st_page_func {
    page_open_t open;
    page_close_t close;
} page_func_t;

static page_func_t g_page_funcs[] = {
    { vm_open_page, vm_close_page },
    { pm_open_page, pm_close_page },
};

#define VM_OPEN(seg, entry, buf) (&g_page_funcs[(entry)->pm_flag])->open(seg, (entry)->page_id, buf)
#define VM_CLOSE(seg, entry) (&g_page_funcs[(entry)->pm_flag])->close(seg, (entry)->page_id)

#define VM_CLOSE_TWO_PAGES(first, second) \
    do {                                  \
        VM_CLOSE(HASH_SEGMENT, (first));  \
        VM_CLOSE(HASH_SEGMENT, (second)); \
    } while (0)

#define VM_CLOSE_THREE_PAGES(first, second, third) \
    do {                                           \
        VM_CLOSE(HASH_SEGMENT, (first));           \
        VM_CLOSE(HASH_SEGMENT, (second));          \
        VM_CLOSE(HASH_SEGMENT, (third));           \
    } while (0)

status_t vm_hash_open_page(hash_segment_t *seg, page_entry_t *entry, char **page_buf)
{
    return VM_OPEN(seg, entry, page_buf);
}

void vm_hash_close_page(hash_segment_t *seg, page_entry_t *entry)
{
    VM_CLOSE(seg, entry);
}

static inline status_t vm_hash_table_get_head(hash_table_t **hash_table, hash_segment_t *seg, hash_table_entry_t *table)
{
    char *page_buf = NULL;
    CT_RETURN_IFERR(VM_OPEN(HASH_SEGMENT, &table->page, &page_buf));
    *hash_table = (hash_table_t *)(page_buf + table->offset);
    return CT_SUCCESS;
}

static inline status_t vm_hash_table_get_node(hash_node_t **hash_node, hash_entry_t *node_entry, hash_segment_t *seg)
{
    char *page_buf = NULL;
    if (VM_OPEN(HASH_SEGMENT, &node_entry->page, &page_buf) != CT_SUCCESS) {
        return CT_ERROR;
    }
    *hash_node = (hash_node_t *)(page_buf + node_entry->offset);
    return CT_SUCCESS;
}

static inline status_t vm_hash_get_hash_table(hash_table_t **hash_table, hash_segment_t *seg, hash_table_entry_t *table,
    hash_table_iter_t *iter)
{
    if (iter->hash_table == NULL) {
        CT_RETURN_IFERR(vm_hash_table_get_head(&(iter->hash_table), seg, table));
    }

    *hash_table = iter->hash_table;
    return CT_SUCCESS;
}

static inline status_t vm_hash_alloc_page(hash_segment_t *seg, page_entry_t *page_entry)
{
    vm_page_t *page = NULL;
    uint32 page_id;

    if (HASH_PM_POOL(seg) != NULL && pm_alloc(HASH_PM_POOL(seg), &page_id) == CT_SUCCESS) {
        page_entry->page_id = page_id;
        page_entry->pm_flag = CT_TRUE;
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(vm_alloc_and_append(HASH_SESSION(seg), HASH_POOL(seg), HASH_PAGE_LIST(seg)));

    page_entry->page_id = HASH_PAGE_LIST(seg)->last;
    page_entry->pm_flag = 0;

    // if pages hold threshold not reached, do an extra open for hold purpose
    if (HASH_PAGE_LIST(seg)->count <= seg->pages_hold) {
        return vm_open(HASH_SESSION(seg), HASH_POOL(seg), HASH_PAGE_LIST(seg)->last, &page);
    }
    return CT_SUCCESS;
}

void vm_hash_segment_init(handle_t sess, vm_pool_t *pool, hash_segment_t *segment, pma_t *pma, uint32 pages_hold,
    uint64 max_size)
{
    segment->sess = sess;
    segment->pool = pool;
    segment->pages_hold = pages_hold;
    segment->last_page_used = CT_VMEM_PAGE_SIZE;
    segment->last_page = g_invalid_page_entry;
    segment->vm_list.count = 0;

    if (pm_create_pool(pma, max_size, &segment->pm_pool) != CT_SUCCESS) {
        cm_reset_error();
        segment->pm_pool = NULL;
    }
}

void vm_hash_segment_deinit(hash_segment_t *segment)
{
    uint32 loop;
    vm_ctrl_t *ctrl = NULL;
    uint32 curr_id, next_id;

    curr_id = segment->vm_list.first;
    for (loop = 0; loop < segment->vm_list.count; ++loop) {
        ctrl = vm_get_ctrl(segment->pool, curr_id);
        next_id = ctrl->next;
        vm_free(segment->sess, segment->pool, curr_id);
        curr_id = next_id;
    }
    segment->last_page_used = CT_VMEM_PAGE_SIZE;
    segment->last_page = g_invalid_page_entry;
    segment->vm_list.count = 0;

    pm_release_pool(segment->pm_pool);
    segment->pm_pool = NULL;
}

static inline uint32 vm_hash_table_get_bucket_size(uint32 bucket_num)
{
    uint32 bucket_size;
    if (bucket_num >= MAX_HASH_BUCKET_SIZE) {
        return MAX_HASH_BUCKET_SIZE;
    }
    bucket_size = MIN_HASH_BUCKET_SIZE;
    while (bucket_size < bucket_num) {
        bucket_size <<= 1;
    }
    return bucket_size;
}

static inline uint32 vm_hash_table_calc_bucket(hash_table_t *hash_table, uint32 hash_val)
{
    uint32 bucket_size = hash_val & hash_table->high_mask;
    if (bucket_size > hash_table->max_bucket) {
        bucket_size &= hash_table->low_mask;
    }
    return bucket_size;
}

static status_t vm_hash_table_set_page_entries(hash_table_t *hash_table, hash_segment_t *seg)
{
    errno_t ret_memset;
    char *page_buf = NULL;
    page_entry_t page_entry;
    uint32 loop, bucket_pages;
    uint32 entry_num = hash_table->nentries;
    uint32 buckets_size = HASH_BUCKET_NODE_SIZE * hash_table->bucket_num;

    bucket_pages = CM_ALIGN_CEIL(buckets_size, CT_VMEM_PAGE_SIZE);
    for (loop = 0; loop < bucket_pages; ++loop) {
        if (vm_hash_alloc_page(seg, &page_entry) != CT_SUCCESS) {
            return CT_ERROR;
        }
        hash_table->page_entries[entry_num++] = page_entry;
        if (VM_OPEN(HASH_SEGMENT, &page_entry, &page_buf) != CT_SUCCESS) {
            return CT_ERROR;
        }
        ret_memset = memset_sp(page_buf, CT_VMEM_PAGE_SIZE, 0xFF, CT_VMEM_PAGE_SIZE);
        if (ret_memset != EOK) {
            VM_CLOSE(HASH_SEGMENT, &page_entry);
            CT_THROW_ERROR(ERR_SYSTEM_CALL, ret_memset);
            return CT_ERROR;
        }
        VM_CLOSE(HASH_SEGMENT, &page_entry);
    }
    hash_table->nentries = entry_num;
    return CT_SUCCESS;
}

status_t vm_hash_table_alloc(hash_table_entry_t *table, hash_segment_t *seg, uint32 temp_bucket_num)
{
    status_t ret;
    id_list_t vm_list;
    char *page_buffer = NULL;
    page_entry_t page_entry;
    hash_table_t *hash_table = NULL;
    uint32 buckets_size, hash_table_head_size;
    uint32 bucket_num = temp_bucket_num;

    bucket_num = vm_hash_table_get_bucket_size(bucket_num);

    // total hash node entry size
    buckets_size = HASH_BUCKET_NODE_SIZE * MAX_HASH_BUCKET_SIZE;

    // space needed to store page entry,  buckets entry vm page num and hash table structure
    // vm page num: (ceil(buckets_size/CT_VMEM_PAGE_SIZE) + 1)
    // additions 1 page hit scenario: buckets_size%CT_VMEM_PAGE_SIZE > first buckets entry vm page free size
    hash_table_head_size = (CM_ALIGN_CEIL(buckets_size, CT_VMEM_PAGE_SIZE) + 1) * sizeof(uint32) + sizeof(hash_table_t);
    hash_table_head_size = CM_ALIGN_ANY(hash_table_head_size, HASH_BUCKET_NODE_SIZE);
    if (hash_table_head_size > CT_VMEM_PAGE_SIZE) {
        CT_THROW_ERROR(ERR_HASH_TABLE_TOO_LARGE, bucket_num);
        return CT_ERROR;
    }

    // make sure remained space of current page is enough to store hash table structure and page entries
    // after aligned, HASH_LAST_PAGE_USED(seg) may be large than CT_VMEM_PAGE_SIZE, so convert them to signed integer
    CT_RETURN_IFERR(vm_hash_alloc_page(seg, &page_entry));
    HASH_LAST_PAGE(seg) = page_entry;
    HASH_LAST_PAGE_USED(seg) = 0;

    CT_RETURN_IFERR(VM_OPEN(HASH_SEGMENT, &page_entry, &page_buffer));
    hash_table = (hash_table_t *)page_buffer;
    MEMS_RETURN_IFERR(memset_sp(hash_table, sizeof(hash_table_t), 0, sizeof(hash_table_t)));

    hash_table->rnums = 0;
    hash_table->nentries = 0;
    hash_table->seg = seg;
    hash_table->ffact = HASH_FILL_FACTOR;
    hash_table->hash = sql_hash_func;
    hash_table->equal = sql_hash_equal_func;
    hash_table->bucket_num = bucket_num;
    hash_table->max_bucket = bucket_num - 1;
    hash_table->high_mask = bucket_num - 1;
    hash_table->low_mask = bucket_num - 1;

    // set table entry in a virtual page
    hash_table->self.page = page_entry;
    hash_table->self.offset = HASH_LAST_PAGE_USED(seg);
    HASH_LAST_PAGE_USED(seg) += hash_table_head_size;
    *table = hash_table->self;

    // initialize null mark of hash table for hash join
    hash_table->has_null_key = CT_FALSE;
    hash_table->is_empty = CT_TRUE;

    // set page entries
    vm_list = seg->vm_list;
    seg->vm_list.count = 0;
    ret = vm_hash_table_set_page_entries(hash_table, seg);
    vm_append_list(HASH_POOL(seg), HASH_PAGE_LIST(seg), &vm_list);
    VM_CLOSE(HASH_SEGMENT, HASH_TABLE_ENTRY_VMID);
    return ret;
}

status_t vm_hash_table_init(hash_segment_t *seg, hash_table_entry_t *table, oper_func_t i_oper, oper_func_t q_oper,
    void *oper_ctx)
{
    char *page_buffer = NULL;
    hash_table_t *hash_table = NULL;

    CT_RETURN_IFERR(VM_OPEN(HASH_SEGMENT, &table->page, &page_buffer));
    hash_table = (hash_table_t *)(page_buffer + table->offset);
    hash_table->i_oper = i_oper;
    hash_table->q_oper = q_oper;
    hash_table->callback_ctx = oper_ctx;
    VM_CLOSE(HASH_SEGMENT, &table->page);
    return CT_SUCCESS;
}

status_t vm_hash_table_set_func(hash_segment_t *seg, hash_table_entry_t *table, hash_func_t hash, equal_func_t equal)
{
    hash_table_t *hash_table = NULL;

    CT_RETURN_IFERR(vm_hash_table_get_head(&hash_table, seg, table));
    hash_table->hash = hash;
    hash_table->equal = equal;
    VM_CLOSE(HASH_SEGMENT, &table->page);
    return CT_SUCCESS;
}

static status_t vm_hash_table_get_bucket(hash_table_t *hash_table, page_entry_t *self, hash_entry_t **next,
    hash_segment_t *seg, uint32 idx)
{
    char *page_buf = NULL;
    uint32 bucket = idx;

    *self = hash_table->page_entries[bucket / HASH_BUCKETS_PER_PAGE];
    if (VM_OPEN(HASH_SEGMENT, self, &page_buf) != CT_SUCCESS) {
        return CT_ERROR;
    }
    bucket = bucket % HASH_BUCKETS_PER_PAGE;
    *next = (hash_entry_t *)(page_buf + bucket * HASH_BUCKET_NODE_SIZE);
    return CT_SUCCESS;
}

static status_t vm_hash_table_get_bucket_entry(hash_table_t *hash_table, page_entry_t *self, hash_entry_t **next,
    hash_segment_t *seg, uint32 idx)
{
    if (vm_hash_table_get_bucket(hash_table, self, next, seg, idx) != CT_SUCCESS) {
        VM_CLOSE(HASH_SEGMENT, HASH_TABLE_ENTRY_VMID);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t vm_hash_table_move_bucket_node(hash_table_t *hash_table, hash_segment_t *seg, uint32 old_bucket,
    uint32 new_bucket)
{
    uint32 bucket_num;
    hash_node_t *hash_node = NULL;
    hash_node_t *l_node = NULL;
    hash_node_t *h_node = NULL;
    hash_entry_t *l_entry = NULL;
    hash_entry_t *h_entry = NULL;
    hash_entry_t *prev_next = NULL;
    page_entry_t l_vmid, h_vmid, tmp_vmid;
    page_entry_t l_node_vmid = g_invalid_page_entry;
    page_entry_t h_node_vmid = g_invalid_page_entry;
    status_t status = CT_SUCCESS;

    if (vm_hash_table_get_bucket_entry(hash_table, &l_vmid, &l_entry, seg, old_bucket) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (vm_hash_table_get_bucket_entry(hash_table, &h_vmid, &h_entry, seg, new_bucket) != CT_SUCCESS) {
        VM_CLOSE(HASH_SEGMENT, &l_vmid);
        return CT_ERROR;
    }
    prev_next = l_entry;

    while (prev_next->vmid != CT_INVALID_ID32) {
        if (vm_hash_table_get_node(&hash_node, prev_next, seg) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }
        tmp_vmid = prev_next->page;

        /* re-calc node bucket, if the new bucket is greater than old bucket_num,
         * the node should be moved to the right bucket.
         */
        bucket_num = vm_hash_table_calc_bucket(hash_table, hash_node->hash_value);
        if (bucket_num != old_bucket) {
            if (h_node != NULL) {
                h_node->next = *prev_next;
                VM_CLOSE(HASH_SEGMENT, &h_node_vmid);
            } else {
                *h_entry = *prev_next;
            }
            h_node = hash_node;
            h_node_vmid = tmp_vmid;
        } else {
            if (l_node != NULL) {
                l_node->next = *prev_next;
                VM_CLOSE(HASH_SEGMENT, &l_node_vmid);
            } else {
                *l_entry = *prev_next;
            }
            l_node = hash_node;
            l_node_vmid = tmp_vmid;
        }
        prev_next = &hash_node->next;
    }

    if (l_node == NULL) {
        l_entry->page = g_invalid_page_entry;
    }
    if (h_node == NULL) {
        h_entry->page = g_invalid_page_entry;
    }

    if (!IS_INVALID_PAGE_ENTRY(&l_node_vmid)) {
        l_node->next.page = g_invalid_page_entry;
        VM_CLOSE(HASH_SEGMENT, &l_node_vmid);
    }
    if (!IS_INVALID_PAGE_ENTRY(&h_node_vmid)) {
        h_node->next.page = g_invalid_page_entry;
        VM_CLOSE(HASH_SEGMENT, &h_node_vmid);
    }
    VM_CLOSE_TWO_PAGES(&l_vmid, &h_vmid);
    return status;
}

static status_t vm_hash_table_extend_entries(hash_table_t *hash_table, hash_segment_t *seg)
{
    id_list_t vm_list;
    char *page_buf = NULL;
    errno_t rc_memset;
    page_entry_t page_entry;

    // save last vm page
    vm_list = seg->vm_list;
    seg->vm_list.count = 0;

    if (vm_hash_alloc_page(seg, &page_entry) != CT_SUCCESS) {
        vm_append_list(HASH_POOL(seg), &seg->vm_list, &vm_list);
        return CT_ERROR;
    }
    hash_table->page_entries[hash_table->nentries++] = page_entry;

    if (VM_OPEN(HASH_SEGMENT, &page_entry, &page_buf) != CT_SUCCESS) {
        vm_append_list(HASH_POOL(seg), &seg->vm_list, &vm_list);
        return CT_ERROR;
    }
    rc_memset = memset_sp(page_buf, CT_VMEM_PAGE_SIZE, 0xFF, CT_VMEM_PAGE_SIZE);
    VM_CLOSE(HASH_SEGMENT, &page_entry);
    vm_append_list(HASH_POOL(seg), &seg->vm_list, &vm_list);
    if (rc_memset != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, rc_memset);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t vm_hash_table_extend(hash_table_t *hash_table, hash_segment_t *seg)
{
    uint32 old_bucket, new_bucket;
    uint32 page_entry;
    // calc bucket of (max_bucket+1) before extend
    old_bucket = vm_hash_table_calc_bucket(hash_table, hash_table->max_bucket + 1);
    // extend page entries if needed
    page_entry = (hash_table->max_bucket + 1) / HASH_BUCKETS_PER_PAGE;
    if (page_entry >= hash_table->nentries) {
        CT_RETURN_IFERR(vm_hash_table_extend_entries(hash_table, seg));
    }
    ++hash_table->max_bucket;
    if (hash_table->max_bucket > hash_table->high_mask) {
        hash_table->bucket_num <<= 1;
        hash_table->low_mask = hash_table->high_mask;
        hash_table->high_mask = hash_table->max_bucket | hash_table->low_mask;
    }
    // calc bucket of (max_bucket+1) after extend
    new_bucket = vm_hash_table_calc_bucket(hash_table, hash_table->max_bucket);
    // adjust node in old bucket
    if (vm_hash_table_move_bucket_node(hash_table, seg, old_bucket, new_bucket) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static inline bool32 vm_hash_table_need_extend(hash_table_t *hash_table)
{
    if (hash_table->rnums < (uint32)(int32)(hash_table->ffact * (hash_table->max_bucket + 1))) {
        return CT_FALSE;
    }
    if (hash_table->bucket_num == MAX_HASH_BUCKET_SIZE && hash_table->max_bucket == hash_table->high_mask) {
        return CT_FALSE;
    }
    return CT_TRUE;
}

status_t vm_hash_segment_insert(hash_node_t **node_out, hash_entry_t *prev_next, hash_segment_t *seg,
                                const char *buf, uint32 size, uint32 hash_value, bool32 is_new_key)
{
    char *page_buffer = NULL;
    page_entry_t page_entry;
    hash_node_t *hash_node = NULL;
    uint32 node_size, remain_size;
    int32 ret_memcpy;

    remain_size = CT_VMEM_PAGE_SIZE - HASH_LAST_PAGE_USED(seg);
    node_size = sizeof(hash_node_t) + size;
    if (node_size > remain_size) {
        CT_RETURN_IFERR(vm_hash_alloc_page(seg, &page_entry));
        HASH_LAST_PAGE_USED(seg) = 0;
        HASH_LAST_PAGE(seg) = page_entry;
    }

    CT_RETURN_IFERR(VM_OPEN(HASH_SEGMENT, &HASH_LAST_PAGE(seg), &page_buffer));

    hash_node = (hash_node_t *)(page_buffer + HASH_LAST_PAGE_USED(seg));

    hash_node->next.page = prev_next->page;
    hash_node->next.offset = prev_next->offset;
    prev_next->page = HASH_LAST_PAGE(seg);
    prev_next->offset = HASH_LAST_PAGE_USED(seg);

    hash_node->size = size;
    hash_node->is_new_key = is_new_key;
    hash_node->is_deleted = CT_FALSE;
    hash_node->unused = 0;
    hash_node->hash_value = hash_value;
    ret_memcpy = memcpy_sp(hash_node->data, size, buf, size);
    if (ret_memcpy != EOK) {
        VM_CLOSE(HASH_SEGMENT, &HASH_LAST_PAGE(seg));
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret_memcpy);
        return CT_ERROR;
    }

    HASH_LAST_PAGE_USED(seg) += node_size;

    if (node_out == NULL) {
        VM_CLOSE(HASH_SEGMENT, &HASH_LAST_PAGE(seg));
        return CT_SUCCESS;
    }
    *node_out = hash_node;
    return CT_SUCCESS;
}

status_t vm_hash_table_insert(bool32 *found, hash_segment_t *seg, hash_table_entry_t *table, const char *buf,
    uint32 size)
{
    hash_table_t *hash_table = NULL;
    hash_entry_t *prev_next = NULL;
    hash_node_t *hash_node = NULL;
    page_entry_t prev_vmid, tmp_vmid;
    uint32 bucket, hash_value;
    status_t ret;

    CT_RETURN_IFERR(vm_hash_table_get_head(&hash_table, seg, table));
    hash_table->is_empty = CT_FALSE;

    if (buf == NULL) { // for hash join optimize
        hash_table->has_null_key = CT_TRUE;
        VM_CLOSE(HASH_SEGMENT, &table->page);
        return CT_SUCCESS;
    }

    // extend hash table if necessary
    if (vm_hash_table_need_extend(hash_table)) {
        if (vm_hash_table_extend(hash_table, seg) != CT_SUCCESS) {
            VM_CLOSE(HASH_SEGMENT, &table->page);
            return CT_ERROR;
        }
    }

    hash_value = hash_table->hash(buf);
    bucket = vm_hash_table_calc_bucket(hash_table, hash_value);
    CT_RETURN_IFERR(vm_hash_table_get_bucket_entry(hash_table, &prev_vmid, &prev_next, seg, bucket));

    *found = CT_FALSE;

    while (!IS_INVALID_PAGE_ENTRY(&prev_next->page)) {
        if (vm_hash_table_get_node(&hash_node, prev_next, seg) != CT_SUCCESS) {
            VM_CLOSE_TWO_PAGES(&prev_vmid, &table->page);
            return CT_ERROR;
        }
        if (hash_value == hash_node->hash_value &&
            hash_table->equal(found, HASH_CALLBACK_CTX(hash_table), hash_node->data, hash_node->size, buf, size) != CT_SUCCESS) {
            VM_CLOSE_THREE_PAGES(&prev_next->page, &prev_vmid, &table->page);
            return CT_ERROR;
        }
        if (*found) {
            ++hash_table->rnums;
            ret = vm_hash_segment_insert(NULL, &hash_node->next, seg, buf, size, hash_value, CT_FALSE);
            VM_CLOSE_THREE_PAGES(&prev_next->page, &prev_vmid, &table->page);
            return ret;
        }
        tmp_vmid = prev_next->page;
        VM_CLOSE(HASH_SEGMENT, &prev_vmid);
        prev_vmid = tmp_vmid;
        prev_next = &hash_node->next;
    }

    *found = CT_FALSE;
    ++hash_table->rnums;
    ret = vm_hash_segment_insert(NULL, prev_next, seg, buf, size, hash_value, CT_TRUE);
    VM_CLOSE_TWO_PAGES(&prev_vmid, &table->page);
    return ret;
}

status_t vm_hash_table_insert2(bool32 *found, hash_segment_t *seg, hash_table_entry_t *table, const char *buf,
    uint32 size)
{
    hash_table_t *hash_table = NULL;
    hash_entry_t *prev_next = NULL;
    hash_node_t *hash_node = NULL;
    page_entry_t prev_vmid, tmp_vmid;
    uint32 bucket, hash_value;
    status_t ret;

    CT_RETURN_IFERR(vm_hash_table_get_head(&hash_table, seg, table));
    hash_table->is_empty = CT_FALSE;

    if (buf == NULL) { // for hash join optimize
        hash_table->has_null_key = CT_TRUE;
        VM_CLOSE(HASH_SEGMENT, &table->page);
        return CT_SUCCESS;
    }

    // extend hash table if necessary
    if (vm_hash_table_need_extend(hash_table)) {
        if (vm_hash_table_extend(hash_table, seg) != CT_SUCCESS) {
            VM_CLOSE(HASH_SEGMENT, &table->page);
            return CT_ERROR;
        }
    }

    hash_value = hash_table->hash(buf);
    bucket = vm_hash_table_calc_bucket(hash_table, hash_value);
    CT_RETURN_IFERR(vm_hash_table_get_bucket_entry(hash_table, &prev_vmid, &prev_next, seg, bucket));

    *found = CT_FALSE;

    while (!IS_INVALID_PAGE_ENTRY(&prev_next->page)) {
        if (vm_hash_table_get_node(&hash_node, prev_next, seg) != CT_SUCCESS) {
            VM_CLOSE_TWO_PAGES(&prev_vmid, &table->page);
            return CT_ERROR;
        }
        if (hash_value == hash_node->hash_value &&
            hash_table->equal(found, HASH_CALLBACK_CTX(hash_table), hash_node->data, hash_node->size, buf, size) != CT_SUCCESS) {
            VM_CLOSE_THREE_PAGES(&prev_next->page, &prev_vmid, &table->page);
            return CT_ERROR;
        }
        if (*found) {
            ret = hash_table->i_oper == NULL ?
                CT_SUCCESS :
                hash_table->i_oper(HASH_CALLBACK_CTX(hash_table), buf, size, hash_node->data, hash_node->size, CT_TRUE);
            VM_CLOSE_THREE_PAGES(&prev_next->page, &prev_vmid, &table->page);
            return ret;
        }
        tmp_vmid = prev_next->page;
        VM_CLOSE(HASH_SEGMENT, &prev_vmid);
        prev_vmid = tmp_vmid;
        prev_next = &hash_node->next;
    }

    *found = CT_FALSE;
    ++hash_table->rnums;
    if (vm_hash_segment_insert(&hash_node, prev_next, seg, buf, size, hash_value, CT_TRUE) != CT_SUCCESS) {
        VM_CLOSE_TWO_PAGES(&prev_vmid, &table->page);
        return CT_ERROR;
    }
    ret = hash_table->i_oper == NULL ? CT_SUCCESS :
        hash_table->i_oper(HASH_CALLBACK_CTX(hash_table), buf, size, hash_node->data, hash_node->size, CT_FALSE);
    VM_CLOSE_THREE_PAGES(&prev_next->page, &prev_vmid, &table->page);
    return ret;
}

#define IS_VALID_HASH_NODE(iter, node)                                                    \
    (((iter)->flags == 0) || ((iter)->flags == ITER_IGNORE_DEL && !(node)->is_deleted) || \
        ((iter)->flags == ITER_FETCH_DEL && (node)->is_deleted))

static status_t vm_hash_match_first_value(bool32 *found, hash_segment_t *seg, hash_table_t *hash_table,
    const char *key_buf, uint32 key_sz, hash_table_iter_t *iter)
{
    hash_node_t *hash_node = NULL;
    hash_entry_t *prev_next = NULL;
    page_entry_t prev_vmid, tmp_vmid;
    uint32 bucket, hash_value;

    hash_value = hash_table->hash(key_buf);
    bucket = vm_hash_table_calc_bucket(hash_table, hash_value);
    if (vm_hash_table_get_bucket_entry(hash_table, &prev_vmid, &prev_next, seg, bucket) != CT_SUCCESS) {
        return CT_ERROR;
    }

    while (!IS_INVALID_PAGE_ENTRY(&prev_next->page)) {
        if (vm_hash_table_get_node(&hash_node, prev_next, seg) != CT_SUCCESS) {
            VM_CLOSE(HASH_SEGMENT, &prev_vmid);
            return CT_ERROR;
        }
        if (IS_VALID_HASH_NODE(iter, hash_node)) {
            if (hash_table->equal(found, HASH_CALLBACK_CTX(hash_table),
                                  hash_node->data, hash_node->size, key_buf, key_sz) != CT_SUCCESS) {
                VM_CLOSE(HASH_SEGMENT, &prev_next->page);
                VM_CLOSE(HASH_SEGMENT, &prev_vmid);
                return CT_ERROR;
            }
            if (*found) {
                // if hash_table is not the root table, the caller should
                // assign the curr_match and curr_table to the root hash table
                iter->curr_match = *prev_next;
                VM_CLOSE(HASH_SEGMENT, &prev_next->page);
                VM_CLOSE(HASH_SEGMENT, &prev_vmid);
                return CT_SUCCESS;
            }
        }
        tmp_vmid = prev_next->page;
        VM_CLOSE(HASH_SEGMENT, &prev_vmid);
        prev_vmid = tmp_vmid;
        prev_next = &hash_node->next;
    }
    VM_CLOSE(HASH_SEGMENT, &prev_vmid);
    *found = CT_FALSE;
    iter->curr_match.page = g_invalid_page_entry;
    return CT_SUCCESS;
}

status_t vm_hash_table_probe(bool32 *eof, hash_segment_t *seg, hash_table_entry_t *table,
    hash_scan_assist_t *scan_assit)
{
    hash_table_t *hash_table = NULL;
    bool32 found = CT_FALSE;
    hash_table_iter_t iter;
    sql_init_hash_iter(&iter, NULL);

    CT_RETURN_IFERR(vm_hash_table_get_head(&hash_table, seg, table));

    if (scan_assit->scan_mode == HASH_FULL_SCAN) {
        *eof = hash_table->is_empty;
        VM_CLOSE(HASH_SEGMENT, &table->page);
        return CT_SUCCESS;
    }

    if (vm_hash_match_first_value(&found, seg, hash_table, HASH_KEY_SCAN_BUF(scan_assit),
                                  HASH_KEY_SCAN_SIZE(scan_assit), &iter) != CT_SUCCESS) {
        VM_CLOSE(HASH_SEGMENT, &table->page);
        return CT_ERROR;
    }
    VM_CLOSE(HASH_SEGMENT, &table->page);
    *eof = !found;
    return CT_SUCCESS;
}

status_t vm_hash_table_open(hash_segment_t *seg, hash_table_entry_t *table, hash_scan_assist_t *scan_assit,
    bool32 *found, hash_table_iter_t *iter)
{
    hash_table_t *hash_table = NULL;
    hash_entry_t *prev_next = NULL;
    page_entry_t prev_vmid;

    CT_RETURN_IFERR(vm_hash_get_hash_table(&hash_table, seg, table, iter));
    iter->scan_mode = scan_assit->scan_mode;

    if (scan_assit->scan_mode == HASH_FULL_SCAN) {
        if (vm_hash_table_get_bucket_entry(hash_table, &prev_vmid, &prev_next, seg, 0) != CT_SUCCESS) {
            VM_CLOSE(HASH_SEGMENT, &table->page);
            iter->hash_table = NULL;
            return CT_ERROR;
        }
        iter->curr_match = *prev_next;
        iter->curr_bucket = 0;
        VM_CLOSE(HASH_SEGMENT, &prev_vmid);
        return CT_SUCCESS;
    }

    if (vm_hash_match_first_value(found, seg, hash_table, HASH_KEY_SCAN_BUF(scan_assit),
                                  HASH_KEY_SCAN_SIZE(scan_assit), iter) != CT_SUCCESS) {
        VM_CLOSE(HASH_SEGMENT, &table->page);
        iter->hash_table = NULL;
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t vm_hash_table_full_fetch(bool32 *eof, hash_segment_t *seg, hash_table_t *hash_table,
                                  hash_table_iter_t *table_iter)
{
    hash_node_t *hash_node = NULL;
    hash_entry_t *prev_next = NULL;
    page_entry_t prev_vmid, tmp_vmid;
    status_t ret;
    void *callback_ctx = (table_iter->callback_ctx == NULL) ? HASH_CALLBACK_CTX(hash_table) : table_iter->callback_ctx;

    for (;;) {
        while (IS_INVALID_PAGE_ENTRY(&table_iter->curr_match.page)) {
            ++table_iter->curr_bucket;
            if (table_iter->curr_bucket > hash_table->max_bucket) {
                *eof = CT_TRUE;
                return CT_SUCCESS;
            }
            CT_RETURN_IFERR(vm_hash_table_get_bucket(hash_table, &prev_vmid, &prev_next, seg, table_iter->curr_bucket));
            table_iter->curr_match = *prev_next;
            VM_CLOSE(HASH_SEGMENT, &prev_vmid);
        }

        CT_RETURN_IFERR(vm_hash_table_get_node(&hash_node, &table_iter->curr_match, seg));
        CT_BREAK_IF_TRUE(IS_VALID_HASH_NODE(table_iter, hash_node));

        tmp_vmid = table_iter->curr_match.page;
        table_iter->curr_match = hash_node->next;
        VM_CLOSE(HASH_SEGMENT, &tmp_vmid);
    }

    ret = hash_table->q_oper == NULL ?
        CT_SUCCESS :
        hash_table->q_oper(callback_ctx, NULL, 0, hash_node->data, hash_node->size, CT_TRUE);
    if (ret != CT_SUCCESS) {
        VM_CLOSE(HASH_SEGMENT, &table_iter->curr_match.page);
        return CT_ERROR;
    }

    *eof = CT_FALSE;
    tmp_vmid = table_iter->curr_match.page;
    table_iter->curr_match = hash_node->next;
    VM_CLOSE(HASH_SEGMENT, &tmp_vmid);
    return CT_SUCCESS;
}

static status_t vm_hash_table_key_prefetch(hash_node_t *hash_node, hash_segment_t *seg, hash_table_iter_t *table_iter)
{
    page_entry_t tmp_vmid;
    hash_entry_t next_entry = hash_node->next;
    hash_node_t *next_node = NULL;

    while (!IS_INVALID_PAGE_ENTRY(&next_entry.page)) {
        // pre-fetch next record, check whether match
        if (vm_hash_table_get_node(&next_node, &next_entry, seg) != CT_SUCCESS) {
            VM_CLOSE(HASH_SEGMENT, &table_iter->curr_match.page);
            table_iter->curr_match.page = g_invalid_page_entry;
            return CT_ERROR;
        }

        if (next_node->is_new_key) {
            VM_CLOSE(HASH_SEGMENT, &next_entry.page);
            VM_CLOSE(HASH_SEGMENT, &table_iter->curr_match.page);
            table_iter->curr_match.page = g_invalid_page_entry;
            return CT_SUCCESS;
        }

        if (IS_VALID_HASH_NODE(table_iter, next_node)) {
            VM_CLOSE(HASH_SEGMENT, &next_entry.page);
            break;
        }

        tmp_vmid = next_entry.page;
        next_entry = next_node->next;
        VM_CLOSE(HASH_SEGMENT, &tmp_vmid);
    }

    tmp_vmid = table_iter->curr_match.page;
    table_iter->curr_match = next_entry;
    VM_CLOSE(HASH_SEGMENT, &tmp_vmid);
    return CT_SUCCESS;
}

status_t vm_hash_table_key_fetch(bool32 *eof, hash_segment_t *seg, hash_table_t *hash_table,
                                 hash_table_iter_t *table_iter)
{
    hash_node_t *hash_node = NULL;
    void *callbak_ctx = (table_iter->callback_ctx == NULL) ? HASH_CALLBACK_CTX(hash_table) : table_iter->callback_ctx;

    if (table_iter->curr_match.vmid == CT_INVALID_ID32) {
        *eof = CT_TRUE;
        return CT_SUCCESS;
    }

    *eof = CT_FALSE;
    if (vm_hash_table_get_node(&hash_node, &table_iter->curr_match, seg) != CT_SUCCESS) {
        return CT_ERROR;
    }

    /*
      callback operation function is used to deal with the record matched
      e.g., in this callback, hash-join can copy rowid(s) of materialized record(s) out
    */
    if (hash_table->q_oper != NULL &&
        hash_table->q_oper(callbak_ctx, NULL, 0, hash_node->data, hash_node->size, CT_TRUE) != CT_SUCCESS) {
        VM_CLOSE(HASH_SEGMENT, &table_iter->curr_match.page);
        return CT_ERROR;
    }

    // pre-fetch next record
    return vm_hash_table_key_prefetch(hash_node, seg, table_iter);
}

status_t vm_hash_table_fetch(bool32 *eof, hash_segment_t *seg, hash_table_entry_t *table, hash_table_iter_t *table_iter)
{
    hash_table_t *hash_table = NULL;

    CT_RETURN_IFERR(vm_hash_get_hash_table(&hash_table, seg, table, table_iter));
    if (table_iter->scan_mode == HASH_FULL_SCAN) {
        return vm_hash_table_full_fetch(eof, seg, hash_table, table_iter);
    } else {
        return vm_hash_table_key_fetch(eof, seg, hash_table, table_iter);
    }
}

status_t vm_hash_table_has_null_key(bool32 *has_null_key, hash_segment_t *seg, hash_table_entry_t *table)
{
    hash_table_t *hash_table = NULL;

    CT_RETURN_IFERR(vm_hash_table_get_head(&hash_table, seg, table));
    *has_null_key = hash_table->has_null_key;
    VM_CLOSE(HASH_SEGMENT, &table->page);
    return CT_SUCCESS;
}

status_t vm_hash_table_empty(bool32 *empty, hash_segment_t *seg, hash_table_entry_t *table)
{
    hash_table_t *hash_table = NULL;

    CT_RETURN_IFERR(vm_hash_table_get_head(&hash_table, seg, table));
    *empty = hash_table->is_empty;
    VM_CLOSE(HASH_SEGMENT, &table->page);
    return CT_SUCCESS;
}

status_t vm_hash_table_get_rows(uint32 *rnums, hash_segment_t *seg, hash_table_entry_t *table)
{
    hash_table_t *hash_table = NULL;

    CT_RETURN_IFERR(vm_hash_table_get_head(&hash_table, seg, table));
    *rnums = hash_table->rnums;
    VM_CLOSE(HASH_SEGMENT, &table->page);
    return CT_SUCCESS;
}

status_t vm_hash_table_delete(hash_segment_t *seg, hash_table_entry_t *table, hash_table_iter_t *table_iter)
{
    hash_node_t *hash_node = NULL;

    if (IS_INVALID_PAGE_ENTRY(&table_iter->curr_match.page)) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(vm_hash_table_get_node(&hash_node, &table_iter->curr_match, seg));

    hash_node->is_deleted = CT_TRUE;
    VM_CLOSE(HASH_SEGMENT, &table_iter->curr_match.page);
    return CT_SUCCESS;
}

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
 * dsw_shm.c
 *
 *
 * IDENTIFICATION
 * src/tse/message_queue/dsw_shm.c
 *
 * -------------------------------------------------------------------------
 */

#include <unistd.h>
#include <sys/syscall.h> /* For SYS_xxx definitions */
#include <stdio.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <fcntl.h>    /* For O_* constants */
#include <sys/stat.h> /* For mode constants */
#include <semaphore.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <sched.h>
#ifndef __USE_GNU
#define __USE_GNU
#endif
#include "dsw_shm_pri.h"
#include "shm_thread_pool.h"

static __thread int t_thread_num[MAX_SHM_SEG_NUM] = { 0 };
uint32_t g_thread_cool_time = 0;
pthread_t g_client_health_check_thd;

SHM_THREAD_POOL_T *g_shm_tpool = NULL;

#define gettid() syscall(__NR_gettid)

#define TOO_LONG_SLEEP_TIME (2000000000UL)
#define SHM_MQ_CHECK_INTERVAL (100000)  // 100ms
#define SHM_MQ_CHECK_BUSY_THRESHOLD (5)

typedef struct shm_hot_thread_params {
    int *is_hot_thread;
    uint32_t *hot_thread_num;
    int is_fixed;
    int is_done;
    struct timeval *last_work_time;
} hot_thread_params_t;

void *shm_malloc(size_t len)
{
    return malloc(len);
}

int shm_proc_is_alive(shm_proc_t *p)
{
    return p->state == SHM_PROC_STATE_WORKING;
}

int shm_proc_is_checking(shm_proc_t *p)
{
    return p->state == SHM_PROC_STATE_NEEDCHECKING;
}

int shm_get_proc_state(shm_proc_t *p)
{
    return p->state;
}

uint32_t shm_get_thread_cool_time(void)
{
    return g_thread_cool_time;
}

void shm_set_thread_cool_time(uint32_t time_us)
{
    g_thread_cool_time = time_us;
}

int sysv_is_shm(struct shm_seg_s *_seg, void *addr)
{
    long _addr = (long)addr;
    long start;
    struct shm_seg_sysv_s *seg = (struct shm_seg_sysv_s *)_seg->priv;

    if (seg == NULL) {
        LOG_SHM_ERROR("the segment is NULL!please check the code!");
        cm_panic(0);
        return 0;
    }
    start = (long)(seg->all_seg_shm);
    return _addr >= start && _addr < (start + SHM_MAX_LEN);
}

inline shm_mem_list_t *find_mem_list(shm_area_t *all_shm, size_t size, int *start_idx)
{
    for (int i = *start_idx; i < all_shm->head.nr_mem_class; i++) {
        if (all_shm->mem_list[i].size >= size) {
            *start_idx = i;
            return &all_shm->mem_list[i];
        }
    }
    return NULL;
}

mem_blk_hdr_t *shm_get_blk_from_list(struct shm_seg_sysv_s *seg, shm_mem_list_t *m)
{
    mem_blk_hdr_t   *hdr = NULL;
    uint32_t       shm_hdr;
    shm_free_list_t old_fl, new_fl;

    do {
        old_fl = ((volatile shm_mem_list_t *)m)->free_list;

        if (old_fl.head == SHM_NULL) {
            return NULL;
        }

        shm_hdr = old_fl.head;
        hdr = shm2ptr((char *)(seg->all_seg_shm), shm_hdr);  // find the head start address(offset address)
        cm_panic(hdr->hdr_magic == SHM_HDR_MAGIC);

        new_fl.head = hdr->next;  // this address in size_chain[]
        new_fl.fl_version = old_fl.fl_version + 1;

        // swap once and use new_dl.val assign to current free_list
    } while (__sync_val_compare_and_swap(&(m->free_list.val), old_fl.val, new_fl.val) != old_fl.val);

    hdr->list_id = m->list_id;
    return hdr;
}

void *_shm_alloc(struct shm_seg_sysv_s *seg, size_t size, int proc_id, int qbit_op)
{
    int mem_list_idx = 0;
    mem_blk_hdr_t *hdr = NULL;
    shm_mem_list_t *mem_list = find_mem_list(seg->all_seg_shm, size, &mem_list_idx);
    int match_list_idx = mem_list_idx;

    while (mem_list != NULL) {
        hdr = shm_get_blk_from_list(seg, mem_list);
        if (hdr == NULL && size == BIG_RECORD_SIZE) {
            return NULL;
        }
        if (hdr != NULL) {
            break;
        }
        mem_list_idx++;
        mem_list = find_mem_list(seg->all_seg_shm, size, &mem_list_idx);
    }

    if (mem_list == NULL) {
        LOG_SHM_ERROR("Alloc error!The size(%d) is not in the mem_class[] and buddy pool is NULL.", size);
        return NULL;
    }

    if (hdr == NULL) {
        LOG_SHM_ERROR("unexpected error, hdr is null, size(%d)", size);
        return NULL;
    }

    if (hdr->proc_id != -1) {
        LOG_SHM_ERROR("mem is already allocated, seg, hdr, mem_list_id(%d), mem_list_size(%d), size(%d)",
                      mem_list->list_id, mem_list->size, size);
        cm_panic(0);
        return NULL;
    }

    hdr->proc_id = proc_id;
    hdr->flags |= SHM_BF_INFL;
    return (void *)(hdr + 1);
}

void *shm_sysv_alloc(struct shm_seg_s *_seg, size_t size)
{
    struct shm_seg_sysv_s *seg = (struct shm_seg_sysv_s *)_seg->priv;
    void *ret = NULL;

    if (seg == NULL) {
        LOG_SHM_ERROR("the segment is NULL!please check the code!");
        cm_panic(0);
        return NULL;
    }
    ret = _shm_alloc(seg, size, seg->seg_proc, SHM_QBIT_NOP);
    return ret;
}

void shm_sysv_free(struct shm_seg_s *_seg, void *blk)
{
    struct shm_seg_sysv_s *seg = (struct shm_seg_sysv_s *)_seg->priv;
    shm_mem_list_t *m = NULL;
    mem_blk_hdr_t *hdr = NULL;
    uint64_t old_ref, new_ref, proc_ref;
    shm_free_list_t old_fl, new_fl;
    shm_area_t *all_seg_shm = NULL;

    if (seg == NULL) {
        LOG_SHM_ERROR("the segment is NULL!please check the code!");
        cm_panic(0);
    }
    if (sysv_is_shm(seg->_seg, blk) == 0) {
        LOG_SHM_ERROR("address error ! the blk is not in the shm_area");
        cm_panic(0);
    }

    hdr = (mem_blk_hdr_t *)((char *)blk - sizeof(mem_blk_hdr_t));
    if (hdr->hdr_magic != SHM_HDR_MAGIC) {
        LOG_SHM_ERROR("hdr->hdr_magic = 0x%x", hdr->hdr_magic);
        cm_panic(0);
    }

    if (hdr->proc_id == -1) {
        LOG_SHM_ERROR("mem is already free");
        cm_panic(0);
    }

    hdr->flags &= ~SHM_BF_INFL;
    hdr->proc_id = -1;
    all_seg_shm = seg->all_seg_shm;

    /* put block back to the free list */
    m = &(all_seg_shm)->mem_list[hdr->list_id];
    do {
        old_fl = ((volatile shm_mem_list_t *)m)->free_list;
        hdr->next = old_fl.head;
        new_fl.head = ptr2shm((char *)all_seg_shm, hdr);
        new_fl.fl_version = old_fl.fl_version + 1;
    } while (!__sync_bool_compare_and_swap(&(m->free_list.val), old_fl.val, new_fl.val)); // the same to __shm_alloc
}

int _shm_send_msg(struct shm_seg_sysv_s *seg, int proc_id, dsw_message_block_t *msg)
{
    shm_area_t *all_seg_shm = seg->all_seg_shm;
    shm_proc_t *p = &all_seg_shm->procs[proc_id];
    mem_blk_hdr_t   *hdr = NULL;
    uint32_t       shm_hdr;
    shm_rcvq_t      old_q, new_q;

    hdr = (mem_blk_hdr_t *)((char *)msg - sizeof(mem_blk_hdr_t));
    shm_hdr = ptr2shm((char *)(all_seg_shm), hdr);
                             
    do {
        old_q = *(volatile shm_rcvq_t *)(&p->rcvq_high);

        hdr->next = old_q.q_head;
        new_q.q_head = shm_hdr;
        new_q.q_version = old_q.q_version + 1;
    } while (!__sync_bool_compare_and_swap(&p->rcvq_high.val, old_q.val, new_q.val));
    __sync_fetch_and_add(&p->waiting_msg_num, 1);
    sem_post(&p->sem);

    return 0;
}


#define SHM_SEND_ALLOC(ret, size, seg, alloc_blks, nr_alloc) do {                  \
    ret = _shm_alloc((seg), (size), -1, SHM_QBIT_SET);                             \
    if ((ret) == NULL) goto err;                                                   \
    (alloc_blks)[(nr_alloc)++] = ret;                                              \
} while (0)

int shm_sysv_send_msg(struct shm_seg_s *_seg, int proc_id, dsw_message_block_t *msg)
{
    struct shm_seg_sysv_s *seg = (struct shm_seg_sysv_s *)_seg->priv;
    dsw_message_block_t *shm_msg = NULL;
    int i, ret = -1;
    void *seg_shm = NULL;
    void *alloc_blks[DSW_MESSAGE_SEGMENT_NUM_MAX] = { 0 };  // can send four messages at a time
    int nr_alloc = 0;

    if ((proc_id < 0) || (proc_id >= MAX_SHM_PROC)) {
        LOG_SHM_ERROR("the proc_id is %d !please check the code!", proc_id);
        cm_panic(0);
    }

    shm_wait_recovering(&seg->all_seg_shm->head.recovering);

    /*if the mem not in the shm , do copy*/
    if (!sysv_is_shm(seg->_seg, msg)) {
        SHM_SEND_ALLOC(shm_msg, sizeof(dsw_message_block_t), seg, alloc_blks, nr_alloc);
        memcpy_s(shm_msg, sizeof(dsw_message_block_t), msg, sizeof(*msg));
    } else {
        shm_msg = msg;
    }

    for (i = 0; i < msg->head.seg_num; i++) {
        if (sysv_is_shm(seg->_seg, msg->seg_buf[i])) {
            continue;
        }
        if (shm_msg == NULL) {
            SHM_SEND_ALLOC(shm_msg, sizeof(dsw_message_block_t), seg, alloc_blks, nr_alloc);
            memcpy_s(shm_msg, sizeof(dsw_message_block_t), msg, sizeof(*msg));
        }
        SHM_SEND_ALLOC(seg_shm, msg->head.seg_desc[i].length, seg, alloc_blks, nr_alloc);
        ret = memcpy_s(seg_shm, sizeof(dsw_message_block_t), msg->seg_buf[i], msg->head.seg_desc[i].length);
        if (ret != EOK) {
            LOG_SHM_ERROR("memcpy_s msg seg_buf error, err_no: %d", ret)
            goto err;
        }
        shm_msg->seg_buf[i] = seg_shm;
    }

    if (shm_msg == NULL) {
        shm_msg = msg;
    }

    ret = _shm_send_msg(seg, proc_id, shm_msg);

err:
    if (ret < 0) {
        cm_panic(shm_msg != NULL);
        for (i = 0; i < nr_alloc; i++) {
            shm_sysv_free((struct shm_seg_s *)seg, alloc_blks[i]);
        }
    }

    return ret;
}

/*Reverse the recv list*/
uint32_t reverse_list(shm_area_t *all_shm, uint32_t head, uint64_t *qlen, uint64_t *msg)
{
    uint32_t       curr, next, tmp;
    mem_blk_hdr_t   *p_curr = NULL, *p_next = NULL;
    uint64_t        i = 0;

    curr = head;
    p_curr = (mem_blk_hdr_t *)shm2ptr((char *)all_shm, curr);
    next = p_curr->next;
    p_curr->next = SHM_NULL;
    while (next != SHM_NULL) {
        *qlen += i;
        i++;
        p_next = (mem_blk_hdr_t *)shm2ptr((char *)all_shm, next);
        tmp = p_next->next;
        p_next->next = curr;

        curr = next;
        next = tmp;
    }
    *msg += i;

    return curr;
}

static void deal_msg(uint32_t q_head, struct shm_seg_s *_seg,
    int (*recv_msg)(struct shm_seg_s *, dsw_message_block_t *))
{
    mem_blk_hdr_t *hdr = NULL;
    dsw_message_block_t *msg = NULL;
    struct shm_seg_sysv_s *seg = (struct shm_seg_sysv_s *)_seg->priv;
    struct shm_seg_s *client_seg = g_seg_array[g_current_seg_num - 1]->_seg;
    uint32_t q_temp = q_head;
    while (q_temp != SHM_NULL) {
        hdr = shm2ptr((char *)(seg->all_seg_shm), q_temp);
        q_temp = hdr->next;
        msg = (dsw_message_block_t *)((char *)hdr + sizeof(mem_blk_hdr_t));
        int src = msg->head.src_nid;
        if  (src < MIN_SHM_PROC || src >= MAX_SHM_PROC) {
            LOG_SHM_ERROR("the src_nid %d is invaild", src);
            continue;
        }
        if (src < MYSQL_PROC_START) {
            recv_msg(_seg, msg);
            continue;
        }
        int *clean_up_flag = get_clean_up_flag(seg->seg_id, src);
        int *client_id_list = get_client_id_list();
        int shm_client_status = client_id_list[src];
        __sync_add_and_fetch(clean_up_flag, 1);
        if (shm_client_status == SHM_CLIENT_STATUS_WORKING || shm_client_status == SHM_CLIENT_STATUS_CONNECTING) {
            recv_msg(_seg, msg);
        }
        __sync_add_and_fetch(clean_up_flag, -1);
    }
}

static void hot_thread_cool(hot_thread_params_t *hot_thread_arg, shm_proc_t *p, struct shm_seg_sysv_s *seg)
{
    int *is_hot_thread = hot_thread_arg->is_hot_thread;
    uint32_t *hot_thread_num = hot_thread_arg->hot_thread_num;
    int is_fixed = hot_thread_arg->is_fixed;
    struct timeval *last_work_time = hot_thread_arg->last_work_time;

    struct timeval current_time;
    int idle_time;
    uint32_t cool_time = shm_get_thread_cool_time();

    if (!(*is_hot_thread)) {
        int new_hot_thread_num = __sync_add_and_fetch(hot_thread_num, 1);
        if (new_hot_thread_num == 1) {
            *is_hot_thread = 1;
            gettimeofday(last_work_time, NULL);
            return;
        } else if (new_hot_thread_num > 1) {
            __sync_sub_and_fetch(hot_thread_num, 1);
            if (((volatile shm_rcvq_t *)(&p->rcvq_high))->q_head != SHM_NULL) {
                return;
            }
            if (!is_fixed) {
                hot_thread_arg->is_done = 1;
                return;
            }
            sem_wait(&p->sem);
        } else {
            LOG_SHM_ERROR("hot thread num %d", new_hot_thread_num);
        }
    } else {
        gettimeofday(&current_time, NULL);
        idle_time = 1000000 * (current_time.tv_sec - (*last_work_time).tv_sec) +
            current_time.tv_usec - (*last_work_time).tv_usec;
        if (idle_time > cool_time) {
            *is_hot_thread = 0;
            __sync_sub_and_fetch(hot_thread_num, 1);
            sched_yield();
            if (((volatile shm_rcvq_t *)(&p->rcvq_high))->q_head != SHM_NULL) {
                return;
            }
            sem_wait(&p->sem);
        } else {
            sched_yield();
        }
    }
    if (!seg->running) {
        hot_thread_arg->is_done = 1;
        return;
    }
}

static void *shm_proc_func(void *arg)
{
    uint32_t       q_head, r_head;
    shm_rcvq_t      old_q, new_q;
    int             i;
    shm_arg_proc_t *arg_proc = (shm_arg_proc_t *)arg;
    shm_proc_t *p = arg_proc->proc;
    struct shm_seg_s *_seg = arg_proc->seg;
    struct shm_seg_sysv_s *seg = (struct shm_seg_sysv_s *)_seg->priv;

    int thd_id = __sync_fetch_and_add(&p->running_thd_num, 1);
    int is_fixed = 0;
    if (thd_id < p->fixed_thd_num) {
        is_fixed = 1;
        pthread_setaffinity_np(pthread_self(), sizeof(*arg_proc->mask), arg_proc->mask);
    }

    hot_thread_params_t *hot_thread_arg = (hot_thread_params_t *)malloc(sizeof(hot_thread_params_t));
    if (hot_thread_arg == NULL) {
        LOG_SHM_ERROR("shm_proc_func malloc failed");
        cm_panic(0);
        return NULL;
    }

    struct timeval last_work_time;
    mem_blk_hdr_t *q_head_hdr;
    int is_hot_thread = 0;
    uint32_t *hot_thread_num = &(p->hot_thd_num);

    hot_thread_arg->hot_thread_num = hot_thread_num;
    hot_thread_arg->is_fixed = is_fixed;
    hot_thread_arg->is_hot_thread = &is_hot_thread;
    hot_thread_arg->is_done = 0;
    hot_thread_arg->last_work_time = &last_work_time;

    int is_done = 0;

    while (seg->running) {
        while (((volatile shm_rcvq_t *)(&p->rcvq_high))->q_head == SHM_NULL) {
            hot_thread_cool(hot_thread_arg, p, seg);
            if (hot_thread_arg->is_done) {
                goto done;
            }
        }

        do {
            old_q = *(volatile shm_rcvq_t *)(&p->rcvq_high);
            if (old_q.q_head == SHM_NULL) {
                break;
            }
            q_head_hdr = shm2ptr((char *)(seg->all_seg_shm), old_q.q_head);
            new_q.q_head = q_head_hdr->next;
            new_q.q_version = old_q.q_version + 1;
        } while (!__sync_bool_compare_and_swap(&p->rcvq_high.val, old_q.val, new_q.val));

        if (old_q.q_head == SHM_NULL) {
            continue;
        }
        __sync_fetch_and_sub(&p->waiting_msg_num, 1);
        if (is_hot_thread) {
            is_hot_thread = 0;
            __sync_fetch_and_sub(hot_thread_num, 1);
        }
        q_head_hdr = shm2ptr((char *)(seg->all_seg_shm), old_q.q_head);
        q_head_hdr->next = SHM_NULL;
        q_head = old_q.q_head;
        deal_msg(q_head, _seg, p->recv_msg);
    }

done:
    __sync_fetch_and_sub(&p->running_thd_num, 1);
    if (is_hot_thread) {
        is_hot_thread = 0;
        __sync_fetch_and_sub(&p->hot_thd_num, 1);
    }
    __sync_fetch_and_sub(&seg->nr_proc, 1);
    free(hot_thread_arg);
    free(arg);
    return NULL;
}

int shm_create_recv_threads(struct shm_seg_sysv_s *seg, int thread_num, shm_proc_t *p, cpu_set_t *mask)
{
    int i, ret = 0;

    for (i = 0; i < thread_num; i++) {
        /* this struct point will be free in thread of proc */
        shm_arg_proc_t *arg = (shm_arg_proc_t *)malloc(sizeof(shm_arg_proc_t));
        if (arg == NULL) {
            LOG_SHM_ERROR("[shm] shm_arg_proc_t malloc failed");
            return -1;
        }
        arg->proc = p;
        arg->seg = seg->_seg;
        arg->mask = mask;

        SHM_THREAD_JOB_T job = { shm_proc_func, arg };
        // job.handler = shm_proc_func;
        // job.args = arg;
        ret = shm_add_job_to_thread_pool(g_shm_tpool, &job);
        if (ret != 0) {
            LOG_SHM_ERROR("[shm] seg_shm thread %d is failed!", i);
            free(arg);
            return -1;
        }
        __sync_fetch_and_add(&seg->nr_proc, 1);
    }
    return 0;
}

void *shm_thd_scheduler_func(void *arg)
{
    shm_arg_proc_t *arg_proc = (shm_arg_proc_t *)arg;
    shm_proc_t *p = arg_proc->proc;
    int busy_cnt = 0;
    struct shm_seg_s *_seg = arg_proc->seg;
    struct shm_seg_sysv_s *seg = (struct shm_seg_sysv_s *)_seg->priv;
    int ret = shm_create_recv_threads(seg, p->fixed_thd_num, p, arg_proc->mask);
    if (ret != 0) {
        LOG_SHM_ERROR("init recv thds failed, proc_id(%d), thd_num(%d), ret(%d)", p->proc_id,
                      p->fixed_thd_num, ret);
        pthread_detach(pthread_self()); /* restore thread resource */
        free(arg);
        return NULL;
    }
    if (!arg_proc->is_dynamic) {
        pthread_detach(pthread_self()); /* restore thread resource */
        free(arg);
        return NULL;
    }
    while (seg->running) {
        int waiting_msg_num = p->waiting_msg_num;
        if (waiting_msg_num > 0) {
            if (busy_cnt < SHM_MQ_CHECK_BUSY_THRESHOLD) {
                busy_cnt++;
                usleep(SHM_MQ_CHECK_INTERVAL);
                continue;
            }
            LOG_SHM_INFO_LIMIT(SHM_LOG_INTERVAL_SECOND_20, "scheduler: create recv thd. proc_id(%d), thd_num(%d)",
                               p->proc_id, waiting_msg_num);
            if (shm_create_recv_threads(seg, waiting_msg_num, p, arg_proc->mask) != 0) {
                LOG_SHM_ERROR("init recv thds failed, proc_id(%d), waiting_msg_num(%d).", p->proc_id, waiting_msg_num);
            }
        }
        busy_cnt = 0;
        sched_yield();
        usleep(SHM_MQ_CHECK_INTERVAL);
    }
    pthread_detach(pthread_self()); /*restore thread resource*/
    free(arg);
    return NULL;
}

int shm_create_scheduler_thread(struct shm_seg_sysv_s *seg, shm_proc_t *p, cpu_set_t *mask, int is_dynamic)
{
    pthread_t scheduler_thd;
    shm_arg_proc_t *arg = (shm_arg_proc_t *)shm_malloc(sizeof(shm_arg_proc_t));
    if (arg == NULL) {
        LOG_SHM_ERROR("arg == NULL, malloc failed, please check malloc!! porc_id=%d", p->proc_id);
        return -1;
    }

    pthread_attr_t shm_attr;
    struct sched_param sched;
    int ret = pthread_attr_init(&shm_attr);
    if (ret != 0) {
        LOG_SHM_ERROR("[shm] init attr error, ret=%d, porc_id=%d", ret, p->proc_id);
    }
    ret = pthread_attr_getschedparam(&shm_attr, &sched);
    if (ret != 0) {
        LOG_SHM_ERROR("[shm] get attr sched ERROR, ret=%d, porc_id=%d", ret, p->proc_id);
    }
    ret = pthread_attr_setschedpolicy(&shm_attr, SCHED_RR);
    if (ret != 0) {
        LOG_SHM_ERROR("[shm] set arrt schedpolicy ERROR, ret=%d, porc_id=%d", ret, p->proc_id);
    }

    sched.sched_priority = sched_get_priority_max(SCHED_RR);

    ret = pthread_attr_setschedparam(&shm_attr, &sched);
    if (ret != 0) {
        LOG_SHM_ERROR("[shm] set attr sched ERROR, ret=%d, porc_id=%d", ret, p->proc_id);
    }

    arg->proc = p;
    arg->seg = seg->_seg;
    arg->mask = mask;
    arg->is_dynamic = is_dynamic ? 1 : 0;
    ret = pthread_create(&scheduler_thd, &shm_attr, shm_thd_scheduler_func, (void *)arg);
    if (ret != 0) {
        LOG_SHM_ERROR("[shm] start scheduler failed, proc_id(%d).", p->proc_id);
        free(arg);
        return ret;
    }
    return 0;
}

/********* the code is for unix_socket**********/
#define SHM_CLIENT_EPOLL_NUM (2)

static int shm_app_epoll_func(int listen_fd)
{
    int epoll_ret = -1;
    struct epoll_event shm_evs[SHM_CLIENT_EPOLL_NUM];

    int shm_app_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (shm_app_epoll_fd < 0) {
        LOG_SHM_ERROR("[shm] create epoll failed, shm_app_epoll_fd(%d), errno(%d)", shm_app_epoll_fd, errno);
        return -1;
    }

    if (shm_add_epoll_events(shm_app_epoll_fd, listen_fd, (uint32_t)EPOLLRDHUP) < 0) {
        LOG_SHM_ERROR("[shm] add_epoll_events fail, clientfd(%d)", listen_fd);
        close(shm_app_epoll_fd);
        return -1;
    }

    for (;;) {
        epoll_ret = epoll_wait(shm_app_epoll_fd, shm_evs, SHM_CLIENT_EPOLL_NUM, 100);
        if (epoll_ret < 0) {
            if (EINTR == errno) {
                /* interupt input, log and continue */
                LOG_SHM_INFO("[shm] epoll_wait interrupted by system call, wait again");
                continue;
            } else {
                /* any error will be try connect */
                LOG_SHM_ERROR("[shm] epoll_wait fail, errno(%d)", errno);
                break;
            }
        }

        /*  deal even information */
        if (epoll_ret > 0) {
            LOG_SHM_ERROR("[shm] the connection to master have been disconnected by master, will abort");
            close(shm_app_epoll_fd);
            return -1;
        }
    }

    if (shm_del_epoll_events(shm_app_epoll_fd, listen_fd, (uint32_t)EPOLLRDHUP) < 0) {
        LOG_SHM_ERROR("[shm] shm_del_epoll_events failed, cli_fd(%d)", listen_fd);
        close(shm_app_epoll_fd);
        return -1;
    }

    close(shm_app_epoll_fd);
    return 0;
}

int shm_send_all(int sd, char *buf, int len)
{
    int ret, sendp = 0;
    while (sendp < len) {
        ret = send(sd, buf + sendp, len - sendp, MSG_NOSIGNAL);
        if (ret <= 0) {
            LOG_SHM_ERROR("the proc_id send failed, ret = %d, errno = %d, %s", ret, errno, strerror(errno));
            return ret;
        }
        sendp += ret;
    }
    return sendp;
}

int shm_recv_all(int sd, char *buf, int len)
{
    int ret, rcvp = 0;

    while (rcvp < len) {
        ret = recv(sd, buf + rcvp, len - rcvp, 0);
        if (ret < 0) {
            LOG_SHM_ERROR("the proc_id recv failed, ret = %d, errno = %d, %s", ret, errno, strerror(errno));
            return -1;
        } else if (ret == 0) {
            LOG_SHM_ERROR("the socket connection is closed by remote peer.");
            return -1;
        }

        rcvp += ret;
    }
    return rcvp;
}

int shm_create_and_init_socket(void)
{
    int cli_fd = -1;
    struct linger sSockOptLinger;
    // create socket
    cli_fd = socket(AF_UNIX, ((int)SOCK_STREAM | (int)SOCK_CLOEXEC), 0);
    if (cli_fd < 0) {
        LOG_SHM_ERROR("[shm] socket create failed, errno=(%d)", errno);
        return -1;
    }

    sSockOptLinger.l_onoff = 0;
    sSockOptLinger.l_linger = 0;
    if (setsockopt(cli_fd, SOL_SOCKET, SO_LINGER, &sSockOptLinger, (socklen_t)sizeof(sSockOptLinger)) < 0) {
        LOG_SHM_ERROR("[shm] setsockopt SO_LINGER fail, cli_fd(%d), errno(%d)", cli_fd, errno);
        close(cli_fd);
        return -1;
    }
    return cli_fd;
}

void *shm_client_health_check_func(void *_arg)
{
    int client_id = -1;
    char socket_name[SHM_PATH_MAX] = { '\0' };
    struct sockaddr_un shm_app_uaddr;
    socklen_t iSrvAddrLen;
    client_health_check_arg_t *arg = (client_health_check_arg_t *)_arg;
    shm_key_t *shm_key = arg->shm_key;
    pthread_detach(pthread_self());
    LOG_SHM_INFO("[shm] client health check thread start.");
    // init socket
    int cli_fd = shm_create_and_init_socket();
    if (cli_fd < 0) {
        LOG_SHM_ERROR("[SHM] shm_create_and_init_socket failed");
        cm_panic(0);
    }

    // socket connect
    if (snprintf_s(socket_name, SHM_PATH_MAX, SHM_PATH_MAX - 1, "%s/%s.%s", MQ_SHM_MMAP_DIR,
        shm_key->shm_name, SHM_SOCK_NAME) < 0) {
        LOG_SHM_ERROR("[shm] build socket name failed! shm_name(%s)", shm_key->shm_name);
        cm_panic(0);
    }

    memset_s(&shm_app_uaddr, sizeof(struct sockaddr_un), 0, sizeof(struct sockaddr_un));
    shm_app_uaddr.sun_family = AF_UNIX;
    int ret = strcpy_s(shm_app_uaddr.sun_path, sizeof(shm_app_uaddr.sun_path), socket_name);
    if (ret != 0) {
        LOG_SHM_ERROR("[shm] strcpy_s failed. %d", ret);
        cm_panic(0);
    }

    iSrvAddrLen = (socklen_t)sizeof(shm_app_uaddr.sun_family) + (socklen_t)strlen(shm_app_uaddr.sun_path);
    ret = connect(cli_fd, (struct sockaddr *)&shm_app_uaddr, (uint32_t)iSrvAddrLen);
    if (ret < 0) {
        LOG_SHM_ERROR("[SHM] socket connect fail, socket_name(%s), cli_fd(%d), errno(%d)", socket_name, cli_fd, errno);
        cm_panic(0);
    }

    // 接受clientid分配消息
    if (shm_recv_all(cli_fd, (char *)&client_id, sizeof(int)) < 0) {
        LOG_SHM_ERROR("[SHM] get client_id form socket failed, cli_fd(%d)", cli_fd);
        close(cli_fd);
        cm_panic(0);
    }
    *(arg->client_id) = client_id;
    sem_post(&arg->sem);
    LOG_SHM_INFO("[shm] the shm connect successful, client_id(%d)", client_id);
    // epoll监听
    if (shm_app_epoll_func(cli_fd) < 0) {
        LOG_SHM_ERROR("[SHM] epoll have been got an error, client must to exit. client_id(%d)", client_id);
        close(cli_fd);
        cm_panic(0);
    }

    LOG_SHM_INFO("[shm] client health check thread exit.");
    pthread_join(pthread_self(), NULL);
    return NULL;
}

int shm_start_client_health_check_thread(shm_key_t *shm_key, int *client_id)
{
    client_health_check_arg_t *arg = malloc(sizeof(client_health_check_arg_t));
    if (arg == NULL) {
        LOG_SHM_ERROR("[shm] mem alloc failed");
        return -1;
    }
    arg->shm_key = shm_key;
    arg->client_id = client_id;
    sem_init(&arg->sem, 1, 0);

    if (pthread_create(&g_client_health_check_thd, NULL, shm_client_health_check_func, (void *)arg) < 0) {
        free(arg);
        LOG_SHM_ERROR("[shm] pthread_create error, errno(%d)", errno);
        return -1;
    }
    sem_wait(&arg->sem);
    free(arg);
    return 0;
}

int shm_client_connect(shm_key_t *shm_key, int *client_id)
{
    return shm_start_client_health_check_thread(shm_key, client_id);
}

void shm_client_disconnect(void)
{
    pthread_cancel(g_client_health_check_thd);
}

/*****************************************/

int shm_proc_start_judgement(struct shm_seg_sysv_s *seg, shm_proc_t *p, int proc_id)
{
    if (seg->_seg->type != SHM_KEY_IV) { /* judge app is or not double start <unix domain socket>*/
        if (!(shm_proc_is_alive(p) || shm_proc_is_checking(p))) {
            while (seg->all_seg_shm->head.recovering == 1) {
                LOG_SHM_INFO("the state = %d, recovering = %d , start wait master do with it.", shm_get_proc_state(p),
                             seg->all_seg_shm->head.recovering);
                usleep(100 * 1000);
            }
        } else {
            LOG_SHM_ERROR("the seg[mmap_name: %s ] proc_id = %d has been double started!", seg->shm_key.mmap_name,
                          proc_id);
            return -1;
        }
    } else { /*timer tick*/
        if (p->last_ticks <= SHM_MASTER_LIMIT_TICK) {
            LOG_SHM_ERROR("the proc_id = %d process may have alive. please check the code! tick = %d", proc_id,
                          p->last_ticks);
            return -1;
        }

        while (p->last_ticks != SHM_NULL_TICK || seg->all_seg_shm->head.recovering == 1) {
            LOG_SHM_INFO("the p->last_ticks = 0x%x, recovering = %d , start wait master do with it.", p->last_ticks,
                         seg->all_seg_shm->head.recovering);
            usleep(100 * 1000);
        }
        p->last_ticks = 0;
    }
    return 0;
}

int shm_sysv_proc_start(struct shm_seg_s *_seg, int proc_id, int thread_num, cpu_set_t *mask, int is_dynamic,
                        int (*recv_msg)(struct shm_seg_s *, dsw_message_block_t *))
{
    struct shm_seg_sysv_s *seg = (struct shm_seg_sysv_s *)_seg->priv;
    shm_proc_t *p = NULL;
    shm_area_t *all_seg_shm = NULL;
    int ret = -1;

    if (seg == NULL) {
        LOG_SHM_ERROR("the segment is NULL!please check the code!");
        cm_panic(0);
        return -1;
    }

    if (g_shm_tpool == NULL || g_shm_tpool->status != SHM_STATUS_RUNNING) {
        LOG_SHM_ERROR("[shm] the mq tpool is abnormal");
        cm_panic(0);
        return -1;
    }

    if ((proc_id < 0) || (proc_id >= MAX_SHM_PROC)) {
        LOG_SHM_ERROR("the proc_id is %d !please check the code!", proc_id);
        cm_panic(0);
        return -1;
    }

    if (thread_num > SHM_MAX_THREAD_NUM || thread_num < 1) {
        LOG_SHM_ERROR("please input the number between 1-64, now the number is 1");
        return ret;
    }

    if (recv_msg == NULL) {
        LOG_SHM_ERROR("the recv_msg is NULL.");
        return -1;
    }

    seg->running = 1;
    all_seg_shm = seg->all_seg_shm;
    p = &all_seg_shm->procs[proc_id];
    seg->seg_proc = proc_id;
    p->proc_id = proc_id;

    if (shm_proc_start_judgement(seg, p, proc_id) < 0) {
        return -1;
    }

    if (seg->running == 0) {
        LOG_SHM_ERROR("shm_start_watch_thread func have been failed.");
        return -1;
    }

    p->version = 0;
    p->last_ticks = SHM_NULL_TICK;
    p->rcvq_high.q_head = SHM_NULL;
    p->rcvq_high.q_version = 0;
    p->rcvq_normal.q_head = SHM_NULL;
    p->rcvq_normal.q_version = 0;
    p->shm_ref = 0;
    p->recv_msg = recv_msg;
    p->fixed_thd_num = thread_num;

    ret = shm_create_scheduler_thread(seg, p, mask, is_dynamic);
    if (ret != 0) {
        LOG_SHM_ERROR("[shm] shm_create_scheduler_thread func have been failed.");
    }
    return ret;
}

int shm_tpool_init(int thd_num)
{
    if (g_shm_tpool != NULL) {
        LOG_SHM_ERROR("[shm] thread pool is already inited");
        return -1;
    }

    CREATE_SHM_THREAD_POOL_PARAMS_T param = { thd_num };
    return shm_create_thread_pool(&param, &g_shm_tpool);
}

void shm_tpool_destroy(void)
{
    if (g_shm_tpool == NULL) {
        LOG_SHM_ERROR("[shm] thread pool is null");
        cm_panic(0);
    }

    shm_destroy_thread_pool(&g_shm_tpool);
    g_shm_tpool = NULL;
}

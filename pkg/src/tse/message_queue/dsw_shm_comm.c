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
 * dsw_shm_comm.c
 *
 *
 * IDENTIFICATION
 * src/tse/message_queue/dsw_shm_comm.c
 *
 * -------------------------------------------------------------------------
 */

#include <unistd.h>
#include <stdio.h>
#include <sys/shm.h>
#include <semaphore.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "dsw_shm_pri.h"
#include "dsw_shm_comm_pri.h"

#define SHM_END_ADDR (SHM_ADDR + SHM_MAX_SIZE * MAX_SHM_SEG_NUM)

static struct shm_ops_s *shm_ops[SHM_KEY_MAX] = {
    [0] = NULL,
    [SHM_KEY_SYSV] = &g_shm_sysv_ops,
    [SHM_KEY_MMAP] = &g_shm_sysv_ops,
};

static void shm_log_printer(char *log_info, int length);
static pthread_mutex_t g_shm_log_mutex = PTHREAD_MUTEX_INITIALIZER;
static void (*g_shm_info_log_printer)(char *, int) = shm_log_printer;
static void (*g_shm_error_log_printer)(char *, int) = shm_log_printer;
struct shm_seg_s            *g_slot2seg[MAX_SHM_SEG_NUM] = {NULL};


static void shm_log_printer(char *log_info, int length)
{
    if (NULL == log_info) {
        return;
    }
    fprintf(stderr, "[shm_log]%s, length=%d\n", log_info, length);
}

void shm_write_log_info(char *log_text, int length)
{
    if (g_shm_info_log_printer != NULL) {
        g_shm_info_log_printer(log_text, length);
    }
}

void shm_write_log_error(char *log_text, int length)
{
    if (g_shm_error_log_printer != NULL) {
        g_shm_error_log_printer(log_text, length);
    }
}

void shm_trace_print(shm_log_level_t log_level, const char *format, ...)
{
    char        shm_log[SHM_MAX_LOG_LENTH] = {0};
    va_list argument;
    int shm_log_length = 0;

    va_start(argument, format);
    shm_log_length = vsnprintf_s(shm_log, SHM_MAX_LOG_LENTH, SHM_MAX_LOG_LENTH - 1, format, argument);
    switch (log_level) {
        case SHM_LOG_LEVEL_INFO:
            shm_write_log_info(shm_log, shm_log_length);
            break;
        case SHM_LOG_LEVEL_ERROR:
            shm_write_log_error(shm_log, shm_log_length);
            break;
        default:
            break;
    }

    va_end(argument);
}

void shm_set_info_log_writer(void (*writer)(char *, int))
{
    pthread_mutex_lock(&g_shm_log_mutex);
    g_shm_info_log_printer = writer;
    pthread_mutex_unlock(&g_shm_log_mutex);
}

void shm_set_error_log_writer(void (*writer)(char *, int))
{
    pthread_mutex_lock(&g_shm_log_mutex);
    g_shm_error_log_printer = writer;
    pthread_mutex_unlock(&g_shm_log_mutex);
}

#define SHM_CALL_OP_RET(ret, op, seg, ...)                                                                             \
    if (seg && seg->ops && seg->ops->op) {                                                                             \
        ret = seg->ops->op(seg, ##__VA_ARGS__);                                                                        \
    } else {                                                                                                           \
        LOG_SHM_ERROR("SHM_CALL_OP error, op_name=%s", #op);                                                           \
    }

#define SHM_CALL_OP_VOID(op, seg, ...)                                                                                 \
    if (seg && seg->ops && seg->ops->op) {                                                                             \
        seg->ops->op(seg, ##__VA_ARGS__);                                                                              \
    } else {                                                                                                           \
        LOG_SHM_ERROR("SHM_CALL_OP error, op_name=%s", #op);                                                           \
    }

static struct shm_seg_s *shm_get_seg(void *addr)
{
    unsigned long ul_addr;
    int slot;

    ul_addr = (unsigned long)(long)addr;
    if (ul_addr < SHM_ADDR || ul_addr >= SHM_END_ADDR) {
        return NULL;
    }

    slot = shm_addr2slot(ul_addr);
    return g_slot2seg[slot];
}

int is_shm(struct shm_seg_s *seg, void *addr)
{
    int ret = 0;
    struct shm_seg_s *p_seg = seg ? seg : shm_get_seg(addr);

    if (NULL == p_seg) {
        return ret;
    }
    SHM_CALL_OP_RET(ret, is_shm, p_seg, addr);

    return ret;
}

static int shm_get_slot(struct shm_seg_s *seg)
{
    int i;

    for (i = 0; i < MAX_SHM_SEG_NUM; i++) {
        if (g_slot2seg[i] == seg) {
            return i;
        }
    }

    return -1;
}

void shm_seg_stop(struct shm_seg_s *seg)
{
    int slot = shm_get_slot(seg);
    if (slot == -1) {
        LOG_SHM_ERROR("shm_get_slot fail");
        return;
    }

    SHM_CALL_OP_VOID(shm_seg_stop, seg);
}

void shm_seg_exit(struct shm_seg_s *seg)
{
    int slot = shm_get_slot(seg);
    if (slot == -1) {
        LOG_SHM_ERROR("shm_get_slot fail");
        return;
    }

    if (!__sync_bool_compare_and_swap(&g_slot2seg[slot], seg, NULL)) {
        LOG_SHM_ERROR("set shm_seg_addr table fail");
        return;
    }

    SHM_CALL_OP_VOID(shm_seg_exit, seg);
}

void *shm_alloc(struct shm_seg_s *seg, size_t size)
{
    void *ret = NULL;

    SHM_CALL_OP_RET(ret, shm_alloc, seg, size);

    return ret;
}

void shm_free(struct shm_seg_s *seg, void *ptr)
{
    struct shm_seg_s *p_seg = seg ? seg : shm_get_seg(ptr);

    SHM_CALL_OP_VOID(shm_free, p_seg, ptr);
}

void shm_assign_proc_id(struct shm_seg_s *seg, int proc_id)
{
    SHM_CALL_OP_VOID(shm_assign_proc_id, seg, proc_id);
}

int shm_send_msg(struct shm_seg_s *seg, int proc_id, dsw_message_block_t *msg)
{
    int ret = -1;
    SHM_CALL_OP_RET(ret, shm_send_msg, seg, proc_id, msg);
    return ret;
}

int shm_proc_start(struct shm_seg_s *seg, int proc_id, int thread_num, cpu_set_t *mask, int is_dynamic,
    int (*recv_msg)(struct shm_seg_s *, dsw_message_block_t *))
{
    int ret = -1;
    SHM_CALL_OP_RET(ret, shm_proc_start, seg, proc_id, thread_num, mask, is_dynamic, recv_msg);
    return ret;
}

int shm_proc_alive(struct shm_seg_s *seg, int proc_id)
{
    int ret = -1;
    SHM_CALL_OP_RET(ret, shm_proc_alive, seg, proc_id);
    return ret;
}

struct shm_seg_s *shm_master_init(shm_key_t *shm_key, shm_mem_class_t mem_class[], int nr_mem_class, int start_lsnr)
{
    if (shm_ops[shm_key->type]->shm_master_init) {
        return shm_ops[shm_key->type]->shm_master_init(shm_key, mem_class, nr_mem_class, start_lsnr);
    }
    return NULL;
}

struct shm_seg_s *shm_init(shm_key_t *shm_key, int is_server)
{
    void *addr;
    unsigned long ul_addr;
    struct shm_seg_s *ret;
    int slot;

    if (shm_ops[shm_key->type]->shm_init == NULL) {
        LOG_SHM_ERROR("init function is NULL");
        return NULL;
    }

    ret = shm_ops[shm_key->type]->shm_init(shm_key, is_server, &addr);
    if (ret == NULL) {
        LOG_SHM_ERROR("initailization fail");
        return NULL;
    }

    ul_addr = (unsigned long)(long)addr;
    if (ul_addr < SHM_ADDR || ul_addr >= SHM_END_ADDR) {
        LOG_SHM_ERROR("seg's address is out of range.");
        return ret;
    }

    slot = shm_addr2slot(ul_addr);
    if (!__sync_bool_compare_and_swap(&g_slot2seg[slot], NULL, ret)) {
        LOG_SHM_ERROR("set shm_seg_addr table fail");
    }
    return ret;
}

int shm_master_exit(struct shm_seg_s *seg)
{
    int ret = -1;
    SHM_CALL_OP_RET(ret, shm_master_exit, seg);
    return ret;
}

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
 * dsw_shm_comm_pri.h
 *
 *
 * IDENTIFICATION
 * src/tse/message_queue/dsw_shm_comm_pri.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __dsw_shm_comm_pri_h__
#define __dsw_shm_comm_pri_h__

#include <time.h>
#include "dsw_shm.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

#define SHM_MAGIC 0xdf5da7a972345678

#define SHM_HDR_MAGIC 0x6819

#define SHM_MAX_KEY_NUM MAX_SHM_SEG_NUM

#define SHM_MAX_SIZE_SHIFT 32
#define SHM_MAX_SIZE (1UL << SHM_MAX_SIZE_SHIFT)

#define SHM_TRUE 1
#define SHM_FALSE 0
#define SHM_LOG_INTERVAL_SECOND_20 20

struct shm_ops_s {
    struct shm_seg_s *(*shm_init)(shm_key_t *shm_key, int is_server, void **addr);
    int (*is_shm)(struct shm_seg_s *seg, void *addr);
    void *(*shm_alloc)(struct shm_seg_s *seg, size_t size);
    void (*shm_free)(struct shm_seg_s *seg, void *ptr);
    int (*shm_proc_start)(struct shm_seg_s *seg, int proc_id, int thread_num, cpu_set_t *mask, int is_dynamic,
        int (*recv_msg)(struct shm_seg_s *, dsw_message_block_t *));
    void (*shm_assign_proc_id)(struct shm_seg_s *seg, int proc_id);
    int (*shm_proc_alive)(struct shm_seg_s *seg, int proc_id);
    int (*shm_send_msg)(struct shm_seg_s *seg, int proc_id, dsw_message_block_t *msg);
    void (*shm_seg_exit)(struct shm_seg_s *seg);
    struct shm_seg_s *(*shm_master_init)(shm_key_t *shm_key, shm_mem_class_t mem_class[], int nr_mem_class);
    int (*shm_master_exit)(struct shm_seg_s *seg);
};

struct shm_seg_s {
    int type;
    struct shm_ops_s *ops;
    void *priv;
};

extern struct shm_ops_s g_shm_sysv_ops;


static inline int shm_addr2slot(unsigned long addr)
{
    return (int)(long)((addr - SHM_ADDR) >> SHM_MAX_SIZE_SHIFT);
}

static inline unsigned long shm_slot2addr(int slot)
{
    return SHM_ADDR + (((unsigned long)(long)slot) << SHM_MAX_SIZE_SHIFT);
}


#define SHM_NS_PER_SEC 1000000000L

static inline uint64_t shm_get_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * SHM_NS_PER_SEC + ts.tv_nsec;
}


/* following code is only for shm log */
void shm_trace_print(shm_log_level_t log_level, const char *format, ...) __attribute__((format(printf, 2, 3)));

#define LOG_SHM_INFO(format, ...)                                                                                  \
    {                                                                                                              \
        shm_trace_print(SHM_LOG_LEVEL_INFO, "[INFO]: %s:%d ns=0x%016lx " format, __FILE__, __LINE__, shm_get_ns(), \
            ##__VA_ARGS__);                                                                                        \
    }

#define LOG_SHM_ERROR(format, ...)                                                                                    \
    {                                                                                                                 \
        shm_trace_print(SHM_LOG_LEVEL_ERROR, "[ERROR]: %s:%d  ns=0x%016lx " format, __FILE__, __LINE__, shm_get_ns(), \
            ##__VA_ARGS__);                                                                                           \
    }

#define shm_assert(cond)                                                                                            \
    if (!(cond)) {                                                                                                  \
        LOG_SHM_ERROR("assertion failed, at %s:%d, errno=%d, Info:%s", __FILE__, __LINE__, errno, strerror(errno)); \
        abort();                                                                                                    \
    }

#define LOG_SHM_LIMIT_PERIOD(interval, can)                  \
    do {                                                     \
        static uint64_t ulMaxToks = (interval);              \
        static uint64_t ulToks = (interval);                 \
        static uint64_t ulLast = 0;                          \
        uint64_t ulNow = time(NULL);                         \
        ulToks += ulNow - ulLast;                            \
        ulToks = (ulToks > ulMaxToks) ? ulMaxToks : ulToks;  \
        if (ulToks >= (interval)) {                          \
            ulToks -= (interval);                            \
            (can) = SHM_FALSE;                               \
        } else {                                             \
            (can) = SHM_TRUE;                                \
        }                                                    \
        ulLast = ulNow;                                      \
    } while (0)

#define LOG_SHM_INFO_LIMIT(interval, format, ...)                                                                   \
    do {                                                                                                            \
            int bCan = SHM_FALSE;                                                                                   \
            LOG_SHM_LIMIT_PERIOD(interval, bCan);                                                                   \
            if (bCan == SHM_TRUE) {                                                                                 \
                shm_trace_print(SHM_LOG_LEVEL_INFO, "[INFO]: %s:%d ns=0x%016lx " format, __FILE__, __LINE__,        \
                                shm_get_ns(), ##__VA_ARGS__);                                                       \
            }                                                                                                       \
    } while (0)

#ifdef __cplusplus
}
#endif /* __cpluscplus */

#endif // __dsw_shm_comm_pri_h__

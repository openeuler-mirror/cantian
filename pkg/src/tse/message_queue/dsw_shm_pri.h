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
 * dsw_shm_pri.h
 *
 *
 * IDENTIFICATION
 * src/tse/message_queue/dsw_shm_pri.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef dsw_shm_h__
#define dsw_shm_h__

#include "dsw_shm.h"
#include "dsw_shm_comm_pri.h"
#include "dsw_shm_diag.h"

#include <stdint.h>
#include <pthread.h>
#include <semaphore.h>
#include <unistd.h>
#include <securec.h>


#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

#define SHM_PAGE_SIZE (4096) /* if use hugetbl, it should be changed to 2M */

#define SHM_NULL 0

#define SHM_MAX_THREAD_NUM (1024)

#define MAX_SIZE_CHAIN (2 * MAX_MEM_CLASS)

#define SHM_REF_SHIFT 3
#define SHM_REF_MASK (((uint64_t)1 << SHM_REF_SHIFT) - 1)

struct shm_seg_sysv_s;

#define SHM_BLK_QUEUING 0x8000000000000000UL
#define SHM_QBIT_NOP 0
#define SHM_QBIT_SET 1
#define SHM_QBIT_CLR 2

#define SHM_POLL_NUM 0

#define SHM_QBIT_OP(ref_proc, op)           \
    do {                                    \
        if ((op) == SHM_QBIT_SET)           \
            (ref_proc) |= SHM_BLK_QUEUING;  \
        else if ((op) == SHM_QBIT_CLR)      \
            (ref_proc) &= ~SHM_BLK_QUEUING; \
    } while (0)

#define SHM_QBIT_IS_SET(ref_proc) (((ref_proc) | SHM_BLK_QUEUING) != 0)

#define SHM_BF_QUEUING 0x01
#define SHM_BF_FREE 0x02
#define SHM_BF_PROC 0x04
#define SHM_BF_INFL 0x10

#define SHM_MASTER_LIMIT_TICK (6)
#define SHM_NULL_TICK (0xffff)        /* δ��ʹ�õ�tick */
#define SHM_NORMAL_EXIT_TICK (0x00ff) /* �����˳�ʱmaster ��Ӧ�����м�״̬��tick */

#define SHM_PROC_STATE_DOWN (0)
#define SHM_PROC_STATE_WORKING (1)
#define SHM_PROC_STATE_NEEDCHECKING (2)
#define SHM_PROC_STATE_RECOVERY (3)
#define SHM_PROC_STATE_UNKNOWN (4)

#define SHM_CLIENT_STATUS_DOWN (0)
#define SHM_CLIENT_STATUS_WORKING (1)
#define SHM_CLIENT_STATUS_CONNECTING (2)
#define SHM_CLIENT_STATUS_RELEASING (3)

#define SHM_PATH_MAX (256 + 32)

#define SHM_SOCK_NAME "shm_unix_sock"

typedef enum {
    shm_segtype_master,
    shm_segtype_app,

    shm_segtype_count
} shm_type_e;


#define SHM_BLK2HDR(blk) (mem_blk_hdr_t *)((char *)(blk) - sizeof(mem_blk_hdr_t))
#define SHM_HDR2BLK(hdr) (void *)((char *)(hdr) + sizeof(mem_blk_hdr_t))
#define SHM_HDR2MSG(hdr) (dsw_message_block_t *)((char *)(hdr) + sizeof(mem_blk_hdr_t))

struct shm_list_hdr_s {
    uint32_t h_next;
    uint32_t h_prev;
};

typedef struct mem_blk_hdr {
    int32_t proc_id;
    uint16_t hdr_magic;
    uint8_t list_id;
    uint8_t flags; /* for recover */
    uint32_t next;
    union {
        struct shm_list_hdr_s node;
        /*
           It is a refcnt array its one element corresponds to a process,
           the MSB is a flag for SHM_BF_QUEUING
        */
        uint64_t ref_proc;
    };
} mem_blk_hdr_t;

/* The head of a shared-memory-segment */
typedef struct shm_head {
    unsigned long magic; /* if shm init or not */
    uint32_t version;    /* need to add translate logic */

    unsigned long forvm_bits_map[64]; /* add for vm bits_map */

    unsigned long addr;       /* the address that map to process address space */
    unsigned long total_size; /* shm total size include the size of shm_area_t */
    unsigned long used_size;
    int nr_mem_class; /* the type count of shm block size */
    int recovering;
    uint32_t master_ticks;      /* use by listen */
    uint32_t delay_stat_switch; /* use to count the delay */
    char reserve[128];          // need modify, must memset as 0
} shm_head_t;

/* recive queue version information */
typedef struct shm_rcvq {
    union {
        struct {
            uint32_t q_version;
            uint32_t q_head;
        };
        uint64_t val;
    };
} __attribute__((aligned(8))) shm_rcvq_t;


typedef struct shm_proc_tracker_s {
    int pad;
    uint32_t changing_time; /* It is used to record 'last_ticks' changing time */
    uint64_t last_ticks;    /* It is used to record 'last_ticks' in the shm_proc_t */
} shm_proc_tracker_t;

/* shm process infomation */
typedef struct shm_proc {
    uint32_t version; /* need to add translate logic */
    int32_t proc_id;
    shm_rcvq_t rcvq_high;
    shm_rcvq_t rcvq_normal;

    sem_t sem;
    uint32_t nr_poll;
    uint32_t nr_poll_init;
    uint64_t last_ticks;
    uint64_t nr_total_msg;  /* for performance statistics only */
    uint64_t nr_total_qlen; /* for performance statistics only */
    int (*recv_msg)(struct shm_seg_s *, dsw_message_block_t *);
    int state;
    int sock_fd; /* record the sock_fd alloted by ud socket, only master can use */
    int shm_ref; /* the proc have shm_ref thread in shm */
    uint32_t running_thd_num;
    uint32_t hot_thd_num;
    int waiting_msg_num;
    uint32_t processing_msg_num;
    uint32_t fixed_thd_num;

    char reserve[128]; // need modify
} shm_proc_t;

/* shm free list version information */
typedef struct shm_free_list {
    union {
        struct {
            uint32_t fl_version;
            uint32_t head;
        };
        uint64_t val;
    };
} __attribute__((aligned(8))) shm_free_list_t;

typedef struct shm_mem_list {
    shm_free_list_t free_list;
    uint32_t version; /* need to add translate logic */
    int size;         /* size of block (not including mem_blk_hdr_t) */
    int total;        /* total number of blocks */
    uint8_t list_id;
    uint8_t pad[3];
    uint32_t start; /* first block address, for crash recovery */
    uint32_t next;  /* point to next in the 'size_chain' */
    char reserve[32];
} shm_mem_list_t;

/* shm total memory information */
typedef struct shm_area {
    shm_head_t head;
    shm_proc_t procs[MAX_SHM_PROC];
    shm_mem_list_t mem_list[MAX_MEM_CLASS];
    uint32_t size_chain[MAX_SIZE_CHAIN];
} shm_area_t;

#define SHM_MASTER_WORKING 1
#define SHM_MASTER_RECOVERING 2

struct shm_timer_s;

/* The shared memory segment, any signle process can connect multi shared segment */
struct shm_seg_sysv_s {
    struct shm_seg_s *_seg;
    shm_area_t *all_seg_shm; /* old version g_shm */
    shm_type_e type;
    shm_key_t shm_key;
    int master_status;
    int seg_proc;
    int seg_init;
    int t_thread_nr;
    int seg_id;
    int shm_id;
    int recv_t_nr;
    int is_server;
    bool running;
    int nr_proc;
    int listen_fd; /* for unix domain socket */
    int hot_thread_num;
    sem_t epoll_sem;
    pthread_mutex_t master_recovery_mutex;
    struct shm_timer_s *recover_timer;
    // ---------using by master proc under this line-------------
    shm_proc_tracker_t seg_proc_tracker[MAX_SHM_PROC];
};

typedef struct shm_hb_info {
    struct shm_timer_s *shm_hb_timer;
    int shm_is_hb_init;
    int shm_max_sec_of_hb; /* feed dog maximum sec */
    void *shm_arg_of_hb;
    void (*shm_hb_func)(void *);
} shm_hb_info_t;

typedef struct shm_arg_proc_s {
    shm_proc_t *proc;
    struct shm_seg_s *seg;
    cpu_set_t *mask;
    int is_dynamic;
} shm_arg_proc_t;

typedef struct client_health_check_arg_s {
    int *client_id;
    shm_key_t *shm_key;
    sem_t sem;
} client_health_check_arg_t;

extern struct shm_seg_sysv_s *g_seg_array[];
extern int g_current_seg_num;

int *get_client_id_list(void);
int *get_clean_up_flag(int seg_id, int proc_id);
void set_shm_master_pre_clean_up(int (*pre_clean_up_func)(int));
void set_shm_master_clean_up(int (*clean_up)(int));
void remove_bad_client(int proc_id);
int shm_detach_mmap(void *addr, unsigned long total_size);

int shm_unlink_mmap(const char *name);

int shm_proc_is_alive(shm_proc_t *p);
int shm_proc_is_checking(shm_proc_t *p);
int shm_get_proc_state(shm_proc_t *p);

mem_blk_hdr_t *shm_get_blk_from_list(struct shm_seg_sysv_s *seg, shm_mem_list_t *m);
uint32_t reverse_list(shm_area_t *all_shm, uint32_t head, uint64_t *qlen, uint64_t *msg);
shm_mem_list_t *find_mem_list(shm_area_t *all_shm, size_t size, int *start_idx);

int shm_add_epoll_events(int epoll_fd, int sock_fd, uint32_t uEvents);
int shm_del_epoll_events(int epoll_fd, int sock_fd, uint32_t uEvents);


int shm_get_seg_config(shm_key_t *key, int is_master, int is_server, void **addr, unsigned long *total_size);
int shm_judge_process_alive(struct shm_seg_sysv_s *seg);
int shm_treat_proc_state(struct shm_seg_sysv_s *seg);
int shm_was_init(struct shm_seg_sysv_s *seg, shm_key_t *shm_key, shm_mem_class_t mem_class[], int nr_mem_class,
    int is_master, int *master_alive);
void shm_start(struct shm_seg_sysv_s *seg, shm_mem_class_t mem_class[], int nr_mem_class);
int shm_delete_seg_key_item(shm_key_t key);

int sysv_is_shm(struct shm_seg_s *_seg, void *addr);
int _shm_send_msg(struct shm_seg_sysv_s *seg, int proc_id, dsw_message_block_t *msg);
void shm_sysv_and_mmap_seg_exit(struct shm_seg_s *_seg);
void *shm_sysv_alloc(struct shm_seg_s *_seg, size_t size);
void shm_sysv_free(struct shm_seg_s *_seg, void *blk);
int shm_sysv_send_msg(struct shm_seg_s *_seg, int proc_id, dsw_message_block_t *msg);
int shm_sysv_proc_start(struct shm_seg_s *_seg, int proc_id, int thread_num, cpu_set_t *mask, int is_dynamic,
    int (*recv_msg)(struct shm_seg_s *, dsw_message_block_t *));
void shm_sysv_assign_proc_id(struct shm_seg_s *_seg, int proc_id);
int shm_sysv_proc_alive(struct shm_seg_s *_seg, int proc_id);
void get_alive_proc(struct shm_seg_sysv_s *seg, uint64_t *alive_bits);
int shm_sysv_master_exit(struct shm_seg_s *_seg);
struct shm_seg_s *shm_sysv_init(shm_key_t *shm_key, int is_server, void **addr);
struct shm_seg_s *shm_sysv_master_init(shm_key_t *shm_key, shm_mem_class_t mem_class[], int nr_mem_class);
void *shm_thd_scheduler_func(void *arg);
void shm_walk_all_block(struct shm_seg_sysv_s *seg,
    void (*cb)(struct shm_seg_sysv_s*, int, int, mem_blk_hdr_t *, uint64_t), uint64_t arg);
int shm_send_all(int sd, char* buf, int len);
int shm_recv_all(int sd, char* buf, int len);
int shm_create_and_init_socket(void);
void set_client_status(int client_id, int client_status);

/* According to the offset address to obtain the actual address of shared memory */
static inline void *shm2ptr(char *all_shm, uint32_t shm)
{
    return all_shm + shm;
}

/* Take the shared memory offset address in the entire memory */
static inline uint32_t ptr2shm(char *all_shm, void *ptr)
{
    return (uint32_t)(long)((char *)ptr - all_shm);
}

/*
    murmur hash - It is a new hash algorithm invented by google
*/
static inline unsigned murmur(unsigned i, unsigned v)
{
    unsigned k = v;
    unsigned h = i;

    k *= 0xcc9e2d51;
    k = (k << 15) | (k >> 17);
    k *= 0x1b873593;
    h ^= k;
    h = (h << 13) | (h >> 19);
    h = (h * 5) + 0xe6546b64;
    return h;
}

static inline int size_hash(int size)
{
    return (int)(murmur(0, (unsigned)size) & (MAX_SIZE_CHAIN - 1));
}


static inline void shm_wait_recovering(volatile int *recovering)
{
    while (*recovering) {
        usleep(1000);
    }
}

#ifdef __cplusplus
}
#endif /* __cpluscplus */

#endif /* dsw_shm_h__ */

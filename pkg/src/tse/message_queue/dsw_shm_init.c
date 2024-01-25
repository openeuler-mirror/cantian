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
 * dsw_shm_init.c
 *
 *
 * IDENTIFICATION
 * src/tse/message_queue/dsw_shm_init.c
 *
 * -------------------------------------------------------------------------
 */

#include <unistd.h>
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
#include <sys/mman.h>
#include <string.h>
#include "dsw_shm_pri.h"

#define TSC_HZ 1000000000UL
#define TSC_TIME_OUT (TSC_HZ)
#define TSC_UPDATE (TSC_HZ / 10)
#define INIT_WAIT_TIME (1)
#define MMAP_FILE_UMASK (0117)
#define MMAP_FILE_MODE (0660)

static pthread_mutex_t g_init_mutex = PTHREAD_MUTEX_INITIALIZER;
struct shm_seg_sysv_s *g_seg_array[MAX_SHM_SEG_NUM] = { NULL };
struct shm_ops_s g_shm_sysv_ops = {
    .shm_init = shm_sysv_init,
    .is_shm = sysv_is_shm,
    .shm_alloc = shm_sysv_alloc,
    .shm_free = shm_sysv_free,
    .shm_proc_start = shm_sysv_proc_start,
    .shm_proc_alive = shm_sysv_proc_alive,
    .shm_assign_proc_id = shm_sysv_assign_proc_id,
    .shm_send_msg = shm_sysv_send_msg,
    .shm_seg_stop = shm_sysv_seg_stop,
    .shm_seg_exit = shm_sysv_and_mmap_seg_exit,
    .shm_master_init = shm_sysv_master_init,
    .shm_master_exit = shm_sysv_master_exit,
};

/*Count the actual registration number of the current segment*/
int g_current_seg_num = 0;

int shm_detach_mmap(void *addr, unsigned long total_size)
{
    int ret;
    ret = munmap(addr, total_size);
    if (ret < 0) {
        LOG_SHM_ERROR("the addr is detache error, total size = %d, the err = %d.", total_size, errno);
        return -1;
    }

    return 0;
}

int shm_unlink_mmap(const char *name)
{
    int res;
    res = shm_unlink(name);
    if (res < 0) {
        LOG_SHM_ERROR("the name = %s shm_unlink error, the errno = %d.", name, errno);
        return -1;
    }
    return res;
}

static int shm_exit_one_from_seg_array(struct shm_seg_sysv_s *seg)
{
    int i;
    for (i = 0; i < g_current_seg_num; i++) {
        if (g_seg_array[i] == seg) {
            g_seg_array[i] = g_seg_array[g_current_seg_num - 1];
            g_seg_array[g_current_seg_num - 1] = NULL;
            g_current_seg_num--;
            return 0;
        }
    }
    return -1;
}

void shm_sysv_seg_stop(struct shm_seg_s *_seg)
{
    struct shm_seg_sysv_s *seg = (struct shm_seg_sysv_s *)_seg->priv;

    if ((_seg == NULL) || (_seg->priv == NULL)) {
        LOG_SHM_ERROR("the segment is NULL!please check the code!");
        cm_panic(0);
        return;
    }
    LOG_SHM_INFO("seg will exit, all business proc must call shm_seg_exit before call this function. _seg->type = %d %d",
                 _seg->type, getpid());
    // just influence mysqld or cantiand 1. stop scheduler thds 2. necessary condition for stopping job thds
    seg->running = 0;
    int thd_num = seg->nr_proc;
    for (int i = 0; i < MAX_SHM_PROC; i++) {
        shm_proc_t *p = &seg->all_seg_shm->procs[i];
        // sem_post to hot_thread_cool sem_wait, make job thds change running to sleeping
        for (int j = 0; j < thd_num; j++) {
            sem_post(&p->sem);
        }
    }
    // this seg`s job thread all stoped
    while (__sync_fetch_and_add(&seg->nr_proc, 0) != 0) {
        LOG_SHM_INFO("the seg [%s] have job work thread in proccess!running thd num %d, waitting...",
                     seg->shm_key.mmap_name, seg->nr_proc);
        usleep(100 * 1000);
    }
    for (int i = 0; i < MAX_SHM_PROC; i++) {
        shm_proc_t *p = &seg->all_seg_shm->procs[i];
        // destroy job recv thds sem.
        for (int j = 0; j < thd_num; j++) {
            sem_destroy(&p->sem);
        }
    }
}

void shm_sysv_and_mmap_seg_exit(struct shm_seg_s *_seg)
{
    struct shm_seg_sysv_s *seg = (struct shm_seg_sysv_s *)_seg->priv;

    if ((_seg == NULL) || (_seg->priv == NULL)) {
        LOG_SHM_ERROR("the segment is NULL!please check the code!");
        cm_panic(0);
        return;
    }

    if (_seg->type == SHM_KEY_SYSV) {
        if (seg->type == shm_segtype_master) {
            shmdt(seg->all_seg_shm);
            shmctl(seg->shm_id, IPC_RMID, 0);
        } else {
            shmdt(seg->all_seg_shm);
        }
    } else if (_seg->type == SHM_KEY_MMAP) {
        (void)shm_detach_mmap(seg->all_seg_shm, seg->all_seg_shm->head.total_size);
        if (seg->type == shm_segtype_master) {
            close(seg->listen_fd);
            (void)shm_unlink_mmap(seg->shm_key.mmap_name);
        }
    } else {
        LOG_SHM_ERROR("_seg->type  error _seg->type =%d", _seg->type);
    }

    pthread_mutex_lock(&g_init_mutex);
    if (shm_exit_one_from_seg_array(seg) == -1) {
        LOG_SHM_ERROR("the seg have been delete! there are no this seg in seg_array");
    }
    if (seg->type == shm_segtype_master && shm_delete_seg_key_item(seg->shm_key) == -1) {
        LOG_SHM_ERROR("the key_list have been delete! there are no this seg in seg_array.");
    }
    pthread_mutex_unlock(&g_init_mutex);

    LOG_SHM_INFO("[ %s ] the proc : %d exit successful!type = %d", seg->shm_key.mmap_name, seg->seg_proc,
                 shm_segtype_master);

    free(seg);
    free(_seg);
    seg = NULL;
    _seg = NULL;
}

static inline int alloc_empty_mem_list(struct shm_seg_sysv_s *seg, int size)
{
    int i;

    for (i = 0; i < MAX_MEM_CLASS; i++) {
        if (seg->all_seg_shm->mem_list[i].size == 0) {
            seg->all_seg_shm->mem_list[i].size = size;
            return i;
        }
    }
    LOG_SHM_ERROR("alloc_empty_mem_list failed, the mem_list already was assigned!");
    cm_panic(i < MAX_MEM_CLASS);
    return -1;
}

/* return total size of a shared-memory-segment */
static unsigned long shm_total_size(shm_mem_class_t mem_class[], int nr_mem_class, uint32_t *p_vsize, shm_head_t *h)
{
    (void)(h);
    int i;
    unsigned long total_size = sizeof(shm_area_t);
    unsigned long v_total = 0;  // v_total e_size record buddy pool total size and each buddy pool size
    uint32_t v_size = 0;

    for (i = 0; i < nr_mem_class; i++) {
        total_size += ((unsigned long)(long)mem_class[i].size + sizeof(mem_blk_hdr_t)) * mem_class[i].num;
    }

    total_size += v_total;

    if (p_vsize) {
        *p_vsize = v_size;
    }

    total_size = ((total_size + SHM_PAGE_SIZE - 1) / SHM_PAGE_SIZE) * SHM_PAGE_SIZE;

    if (total_size > SHM_MAX_LEN) {
        LOG_SHM_ERROR("size is too large, total_size=%lx, SHM_MAX_SIZE=%lx", total_size, SHM_MAX_LEN);
        cm_panic(0);
    }

    return total_size;
}

static int shm_mmap_create_file(int *fd, unsigned long total_size, const char *mmap_name)
{
    mode_t pre_umask = umask(MMAP_FILE_UMASK);
    *fd = shm_open(mmap_name, O_RDWR | O_CREAT | O_TRUNC, MMAP_FILE_MODE);
    umask(pre_umask);
    if (*fd == -1) {
        LOG_SHM_ERROR("shm create and open mmap file failed! file=%s, errno = %d", mmap_name, errno);
        return -1;
    }

    int ret = ftruncate(*fd, (long)total_size);
    if (ret != 0) {
        LOG_SHM_ERROR("shm ftruncate mmap file failed! file=%s, errno = %d", mmap_name, ret);
        close(*fd);
        return -1;
    }
    return 0;
}

static int shm_mmap_open_file(int *fd, const char *mmap_name)
{
    *fd = shm_open(mmap_name, O_RDWR, MMAP_FILE_MODE);
    if (*fd == -1) {
        LOG_SHM_ERROR("shm open mmap file failed! file=%s, errno = %d", mmap_name, errno);
        return -1;
    }

    return 0;
}

static int shm_mmap_get_attach(struct shm_seg_sysv_s *seg, shm_key_t *shm_key, unsigned long total_size, void *addr,
                               int is_master)
{
    int fd;

    if (is_master) {
        shm_mmap_create_file(&fd, total_size, shm_key->mmap_name);
    } else {
        shm_mmap_open_file(&fd, shm_key->mmap_name);
    }

    seg->all_seg_shm = (shm_area_t *)mmap(addr, total_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    if (MAP_FAILED == seg->all_seg_shm) {
        LOG_SHM_ERROR("shm_mmap_get_attach mmap error! total_size = %ld, errno = %d", total_size, errno);
        seg->all_seg_shm = NULL;
        close(fd);
        return -1;
    }

    if (seg->all_seg_shm != addr) {
        LOG_SHM_ERROR("mmap error! the addr is not the true seg_addr, pls checked the code");
        (void)shm_detach_mmap(addr, total_size);
        (void)shm_unlink_mmap(shm_key->mmap_name);
        seg->all_seg_shm = NULL;
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

static int shm_sysv_get_attach(struct shm_seg_sysv_s *seg, shm_key_t *shm_key, unsigned long total_size, void *addr,
                               int is_master)
{
    int shm_id;
    if (is_master) {
        LOG_SHM_INFO("master will upload!");
        shm_id = shmget(shm_key->sysv_key, total_size, IPC_CREAT | 0600); /* Newly requested shared memory */
    } else {
        LOG_SHM_INFO("App process will upload!");
        shm_id = shmget(shm_key->sysv_key, 0, 0); /* Reference master application of shared memory */
    }
    if (shm_id == -1) {
        LOG_SHM_ERROR("can not shmget, errno = %d", errno);
        return -1;
    }

    seg->shm_id = shm_id;
    seg->all_seg_shm = (shm_area_t *)shmat(shm_id, addr, 0);
    if (seg->all_seg_shm == (void *)-1) {
        LOG_SHM_ERROR("seg->all_seg_shm == NULL! shmat error!");
        return -1;
    }

    return 0;
}

static int shm_get_process_addr(struct shm_seg_sysv_s *seg, shm_key_t *shm_key, shm_mem_class_t mem_class[],
                                int nr_mem_class, int is_master)
{
    int ret;
    unsigned long total_size;
    void *addr = NULL;

    seg->seg_init = -1;
    seg->t_thread_nr = 0;
    ret = shm_get_seg_config(shm_key, is_master, seg->is_server, &addr, &total_size);
    if (ret < 0) {
        LOG_SHM_ERROR("shm_get_seg_config error");
        return -1;
    }

    if (is_master) {
        total_size = shm_total_size(mem_class, nr_mem_class, NULL, NULL);
    }

    if (shm_key->type == SHM_KEY_SYSV) {
        ret = shm_sysv_get_attach(seg, shm_key, total_size, addr, is_master);
    } else if (shm_key->type == SHM_KEY_MMAP) {
        ret = shm_mmap_get_attach(seg, shm_key, total_size, addr, is_master);
    } else {
        LOG_SHM_ERROR("shm_get_seg_config error");
        return -1;
    }

    if (ret < 0) {
        LOG_SHM_ERROR("attach error");
        return -1;
    }

    if (seg->all_seg_shm->head.magic != SHM_MAGIC) {
        return seg->seg_init;
    }

    return 0;
}

int shm_judge_process_alive(struct shm_seg_sysv_s *seg)
{
    int i, alive = 0;

    for (i = 0; i < MAX_SHM_PROC; i++) {
        if (shm_proc_is_alive(&seg->all_seg_shm->procs[i]) || shm_proc_is_checking(&seg->all_seg_shm->procs[i])) {
            LOG_SHM_INFO("[ %s ] the proc_id : %d alived in shmem!state : %d", seg->shm_key.mmap_name, i,
                         shm_get_proc_state(&seg->all_seg_shm->procs[i]));
            alive = 1;
        }
    }

    return alive;
}

int shm_treat_proc_state(struct shm_seg_sysv_s *seg)
{
    int i;

    for (i = 0; i < MAX_SHM_PROC; i++) {
        seg->all_seg_shm->procs[i].state = SHM_PROC_STATE_UNKNOWN;
        seg->all_seg_shm->procs[i].sock_fd = -1; /*new master start, new sock connect will be established*/
    }
    return 0;
}

/* get whether the shared memory area is initialized or not
    return value:
       initialized -   0
       not         -  -1
*/
int shm_was_init(struct shm_seg_sysv_s *seg, shm_key_t *shm_key, shm_mem_class_t mem_class[], int nr_mem_class,
                 int is_master, int *master_alive)
{
    (void)(master_alive);
    int alive = 0;
    int ret;

    ret = shm_get_process_addr(seg, shm_key, mem_class, nr_mem_class, is_master);
    if (-1 == ret) {
        return -1;
    }

    alive = shm_judge_process_alive(seg);

    if (seg->all_seg_shm != NULL && seg->all_seg_shm->head.magic == SHM_MAGIC) {
        if (is_master) {
            /* if any proc is alive in shm, master will treat proc state, or master will init all shm*/
            if (alive == 1) {
                LOG_SHM_INFO("master start but not init, master will clear proc alive flag.");
                (void)shm_treat_proc_state(seg);
                return 0;
            } else {
                LOG_SHM_INFO("master start and init");
                return -1;
            }
        } else {
            while (seg->all_seg_shm->head.recovering) {
                LOG_SHM_ERROR("master is recovering, init need wait.");
                sleep(INIT_WAIT_TIME);
            }
            return 0;
        }
    } else {
        LOG_SHM_INFO("the shm has not been inited,you should start master process first.");
        return -1;
    }
    return -1; /* can not reach here */
}

/*feed size_chain[] and link shm_mem_list_t element*/
static void add_size_chain(shm_area_t *all_shm, shm_mem_list_t *m)
{
    int h = size_hash(m->size);

    m->next = all_shm->size_chain[h];
    all_shm->size_chain[h] = ptr2shm((char *)all_shm, m);
}

void shm_proc_init(struct shm_seg_sysv_s *seg, shm_proc_t  **p)
{
    for (int i = 0; i < MAX_SHM_PROC; i++) {
        *p = &(seg->all_seg_shm)->procs[i];
        int ret = sem_init(&(*p)->sem, 1, 0);
        if (ret != 0) {
            LOG_SHM_ERROR("sem_init error!, ");
            cm_panic(0);
            return;
        }
        (*p)->version = 0;
        (*p)->last_ticks = SHM_NULL_TICK;
        (*p)->rcvq_high.q_head = SHM_NULL;
        (*p)->rcvq_high.q_version = 0;
        (*p)->rcvq_normal.q_head = SHM_NULL;
        (*p)->rcvq_normal.q_version = 0;
        (*p)->recv_msg = NULL;
        (*p)->nr_poll = 0;
        (*p)->nr_poll_init = SHM_POLL_NUM;
        (*p)->sock_fd = -1;
        (*p)->state = SHM_PROC_STATE_DOWN;
        memset_s((*p)->reserve, sizeof(char) * 128, 0, sizeof(char) * 128);
    }
}

void shm_mem_list_init(struct shm_seg_sysv_s *seg, int nr_mem_class, shm_head_t *h, shm_mem_class_t mem_class[])
{
    int k, sz;
    shm_mem_class_t *c;
    shm_mem_list_t  *m;
    uint32_t        shm_hdr;
    mem_blk_hdr_t   *hdr;

    memset_s(seg->all_seg_shm->mem_list, MAX_MEM_CLASS * sizeof(shm_mem_list_t), 0,
             MAX_MEM_CLASS * sizeof(shm_mem_list_t));
    
    for (int i = 0; i < nr_mem_class; i++) {
        c = &mem_class[i];
        k = alloc_empty_mem_list(seg, c->size);
        m = &(seg->all_seg_shm)->mem_list[k];
        m->version = 0;
        m->total = c->num;
        m->free_list.fl_version = 0;
        m->free_list.head = SHM_NULL;
        m->size = c->size;
        m->start = h->used_size;
        m->list_id = (uint8_t)k;
        memset_s(m->reserve, sizeof(char) * 32, 0, sizeof(char) * 32);

        sz = c->size + sizeof(mem_blk_hdr_t);

        for (int j = 0; j < c->num; j++) {
            shm_hdr = seg->all_seg_shm->head.used_size;
            hdr = (mem_blk_hdr_t *)shm2ptr((char *)(seg->all_seg_shm), shm_hdr);
            memset_s(hdr, sizeof(mem_blk_hdr_t), 0, sizeof(mem_blk_hdr_t));
            hdr->hdr_magic = SHM_HDR_MAGIC;
            hdr->ref_proc = 0;
            hdr->list_id = (uint8_t)k;
            hdr->proc_id = -1;
            hdr->next = m->free_list.head;
            m->free_list.head = shm_hdr;
            h->used_size += (uint32_t)sz;
            cm_panic(h->used_size <= h->total_size);
        }

        add_size_chain(seg->all_seg_shm, m);
    }
}

void shm_start(struct shm_seg_sysv_s *seg, shm_mem_class_t mem_class[], int nr_mem_class)
{
    shm_proc_t *p = NULL;
    uint32_t v_size;
    shm_head_t *h;

    cm_panic(nr_mem_class <= MAX_MEM_CLASS);

    memset_s(seg->all_seg_shm, sizeof(*(seg->all_seg_shm)), 0, sizeof(*(seg->all_seg_shm)));

    h = &seg->all_seg_shm->head;
    h->version = 0;

    h->total_size = shm_total_size(mem_class, nr_mem_class, &v_size, h);
    h->magic = SHM_MAGIC;
    h->used_size = sizeof(shm_area_t);
    h->master_ticks = 0;
    h->recovering = 0;
    h->addr = (unsigned long)seg->all_seg_shm;
    h->delay_stat_switch = 0;

    memset_s(h->forvm_bits_map, sizeof(unsigned long) * 64, 0, sizeof(unsigned long) * 64);
    memset_s(h->reserve, sizeof(char) * 128, 0, sizeof(char) * 128);

    shm_proc_init(seg, &p);
    
    h->nr_mem_class = nr_mem_class;
    
    shm_mem_list_init(seg, nr_mem_class, h, mem_class);
}

struct shm_seg_s *shm_sysv_init(shm_key_t *shm_key, int is_server, void **addr)
{
    int ret;
    struct shm_seg_sysv_s *seg;
    struct shm_seg_s *_seg;

    if (g_current_seg_num == MAX_SHM_SEG_NUM) {
        LOG_SHM_ERROR(" the Segment have been the maximum");
        return NULL;
    }

    _seg = (struct shm_seg_s *)malloc(sizeof(struct shm_seg_s));
    if (_seg == NULL) {
        LOG_SHM_ERROR(" malloc error !the segment is NULL, errno = %d", errno);
        return NULL;
    }
    memset_s(_seg, sizeof(struct shm_seg_s), 0, sizeof(struct shm_seg_s));

    seg = (struct shm_seg_sysv_s *)malloc(sizeof(struct shm_seg_sysv_s));
    if (seg == NULL) {
        free(_seg);
        LOG_SHM_ERROR(" malloc error !the segment is NULL, errno = %d", errno);
        return NULL;
    }
    memset_s(seg, sizeof(struct shm_seg_sysv_s), 0, sizeof(struct shm_seg_sysv_s));

    _seg->type = shm_key->type;
    _seg->ops = &g_shm_sysv_ops;
    _seg->priv = seg;

    pthread_mutex_lock(&g_init_mutex);
    seg->nr_proc = 0;
    seg->type = shm_segtype_app;
    seg->seg_id = g_current_seg_num;
    seg->is_server = is_server;
    memcpy_s(&seg->shm_key, sizeof(shm_key_t), shm_key, sizeof(shm_key_t));
    g_current_seg_num++;
    pthread_mutex_unlock(&g_init_mutex);

    ret = shm_was_init(seg, shm_key, NULL, 0, 0, NULL);
    if (ret != 0) {
        free(seg);
        free(_seg);
        LOG_SHM_ERROR("Shm init failed");
        return NULL;
    }

    g_seg_array[seg->seg_id] = seg;
    seg->_seg = _seg;
    *addr = (void *)seg->all_seg_shm;
    return _seg;
}

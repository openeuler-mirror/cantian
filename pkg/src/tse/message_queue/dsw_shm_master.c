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
 * dsw_shm_master.c
 *
 *
 * IDENTIFICATION
 * src/tse/message_queue/dsw_shm_master.c
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
#include <time.h>
#include <sys/epoll.h>

#include "dsw_shm_pri.h"

#define NS_PER_SEC (1000000000)
#define MAX_RECV_CHECK_LEN (2000)
#define DEAD_LOOP_PRINT_PER_TIMES (50)
#define SOCKET_UMASK (0117)

/* ---------- The following code implement a timer ------------ */
struct shm_timer_s {
    struct shm_timer_s *next;
    struct timespec expire;
    void *arg;
    void (*func)(struct shm_timer_s *);
};

static struct shm_timer_s *g_shm_timer_head = NULL;
static pthread_cond_t g_shm_timer_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t g_master_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_condattr_t g_master_cattr;
static shm_hb_info_t g_shm_hb_info = { 0 };
static int g_shm_is_master_thread_init = 0;
static int g_client_id_list[MAX_SHM_PROC] = { 0 };
static int g_client_fd_list[MAX_SHM_PROC] = { 0 };
static pthread_mutex_t g_client_mutex = PTHREAD_MUTEX_INITIALIZER;
static int g_clean_up_proc_flags[MAX_SHM_SEG_NUM][MAX_SHM_PROC] = { 0 };
static int (*g_clean_up_proc)(int, int *);
static int (*g_pre_clean_up_proc)(int, int *);
static int (*g_proc_connected_callback)(int *);

int *get_client_id_list(void)
{
    return g_client_id_list;
}

void set_client_status(int client_id, int client_status)
{
    int *client_id_list = get_client_id_list();
    pthread_mutex_lock(&g_client_mutex);
    client_id_list[client_id] = client_status;
    pthread_mutex_unlock(&g_client_mutex);
}

int get_free_client_id(void)
{
    int *client_id_list = get_client_id_list();
    pthread_mutex_lock(&g_client_mutex);
    for (int i = MYSQL_PROC_START; i < MAX_SHM_PROC; i++) {
        if (client_id_list[i] == SHM_CLIENT_STATUS_DOWN) {
            client_id_list[i] = SHM_CLIENT_STATUS_CONNECTING;
            LOG_SHM_INFO("[shm] alloc new client id, client_id(%d)", i);
            pthread_mutex_unlock(&g_client_mutex);
            return i;
        }
    }
    pthread_mutex_unlock(&g_client_mutex);
    return -1;
}

void release_client_id(int client_id)
{
    set_client_status(client_id, SHM_CLIENT_STATUS_DOWN);
}

int *get_clean_up_flag(int seg_id, int proc_id)
{
    return &g_clean_up_proc_flags[seg_id][proc_id];
}

void set_shm_master_pre_clean_up(int (*pre_clean_up_func)(int, int*))
{
    g_pre_clean_up_proc = pre_clean_up_func;
}

void set_shm_master_clean_up(int (*clean_up)(int, int *))
{
    g_clean_up_proc = clean_up;
}

void set_shm_client_socket_fd(int client_id, int fd)
{
    pthread_mutex_lock(&g_client_mutex);
    g_client_fd_list[client_id] = fd;
    pthread_mutex_unlock(&g_client_mutex);
}

int get_shm_cient_socket_fd(int client_id)
{
    return g_client_fd_list[client_id];
}

static void clean_up_proc_resource(int *proc_id_ptr)
{
    pthread_detach(pthread_self());
    int client_id = (int)proc_id_ptr;
    shm_proc_t *p = &g_seg_array[g_current_seg_num - 1]->all_seg_shm->procs[client_id];
    sem_post(&p->sem);
    p->state = SHM_PROC_STATE_DOWN;  // must set this proc dead and then recovery the memory
    p->sock_fd = -1;
    if (g_client_id_list[client_id] == SHM_CLIENT_STATUS_RELEASING) {
        LOG_SHM_INFO("[shm] client already in releasing, client_id(%d)", client_id);
        return;
    }

    LOG_SHM_INFO("[shm] start to clean up proc resource, client_id(%d)", client_id);
    set_client_status(client_id, SHM_CLIENT_STATUS_RELEASING);

    if (g_pre_clean_up_proc != NULL && g_pre_clean_up_proc(client_id, &g_client_id_list[client_id]) != 0) {
        LOG_SHM_ERROR("[shm] pre clean up for bad mysql failed! client_id(%d)", client_id);
        pthread_join(pthread_self(), NULL);
        return;
    }

    if (g_clean_up_proc != NULL && g_clean_up_proc(client_id, &g_client_id_list[client_id]) < 0) {
        LOG_SHM_ERROR("[shm] clean up bad mysql failed! client_id(%d)", client_id);
        pthread_join(pthread_self(), NULL);
        return;
    }

    set_client_status(client_id, SHM_CLIENT_STATUS_DOWN);
    LOG_SHM_INFO("[shm] success to clean up proc resource, client_id(%d)", client_id);
    pthread_join(pthread_self(), NULL);
}

void remove_bad_client(int proc_id)
{
    int *client_id_list = get_client_id_list();
    if (client_id_list[proc_id] == SHM_CLIENT_STATUS_WORKING) {
        LOG_SHM_ERROR("will disconnect client, proc_id=%d", proc_id);
        int cli_fd = get_shm_cient_socket_fd(proc_id);
        if (cli_fd > 0) {
            close(cli_fd);
            set_shm_client_socket_fd(proc_id, 0);
        }
        pthread_t thd;
        if (pthread_create(&thd, NULL, clean_up_proc_resource, (void *)proc_id) != 0) {
            LOG_SHM_ERROR("create thread for clean_up_proc_resource failed, mmap_index=%d, proc_id=%d", proc_id);
        }
    }
}

static int ts_before(struct timespec *a, struct timespec *b)
{
    if (a->tv_sec < b->tv_sec) {
        return 1;
    }
    if (a->tv_sec == b->tv_sec && a->tv_nsec < b->tv_nsec) {
        return 1;
    }
    return 0;
}

static void shm_timer_free(struct shm_timer_s *timer)
{
    free(timer);
}

/* You have to hold the 'g_master_mutex' before you call this function */
static void shm_timer_del(struct shm_timer_s *timer)
{
    struct shm_timer_s **pp;

    for (pp = &g_shm_timer_head; *pp; pp = &(*pp)->next) {
        if (*pp == timer) {
            *pp = timer->next;
            timer->next = NULL;
            break;
        }
    }
}

static void *shm_timer_thread_func(void *arg)
{
    (void)(arg);
    struct timespec ts, *tp;
    struct shm_timer_s *timer;

    // this timer is updated per second
    while (1) {
        pthread_mutex_lock(&g_master_mutex);
        clock_gettime(CLOCK_MONOTONIC, &ts);
        do {
            ts.tv_sec += 1;
            tp = (g_shm_timer_head == NULL ? &ts : &g_shm_timer_head->expire);

            pthread_cond_timedwait(&g_shm_timer_cond, &g_master_mutex, tp);

            clock_gettime(CLOCK_MONOTONIC, &ts);
        } while (g_shm_timer_head == NULL || ts_before(&ts, &g_shm_timer_head->expire));

        /* cut off the head and run it */
        timer = g_shm_timer_head;
        g_shm_timer_head = timer->next;
        timer->next = NULL;

        timer->func(timer);
        pthread_mutex_unlock(&g_master_mutex);
    }
    return NULL;
}

static int shm_timer_thread_start(void)
{
    pthread_t pth;
    int ret;

    pthread_condattr_init(&g_master_cattr);
    pthread_condattr_setclock(&g_master_cattr, CLOCK_MONOTONIC);
    pthread_cond_init(&g_shm_timer_cond, &g_master_cattr);

    ret = pthread_create(&pth, NULL, shm_timer_thread_func, NULL);
    if (ret < 0) {
        LOG_SHM_ERROR("pthread_create error, errno=%d", errno);
        return -1;
    }
    return 0;
}

/* ---------- The following code is used to implement shm unix domain socket timer--------- */
#define MAXEPOLL (2560)
#define SHM_EPOLLEVENTS_NUM (128)      /*epoll events num*/
#define SHM_EPOLL_WAIT_TIMEOUT (10000) /* milliseconds =10s */

typedef struct shm_poller_s {
    int shm_epoll_fd;
    struct epoll_event shm_evs[MAXEPOLL];
    sem_t shm_epoll_init_sem;
} shm_poller_t;

static shm_poller_t shm_poller;
static int g_shm_master_listen_fd;

int shm_add_epoll_events(int epoll_fd, int sock_fd, uint32_t uEvents)
{
    int iRet;
    struct epoll_event sEpollEvent;

    if (epoll_fd < 0 || sock_fd < 0) {
        LOG_SHM_ERROR("parameter error, iEpollFd:%d, iFd:%d", epoll_fd, sock_fd);
        return -1;
    }

    sEpollEvent.events = uEvents;
    sEpollEvent.data.fd = sock_fd;
    iRet = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock_fd, &sEpollEvent);
    if (iRet < 0) {
        LOG_SHM_ERROR("iEpollFd:%d add iFd:%d uEvents:0x%x failed, errno=%d", epoll_fd, sock_fd, uEvents, errno);
        return -1;
    }

    return 0;
}

int shm_del_epoll_events(int epoll_fd, int sock_fd, uint32_t uEvents)
{
    int iRet;
    struct epoll_event sEpollEvent;

    if (epoll_fd < 0 || sock_fd < 0) {
        LOG_SHM_ERROR("parameter error, iEpollFd:%d, iFd:%d", epoll_fd, sock_fd);
        return -1;
    }

    sEpollEvent.events = uEvents;
    sEpollEvent.data.fd = sock_fd;
    iRet = epoll_ctl(epoll_fd, EPOLL_CTL_DEL, sock_fd, &sEpollEvent);
    if (iRet < 0) {
        LOG_SHM_ERROR("parameter error, iEpollFd:%d, iFd:%d", epoll_fd, sock_fd);
        return -1;
    }

    return 0;
}

static int shm_set_sock_nonblocking(int iFd)
{
    int iFdFlags, iRet;

    if (iFd < 0) {
        LOG_SHM_ERROR("invalid parameter");
        return -1;
    }

    iFdFlags = fcntl(iFd, F_GETFL, 0);
    if (-1 == iFdFlags) {
        LOG_SHM_ERROR("get fd flag failed, errno=%d", errno);
        return -1;
    }

    iRet = fcntl(iFd, F_SETFL, ((uint32_t)iFdFlags | O_NONBLOCK));
    if (-1 == iRet) {
        LOG_SHM_ERROR("set fd flag failed, errno=%d", errno);
        return -1;
    }

    return 0;
}

void shm_set_proc_connected_callback(int (*func)(int *))
{
    g_proc_connected_callback = func;
}

int shm_sock_accept_conn(int listen_fd, int *client_fd)
{
    *client_fd = accept(listen_fd, NULL, NULL);
    if (*client_fd < 0) {
        LOG_SHM_ERROR("listenfd=%d accept failed, errno=%d", listen_fd, errno);
        return -1;
    }
    return 0;
}

int shm_init_client_sock(int client_fd)
{
    struct linger sSockOptLinger;
    sSockOptLinger.l_onoff = 0;
    sSockOptLinger.l_linger = 0;

    if (setsockopt(client_fd, SOL_SOCKET, SO_LINGER, &sSockOptLinger, (socklen_t)sizeof(sSockOptLinger)) < 0) {
        LOG_SHM_ERROR("setsockopt SO_LINGER fail, client_fd=%d, errno=%d", client_fd, errno);
        return -1;
    }

    if (fcntl(client_fd, F_SETFD, FD_CLOEXEC) < 0) {
        LOG_SHM_ERROR("set close-on-exec fail, client_fd=%d, errno=%d", client_fd, errno);
        return -1;
    }
    return 0;
}

int shm_handle_accept(int efd)
{
    int cli_fd = -1;
    int client_id = -1;
    int ret = 0;

    ret = shm_sock_accept_conn(g_shm_master_listen_fd, &cli_fd);
    if (ret != 0) {
        LOG_SHM_ERROR("shm_sock_accept_conn failed");
        close(cli_fd);
        return -1;
    }

    client_id = get_free_client_id();
    if (client_id < 0) {
        LOG_SHM_ERROR("[shm] no free client id left, please check.");
    }

    if (get_shm_cient_socket_fd(client_id) > 0) {
        LOG_SHM_ERROR("[shm] client is already connected, client_id(%d)", client_id);
        close(cli_fd);
        release_client_id(client_id);
        return -1;
    }

    int customized_client_id = client_id;
    if (g_proc_connected_callback != NULL && g_proc_connected_callback(&customized_client_id) != 0) {
        close(cli_fd);
        release_client_id(client_id);
        LOG_SHM_ERROR("[shm] g_proc_connected_callback fail, client_id(%d)", client_id);
        return -1;
    }

    if (shm_init_client_sock(cli_fd) != 0) {
        LOG_SHM_ERROR("[shm] shm_init_client_sock failed, client_id(%d)", client_id);
        close(cli_fd);
        release_client_id(client_id);
        return -1;
    }

    set_shm_client_socket_fd(client_id, cli_fd);

    if (shm_add_epoll_events(efd, cli_fd, ((uint32_t)EPOLLIN | (uint32_t)EPOLLRDHUP)) < 0) {
        LOG_SHM_ERROR("[shm] shm_add_epoll_events failed, efd(%d), cli_fd(%d) client_id(%d)", efd, cli_fd, client_id);
        close(cli_fd);
        release_client_id(client_id);
        return -1;
    }

    if (shm_send_all(cli_fd, (char *)&customized_client_id, (sizeof(int))) <= 0) {
        LOG_SHM_ERROR("[shm] send client_id failed, cli_fd(%d), client_id(%d)", cli_fd, client_id);
        close(cli_fd);
        release_client_id(client_id);
        return -1;
    }

    return 0;
}

int shm_create_unix_sock(shm_key_t *shm_key, int *shm_sock_fd)
{
    char sockname[SHM_PATH_MAX] = { '\0' };
    int ret;
    mode_t pre_umask;

    struct sockaddr_un shm_sin;
    socklen_t slen;

    if (snprintf_s(sockname, SHM_PATH_MAX, SHM_PATH_MAX - 1, "%s/%s.%s",
        MQ_SHM_MMAP_DIR, shm_key->shm_name, SHM_SOCK_NAME) < 0) {
        LOG_SHM_ERROR("build socket name failed! shm_name(%s)", shm_key->shm_name);
        return -1;
    }
    LOG_SHM_INFO("the socket file name is %s", sockname);

    *shm_sock_fd = shm_create_and_init_socket();
    if (*shm_sock_fd < 0) {
        LOG_SHM_ERROR("[shm] master create socket listener failed!");
        return -1;
    }

    if (shm_set_sock_nonblocking(*shm_sock_fd) < 0) {
        LOG_SHM_ERROR("set_sock_nonblocking failed!");
        close(*shm_sock_fd);
        return -1;
    }

    unlink(sockname);  // delete old socket file

    memset_s(&shm_sin, sizeof(struct sockaddr_un), 0, sizeof(struct sockaddr_un));
    shm_sin.sun_family = AF_UNIX;
    ret = strcpy_s(shm_sin.sun_path, sizeof(shm_sin.sun_path), sockname);
    if (ret != 0) {
        LOG_SHM_ERROR("strcpy_s failed. %d", ret);
        close(*shm_sock_fd);
        return -1;
    }

    slen = (socklen_t)sizeof(shm_sin.sun_family) + (socklen_t)strlen(shm_sin.sun_path);

    pre_umask = umask(SOCKET_UMASK);
    if (bind(*shm_sock_fd, (struct sockaddr *)(void *)&shm_sin, (unsigned int)slen) < 0) {
        LOG_SHM_ERROR("sock bind fail, errno=%d", errno);
        close(*shm_sock_fd);
        umask(pre_umask);
        return -1;
    }
    umask(pre_umask);

    if (listen(*shm_sock_fd, MAX_SHM_PROC) < 0) {
        LOG_SHM_ERROR("sock listen fail, errno=%d", errno);
        close(*shm_sock_fd);
        return -1;
    }

    return 0;
}

int shm_add_master_listener(shm_key_t *shm_key, int efd)
{
    if (shm_create_unix_sock(shm_key, &g_shm_master_listen_fd) == -1) {
        LOG_SHM_ERROR("shm_unix_sock_func thread failed");
        return -1;
    }

    if (shm_add_epoll_events(efd, g_shm_master_listen_fd, ((uint32_t)EPOLLIN | (uint32_t)EPOLLRDHUP)) < 0) {
        LOG_SHM_ERROR("shm_poller.shm_epoll_fd = %d, shm_sock_fd = %d add_epoll_events fail", efd,
                      g_shm_master_listen_fd);
        close(g_shm_master_listen_fd);
        g_shm_master_listen_fd = 0;
        return -1;
    }
    return 0;
}

int shm_app_disconnect_procedure(int disc_fd, int efd)
{
    int client_id = -1;

    for (int i = 0; i < MAX_SHM_PROC; i++) {
        if (get_shm_cient_socket_fd(i) == disc_fd) {
            client_id = i;
            set_shm_client_socket_fd(i, 0);
        }
    }

    if (client_id == -1) {
        LOG_SHM_ERROR("the fd = %d is not in the shm!", disc_fd);
        (void)shm_del_epoll_events(efd, disc_fd, ((uint32_t)EPOLLIN | (uint32_t)EPOLLRDHUP));
        close(disc_fd);
        return -1;
    }

    LOG_SHM_ERROR("[shm] the client(%d) is dead!", client_id);
    pthread_t thd;
    if (pthread_create(&thd, NULL, clean_up_proc_resource, (void *)client_id) != 0) {
        LOG_SHM_ERROR("[shm] create thread for clean_up_proc_resource failed, client_id(%d)", client_id);
    }

    (void)shm_del_epoll_events(efd, disc_fd, ((uint32_t)EPOLLIN | (uint32_t)EPOLLRDHUP));
    close(disc_fd);
    return 0;
}

static void *shm_unix_sock_func(void *arg)
{
    int epoll_ret = -1;
    int i, j;
    shm_poller_t *poller = (shm_poller_t *)arg;

    poller->shm_epoll_fd = epoll_create1(EPOLL_CLOEXEC);

    if (poller->shm_epoll_fd < 0) {
        LOG_SHM_ERROR("epoll_create fail, errno=%d", errno);
        sem_post(&poller->shm_epoll_init_sem);
        return NULL;
    }
    sem_post(&poller->shm_epoll_init_sem);

    while (1) {
        if ((epoll_ret = epoll_wait(poller->shm_epoll_fd, poller->shm_evs, SHM_EPOLLEVENTS_NUM,
                                    SHM_EPOLL_WAIT_TIMEOUT)) == -1) {
            if (EINTR == errno) {
                LOG_SHM_ERROR("[shm] epoll_wait interrupted by system call, wait again");
                continue;
            } else {
                LOG_SHM_ERROR("[shm] epoll_wait fail, errno(%d)", errno);
                break;
            }
        }

        for (i = 0; i < epoll_ret; i++) {
            pthread_mutex_lock(&g_master_mutex);
            if (poller->shm_evs[i].data.fd == g_shm_master_listen_fd) {
                shm_handle_accept(poller->shm_epoll_fd);
                pthread_mutex_unlock(&g_master_mutex);
                break;
            }

            if (poller->shm_evs[i].events & EPOLLRDHUP) {
                (void)shm_app_disconnect_procedure(poller->shm_evs[i].data.fd, poller->shm_epoll_fd);
            }
            pthread_mutex_unlock(&g_master_mutex);
        }
    }

    close(poller->shm_epoll_fd);
    return NULL;
}

static int shm_unix_sock_timer_start(void)
{
    pthread_t pth;
    int ret;

    shm_poller_t *poller = &shm_poller;

    sem_init(&poller->shm_epoll_init_sem, 1, 0);

    ret = pthread_create(&pth, NULL, shm_unix_sock_func, (void *)poller);
    if (ret < 0) {
        LOG_SHM_ERROR("pthread_create error, errno=%d", errno);
        return -1;
    }
    return 0;
}

/* ---------- The following code is used to implement master ------------ */

#define SHM_PROC_DIED_TICKS 2
#define PROC_INTERVAL 10
#define SET_HB_TIMES (5)
#define SHM_MASTER_LOOP_US (100 * 1000)

#define SHM_MASTER_WORKING_EXPIRE (500 * 1000)
#define SHM_MASTER_RECOVERING_EXPIRE (100 * 1000)

#define call_by_interval(c, interval, func)   \
    if ((c) >= (interval)) {                  \
        func;                                 \
        (c) = 0;                              \
    } else {                                  \
        (c)++;                                \
    }

void shm_sysv_assign_proc_id(struct shm_seg_s *_seg, int proc_id)
{
    struct shm_seg_sysv_s *seg = (struct shm_seg_sysv_s *)_seg->priv;
    if (seg == NULL) {
        LOG_SHM_ERROR("the segment is NULL!please check the code!");
        cm_panic(0);
        return;
    }
    if ((proc_id < 0) || (proc_id >= MAX_SHM_PROC)) {
        LOG_SHM_ERROR("the proc_id is invalid %d !please check the code!", proc_id);
        cm_panic(0);
        return;
    }
    seg->seg_proc = proc_id;
}

int shm_sysv_proc_alive(struct shm_seg_s *_seg, int proc_id)
{
    struct shm_seg_sysv_s *seg = (struct shm_seg_sysv_s *)_seg->priv;

    if (seg == NULL) {
        LOG_SHM_ERROR("the segment is NULL!please check the code!");
        cm_panic(0);
        return -1;
    }
    if ((proc_id < 0) || (proc_id >= MAX_SHM_PROC)) {
        LOG_SHM_ERROR("the proc_id is %d !please check the code!", proc_id);
        cm_panic(0);
        return -1;
    }
    shm_area_t *all_seg_shm = seg->all_seg_shm;
    return shm_proc_is_alive(&all_seg_shm->procs[proc_id]) || shm_proc_is_checking(&all_seg_shm->procs[proc_id]);
}

int shm_start_checking_thread(shm_key_t *shm_key)
{
    struct shm_timer_s *timer;
    if (g_shm_is_master_thread_init == 0) {
        LOG_SHM_INFO("master timer thread isn't running, will create the thread immediately.");
        if (shm_timer_thread_start() < 0) {
            LOG_SHM_ERROR("the shm_timer_thread_start failed!");
            return -1;
        }
#ifndef WITHOUT_MONITOR
        if (shm_unix_sock_timer_start() < 0) {
            LOG_SHM_ERROR("the shm_unix_sock_timer_start failed!");
            return -1;
        }
        sem_wait(&shm_poller.shm_epoll_init_sem);
        if (shm_add_master_listener(shm_key, shm_poller.shm_epoll_fd) == -1) { /*start unix domain socket listen
                                                                                  thread*/
            LOG_SHM_ERROR("shm_add_one_seg_listenner failed!");
            return -1;
        }
#endif
        g_shm_is_master_thread_init = 1;
    }

    return 0;
}

static void shm_master_fnit(struct shm_seg_sysv_s *seg)
{
    if (seg->shm_key.type == SHM_KEY_MMAP && seg->all_seg_shm != NULL) {
        (void)shm_detach_mmap(seg->all_seg_shm, seg->all_seg_shm->head.total_size);
        (void)shm_unlink_mmap(seg->shm_key.mmap_name);
    }
    if (shm_delete_seg_key_item(seg->shm_key) == -1) {
        LOG_SHM_ERROR("the key_list have been delete! there are no this seg in seg_array.");
    }
}

static void shm_sort_mem_class(shm_mem_class_t mem_class[], int nr_mem_class)
{
    int i, j;
    shm_mem_class_t shm_mem_temp;
    for (i = nr_mem_class - 1; 0 < i; i--) {
        for (j = 0; j < i; j++) {
            if (mem_class[j].size > mem_class[j + 1].size) {
                shm_mem_temp.num = mem_class[j].num;
                shm_mem_temp.size = mem_class[j].size;

                mem_class[j].num = mem_class[j + 1].num;
                mem_class[j].size = mem_class[j + 1].size;

                mem_class[j + 1].num = shm_mem_temp.num;
                mem_class[j + 1].size = shm_mem_temp.size;
            }
        }
    }
}

static void shm_8bytes_align_and_merge(shm_mem_class_t mem_class[], int *nr_mem_class)
{
    int i, j;

    if (nr_mem_class == NULL) {
        return;
    }

    shm_sort_mem_class(mem_class, *nr_mem_class);

    for (i = 0; i < *nr_mem_class; i++) {
        if (mem_class[i].size % 8 != 0) {
            mem_class[i].size = (mem_class[i].size / 8 + 1) * 8;
        }
    }

    for (i = 1; i < *nr_mem_class;) {
        if (mem_class[i - 1].size == mem_class[i].size) {
            mem_class[i - 1].num += mem_class[i].num;
            for (j = i + 1; j < *nr_mem_class; j++) {
                memcpy_s(&mem_class[j - 1], sizeof(shm_mem_class_t), &mem_class[j], sizeof(shm_mem_class_t));
            }
            *nr_mem_class = *nr_mem_class - 1;
        } else {
            i++;
        }
    }
}

int shm_sysv_master_init_prepare(shm_mem_class_t mem_class[], int nr_mem_class, struct  shm_seg_s **_seg,
    struct  shm_seg_sysv_s **seg)
{
    if (g_current_seg_num == MAX_SHM_SEG_NUM || mem_class == NULL || nr_mem_class == 0) {
        LOG_SHM_ERROR("the Segment, the mem_class or the nr_mem_class must not be NULL");
        pthread_mutex_unlock(&g_master_mutex);
        return -1;
    }

    *_seg = (struct shm_seg_s *)calloc(1, sizeof(struct shm_seg_s));
    *seg = (struct shm_seg_sysv_s *)calloc(1, sizeof(struct shm_seg_sysv_s));
    if (*_seg == NULL || *seg == NULL) {
        LOG_SHM_ERROR(" malloc error !the segment is NULL");
        free(*seg);
        free(*_seg);
        pthread_mutex_unlock(&g_master_mutex);
        return -1;
    }

    return 0;
}

struct shm_seg_s *shm_sysv_master_init(shm_key_t *shm_key, shm_mem_class_t mem_class[],
                                       int nr_mem_class, int start_lsnr)
{
    int master_alive = 0, ret, seg_idx;

    shm_8bytes_align_and_merge(mem_class, &nr_mem_class);

    pthread_mutex_lock(&g_master_mutex);

    struct  shm_seg_s *_seg = NULL;
    struct  shm_seg_sysv_s *seg = NULL;

    if (shm_sysv_master_init_prepare(mem_class, nr_mem_class, &_seg, &seg) != 0) {
        return NULL;
    }

    _seg->type = shm_key->type;
    _seg->ops = &g_shm_sysv_ops;
    _seg->priv = seg;

    memcpy_s(&seg->shm_key, sizeof(shm_key_t), shm_key, sizeof(shm_key_t));

    seg->running = 1;
    seg->type = shm_segtype_master;
    ret = pthread_mutex_init(&seg->master_recovery_mutex, NULL);
    if (ret != 0) {
        LOG_SHM_ERROR("the pthread_mutex_init error, ret = %d, errno = %d", ret, errno);
        goto failed;
    }

    ret = shm_was_init(seg, shm_key, mem_class, nr_mem_class, 1, &master_alive);
    if (seg->all_seg_shm == NULL) {
        LOG_SHM_ERROR("master init addr map error, the seg->all_seg_shm = NULL.");
        shm_master_fnit(seg);
        goto failed;
    }
    if (ret < 0) {
        shm_start(seg, mem_class, nr_mem_class);
        memset_s(seg->seg_proc_tracker, sizeof(seg->seg_proc_tracker), 0, sizeof(seg->seg_proc_tracker));
    } else {
        if (master_alive != 0) {                                 /* avoid double master , no use*/
            LOG_SHM_ERROR("master error ! start double master"); /*�ÿɶ�λ�Ա�֤(�����ϲ�ҵ��)*/
            goto failed;
        }
    }

    if (start_lsnr == 1 && shm_start_checking_thread(shm_key) < 0) {
        shm_master_fnit(seg);
        goto failed;
    }

    seg_idx = __sync_fetch_and_add(&g_current_seg_num, 1);
    seg->_seg = _seg;
    g_seg_array[seg_idx] = seg;
    pthread_mutex_unlock(&g_master_mutex);
    return _seg;

failed:
    free(seg);
    free(_seg);
    pthread_mutex_unlock(&g_master_mutex);
    return NULL;
}

/*
   get the bitmap of all alive processes
   alive_bits -- the bit will be setted if its corresponding proc is alive
*/
void get_alive_proc(struct shm_seg_sysv_s *seg, uint64_t *alive_bits)
{
    int i;
    shm_proc_t *p;
    shm_area_t *all_seg_shm = seg->all_seg_shm;

    *alive_bits = 0;
    for (i = 0; i < MAX_SHM_PROC; i++) {
        p = &all_seg_shm->procs[i];
        if (shm_proc_is_alive(p) || shm_proc_is_checking(p)) {
            *alive_bits |= (1UL << i);
        }
    }
}

int shm_sysv_master_exit(struct shm_seg_s *_seg)
{
    struct shm_seg_sysv_s *seg = (struct shm_seg_sysv_s *)_seg->priv;
    uint64_t alive_bits;

    pthread_mutex_lock(&g_master_mutex);

    get_alive_proc(seg, &alive_bits);
    if (alive_bits != 0) {
        LOG_SHM_ERROR("The seg have already had proc is alive, so its master cannot exit. alive_bits = %lx",
                      alive_bits);
        pthread_mutex_unlock(&g_master_mutex);
        return -1;
    }

    if (seg->recover_timer != NULL) {
        shm_timer_del(seg->recover_timer);
        shm_timer_free(seg->recover_timer);
    }

    shm_sysv_and_mmap_seg_exit(_seg);

    pthread_mutex_unlock(&g_master_mutex);
    return 0;
}

void shm_walk_all_block(struct shm_seg_sysv_s *seg,
                        void (*cb)(struct shm_seg_sysv_s*, int, int, mem_blk_hdr_t *, uint64_t), uint64_t arg)
{
    int i, j, sz;
    shm_mem_list_t  *m;
    mem_blk_hdr_t   *hdr;
    uint32_t       ptr;
   
    for (i = 0; i < seg->all_seg_shm->head.nr_mem_class; i++) {
        m = &(seg->all_seg_shm)->mem_list[i];
        if (m->total == 0) {
            continue;
        }
        sz = m->size + sizeof(mem_blk_hdr_t);
        for (ptr = m->start, j = 0; j < m->total; j++, ptr += (uint32_t)sz) {
            hdr = (mem_blk_hdr_t *)shm2ptr((char *)(seg->all_seg_shm), ptr);
            cb(seg, i, j, hdr, arg);
        }
    }
}

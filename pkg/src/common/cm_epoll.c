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
 * cm_epoll.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_epoll.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_epoll.h"

#ifdef WIN32
#include "cm_queue.h"
#include "cm_error.h"
#include "cm_hash.h"
#include <winsock2.h>

#define EPOLL_EPFD_EXTENT_STEP 1
#define EPOLL_MAX_EPFD_COUNT   1024
#define EPOLL_FD_EXTENT_STEP   16
#define EPOLL_MAX_FD_COUNT     10240
#define EPOLL_HASHMAP_BUCKETS  97

typedef struct epoll_event epoll_event_t;

typedef struct st_entry_node {
    uint32 id;
    struct st_entry_node *prev;
    struct st_entry_node *next;
} entry_node_t;

typedef struct st_entry_pool {
    uint32 threshold;
    uint32 steps;
    uint32 extents;
    uint32 entry_size;
    biqueue_t idles;
    char **buf;
} entry_pool_t;

typedef struct st_fd_entry {
    uint32 id;
    struct st_fd_entry *prev;
    struct st_fd_entry *next;
    epoll_event_t evnt;
    bool32 oneshot_flag;
    bool32 oneshot_enable;
} fd_entry_t;

typedef struct st_entry_bucket {
    spinlock_t bucket_lock;
    biqueue_t entry_que;
} entry_bucket_t;

typedef struct st_epfd_entry {
    uint32 epfd;
    struct st_epfd_entry *prev;
    struct st_epfd_entry *next;
    spinlock_t fd_pool_lock;
    entry_pool_t *fd_pool;
    spinlock_t bucket_lock;
    entry_bucket_t *hash_map_fd2id;
    uint32 currbucket;
    biqueue_node_t *currnode;
} epfd_entry_t;

static entry_pool_t *epfd_pool;
static spinlock_t epfd_pool_lock;

static int entry_pool_extend_sync(spinlock_t *lock, entry_pool_t *pool, biqueue_node_t **output)
{
    entry_node_t *node = NULL;
    char *buf = NULL;
    uint32 loop, idx, size;
    bool32 limit_reached = CT_FALSE;
    errno_t rc_memzero;

    for (;;) {
        if (pool->buf[pool->extents - 1] == NULL) {  // some one other is extending the pool
            continue;
        }
        cm_spin_lock(lock, NULL);
        if (pool->buf[pool->extents - 1] == NULL) {
            cm_spin_unlock(lock);
            continue;
        }
        if (!biqueue_empty(&pool->idles)) {
            if (*output != NULL) {
                *output = biqueue_del_head(&pool->idles);
            }
            cm_spin_unlock(lock);
            return CT_SUCCESS;
        }
        limit_reached = pool->extents == pool->threshold / pool->steps;
        idx = pool->extents++;
        cm_spin_unlock(lock);
        break;
    }

    if (limit_reached) {
        --pool->extents;
        CT_THROW_ERROR(ERR_ALLOC_MEMORY_REACH_LIMIT, pool->threshold * pool->entry_size);
        return CT_ERROR;
    }
    size = pool->entry_size * pool->steps;
    if (size == 0 || size / pool->steps != pool->entry_size) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)pool->entry_size * pool->steps, "extending memory");
        --pool->extents;
        return CT_ERROR;
    }
    buf = (char *)malloc(size);
    if (buf == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)size, "extending memory");
        --pool->extents;
        return CT_ERROR;
    }
    rc_memzero = memset_sp(buf, size, 0, size);
    if (rc_memzero != EOK) {
        CM_FREE_PTR(buf);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (rc_memzero));
        --pool->extents;
        return CT_ERROR;
    }

    node = (entry_node_t *)buf;
    node->id = idx * pool->steps;
    *output = QUEUE_NODE_OF(node);

    cm_spin_lock(lock, NULL);
    for (loop = 1; loop < pool->steps; ++loop) {
        node = (entry_node_t *)(buf + pool->entry_size * loop);
        node->id = loop + idx * pool->steps;
        biqueue_add_tail(&pool->idles, QUEUE_NODE_OF(node));
    }
    cm_spin_unlock(lock);

    pool->buf[idx] = buf;

    return CT_SUCCESS;
}

static int entry_pool_extend(entry_pool_t *pool)
{
    entry_node_t *node = NULL;
    uint32 loop, size;
    errno_t rc_memzero;
    if (pool->extents == pool->threshold / pool->steps) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY_REACH_LIMIT, pool->threshold * pool->entry_size);
        return CT_ERROR;
    }
    size = pool->entry_size * pool->steps;
    if (size == 0 || size / pool->steps != pool->entry_size) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)pool->entry_size * pool->steps, "extending memory");
        return CT_ERROR;
    }
    pool->buf[pool->extents] = (char *)malloc(size);
    if (pool->buf[pool->extents] == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)size, "extending memory");
        return CT_ERROR;
    }
    rc_memzero = memset_sp(pool->buf[pool->extents], size, 0, size);
    if (rc_memzero != EOK) {
        CM_FREE_PTR(pool->buf[pool->extents]);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (rc_memzero));
        return CT_ERROR;
    }

    for (loop = 0; loop < pool->steps; ++loop) {
        node = (entry_node_t *)(pool->buf[pool->extents] + pool->entry_size * loop);
        node->id = loop + pool->extents * pool->steps;
        biqueue_add_tail(&pool->idles, QUEUE_NODE_OF(node));
    }
    ++pool->extents;

    return CT_SUCCESS;
}

static int entry_pool_init(entry_pool_t **pool, uint32 steps, uint32 threshold, uint32 entry_size)
{
    uint32 maxextents;
    errno_t rc_memzero;

    *pool = (entry_pool_t *)malloc(sizeof(entry_pool_t));
    if (*pool == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)sizeof(entry_pool_t), "extending memory");
        return CT_ERROR;
    }
    rc_memzero = memset_sp(*pool, sizeof(entry_pool_t), 0, sizeof(entry_pool_t));
    if (rc_memzero != EOK) {
        CM_FREE_PTR(*pool);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, rc_memzero);
        return CT_ERROR;
    }

    if (steps == 0) {
        CM_FREE_PTR(*pool);
        CT_THROW_ERROR(ERR_ZERO_DIVIDE);
        return CT_ERROR;
    }
    threshold = (threshold + steps - 1) / steps * steps;
    maxextents = threshold / steps;
    (*pool)->threshold = threshold;
    (*pool)->steps = steps;
    (*pool)->extents = 0;
    (*pool)->entry_size = entry_size;
    biqueue_init(&(*pool)->idles);
    if (maxextents == 0) {
        CM_FREE_PTR(*pool);
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)maxextents * sizeof(char *), "extending memory");
        return CT_ERROR;
    }
    (*pool)->buf = (char **)malloc(maxextents * sizeof(char *));
    if ((*pool)->buf == NULL) {
        CM_FREE_PTR(*pool);
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)maxextents * sizeof(char *), "extending memory");
        return CT_ERROR;
    }
    rc_memzero = memset_sp((*pool)->buf, maxextents * sizeof(char *), 0, maxextents * sizeof(char *));
    if (rc_memzero != EOK) {
        CM_FREE_PTR((*pool)->buf);
        CM_FREE_PTR(*pool);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, rc_memzero);
        return CT_ERROR;
    }
    return entry_pool_extend(*pool);
}

static biqueue_node_t *entry_pool_find_node(entry_pool_t *pool, uint32 id)
{
    uint32 extent, idx;

    extent = id / pool->steps;
    idx = id % pool->steps;

    if (extent >= pool->extents) {
        return NULL;
    }
    if (idx >= pool->steps) {
        return NULL;
    }
    return QUEUE_NODE_OF ((entry_node_t *)(pool->buf[extent] + idx * pool->entry_size));
}

static biqueue_node_t *entry_queue_find_node(biqueue_t *que, uint32 id)
{
    // find whether the fd already exists
    biqueue_node_t *node = biqueue_first(que);
    biqueue_node_t *end = biqueue_end(que);
    entry_node_t *entry = NULL;  // only for warning C4703
    while (node != end) {
        entry = OBJECT_OF(entry_node_t, node);
        if (entry->id == id) {
            break;
        }
        node = node->next;
    }
    return node == end ? NULL : QUEUE_NODE_OF(entry);
}

static int epoll_ctl_add(epfd_entry_t *entry, int fd, struct epoll_event *event)
{
    entry_bucket_t *entry_bucket = NULL;
    biqueue_node_t *node = NULL;
    uint32 idx;
    fd_entry_t *fd_entry = NULL;

    if (fd < 0) {
        CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "fd(%d) >= 0", fd);
        return -1;
    }

    idx = cm_hash_uint32(fd, EPOLL_HASHMAP_BUCKETS);
    entry_bucket = &entry->hash_map_fd2id[idx];

    cm_spin_lock(&entry_bucket->bucket_lock, NULL);
    // find whether the fd already exists
    node = entry_queue_find_node(&entry_bucket->entry_que, (uint32)fd);
    cm_spin_unlock(&entry_bucket->bucket_lock);
    if (node != NULL) {
        return -1;
    }

    // allocate entry for new fd
    cm_spin_lock(&entry->fd_pool_lock, NULL);
    node = biqueue_del_head(&entry->fd_pool->idles);
    cm_spin_unlock(&entry->fd_pool_lock);
    if (node == NULL) {
        if (CT_SUCCESS != entry_pool_extend_sync(&entry->fd_pool_lock, entry->fd_pool, &node)) {
            return -1;
        }
    }
    fd_entry = OBJECT_OF(fd_entry_t, node);
    fd_entry->evnt = *event;
    if (fd_entry->evnt.events & EPOLLONESHOT) {
        fd_entry->oneshot_flag = CT_TRUE;
        fd_entry->oneshot_enable = CT_TRUE;
    } else {
        fd_entry->oneshot_flag = CT_FALSE;
    }
    fd_entry->id = (uint32)fd;

    cm_spin_lock(&entry_bucket->bucket_lock, NULL);
    biqueue_add_tail(&entry_bucket->entry_que, node);
    cm_spin_unlock(&entry_bucket->bucket_lock);
    return 0;
}

static int epoll_ctl_mod(epfd_entry_t *entry, int fd, struct epoll_event *event)
{
    entry_bucket_t *entry_bucket = NULL;
    biqueue_node_t *node = NULL;
    uint32 idx;
    fd_entry_t *fd_entry = NULL;

    if (fd < 0) {
        CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "fd(%d) >= 0", fd);
        return -1;
    }

    idx = cm_hash_uint32(fd, EPOLL_HASHMAP_BUCKETS);
    entry_bucket = &entry->hash_map_fd2id[idx];

    // find whether the fd already exists, if exists,  modify it
    cm_spin_lock(&entry_bucket->bucket_lock, NULL);
    node = entry_queue_find_node(&entry_bucket->entry_que, (uint32)fd);
    if (node == NULL) {
        cm_spin_unlock(&entry_bucket->bucket_lock);
        return -1;
    }

    fd_entry = OBJECT_OF(fd_entry_t, node);
    fd_entry->evnt = *event;
    if (fd_entry->evnt.events & EPOLLONESHOT) {
        fd_entry->oneshot_flag = CT_TRUE;
        fd_entry->oneshot_enable = CT_TRUE;
    } else {
        fd_entry->oneshot_flag = CT_FALSE;
    }
    cm_spin_unlock(&entry_bucket->bucket_lock);
    return 0;
}

static int epoll_ctl_del(epfd_entry_t *entry, int fd)
{
    biqueue_node_t *node = NULL;

    uint32 idx = cm_hash_uint32(fd, EPOLL_HASHMAP_BUCKETS);
    entry_bucket_t *entry_bucket = &entry->hash_map_fd2id[idx];

    // find whether the fd already exists
    cm_spin_lock(&entry_bucket->bucket_lock, NULL);
    node = entry_queue_find_node(&entry_bucket->entry_que, (uint32)fd);
    if (node == NULL) {
        cm_spin_unlock(&entry_bucket->bucket_lock);
        return -1;
    }

    if (node == entry->currnode) {
        if (node->next == biqueue_end(&entry_bucket->entry_que)) {
            entry->currbucket = (++entry->currbucket) % EPOLL_HASHMAP_BUCKETS;
            entry->currnode = NULL;
        } else {
            entry->currnode = node->next;
        }
    }

    biqueue_del_node(node);
    cm_spin_unlock(&entry_bucket->bucket_lock);

    cm_spin_lock(&entry->fd_pool_lock, NULL);
    biqueue_add_tail(&entry->fd_pool->idles, node);
    cm_spin_unlock(&entry->fd_pool_lock);
    return 0;
}

static void epoll_epfd_clean(epfd_entry_t *entry)
{
    CM_FREE_PTR(entry->fd_pool);
    CM_FREE_PTR(entry->hash_map_fd2id);
    entry->currbucket = 0;
    entry->currnode = NULL;
}

int epoll_init()
{
    struct WSAData wd;
    uint16 version = MAKEWORD(1, 1);
    if (WSAStartup(version, &wd) != 0) {
        CT_THROW_ERROR(ERR_INIT_NETWORK_ENV, "failed to start up Windows Sockets Asynchronous");
        return CT_ERROR;
        ;
    }
    epfd_pool_lock = 0;
    return entry_pool_init(&epfd_pool, EPOLL_EPFD_EXTENT_STEP, EPOLL_MAX_EPFD_COUNT, sizeof(epfd_entry_t));
}

int epoll_create1(int flags)
{
    biqueue_node_t *node = NULL;
    uint32 loop;
    errno_t rc_memzero;

    cm_spin_lock(&epfd_pool_lock, NULL);
    node = biqueue_del_head(&epfd_pool->idles);
    cm_spin_unlock(&epfd_pool_lock);
    if (node == NULL) {
        if (CT_SUCCESS != (entry_pool_extend_sync(&epfd_pool_lock, epfd_pool, &node))) {
            return -1;
        }
    }

    epfd_entry_t *entry = OBJECT_OF(epfd_entry_t, node);
    entry->hash_map_fd2id = malloc(EPOLL_HASHMAP_BUCKETS * sizeof(entry_bucket_t));
    if (entry->hash_map_fd2id == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)EPOLL_HASHMAP_BUCKETS * sizeof(entry_bucket_t), "extending memory");
        return -1;
    }
    rc_memzero = memset_sp(entry->hash_map_fd2id, EPOLL_HASHMAP_BUCKETS * sizeof(entry_bucket_t), 0,
                           EPOLL_HASHMAP_BUCKETS * sizeof(entry_bucket_t));
    if (rc_memzero != EOK) {
        CM_FREE_PTR(entry->hash_map_fd2id);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, rc_memzero);
        return CT_ERROR;
    }
    for (loop = 0; loop < EPOLL_HASHMAP_BUCKETS; ++loop) {
        entry->hash_map_fd2id[loop].bucket_lock = 0;
        biqueue_init(&entry->hash_map_fd2id[loop].entry_que);
    }
    if (CT_SUCCESS != entry_pool_init(&entry->fd_pool, EPOLL_FD_EXTENT_STEP, EPOLL_MAX_FD_COUNT, sizeof(fd_entry_t))) {
        CM_FREE_PTR(entry->hash_map_fd2id);
        return -1;
    }
    entry->currbucket = 0;
    entry->currnode = NULL;
    return entry->epfd;
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    biqueue_node_t *node;
    node = entry_pool_find_node(epfd_pool, epfd);
    if (node == NULL) {
        return -1;
    }
    
    if (event != NULL) {
        CT_BIT_RESET(event->events, EPOLLRDHUP);
        if (event->events == 0) {
            return 0;
        }
    } else if (op != EPOLL_CTL_DEL) {
        return -1;
    }

    switch (op) {
        case EPOLL_CTL_ADD:
            return epoll_ctl_add(OBJECT_OF(epfd_entry_t, node), fd, event);
        case EPOLL_CTL_MOD:
            return epoll_ctl_mod(OBJECT_OF(epfd_entry_t, node), fd, event);
        case EPOLL_CTL_DEL:
            return epoll_ctl_del(OBJECT_OF(epfd_entry_t, node), fd);
        default:
            return -1;
    }
}

int epoll_wait_fd(int epfd, int maxevents, uint32 *loop, fd_entry_t *fds[FD_SETSIZE], fd_set *rfds, fd_set *efds)
{
    entry_bucket_t *entry_bucket = NULL;
    epfd_entry_t *epfd_entry = NULL;
    uint32 currbucket, nfds;

    biqueue_node_t *curr = entry_pool_find_node(epfd_pool, epfd);
    if (curr == NULL) {
        return -1;
    }
    epfd_entry = OBJECT_OF(epfd_entry_t, curr);

    nfds = FD_SETSIZE > maxevents ? maxevents : FD_SETSIZE;
    currbucket = epfd_entry->currbucket;
    curr = epfd_entry->currnode;

    FD_ZERO(rfds);
    FD_ZERO(efds);
    entry_bucket = &epfd_entry->hash_map_fd2id[currbucket];
    cm_spin_lock(&entry_bucket->bucket_lock, NULL);
    do {
        if (curr == NULL) {
            curr = biqueue_first(&entry_bucket->entry_que);
            continue;
        }
        if (curr == biqueue_end(&entry_bucket->entry_que)) {
            cm_spin_unlock(&entry_bucket->bucket_lock);
            currbucket = (++currbucket) % EPOLL_HASHMAP_BUCKETS;
            curr = NULL;
            entry_bucket = &epfd_entry->hash_map_fd2id[currbucket];
            cm_spin_lock(&entry_bucket->bucket_lock, NULL);
        } else {
            fds[*loop] = OBJECT_OF(fd_entry_t, curr);
            if (fds[*loop]->evnt.events != 0 &&
                (!fds[*loop]->oneshot_flag || fds[*loop]->oneshot_enable)) {
                FD_SET(fds[*loop]->id, rfds);
                FD_SET(fds[*loop]->id, efds);
                ++(*loop);
            }
            curr = curr->next;
        }
    } while ((curr != epfd_entry->currnode || currbucket != epfd_entry->currbucket) && *loop < nfds);

    if (curr == biqueue_end(&entry_bucket->entry_que)) {
        epfd_entry->currbucket = (++currbucket) % EPOLL_HASHMAP_BUCKETS;
        epfd_entry->currnode = NULL;
    } else {
        epfd_entry->currbucket = currbucket;
        epfd_entry->currnode = curr;
    }
    cm_spin_unlock(&entry_bucket->bucket_lock);
    return 0;
}

int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
    uint32 loop, nfds, selected;
    fd_entry_t *fds[FD_SETSIZE];
    fd_set rfds, efds;
    bool32 rfdsetted = CT_FALSE;
    bool32 efdsetted = CT_FALSE;
    int ret;
    struct timeval tv;

    loop = 0;

    if (epoll_wait_fd(epfd, maxevents, &loop, fds, &rfds, &efds) != 0) {
        return -1;
    }

    if (loop == 0) {
        cm_sleep(5);
        return 0;
    }

    tv.tv_sec = timeout / 1000;
    tv.tv_usec = (timeout % 1000) * 1000;
    ret = select(0, &rfds, NULL, &efds, &tv);
    if (ret <= 0) {
        return 0;
    }

    nfds = loop;
    selected = 0;
    for (loop = 0; loop < nfds; ++loop) {
        rfdsetted = FD_ISSET(fds[loop]->id, &rfds);
        efdsetted = FD_ISSET(fds[loop]->id, &efds);
        if (rfdsetted || efdsetted) {
            events[selected].events = 0;
            events[selected].events |= rfdsetted ? EPOLLIN : 0;
            events[selected].events |= efdsetted ? EPOLLHUP : 0;
            events[selected++] = fds[loop]->evnt;
            if (fds[loop]->oneshot_flag) {
                fds[loop]->oneshot_enable = CT_FALSE;
            }
        }
    }
    return selected;
}

#endif

int epoll_close(int epfd)
{
#ifndef WIN32
    return close(epfd);
#else
    cm_spin_lock(&epfd_pool_lock, NULL);
    biqueue_node_t *node = entry_pool_find_node(epfd_pool, epfd);
    cm_spin_unlock(&epfd_pool_lock);

    if (node == NULL) {
        return -1;
    }
    epfd_entry_t *entry = OBJECT_OF(epfd_entry_t, node);
    epoll_epfd_clean(entry);
    cm_spin_lock(&epfd_pool_lock, NULL);
    biqueue_add_tail(&epfd_pool->idles, QUEUE_NODE_OF(entry));
    cm_spin_unlock(&epfd_pool_lock);
    return 0;
#endif
}

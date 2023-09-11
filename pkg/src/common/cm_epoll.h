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
 * cm_epoll.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_epoll.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_EPOLL_H__
#define __CM_EPOLL_H__

#ifndef WIN32
#include <sys/epoll.h>
#include <unistd.h>
#else
#include "cm_defs.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
#define EPOLLIN  0x001
#define EPOLLHUP 0x002
#define EPOLLRDHUP  0x004
#define EPOLLONESHOT 0x008

#define EPOLL_CTL_ADD 0
#define EPOLL_CTL_MOD 1
#define EPOLL_CTL_DEL 2

typedef union epoll_data {
    void *ptr;
    int fd;
    uint32 u32;
    uint64 u64;
} epoll_data_t;

struct epoll_event {
    uint32 events;     /* Epoll events */
    epoll_data_t data; /* User data variable */
};

int epoll_init();

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);

int epoll_create1(int flags);

int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);

#endif

int epoll_close(int epfd);

#ifdef __cplusplus
}
#endif

#endif

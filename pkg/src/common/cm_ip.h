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
 * cm_ip.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_ip.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_IP_H__
#define __CM_IP_H__

#include "cm_defs.h"
#include "cm_system.h"
#include "cm_error.h"
#include "cm_text.h"
#include "cm_list.h"
#include "cm_date.h"

#ifndef WIN32
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#else
#include <winsock2.h>
#include <mstcpip.h>
#include <Ws2tcpip.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_sock_addr {
    struct sockaddr_storage addr;
    socklen_t salen;
} sock_addr_t;

// sa: sock_addr_t
#define SOCKADDR(sa)        ((struct sockaddr *)&(sa)->addr)
#define SOCKADDR_IN4(sa)    ((struct sockaddr_in *)&(sa)->addr)
#define SOCKADDR_IN6(sa)    ((struct sockaddr_in6 *)&(sa)->addr)
#define SOCKADDR_FAMILY(sa) (SOCKADDR(sa)->sa_family)
#define SOCKADDR_PORT(sa)   (SOCKADDR_FAMILY(sa) == AF_INET ? SOCKADDR_IN4(sa)->sin_port : SOCKADDR_IN6(sa)->sin6_port)

typedef struct st_cidr {
    struct sockaddr_storage addr;
    int mask;
} cidr_t;

// user white list entry
typedef struct st_uwl_entry {
    bool32 hostssl;
    char user[CT_NAME_BUFFER_SIZE];
    list_t white_list;  // cidr_t
} uwl_entry_t;

typedef struct st_ip_login {
    char ip[CT_HOST_NAME_BUFFER_SIZE];
    uint32 malicious_ip_count;
    date_t start_time;
    date_t last_time;
}ip_login_t;

#define INIT_UWL_ENTRY(entry)                               \
    do {                                                    \
        (entry)->user[0] = '\0';                              \
        cm_create_list(&(entry)->white_list, sizeof(cidr_t)); \
    } while (0)

typedef struct st_white_context {
    spinlock_t lock;

    // ip white list(iwl) from TCP_INVITED_NODES/TCP_EXCLUDED_NODES params
    bool32 iwl_enabled;
    list_t ip_white_list;
    list_t ip_black_list;

    // user white list(uwl) from cthba.conf
    list_t user_white_list;  // uwl_entry_t
} white_context_t;

typedef struct st_mal_ip_context {
    ip_spinlock_t ip_lock;
    list_t malicious_ip_list;
} mal_ip_context_t;

static inline const char *cm_inet_ntop(struct sockaddr *addr, char *buffer, int size)
{
    errno_t errcode = 0;
    void *sin_addr = (addr->sa_family == AF_INET6) ? (void *)&((struct sockaddr_in6 *)addr)->sin6_addr
                                                   : (void *)&((struct sockaddr_in *)addr)->sin_addr;

    buffer[0] = '\0';
    if (inet_ntop(addr->sa_family, sin_addr, buffer, (size_t)size) == NULL) {
        errcode = strncpy_s(buffer, size, "0.0.0.0", sizeof("0.0.0.0") - 1);
        if (SECUREC_UNLIKELY(errcode != EOK)) {
            CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return NULL;
        }
    }

    return buffer;
}

static inline bool32 cm_is_lookback_ip(const char *client_ip)
{
    if (cm_str_equal(client_ip, "127.0.0.1") ||
        cm_str_equal(client_ip, "::1") ||
        cm_str_equal(client_ip, "::ffff:127.0.0.1")) {
        return CT_TRUE;
    }
    return CT_FALSE;
}

static inline bool32 cm_is_equal_ip(const char *client_ip, const char *local_ip)
{
    // IPV6 PREFIX FOR IPV4 ADDR
#define IPV6_PREFIX         "::ffff:"
#define IPV6_PREFIX_LEN     7
#define HAS_IPV6_PREFIX(ip) ((strlen(ip) > IPV6_PREFIX_LEN) && memcmp((ip), IPV6_PREFIX, IPV6_PREFIX_LEN) == 0)
    if (cm_str_equal_ins(client_ip, local_ip) ||
        (HAS_IPV6_PREFIX(client_ip) && cm_str_equal_ins(client_ip + IPV6_PREFIX_LEN, local_ip))) {
        return CT_TRUE;
    }
    return CT_FALSE;
}

#ifdef WIN32
static inline bool32 cm_is_localip_4win32(const char *client_ip)
{
    int ret;
    char *host_name = cm_sys_host_name();
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *cur = NULL;
    struct sockaddr_in *addr = NULL;
    char ipv4[CM_MAX_IP_LEN];
    errno_t rc_memzero;

    if (cm_is_lookback_ip(client_ip)) {
        return CT_TRUE;
    }

    rc_memzero = memset_sp(&hints, sizeof(struct addrinfo), 0, sizeof(struct addrinfo));
    if (SECUREC_UNLIKELY(rc_memzero != EOK)) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, rc_memzero);
        return CT_FALSE;
    }
    hints.ai_family = AF_INET;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_protocol = 0;
    hints.ai_socktype = SOCK_STREAM;
    ret = getaddrinfo(host_name, NULL, &hints, &res);
    if (ret != 0) {
        CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "ret(%d) == 0", ret);
        return CT_FALSE;
    }

    for (cur = res; cur != NULL; cur = cur->ai_next) {
        addr = (struct sockaddr_in *)cur->ai_addr;
        (void)inet_ntop(AF_INET, &addr->sin_addr, ipv4, CM_MAX_IP_LEN);

        if (cm_is_equal_ip(client_ip, ipv4)) {
            freeaddrinfo(res);
            return CT_TRUE;
        }
    }
    freeaddrinfo(res);
    return CT_FALSE;
}
#endif

static inline bool32 cm_is_local_ip(const char *client_ip)
{
#ifdef WIN32
    return cm_is_localip_4win32(client_ip);
#else

    struct ifaddrs *ifa = NULL;
    struct ifaddrs *if_list = NULL;

    if (cm_is_lookback_ip(client_ip)) {
        return CT_TRUE;
    }

    if (getifaddrs(&if_list) == -1) {
        return CT_FALSE;
    }

    for (ifa = if_list; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }

        sa_family_t family = ifa->ifa_addr->sa_family;

        if (family == AF_INET || family == AF_INET6) {
            char ipstr[CM_MAX_IP_LEN];
            (void)cm_inet_ntop(ifa->ifa_addr, ipstr, CM_MAX_IP_LEN);
            if (cm_is_equal_ip(client_ip, ipstr)) {
                freeifaddrs(if_list);
                return CT_TRUE;
            }
        }
    }

    freeifaddrs(if_list);
#endif

    return CT_FALSE;
}

status_t cm_ipport_to_sockaddr(const char *host, int port, sock_addr_t *sock_addr);
status_t cm_ip_to_sockaddr(const char *host, sock_addr_t *sock_addr);
bool32 cm_check_ip_valid(const char *ip);
status_t cm_parse_cidrs(text_t *cidr_texts, list_t *cidr_list);
status_t cm_str_to_cidr(char *cidr_str, cidr_t *cidr, uint32 cidr_str_len);
bool32 cm_check_ip(white_context_t *ctx, const char *ip_str, const char *user, bool32 *hostssl);
status_t cm_ip_in_cidr(const char *ip_str, cidr_t *cidr, bool32 *result);
extern status_t cm_cidr_equals_cidr(cidr_t *cidr1, cidr_t *cidr2, bool32 *result);
status_t cm_check_remote_ip(white_context_t *ctx, const char *ip_str, bool32 *check_res);
status_t cm_verify_lsnr_addr(const char *ipaddrs, uint32 len, uint32 *ip_cnt);
status_t cm_parse_lsnr_addr(const char *ipaddrs, uint32 len, uint32 *ip_cnt, char out[][CM_MAX_IP_LEN]);
status_t cm_split_node_ip(char host[][CT_MAX_INST_IP_LEN], const char *value);
status_t cm_split_host_ip(char host[][CM_MAX_IP_LEN], const char *value);
status_t cm_split_host_port(uint16 ports[], const char *port_addr);
bool32 cm_check_user(white_context_t *ctx, const char *ip_str, const char *user, bool32 *hostssl);
#ifdef __cplusplus
}
#endif

#endif


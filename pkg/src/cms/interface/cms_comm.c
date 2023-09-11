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
 * cms_comm.c
 *
 *
 * IDENTIFICATION
 * src/cms/interface/cms_comm.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_defs.h"
#include "cms_comm.h"
#include "cm_ip.h"
#include "cs_packet.h"
#include "cs_tcp.h"
#include "cms_client.h"
#include "cs_uds.h"
#include "securec.h"

status_t cms_check_addr_dev_stat(struct sockaddr_in* addr)
{
    struct ifaddrs* ifaddr;
    int32 family;

    if (getifaddrs(&ifaddr) == -1) {
        return GS_ERROR;
    }

    for (struct ifaddrs* ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }

        family = ifa->ifa_addr->sa_family;
        if (family == AF_INET &&
            memcmp(&addr->sin_addr, &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr, sizeof(struct in_addr)) == 0) {
            if (ifa->ifa_flags & IFF_UP) {
                freeifaddrs(ifaddr);
                return GS_SUCCESS;
            } else {
                freeifaddrs(ifaddr);
                return GS_ERROR;
            }
        }
    }
    
    freeifaddrs(ifaddr);
    return GS_ERROR;
}

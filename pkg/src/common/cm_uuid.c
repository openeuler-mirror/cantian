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
 * cm_uuid.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_uuid.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_common_module.h"
#include "cm_uuid.h"
#include "cm_error.h"
#include "cm_hash.h"
#include "cm_timer.h"
#include "cm_encrypt.h"

#ifndef _WIN32
static inline status_t get_mac_addr_from_interfaces(struct ifreq *ifr_mac, int sock_mac, struct ifreq *it,
                                                    struct ifreq *end, char *mac, uint16 max_len)
{
    errno_t errcode;

    for (; it != end; ++it) {
        errcode = strncpy_s(ifr_mac->ifr_ifrn.ifrn_name, IFNAMSIZ, it->ifr_ifrn.ifrn_name,
                            strlen(it->ifr_ifrn.ifrn_name));
        if (errcode != EOK) {
            CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return CT_ERROR;
        }

        if (ioctl(sock_mac, SIOCGIFFLAGS, ifr_mac) == 0) {
            // skip loopback(lo) interface
            if (!(ifr_mac->ifr_ifru.ifru_flags & IFF_LOOPBACK) && ioctl(sock_mac, SIOCGIFHWADDR, ifr_mac) == 0) {
                errcode = strncpy_s(mac, max_len, ifr_mac->ifr_ifru.ifru_hwaddr.sa_data, CT_MAC_ADDRESS_LEN);
                if (errcode != EOK) {
                    CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
                    return CT_ERROR;
                }
                break;
            }
        } else {
            CT_THROW_ERROR(ERR_GENERATE_GUID, "ioctl socket failed for mac address.");
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}
#endif

status_t cm_get_mac_address_str(char* mac, uint16 max_len)
{
#ifdef _WIN32
    return CT_SUCCESS;
#else
    struct ifreq ifr_mac;
    struct ifconf ifc;
    int sock_mac = 0;
    char buf[CT_MAX_CHECK_VALUE_LEN];
    struct ifreq* it = NULL;
    struct ifreq* end = NULL;
    errno_t errcode;

    if (mac == NULL) {
        return CT_ERROR;
    }

    sock_mac = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_mac < 0) {
        CT_THROW_ERROR(ERR_GENERATE_GUID, "create socket failed for mac address.");
        return CT_ERROR;
    }

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;

    if (ioctl(sock_mac, SIOCGIFCONF, &ifc) < 0) {
        close(sock_mac);
        CT_THROW_ERROR(ERR_GENERATE_GUID, "ioctl socket failed for mac address.");
        return CT_ERROR;
    }

    errcode = memset_s(&ifr_mac, sizeof(ifr_mac), 0, sizeof(ifr_mac));
    if (errcode != EOK) {
        close(sock_mac);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return CT_ERROR;
    }

    it = ifc.ifc_req;
    end = it + (ifc.ifc_len / sizeof(struct ifreq));

    if (it == end) {
        CT_THROW_ERROR(ERR_GENERATE_GUID, "no physical network card for mac address.");
        close(sock_mac);
        return CT_ERROR;
    }

    status_t status = get_mac_addr_from_interfaces(&ifr_mac, sock_mac, it, end, mac, max_len);

    close(sock_mac);
    return status;
#endif
}

void cm_init_mac_address(char* mac_address, uint16 max_len)
{
    if (cm_get_mac_address_str(mac_address, CT_MAC_ADDRESS_LEN + 1) != CT_SUCCESS) {
        (void)cm_rand((uchar*)mac_address, CT_MAC_ADDRESS_LEN);
        CT_LOG_RUN_WAR("failed to get real mac address and generate rand mac address %s.", mac_address);
    }
}
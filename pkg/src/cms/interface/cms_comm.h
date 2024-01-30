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
 * cms_comm.h
 *
 *
 * IDENTIFICATION
 * src/cms/interface/cms_comm.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CMS_COMM_H
#define CMS_COMM_H

#include "cm_defs.h"
#include "cms_client.h"
#include "cms_log.h"

#ifdef __cplusplus
extern "C" {
#endif

#define cms_panic(condition)                                                                                        \
    do {                                                                                                            \
        if (SECUREC_UNLIKELY(!(condition))) {                                                                       \
            CMS_LOG_ERR("Assertion throws an exception at line %u", (uint32)__LINE__);                              \
            cm_fync_logfile();                                                                                      \
            *((uint32 *)NULL) = 1;                                                                                  \
        }                                                                                                           \
    } while (0);

#define cms_securec_check(err)                                            \
    {                                                                     \
        if (SECUREC_UNLIKELY(EOK != (err))) {                             \
            CMS_LOG_ERR("Secure C lib has thrown an error %d", (err));    \
            cm_fync_logfile();                                            \
            cms_panic(0);                                                 \
        }                                                                 \
    }

#define CMS_LOG_MSG(method, info, msg)                                                                                 \
    do {                                                                                                               \
        method("%s:msg_seq:%lld, src_msg_seq:%lld, msg_type:%d, size:%u, version:%d, src_node:%d,                      \
               dest_node:%d", (info), (msg)->msg_seq, (msg)->src_msg_seq, (msg)->msg_type,                             \
               (msg)->msg_size, (int32)(msg)->msg_version, (msg)->src_node, (msg)->dest_node);                         \
    } while (0);

status_t cms_check_addr_dev_stat(struct sockaddr_in* addr);

#ifdef __cplusplus
}
#endif

#endif

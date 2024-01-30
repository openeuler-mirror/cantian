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
 * cms_defs.h
 *
 *
 * IDENTIFICATION
 * src/cms/interface/cms_defs.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CMS_DEFS_H
#define CMS_DEFS_H

#include "cm_defs.h"
#include "cm_log.h"
#include "cm_date.h"
#include "cms_msgque.h"

#ifdef _WIN32
#define popen _popen
#define pclose _pclose
#define sleep Sleep
#endif

#define CMS_LOGFILE_SIZE                (10 * 1024 * 1024)
#define CMS_LOG_LEVEL                   0xffffffff
#define CMS_LOG_AUDIT                   CT_LOG_AUDIT


#define CMS_BLOCK_SIZE                  512
#define CMS_RESERVED_BLOCKS_SIZE        (CMS_BLOCK_SIZE * 100)
#define CMS_NAME_BUFFER_SIZE            CT_NAME_BUFFER_SIZE
#define CMS_MAX_NAME_LEN                CT_MAX_NAME_LEN
#define CMS_IP_BUFFER_SIZE              CT_NAME_BUFFER_SIZE
#define CMS_MAX_IP_LEN                  CT_MAX_NAME_LEN
#define CMS_INFO_BUFFER_SIZE            CT_NAME_BUFFER_SIZE
#define CMS_MAX_INFO_LEN                CT_MAX_NAME_LEN
#define CMS_FILE_NAME_BUFFER_SIZE       CT_FILE_NAME_BUFFER_SIZE
#define CMS_MAX_FILE_NAME_LEN           CT_MAX_FILE_NAME_LEN
#define CMS_PATH_BUFFER_SIZE            CT_MAX_PATH_BUFFER_SIZE
#define CMS_MAX_PATH_LEN                CT_MAX_PATH_LEN
#define CMS_CMD_BUFFER_SIZE             (CMS_FILE_NAME_BUFFER_SIZE + CT_MAX_CMD_LEN)
#define CMS_MAX_CMD_LEN                 (CMS_CMD_BUFFER_SIZE - 1)
#define CMS_CMD_OUT_BUFFER_SIZE         (CT_MAX_CMD_LEN + 1)
#define CMS_MAX_CMD_OUT_LEN             CT_MAX_CMD_LEN
#define CMS_RES_ATTRS_BUFFER_SIZE       (CMS_FILE_NAME_BUFFER_SIZE + CT_MAX_NAME_LEN)
#define CMS_MAX_RES_ATTRS_LEN           (CMS_RES_ATTRS_BUFFER_SIZE - 1)

#define CMS_MAX_WORKER_THREAD_COUNT     64
#define CMS_DFT_WORKER_THREAD_COUNT     20
#define CMS_MAX_NODES                   64
#define CMS_PAGE_SIZE                   8192
#define CMS_MAX_DETECT_FILE_NAME        256

#define CMS_MAX_VOTEDISK_COUNT          11
#define CMS_MAX_NODE_COUNT              64
#define CMS_MAX_RESOURCE_GRP_COUNT      32
#define CMS_MAX_RESOURCE_COUNT          64
#define CMS_MAX_UDS_CLI_COUNT           64
#define CMS_MAX_UDS_SESSION_COUNT       (CMS_MAX_RESOURCE_COUNT + CMS_MAX_UDS_CLI_COUNT)

#define CMS_EXP_ROW_BUFFER_SIZE         1024
#define CMS_MAX_IMP_FILE_SIZE           SIZE_M(4)
#define CMS_IMP_HEAD_ATTR_NUM           4
#define CMS_IMP_NODE_ATTR_NUM           4
#define CMS_IMP_VOIEDISK_ATTR_NUM       1
#define CMS_IMP_RES_GRP_ATTR_NUM        2
#define CMS_IMP_RES_ATTR_NUM            13

#define CMS_NETWORK_WAIT_TIME           5
#define CMS_BEATING_INTERVAL            100

#define CMS_MAX_DISK_DETECT_FILE        10

#define CMS_GCC_STORAGE_NUM             2
#define CMS_GCC_BACKUP_NUM              6
#define CMS_GCC_BACKUP_INTERVAL         (MICROSECS_PER_SECOND_LL * SECONDS_PER_HOUR * 4)

#define CMS_RES_START_TIMEOUT           5000
#define CMS_RES_STOP_TIMEOUT            5000
#define CMS_RES_CHECK_TIMEOUT           1000
#define CMS_RES_CHECK_INTERVAL          1000
#define CMS_RES_RESTART_INTERVAL        45000
#define CMS_RES_HB_TIMEOUT              10000
#define CMS_REQUEST_STAT_TIMEOUT        200
#define CMS_MAX_CMD_PARAM_COUNT         16
#define CMS_HB_WORKER_FLAG              ((void*)1)
#define CMS_ALIGN_ADDR_512(addr)     ((((uint64)(addr)) & 0x1FFULL) == 0 ? \
    ((uint64)(addr)) : ((((uint64)(addr)) + 0x1FFULL) & 0xFFFFFFFFFFFFFE00ULL))

#define CMS_CMD_RECV_TMOUT_MS           5000
#define CMS_CMD_STOP_RES_TMOUT_MS       10000
#define CMS_CMD_START_ALL_TMOUT_MS      600000
#define CMS_MAX_VOTE_SLOT_COUNT         4
#define CMS_RES_RESTART_TIMES           3
#define CMS_NODE_FAULT_THRESHOLD        5
#define CMS_DISK_LOCK_FILE_REOPEN_NUM   1

typedef enum en_cms_dev_type {
    CMS_DEV_TYPE_SD     = 1, // scsi device
    CMS_DEV_TYPE_FILE   = 2, // normal file
    CMS_DEV_TYPE_NFS    = 3  // nfs
}cms_dev_type_t;

typedef enum en_cms_split_brain_type {
    CMS_OPEN_WITH_SPLIT_BRAIN = 1,
    CMS_OPEN_WITHOUT_SPLIT_BRAIN
} cms_split_brain_type_t;

typedef enum en_cms_io_record_event {
    CMS_IO_RECORD_UDS_GET_STAT_LIST1 = 0,
    CMS_IO_RECORD_UDS_SET_DATA_NEW,
    CMS_IO_RECORD_UDS_GET_DATA_NEW,
    CMS_IO_RECORD_UDS_CLI_HB,
    CMS_IO_RECORD_UDS_IOF_KICK_RES,
    CMS_IO_RECORD_UDS_UNREGISTER,
    CMS_IO_RECORD_UDS_SET_WORK_STAT,
    CMS_IO_RECORD_TRY_BE_MASTER,
    CMS_IO_RECORD_DETECT_DISK,
    CMS_IO_RECORD_HB_AYNC_TIME_GAP,
    CMS_IO_COUNT,
}cms_io_record_event;

typedef struct st_cms_err_info {
    char err_info[CMS_INFO_BUFFER_SIZE];
    uint32 err_len;
} cms_err_info_t;

typedef struct st_cms_res_desc {
    char* name;
    char* type;
    char* group;
    char* attrs;
    char* err_info;
} cms_res_desc_t;

#ifndef WIN32
#include <pthread.h>
typedef pthread_rwlock_t cms_rwlock_t;
#define CMS_RWLOCK_INITIALIZER PTHREAD_RWLOCK_INITIALIZER
#define cms_rwlock_wrlock(lock) pthread_rwlock_wrlock(lock)
#define cms_rwlock_unlock(lock) pthread_rwlock_unlock(lock)
#define cms_rwlock_rdlock(lock) pthread_rwlock_rdlock(lock)
#define cms_rwlock_init(lock, attr) pthread_rwlock_init(lock, attr)
#else
typedef int32 cms_rwlock_t;
#define CMS_RWLOCK_INITIALIZER 0
#define cms_rwlock_wrlock(lock) 0
#define cms_rwlock_unlock(lock) 0
#define cms_rwlock_rdlock(lock) 0
#define cms_rwlock_init(lock, attr) 0
#endif

#endif

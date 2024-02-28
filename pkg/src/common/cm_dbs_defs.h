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
 * cm_dbs_defs.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_dbs_defs.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CM_DBSTOR_DEFS_H
#define CM_DBSTOR_DEFS_H

#include "cm_dbs_defs.h"
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

// define-namespace_type
#ifndef IN
#define IN
#endif
#ifndef OUT
#define OUT
#endif
#ifndef INOUT
#define INOUT
#endif
#define OBJECT_ID_LENGTH 38
#define OBJ_HANDLE_LEN 38
#define CSS_MAX_NAME_LEN 68

// define-namespace
#define NS_MAX_NODE_NUM 64
#define NS_MAX_TERM_NUM 64

// define-pagepool
#define MAX_PAGE_POOL_NUM_IN_NAMESPACE (8192)

// define-ulog
#define MAX_ULOG_PARTITION_NUM 16
#define MAX_LOG_BATCH_NUM 16

// enum-namespace_type
typedef enum {
    DBS_DATA_FORMAT_BUFFER = 0,
    DBS_DATA_FORMAT_PAGE = 1,
    DBS_DATA_FORMAT_BUTT
} DataFormat;

typedef enum en_dbs_init_mode {
    DBS_RUN_CREATE_CMS_GCC = 0,
    DBS_RUN_DEL_CMS_GCC,
    DBS_RUN_CMS_SERVER,
    DBS_RUN_CMS_LOCAL,
    DBS_RUN_CANTIAND_SERVER,
    DBS_RUN_CMS_SERVER_NFS,
} dbs_init_mode;

// enum-namespace
typedef enum {
    NAME_SPACE_RETURN_ERROR = -1,
    NAME_SPACE_RETURN_OK = 0,
    NAME_SPACE_RETURN_EXSIT,
    NAME_SPACE_RETURN_NOT_EXSIT,
    NAME_SPACE_RETURN_BUTT,
} NameSpaceReturnCode;

typedef enum {
    NAME_SPACE_DB_APP = 0,
    NAME_SPACE_APP_BUTT
} NameSpaceApp;

typedef enum {
    CS_TERM_ACCESS_RDWR = 0,
    CS_TERM_ACCESS_FORBID_RDWR,
    CS_TERM_ACCESS_RDONLY,
    CS_TERM_ACCESS_WDONLY,
    CS_TERM_ACCESS_BUTT
} CsTermAccess;

// enum-pagepool
typedef enum {
    CS_PAGE_POOL_WRITE,
    CS_PAGE_POOL_UNMAP,
    CS_PAGE_POOL_READ,
    CS_PAGE_POOL_ASYNC_WRITE,
    CS_PAGE_POOL_BUTT
} CsPagePoolOpCode;

typedef enum  {
    PAGE_POOL_RETURN_OK = 0,
    PAGE_POOL_RETURN_EXSIT,
    PAGE_POOL_RETURN_NOT_EXSIT,
    PAGE_POOL_RETURN_ULOG_READ_INVALID,
    PAGE_POOL_RETURN_OP_DENIED_ERROR,
    PAGE_POOL_RETURN_BUTT
} PagePoolReturnCode;

// enum-ulog
typedef enum {
    // common error
    ULOG_RETURN_OK = 0,
    ULOG_RETURN_ERROR, // normal error
    ULOG_RETURN_INVALID_PARAM, // param error
    ULOG_RETURN_MALLOC_ERROR, // malloc error
    ULOG_RETURN_MMCPY_ERROR, // memcpy error
    ULOG_RETURN_TIMEOUT, // timeout
    ULOG_RETURN_MODE_MISMATCH, // ulog mode mismatch
    ULOG_RETURN_TRANSFER_ERROR, // transfer error
    ULOG_RETURN_SERVER_ERROR, // server error return 
    ULOG_RETURN_GET_STREAMOBJ_ERROR, // get streamObj cache error
    // setting error
    ULOG_RETURN_ALREADY_CREATED,
    ULOG_RETURN_SEGMENT_CREATE_EXIT,
    // append error
    ULOG_APPEND_RETURN_EXIST_RUNNING, // io already in process
    ULOG_APPEND_RETURN_EXIST_OK, // io exist
    ULOG_APPEND_RETURN_STATUS_ERROR, // client status error, please wait for a while（5s） then retry
    ULOG_APPEND_RETURN_CACHE_FULL, // cache full, truncate is necessary
    ULOG_APPEND_RETURN_PREMALLOC_ERROR, // lastSegId flush disk fail
    // read error
    ULOG_READ_RETURN_AGGREGATE_ERROR,
    ULOG_READ_RETURN_AGGREGATE_CONTINUE,
    ULOG_READ_RETURN_REACH_MAX_AGG_COUNT,
    ULOG_READ_RETURN_REACH_MAX_BUF_LEN,
    ULOG_READ_RETURN_LSN_NOT_EXIST, // lsn not found in ulog
    // fence error
    ULOG_RETURN_OP_DENIED_ERROR,
    ULOG_READ_RETURN_LSN_NOT_EXIST_SMALL,
} UlogReturnCode;

typedef enum {
    ULOG_OP_APPEND = 0,
    ULOG_OP_APPEND_ONLY = ULOG_OP_APPEND,
    ULOG_OP_APPEND_WITH_OFFSET,
    ULOG_OP_APPEND_WITH_KEY,
    ULOG_OP_APPEND_WITH_LSN,
    ULOG_OP_READ,
    ULOG_OP_READ_WITH_OFFSET = ULOG_OP_READ,
    ULOG_OP_READ_WITH_KEY,
    ULOG_OP_READ_WITH_LSN,
    ULOG_OP_READ_ITER_WITH_LSN,  // ITERATOR READ
    ULOG_OP_READ_PARTITION,
    ULOG_OP_TRUNCATE,
    ULOG_OP_TRUNCATE_WITH_OFFSET,
    ULOG_OP_TRUNCATE_WITH_KEY,
    ULOG_OP_TRUNCATE_WITH_LSN,
    ULOG_OP_RECOVER,
    ULOG_OP_RECOVER_WITH_LSN = ULOG_OP_RECOVER,
    ULOG_OP_GET_PART_INFO,
    ULOG_OP_CODE_BUTT
} UlogOpCode;

typedef enum {
    ULOG_APP_WAL = 0,
    ULOG_APP_APPEND_ONLY_MODE = 1,
    ULOG_APP_WITH_LSN_MODE = 2,
    ULOG_APP_WITH_OFFSET_MODE = 3,
    ULOG_APP_WITH_KEY_MODE = 4,
    ULOG_APP_BUTT
} UlogApp;

typedef enum {
    ULOG_FT_SNAP = 0,
    ULOG_FT_INDEX,
    ULOG_FT_REPLAYER,
    ULOG_FT_METRO,
    ULOG_FT_SYNC_REP,
    ULOG_FT_ASYNC_REP,
    ULOG_FT_ARCHIVE,
    ULOG_FT_BUTT
} UlogFeature;

typedef enum {
    ULOG_DIST_LOCAL = 0,
    ULOG_DIST_SHARD,
    ULOG_DIST_GLOBAL,
    ULOG_DIST_AZ_GLOBAL,
    ULOG_DIST_BUTT
} UlogDist;

typedef enum {
    ULOG_VIEW_ONLINE = 0,
    ULOG_VIEW_ARCHIVE,
    ULOG_VIEW_BUTT
} UlogView;

typedef uint64_t DbsPageId;
typedef uint64_t LsnId;

// union-namespace_type
/* |4byte-spaceId|4byte-volId|2byte-shardid|8byte-objId|6byte-resv| */
typedef union object_id_t {
    uint8_t rawId[OBJECT_ID_LENGTH];
    struct  {
        uint16_t spaceId;        // space id
        uint32_t backendId;      // 后端ID，映射到LUNID或者VOLUME ID	
        uint32_t snapId;         // 默认为0
        uint64_t type : 4;       // 对于kvs,填KVS_ALGORITHM_E; 其它，填XOBJECT_TYPE_E
        uint64_t shardId : 12;   // shardid
        uint64_t objId : 48;  
        uint8_t  childNum;       // 孩子数量，等于0说明自己就是孩子.haizi的ID等于几ID+1...，shardid等于
    } __attribute__((packed));
    uint8_t objHandle[OBJ_HANDLE_LEN];   // UUID
    int32_t filefd;
} __attribute__((packed)) object_id_t;

typedef object_id_t NameSpaceId;
typedef object_id_t PagePoolId;
typedef object_id_t UlogId;

// struct-namespace_type
typedef struct {
    char *buf;
    uint32_t len;
} DataBuffer;

// 单个数据
typedef struct tagUValue {
    uint32_t type; // DataFormat
    DataBuffer buf;
    struct tagUValue *next;
} UValue;

typedef UValue LogRecord;
typedef UValue PageValue;

// 批量数据(数组+链表)
typedef struct {
    uint32_t type; // DataFormat
    uint32_t dataNum;
    UValue  *dataArray;
} UValueBatch;

typedef void(*CallBackFunc)(void* ctx, int32_t result);

typedef struct {
    CallBackFunc cb;
    void*        ctx;
} CallBack;

// struct-namespace
typedef struct {
    union {
        IN NameSpaceId nameSpaceId;
        char *nsName;
    };
    IN uint64_t sessionId;
    INOUT uint64_t cursor; // last visit cursor, begin with zero.
} SessionId;

typedef struct {
    uint64_t userId; // user id
    uint64_t gid;    // group id
    uint32_t poolId; // storage poolid
    uint32_t app;    // app type
    uint32_t mod;    // work mod
    uint32_t dbVersion;
    uint64_t termId;
} NameSpaceAttr;

typedef struct {
    uint32_t nodeId;   // 节点id，集群内顺序分配，取值范围 0-63
    uint32_t termId;   // 进程id，节点内顺序分配，取值范围0-63
    uint64_t sn;       // 顺序号递增，同一nsId、nodeId、termId对象先发起后到达的不处理
    CsTermAccess accessMode;    // 设置权限
} TermAccessAttr;

// struct-pagepool
typedef struct {
    char             nsName[CSS_MAX_NAME_LEN];
    uint32_t         mod;
    uint32_t         tierType;
    uint64_t         feature; 
    LsnId            recycleLsn;
    uint32_t         pageSize;
    bool             isSupportMVCC;
    OUT uint64_t     totalPageNum;
    OUT uint64_t     usedPageNum;
    uint64_t         maxPageId;
    uint32_t         pagePoolPartNum;    // 支持调用者指定(不大于128)，如果不关心该字段，需要传入0，内部会使用默认值8
    uint64_t         initSize;
} PagePoolAttr;

typedef struct { // 支持写完后构建索引
    uint32_t  priority;
    uint32_t  opcode;
    uint64_t  offset;      // 页面的偏移，支持更改部分页面
    uint32_t  length;
    LsnId     lsn;
    SessionId session;
    CallBack  callBack;
} DbsPageOption;


// struct-ulog
typedef struct {
    IN  uint64_t truncateOffset;
    OUT uint64_t firstOffset;
    OUT uint64_t lastOffset;
} UlogMetaOffset;

typedef struct {
    IN  LsnId truncateLsn;
    OUT LsnId firstLsn;
    OUT LsnId lastLsn;
    OUT LsnId serverLsn;
} UlogMetaLsn;

typedef union {
    UlogMetaOffset ulogOffset;
    UlogMetaLsn    ulogLsn;
} UlogMeta;

typedef struct {
    NameSpaceId nameSpaceId;
    char *nsName;
    uint32_t    appMode; // append only or append with lsn
    uint32_t    mod;
    uint64_t    uid;
    uint64_t    gid;
    UlogMeta    meta;
    uint32_t    tierType;
    uint64_t    feature;
} UlogAttr;

typedef struct {
    LsnId startLsn; //
    LsnId endLsn;   //
    LsnId preLsn;   // 
} LogLsn;

typedef struct {
    uint32_t partId;
    LogLsn start;
    LogLsn end;
}LogPartition;

typedef struct {
    uint32_t  num;
    LogPartition partionInfo[MAX_ULOG_PARTITION_NUM];
}LogPartitionList;


typedef struct {
    int32_t    result;
    uint64_t   offset;
    LsnId      serverLsn; // maximum continuous lsn
    uint64_t   freeSize; // current free size (byte)
} AppendResult;

typedef struct {
    int32_t    result;
    uint32_t   outLen;
    LsnId      endLsn;
} ReadResult;

typedef struct {
    uint64_t freeSize; // current free size (byte)
} TruncResult;

typedef struct {
    void*    ctx;
    void (*callback)(void *ctx, AppendResult *out);
} AppendCallBack;

typedef struct {
    SessionId session;
    uint32_t  opcode; // UlogOpCode
    uint32_t  view;  // online archive
    union {
        IN uint64_t offset;
        IN LogLsn lsn;
    };
    AppendCallBack callBack;
} AppendOption;

typedef struct {
    SessionId session;
    uint32_t  opcode; // UlogOpCode
    uint32_t  view;  // online archive
    union {
        IN uint64_t offset;
        IN LogLsn lsn[MAX_LOG_BATCH_NUM];
    };
    AppendCallBack callBack;
} AppendBatchOption;

typedef struct {
    uint16_t     cnt;         /* cnt */
    LogRecord    *recordList; /* dataList */
} LogRecordList;

typedef struct {
    void*    ctx;
    void (*callback)(void *ctx, ReadResult *out);
} ReadCallBack;

typedef struct {
    SessionId session;
    uint32_t opcode;  // read opcode
    uint32_t view;
    uint32_t partId;
    union {
        IN uint64_t offset;
        IN LogLsn   lsn;
    };
    uint32_t length;
    ReadCallBack callBack;
} ReadLogOption;

typedef struct {
    SessionId session;
    uint32_t opcode;  // read opcode
    uint32_t view;
    uint32_t partId;
    union {
        IN uint64_t offset;
        IN LogLsn   lsn;
    };
    uint32_t length;
    uint32_t logNum;
    ReadCallBack callBack;
} ReadBatchLogOption;

typedef struct {
    SessionId session;
    uint32_t opcode;
    uint32_t  view;
    union {
        IN uint64_t offset;
        IN LsnId   lsn;
    };
} TruncLogOption;

typedef struct {
    NameSpaceId nameSpaceId;
    char* nsName;
    LsnId start;
    LsnId end;
    uint32_t view;
    uint32_t num;
} PartitionOption;

typedef enum {
    DBS_DISASTER_RECOVERY_INVAILD = 0,
    DBS_DISASTER_RECOVERY_MASTER,
    DBS_DISASTER_RECOVERY_SLAVE,
} DbsDisasterRecoveryRole;
typedef struct {
    DbsDisasterRecoveryRole lastRole;
    DbsDisasterRecoveryRole curRole;
} DbsRoleInfo;
 
typedef int32_t (*regCallback)(DbsRoleInfo curRole);

#ifdef __cplusplus
}
#endif
#endif
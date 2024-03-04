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
 * cm_dbs_ulog.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_dbs_ulog.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_dbs_module.h"
#include "cm_dbs_ulog.h"
 
#include <stdint.h>
#include <stdlib.h>
 
#include "cm_error.h"
#include "cm_dbs_map.h"
#include "cm_dbs_ctrl.h"
#include "cm_debug.h"
#include "cm_io_record.h"
#include "cm_dbstore.h"

#define CM_DBS_ULOG_FRAGMENT_RESERVATION SIZE_M(256)
#define CM_DBS_ULOG_UNSUPPORTED(op) CT_LOG_RUN_WAR("Unsupported operation(%s) for dbstor object(ulog).", op)
#define CM_DBS_ULOG_HEAD_SIZE 512
bool32 g_ulog_recycled = CT_FALSE;

int64 cm_dbs_ulog_seek(int32 handle, int64 offset, int32 origin)
{
    CM_DBS_ULOG_UNSUPPORTED("seek");
    return -1;
}

status_t cm_dbs_ulog_create(const char *name, int64 size, uint32 flags, int32 *handle)
{
    int32 ret;
    cm_dbs_map_item_s obj = { 0 };
    UlogAttr attr = { 0 };

    (void)flags;

    ret = cm_dbs_get_ns_name(DEV_TYPE_ULOG, &attr.nsName);
    if (ret == CT_ERROR) {
        CT_LOG_RUN_ERR("Failed to get ulog ns id");
        return CT_ERROR;
    }
    attr.appMode = ULOG_APP_WITH_LSN_MODE;

    ret = dbs_global_handle()->create_ulog((char *)name, &attr, &obj.obj_id);
    if (ret != 0) {
        CT_LOG_RUN_ERR("Failed to create ulog %s", name);
        return CT_ERROR;
    }
    obj.ns_name = attr.nsName;
    obj.ulog.curr_lsn = 0;
    obj.ulog.trun_lsn = 0;
    status_t stat = cm_dbs_map_set(name, &obj, handle);
    if (stat != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed to insert ulog into map");
        return CT_ERROR;
    }
    CT_LOG_DEBUG_INF("Create ulog(%s) success(%d).", name, *handle);
    return CT_SUCCESS;
}

status_t cm_dbs_ulog_destroy(const char *name)
{
    int32 ret;
    UlogAttr attr = { 0 };

    ret = cm_dbs_get_ns_name(DEV_TYPE_ULOG, &attr.nsName);
    if (ret == CT_ERROR) {
        CT_LOG_RUN_ERR("Failed to get ulog ns id");
        return CT_ERROR;
    }

    ret = dbs_global_handle()->destroy_ulog((char *)name, &attr);
    if (ret != 0) {
        CT_LOG_RUN_ERR("Failed to destroy ulog %s", name);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t cm_dbs_ulog_open(const char *name, int32 *handle, uint8 is_retry)
{
    int32 ret;
    cm_dbs_map_item_s obj = { 0 };
    UlogAttr attr = { 0 };

    ret = cm_dbs_get_ns_name(DEV_TYPE_ULOG, &attr.nsName);
    if (ret == CT_ERROR) {
        CT_LOG_RUN_ERR("Failed to get ulog ns id");
        return CT_ERROR;
    }

    attr.appMode = ULOG_APP_WITH_LSN_MODE;
    attr.isRetry = is_retry;

    ret = dbs_global_handle()->open_ulog((char *)name, &attr, &obj.obj_id);
    if (ret != 0) {
        CT_LOG_RUN_ERR("Failed to open ulog");
        return CT_ERROR;
    }

    obj.ns_name = attr.nsName;
    obj.ulog.curr_lsn = attr.meta.ulogLsn.serverLsn;
    obj.ulog.trun_lsn = attr.meta.ulogLsn.truncateLsn;
    status_t stat = cm_dbs_map_set(name, &obj, handle);
    if (stat != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed to insert ulog into map");
        return CT_ERROR;
    }
    CT_LOG_DEBUG_INF("Open ulog(%s, %lu, %lu) success(%d).", name, obj.ulog.trun_lsn, obj.ulog.curr_lsn, *handle);
    return CT_SUCCESS;
}

void cm_dbs_ulog_close(int32 handle)
{
    if (handle == -1) {
        return;
    }
    cm_dbs_map_remove(handle);
    CT_LOG_DEBUG_INF("Close ulog at handle(%d) successfully.", handle);
}

static void cm_dbs_ulog_readpartopt_init(ReadBatchLogOption *option, char* nsName, uint32_t partId,
                                         uint64 startLsn, uint64 endLsn, uint32_t buffer_size)
{
    LogLsn lsn = {0};
    lsn.startLsn = startLsn;
    lsn.endLsn = endLsn;
    option->session.nsName = nsName;
    option->opcode = ULOG_OP_READ_WITH_LSN;
    option->view = ULOG_VIEW_ONLINE;
    option->partId = partId;
    option->callBack.ctx = NULL;
    option->callBack.callback = NULL;
    option->length = buffer_size;
    option->lsn = lsn;
    return;
}
 
status_t cm_dbs_get_used_cap(int32 handle, uint64_t startLsn, uint32_t *sizeKb, uint8 is_retry)
{
    status_t ret;
    cm_dbs_map_item_s obj = { 0 };
    UlogAttr attr = { 0 };
    LogLsn lsn = { 0 };
    if (cm_dbs_map_get(handle, &obj) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed to find ulog by handle(%d).", handle);
        return CT_ERROR;
    }
 
    ret = cm_dbs_get_ns_name(DEV_TYPE_ULOG, &attr.nsName);
    if (ret == CT_ERROR) {
        CT_LOG_RUN_ERR("Failed to get ulog ns id");
        return CT_ERROR;
    }
 
    attr.appMode = ULOG_APP_WITH_LSN_MODE;
    attr.isRetry = is_retry;
    lsn.startLsn = startLsn;

    ret = dbs_global_handle()->get_ulog_used_cap(&obj.obj_id, &attr, lsn, ULOG_VIEW_ONLINE, sizeKb);
    if (ret != 0) {
        CT_LOG_RUN_ERR("Failed to get GetUlogUsedCap");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t cm_dbs_ulog_capacity(int64 *capacity)
{
    uint64_t ulog_cap = 0;
    int32_t ret = dbs_global_handle()->get_ulog_init_capacity(&ulog_cap);
    if (ret != 0) {
        CT_LOG_RUN_ERR("Failed(%d) to get ulog init capacity from dbstor.", ret);
        return CT_ERROR;
    }
    if (ulog_cap <= CM_DBS_ULOG_FRAGMENT_RESERVATION) {
        CT_LOG_RUN_ERR("The capacity(%lu) of ULOG defined by DBStor is too small.", ulog_cap);
        return CT_ERROR;
    }
    *capacity = (int64)(ulog_cap - CM_DBS_ULOG_FRAGMENT_RESERVATION);
    return CT_SUCCESS;
}

int32 cm_dbs_ulog_align_size(int32 space_size)
{
    // return AlignLogSize(space_size); //!fixme DBStor提供新接口完成
    /* DBStor需要对ulog添加512的头部，再整体按照8K对齐 */
    uint32 tmp_size = space_size + CM_DBS_ULOG_HEAD_SIZE;  // 添加头部，512B
    const uint32 round_size = SIZE_K(8);  // 对齐，8K
    return (tmp_size + (round_size - 1)) & (~(round_size - 1));
}

static inline status_t cms_check_part_list(LogPartitionList *partList, uint32_t num)
{
    if (partList->num > num) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}
 
status_t cm_dbs_ulog_batch_read(int32 handle, uint64 startLsn, uint64 endLsn, void *buf,
    int32 size, int32 *r_size, uint64 *outLsn)
{
    uint32_t partId;
    cm_dbs_map_item_s obj;
    ReadBatchLogOption option = {0};
    LogRecord logRecord;
    ReadResult result;
    char* nsName = NULL;
    LogRecordList recordList = {0};
    *r_size = 0;

    if (cm_dbs_map_get(handle, &obj) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed to find ulog by handle(%d).", handle);
        return CT_ERROR;
    }

    int32 ret = cm_dbs_get_ns_name(DEV_TYPE_ULOG, &nsName);
    if (ret == CT_ERROR) {
        CT_LOG_RUN_ERR("Failed to get ulog ns id");
        return CT_ERROR;
    }

    CT_LOG_DEBUG_INF("read ulog in start %llu in end %llu ", startLsn, endLsn);
    partId = CT_INVALID_ID32;
    cm_dbs_ulog_readpartopt_init(&option, obj.ns_name, partId, startLsn, endLsn, size);
    logRecord.type = DBS_DATA_FORMAT_BUFFER;
    logRecord.buf.buf = (char*)buf;
    logRecord.buf.len = size;
    logRecord.next = NULL;
    recordList.cnt = 1;
    recordList.recordList = &logRecord;
    ret = dbs_global_handle()->read_ulog_record_list(&obj.obj_id, &option, &recordList, &result);
    if (ret != 0 || result.result != 0) {
        if (result.result == ULOG_READ_RETURN_REACH_MAX_BUF_LEN) {
            *r_size = result.outLen;
            if (result.outLen == 0) {
                CT_LOG_RUN_ERR("[DBS] read ulog fail, need extend large.");
                return CT_ERROR; // buff not enough
            }
            *outLsn = result.endLsn;
            return CT_SUCCESS;
        }
        if (ret == ULOG_READ_RETURN_LSN_NOT_EXIST || result.result == ULOG_READ_RETURN_LSN_NOT_EXIST) {
            CT_LOG_DEBUG_INF("read ulog fail, lsn not exist.");
            *r_size = 0;
            return CT_SUCCESS;
        }
        CT_LOG_RUN_ERR("[DBS] read ulog fail.");
        return CT_ERROR;
    }
    *r_size = result.outLen;
    *outLsn = result.endLsn;
    return CT_SUCCESS;
}

void cm_dbs_set_log_recycled()
{
    g_ulog_recycled = CT_TRUE;
    CT_LOG_RUN_ERR("ulog has been recycled, wait for sync log");
    for (;;) {
        cm_sleep(CT_INVALID_ID32);
    }
    return;
}

bool32 cm_dbs_log_recycled()
{
    return g_ulog_recycled;
}

status_t cm_dbs_ulog_read(int32 handle, int64 startLsn, void *buf, int32 size, int32 *r_size)
{
    int32 ret;
    timeval_t tv_begin;
    cm_dbs_map_item_s obj = { 0 };
    ReadBatchLogOption option;
    LogRecord logRecord;
    ReadResult result = {0};
    uint32_t partId;
    LogRecordList recordList = {0};
    io_record_stat_t io_stat = IO_STAT_SUCCESS;

    if (cm_dbs_map_get(handle, &obj) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed to find ulog by handle(%d).", handle);
        return CT_ERROR;
    }

    partId = CT_INVALID_ID32;
    cm_dbs_ulog_readpartopt_init(&option, obj.ns_name, partId, startLsn, CT_INVALID_ID64, size);

    logRecord.type = DBS_DATA_FORMAT_BUFFER;
    logRecord.buf.buf = (char*)buf;
    logRecord.buf.len = size;
    logRecord.next = NULL;
    recordList.cnt = 1;
    recordList.recordList = &logRecord;
    cantian_record_io_stat_begin(IO_RECORD_EVENT_NS_BATCH_READ_ULOG, &tv_begin);
    ret = dbs_global_handle()->read_ulog_record_list(&obj.obj_id, &option, &recordList, &result);
    if (ret != CT_SUCCESS || result.result != CT_SUCCESS) {
        if (ret == ULOG_READ_RETURN_LSN_NOT_EXIST) {
            CT_LOG_DEBUG_WAR("LSN(%llu) not found.", startLsn);
            ret = CT_SUCCESS;
        } else if (ret == ULOG_READ_RETURN_REACH_MAX_BUF_LEN) {
            CT_LOG_DEBUG_WAR("The buffer capacity is insufficient for LSN(%llu).", startLsn);
            ret = CT_SUCCESS;
        } else if (ret == ULOG_READ_RETURN_LSN_NOT_EXIST_SMALL) {
            CT_LOG_RUN_ERR("LSN(%llu) not found, redo logs have been recycled", startLsn);
            cm_dbs_set_log_recycled();
            ret = CT_ERROR;
        } else {
            CT_LOG_RUN_ERR("Failed to read ulog ret:%u", ret);
            ret = CT_ERROR;
        }
    }
    io_stat = (ret == CT_SUCCESS ? IO_STAT_SUCCESS : IO_STAT_FAILED);
    cantian_record_io_stat_end(IO_RECORD_EVENT_NS_BATCH_READ_ULOG, &tv_begin, io_stat);
    *r_size = result.outLen;
    return ret;
}

static void cm_dbs_ulog_writeopt_init(AppendOption *option, char* nsName, uint64 preLsn, uint64 startLsn)
{
    option->opcode = ULOG_OP_APPEND_WITH_LSN;
    option->lsn.preLsn = preLsn;
    option->lsn.startLsn = startLsn;
    option->lsn.endLsn = startLsn;
    option->callBack.ctx = NULL;
    option->callBack.callback = NULL;
    memset_s(&option->session, sizeof(SessionId), 0, sizeof(SessionId));
    option->session.nsName = nsName;
    return;
}

status_t cm_dbs_ulog_write(int32 handle, int64 lsn, const void *buf, int32 size, uint64 *free_size)
{
    int32 ret;
    cm_dbs_map_item_s obj = { 0 };
    AppendOption option = { 0 };
    LogRecord logRecord = { 0 };
    AppendResult result = { 0 };

    if (cm_dbs_map_get(handle, &obj) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed to find ulog by handle(%d).", handle);
        return CT_ERROR;
    }

    cm_dbs_ulog_writeopt_init(&option, obj.ns_name, obj.ulog.curr_lsn, (uint64)lsn);

    logRecord.type = DBS_DATA_FORMAT_BUFFER;
    logRecord.buf.buf = (char *)buf;
    logRecord.buf.len = size;

    ret = dbs_global_handle()->append_ulog_record(&obj.obj_id, &option, &logRecord, &result);
    if (ret != 0 || result.result != 0) {
        CT_LOG_RUN_ERR("Failed(%d,%d) to write ulog(%d) with lsn(%lld).", ret, result.result, handle, lsn);
        return CT_ERROR;
    }

    CM_ABORT(lsn == result.serverLsn, "The expected LSN(%lld) is not equal to the actual LSN(%lu).", lsn,
             result.serverLsn);

    obj.ulog.curr_lsn = result.serverLsn;
    cm_dbs_map_update(handle, &obj);
    if (free_size != NULL) {
        *free_size = result.freeSize;
    }

    CT_LOG_DEBUG_INF("[CMDBS]Append ulog(%d) size(%d,%lu) with lsn(%lld) successfully.", handle, size, result.freeSize,

                     lsn);
    return CT_SUCCESS;
}

uint64 cm_dbs_ulog_recycle(int32 handle, uint64 lsn)
{
    cm_dbs_map_item_s obj = { 0 };
    if (cm_dbs_map_get(handle, &obj) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed to find ulog by handle(%d).", handle);
        return 0;
    }
    if (obj.ulog.trun_lsn >= lsn) {
        return 0;
    }
    TruncLogOption option = { 0 };
    TruncResult result = { 0 };
    option.opcode = ULOG_OP_TRUNCATE_WITH_LSN;
    option.lsn = lsn;
    option.session.nsName = obj.ns_name;
    int32 ret = dbs_global_handle()->truncate_ulog(&obj.obj_id, &option, &result);
    if (ret != 0) {
        CT_LOG_RUN_ERR_LIMIT(LOG_PRINT_INTERVAL_SECOND_20, "Failed(%d) to truncate ulog by lsn(%llu).", ret, lsn);
        return 0;
    }
    obj.ulog.trun_lsn = lsn;
    cm_dbs_map_update(handle, &obj);
    CT_LOG_DEBUG_INF("[CMDBS]Recycle ulog(%d) size(%lu) with lsn(%llu) successfully.", handle, result.freeSize, lsn);
    return result.freeSize;
}

status_t cm_dbs_ulog_get_maxLsn(const char *name, uint64 *lsn)
{
    int32 ret;
    UlogId ulog_id;
    UlogAttr attr = { 0 };

    ret = cm_dbs_get_ns_name(DEV_TYPE_ULOG, &attr.nsName);
    if (ret == CT_ERROR) {
        CT_LOG_RUN_ERR("Failed to get ulog ns id");
        return CT_ERROR;
    }

    attr.appMode = ULOG_APP_WITH_LSN_MODE;

    ret = dbs_global_handle()->open_ulog((char *)name, &attr, &ulog_id);
    if (ret != 0) {
        CT_LOG_RUN_ERR("Failed to open ulog");
        return CT_ERROR;
    }

    *lsn = attr.meta.ulogLsn.serverLsn;

    return CT_SUCCESS;
}

bool32 cm_dbs_ulog_is_lsn_valid(int32 handle, uint64 lsn)
{
    cm_dbs_map_item_s obj = { 0 };
    if (cm_dbs_map_get(handle, &obj) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed to find ulog by handle(%d).", handle);
        return CT_FALSE;
    }
    return (lsn > obj.ulog.trun_lsn && lsn <= obj.ulog.curr_lsn) ? CT_TRUE : CT_FALSE;
}

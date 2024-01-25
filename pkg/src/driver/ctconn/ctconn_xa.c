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
 * ctconn_xa.c
 *
 *
 * IDENTIFICATION
 * src/driver/ctconn/ctconn_xa.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctconn_common.h"
#include "ctconn_shard.h"
#include "cs_protocol.h"

#define XID_LEN(xid) ((uint64)(((ctconn_xid_t *)0)->data) + (xid)->gtrid_len + (xid)->bqual_len)
#define XID_BASE16_LEN(xid) (((uint64)((ctconn_xid_t *)0)->data) + (xid)->gtrid_len * 2 + (xid)->bqual_len * 2)
#define CT_MAX_BQUAL_LEN 64
#define CT_MAX_GTRID_LEN 64
#define CT_BASE16_ONE_BYTE_LEN 2

/*
 * The same as Kernel SCN type which is a 64 bit value divided into three parts as follow:
 *
 * uint64 SCN = |--second--|--usecond--|--serial--|
 * uint64 SCN = |---32bit--|---20bit---|--12bit---|
 */
#define CLT_TIMESEQ_TO_SCN(time_val, init_time, seq) \
    (((uint64)((time_val)->tv_sec - (init_time)) << 32) | ((uint64)(time_val)->tv_usec << 12) | (seq))
#define CLT_SCN_TO_TIMESEQ(scn, time_val, init_time)                                          \
    do {                                                                                      \
        ((time_val)->tv_sec) = (long)((((scn) >> 32) & 0x00000000ffffffffULL) + (init_time)); \
        ((time_val)->tv_usec) = (long)(((scn) >> 12) & 0x00000000000fffffULL);                \
    } while (0)

/* ********************************************************************** */
/* XA interface                                                         */
/* ********************************************************************** */
static inline int32 ct_pack_xid(cs_packet_t *pack, ctconn_xid_t *xid)
{
    if (xid->gtrid_len == 0 || xid->gtrid_len > CT_MAX_GTRID_LEN || xid->bqual_len > CT_MAX_BQUAL_LEN) {
        CT_THROW_ERROR_EX(ERR_XA_INVALID_XID, "gtrid len: %d, bqual len: %d", (int)xid->gtrid_len, (int)xid->bqual_len);
        return CT_ERROR;
    }

    uint32 data_len = (uint32)(CM_ALIGN4(XID_BASE16_LEN(xid)));
    CM_CHECK_SEND_PACK_FREE(pack, sizeof(uint32) + data_len);

    (void)cs_put_int32(pack, (uint32)(XID_BASE16_LEN(xid)));

    // format ID
    *(uint64 *)CS_WRITE_ADDR(pack) = cs_format_endian_i64(pack->options, xid->fmt_id);
    pack->head->size += sizeof(uint64);

    // global transaction and branch ID length
    CS_WRITE_ADDR(pack)[0] = xid->gtrid_len * CT_BASE16_ONE_BYTE_LEN;
    CS_WRITE_ADDR(pack)[1] = xid->bqual_len * CT_BASE16_ONE_BYTE_LEN;
    pack->head->size += 2;

    // global transaction ID
    binary_t bin = { (uint8 *)xid->data, xid->gtrid_len };
    (void)cm_bin2str(&bin, CT_FALSE, CS_WRITE_ADDR(pack), CS_REMAIN_SIZE(pack));
    pack->head->size += xid->gtrid_len * CT_BASE16_ONE_BYTE_LEN;

    // branch ID
    if (xid->bqual_len == 0) {
        return CT_SUCCESS;
    }
    bin.bytes = (uint8 *)&xid->data[xid->gtrid_len];
    bin.size = xid->bqual_len;
    (void)cm_bin2str(&bin, CT_FALSE, CS_WRITE_ADDR(pack), CS_REMAIN_SIZE(pack));
    pack->head->size += xid->bqual_len * CT_BASE16_ONE_BYTE_LEN;
    pack->head->size = CM_ALIGN4(pack->head->size);
    return CT_SUCCESS;
}

static inline int32 ctconn_xa_start_core(ctconn_conn_t conn, ctconn_xid_t *xid, uint64 timeout, uint64 flags)
{
    cs_packet_t *packet = &CLT_CONN(conn)->pack;

    cs_init_set(packet, CLT_CONN(conn)->call_version);
    packet->head->cmd = CS_CMD_XA_START;

    CT_RETURN_IFERR(ct_pack_xid(packet, xid));
    CT_RETURN_IFERR(cs_put_int64(packet, timeout));
    CT_RETURN_IFERR(cs_put_int64(packet, flags));

    if (clt_remote_call(CLT_CONN(conn), packet, packet) != CT_SUCCESS) {
        clt_copy_local_error(CLT_CONN(conn));
        return CT_ERROR;
    }
    CLT_CONN(conn)->xact_status = CTCONN_XACT_OPEN;
    CLT_CONN(conn)->auto_commit_xa_backup = CLT_CONN(conn)->auto_commit;
    CLT_CONN(conn)->auto_commit = CT_FALSE;
    return CT_SUCCESS;
}

int32 ctconn_xa_start(ctconn_conn_t conn, ctconn_xid_t *xid, uint64 timeout, uint64 flags)
{
    CTCONN_CHECK_OBJECT_NULL_GS(conn, "connection");
    CTCONN_CHECK_OBJECT_NULL_GS(xid, "XID");
    clt_reset_error((clt_conn_t *)conn);
    CT_RETURN_IFERR(clt_lock_conn(CLT_CONN(conn)));
    int ret = ctconn_xa_start_core(conn, xid, timeout, flags);
    clt_unlock_conn(CLT_CONN(conn));
    return ret;
}

int32 ctconn_xa_end_core(ctconn_conn_t conn, uint64 flags)
{
    cs_packet_t *packet = &CLT_CONN(conn)->pack;

    cs_init_set(packet, CLT_CONN(conn)->call_version);
    packet->head->cmd = CS_CMD_XA_END;

    CT_RETURN_IFERR(cs_put_int64(packet, flags));

    if (clt_remote_call(CLT_CONN(conn), packet, packet) != CT_SUCCESS) {
        clt_copy_local_error(CLT_CONN(conn));
        return CT_ERROR;
    }
    CLT_CONN(conn)->xact_status = CTCONN_XACT_END;
    CLT_CONN(conn)->auto_commit = CLT_CONN(conn)->auto_commit_xa_backup;
    return CT_SUCCESS;
}

int32 ctconn_xa_end(ctconn_conn_t conn, uint64 flags)
{
    CTCONN_CHECK_OBJECT_NULL_GS(conn, "connection");
    clt_reset_error((clt_conn_t *)conn);
    CT_RETURN_IFERR(clt_lock_conn(CLT_CONN(conn)));
    int32 ret = ctconn_xa_end_core(conn, flags);
    clt_unlock_conn(CLT_CONN(conn));
    return ret;
}

static inline int32 ctconn_xa_commit_phase(uint8 cmd, ctconn_conn_t conn, ctconn_xid_t *xid, uint64 flags, struct timeval *ts)
{
    uint64 scn;
    cs_packet_t *packet = &CLT_CONN(conn)->pack;

    cs_init_set(packet, CLT_CONN(conn)->call_version);
    packet->head->cmd = cmd;

    CT_RETURN_IFERR(ct_pack_xid(packet, xid));
    CT_RETURN_IFERR(cs_put_int64(packet, flags));
    if (ts != NULL) {
        packet->head->flags |= CS_FLAG_WITH_TS;
        scn = CLT_TIMESEQ_TO_SCN(ts, CM_GTS_BASETIME, 1);
        CT_RETURN_IFERR(cs_put_scn(packet, &scn));
    }

    if (clt_remote_call(CLT_CONN(conn), packet, packet) != CT_SUCCESS) {
        clt_copy_local_error(CLT_CONN(conn));
        return CT_ERROR;
    }

    cs_init_get(packet);
    if (CS_XACT_WITH_TS(packet->head->flags)) {
        CT_RETURN_IFERR(cs_get_scn(packet, &scn));
        CLT_SCN_TO_TIMESEQ(scn, ts, CM_GTS_BASETIME);
    }

    return CT_SUCCESS;
}

static inline int32 ctconn_xa_prepare_core(ctconn_conn_t conn, ctconn_xid_t *xid, uint64 flags, struct timeval *ts)
{
    cs_packet_t *packet = &CLT_CONN(conn)->pack;
    int32 errcode;

    CT_RETURN_IFERR(ctconn_xa_commit_phase(CS_CMD_XA_PREPARE, conn, xid, flags, ts));
    CLT_CONN(conn)->xact_status = CTCONN_XACT_PHASE1;
    CT_RETURN_IFERR(cs_get_int32(packet, &errcode));
    if (errcode != 0) {
        CT_THROW_ERROR(errcode);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

int32 ctconn_xa_prepare(ctconn_conn_t conn, ctconn_xid_t *xid, uint64 flags, struct timeval *ts)
{
    CTCONN_CHECK_OBJECT_NULL_GS(conn, "connection");
    CTCONN_CHECK_OBJECT_NULL_GS(xid, "XID");
    clt_reset_error((clt_conn_t *)conn);
    CT_RETURN_IFERR(clt_lock_conn(CLT_CONN(conn)));
    int32 ret = ctconn_xa_prepare_core(conn, xid, flags, ts);
    clt_unlock_conn(CLT_CONN(conn));
    return ret;
}

static inline int32 ctconn_xa_commit_core(ctconn_conn_t conn, ctconn_xid_t *xid, uint64 flags, struct timeval *ts)
{
    CT_RETURN_IFERR(ctconn_xa_commit_phase(CS_CMD_XA_COMMIT, conn, xid, flags, ts));
    CLT_CONN(conn)->xact_status = CTCONN_XACT_END;
    return CT_SUCCESS;
}

int32 ctconn_xa_commit(ctconn_conn_t conn, ctconn_xid_t *xid, uint64 flags, struct timeval *ts)
{
    CTCONN_CHECK_OBJECT_NULL_GS(conn, "connection");
    CTCONN_CHECK_OBJECT_NULL_GS(xid, "XID");
    clt_reset_error((clt_conn_t *)conn);
    CT_RETURN_IFERR(clt_lock_conn(CLT_CONN(conn)));
    int32 ret = ctconn_xa_commit_core(conn, xid, flags, ts);
    clt_unlock_conn(CLT_CONN(conn));
    return ret;
}

static inline int32 ctconn_xa_rollback_core(ctconn_conn_t conn, ctconn_xid_t *xid, uint64 flags)
{
    CTCONN_CHECK_OBJECT_NULL_GS(conn, "connection");

    cs_packet_t *packet = &CLT_CONN(conn)->pack;

    cs_init_set(packet, CLT_CONN(conn)->call_version);
    packet->head->cmd = CS_CMD_XA_ROLLBACK;

    CT_RETURN_IFERR(ct_pack_xid(packet, xid));
    CT_RETURN_IFERR(cs_put_int64(packet, flags));

    if (clt_remote_call(CLT_CONN(conn), packet, packet) != CT_SUCCESS) {
        clt_copy_local_error(CLT_CONN(conn));
        return CT_ERROR;
    }
    CLT_CONN(conn)->xact_status = CTCONN_XACT_END;
    return CT_SUCCESS;
}

int32 ctconn_xa_rollback(ctconn_conn_t conn, ctconn_xid_t *xid, uint64 flags)
{
    CTCONN_CHECK_OBJECT_NULL_GS(conn, "connection");
    CTCONN_CHECK_OBJECT_NULL_GS(xid, "XID");
    clt_reset_error((clt_conn_t *)conn);
    CT_RETURN_IFERR(clt_lock_conn(CLT_CONN(conn)));
    int32 ret = ctconn_xa_rollback_core(conn, xid, flags);
    clt_unlock_conn(CLT_CONN(conn));
    return ret;
}

static inline int32 ctconn_xact_status_core(ctconn_conn_t conn, ctconn_xid_t *xid, ctconn_xact_status_t *status)
{
    cs_packet_t *packet = &CLT_CONN(conn)->pack;

    cs_init_set(packet, CLT_CONN(conn)->call_version);
    packet->head->cmd = CS_CMD_XA_STATUS;

    CT_RETURN_IFERR(ct_pack_xid(packet, xid));

    if (clt_remote_call(CLT_CONN(conn), packet, packet) != CT_SUCCESS) {
        clt_copy_local_error(CLT_CONN(conn));
        return CT_ERROR;
    }

    cs_init_get(packet);
    return cs_get_int32(packet, (int32 *)status);
}

int32 ctconn_xact_status(ctconn_conn_t conn, ctconn_xid_t *xid, ctconn_xact_status_t *status)
{
    CTCONN_CHECK_OBJECT_NULL_GS(conn, "connection");
    CTCONN_CHECK_OBJECT_NULL_GS(xid, "XID");
    CTCONN_CHECK_OBJECT_NULL_GS(status, "XA STATUS");
    clt_reset_error((clt_conn_t *)conn);
    CT_RETURN_IFERR(clt_lock_conn(CLT_CONN(conn)));
    int32 ret = ctconn_xact_status_core(conn, xid, status);
    clt_unlock_conn(CLT_CONN(conn));
    return ret;
}

static inline int32 ct_pack_knl_xid(cs_packet_t *pack, text_t *xid)
{
    CM_CHECK_SEND_PACK_FREE(pack, sizeof(uint32) + CM_ALIGN4(xid->len));

    (void)cs_put_int32(pack, xid->len);
    if (CS_DIFFERENT_ENDIAN(pack->options)) {
        *(uint64 *)xid->str = cs_reverse_int64(*(uint64 *)xid->str);
    }
    MEMS_RETURN_IFERR(memcpy_s(CS_WRITE_ADDR(pack), CS_REMAIN_SIZE(pack), xid->str, xid->len));
    pack->head->size += CM_ALIGN4(xid->len);

    return CT_SUCCESS;
}

static inline int32 ctconn_async_xa_rollback_core(ctconn_conn_t conn, text_t *xid, uint64 flags)
{
    cs_packet_t *packet = &CLT_CONN(conn)->pack;

    cs_init_set(packet, CLT_CONN(conn)->call_version);
    packet->head->cmd = CS_CMD_XA_ROLLBACK;

    CS_SERIAL_NUMBER_INC(CLT_CONN(conn), packet);
    CT_RETURN_IFERR(ct_pack_knl_xid(packet, xid));
    CT_RETURN_IFERR(cs_put_int64(packet, flags));

    if (cs_write(&CLT_CONN(conn)->pipe, packet) != CT_SUCCESS) {
        clt_copy_local_error(CLT_CONN(conn));
        return CT_ERROR;
    }
    CLT_CONN(conn)->xact_status = CTCONN_XACT_END;
    return CT_SUCCESS;
}

int32 ctconn_async_xa_rollback(ctconn_conn_t conn, const text_t *xid, uint64 flags)
{
    CTCONN_CHECK_OBJECT_NULL_GS(conn, "connection");
    CTCONN_CHECK_OBJECT_NULL_GS(xid, "XID");
    clt_reset_error((clt_conn_t *)conn);
    CT_RETURN_IFERR(clt_lock_conn(CLT_CONN(conn)));
    int32 ret = ctconn_async_xa_rollback_core(conn, (text_t *)xid, flags);
    clt_unlock_conn(CLT_CONN(conn));
    return ret;
}

static inline int32 ctconn_xa_async_commit_phase(uint8 cmd, ctconn_conn_t conn, text_t *xid, uint64 flags, uint64 *scn)
{
    cs_packet_t *packet = &CLT_CONN(conn)->pack;

    cs_init_set(packet, CLT_CONN(conn)->call_version);
    packet->head->cmd = cmd;

    CS_SERIAL_NUMBER_INC(CLT_CONN(conn), packet);
    CT_RETURN_IFERR(ct_pack_knl_xid(packet, xid));
    CT_RETURN_IFERR(cs_put_int64(packet, flags));

    if (scn != NULL) {
        packet->head->flags |= CS_FLAG_WITH_TS;
        CT_RETURN_IFERR(cs_put_scn(packet, scn));
    }

    if (cs_write(&CLT_CONN(conn)->pipe, packet) != CT_SUCCESS) {
        clt_copy_local_error(CLT_CONN(conn));
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static inline int32 ctconn_async_xa_prepare_core(ctconn_conn_t conn, text_t *xid, uint64 flags, uint64 *scn)
{
    CT_RETURN_IFERR(ctconn_xa_async_commit_phase(CS_CMD_XA_PREPARE, conn, xid, flags, scn));
    CLT_CONN(conn)->xact_status = CTCONN_XACT_PHASE1;
    return CT_SUCCESS;
}

int32 ctconn_async_xa_prepare(ctconn_conn_t conn, const text_t *xid, uint64 flags, uint64 *scn)
{
    CTCONN_CHECK_OBJECT_NULL_GS(conn, "connection");
    CTCONN_CHECK_OBJECT_NULL_GS(xid, "XID");
    clt_reset_error((clt_conn_t *)conn);
    CT_RETURN_IFERR(clt_lock_conn(CLT_CONN(conn)));
    int32 ret = ctconn_async_xa_prepare_core(conn, (text_t *)xid, flags, scn);
    clt_unlock_conn(CLT_CONN(conn));
    return ret;
}

static inline int32 ctconn_async_xa_commit_core(ctconn_conn_t conn, text_t *xid, uint64 flags, uint64 *scn)
{
    CT_RETURN_IFERR(ctconn_xa_async_commit_phase(CS_CMD_XA_COMMIT, conn, xid, flags, scn));
    CLT_CONN(conn)->xact_status = CTCONN_XACT_END;
    return CT_SUCCESS;
}

int32 ctconn_async_xa_commit(ctconn_conn_t conn, const text_t *xid, uint64 flags, uint64 *scn)
{
    CTCONN_CHECK_OBJECT_NULL_GS(conn, "connection");
    CTCONN_CHECK_OBJECT_NULL_GS(xid, "XID");
    clt_reset_error((clt_conn_t *)conn);
    CT_RETURN_IFERR(clt_lock_conn(CLT_CONN(conn)));
    int32 ret = ctconn_async_xa_commit_core(conn, (text_t *)xid, flags, scn);
    clt_unlock_conn(CLT_CONN(conn));
    return ret;
}

static inline int32 ctconn_async_xa_prepare_ack_core(ctconn_conn_t conn, uint64 *ack_scn)
{
    int32 errcode;
    cs_packet_t *pack = &CLT_CONN(conn)->pack;

    CT_RETURN_IFERR(clt_async_get_ack(CLT_CONN(conn), pack));

    cs_init_get(pack);
    if (CS_XACT_WITH_TS(pack->head->flags)) {
        CT_RETURN_IFERR(cs_get_scn(pack, ack_scn));
    }
    CT_RETURN_IFERR(cs_get_int32(pack, &errcode));
    if (errcode != 0) {
        CT_THROW_ERROR(errcode);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

int32 ctconn_async_xa_prepare_ack(ctconn_conn_t conn, uint64 *ack_scn)
{
    CTCONN_CHECK_OBJECT_NULL_GS(conn, "connection");
    clt_reset_error((clt_conn_t *)conn);
    CT_RETURN_IFERR(clt_lock_conn(CLT_CONN(conn)));
    int32 ret = ctconn_async_xa_prepare_ack_core(conn, ack_scn);
    clt_unlock_conn(CLT_CONN(conn));
    return ret;
}

static inline int32 ctconn_async_xa_commit_ack_core(ctconn_conn_t conn, uint64 *ack_scn)
{
    cs_packet_t *pack = &CLT_CONN(conn)->pack;

    CT_RETURN_IFERR(clt_async_get_ack(CLT_CONN(conn), pack));

    cs_init_get(pack);
    if (CS_XACT_WITH_TS(pack->head->flags)) {
        CT_RETURN_IFERR(cs_get_scn(pack, ack_scn));
    }
    return CT_SUCCESS;
}

int32 ctconn_async_xa_commit_ack(ctconn_conn_t conn, uint64 *ack_scn)
{
    CTCONN_CHECK_OBJECT_NULL_GS(conn, "connection");
    clt_reset_error((clt_conn_t *)conn);
    CT_RETURN_IFERR(clt_lock_conn(CLT_CONN(conn)));
    int32 ret = ctconn_async_xa_commit_ack_core(conn, ack_scn);
    clt_unlock_conn(CLT_CONN(conn));
    return ret;
}

int32 ctconn_async_xa_rollback_ack(ctconn_conn_t conn)
{
    CTCONN_CHECK_OBJECT_NULL_GS(conn, "connection");
    clt_reset_error((clt_conn_t *)conn);
    CT_RETURN_IFERR(clt_lock_conn(CLT_CONN(conn)));
    int32 ret = clt_async_get_ack(CLT_CONN(conn), &CLT_CONN(conn)->pack);
    clt_unlock_conn(CLT_CONN(conn));
    return ret;
}

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
 * srv_view_dtc_local.c
 *
 *
 * IDENTIFICATION
 * src/server/srv_view_dtc_local.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_module.h"
#include "cm_base.h"
#include "cm_text.h"
#include "cm_log.h"
#include "cm_system.h"
#include "knl_log.h"
#include "knl_context.h"
#include "knl_interface.h"
#include "knl_session.h"
#include "dtc_context.h"
#include "srv_view.h"
#include "ctsql_stmt.h"
#include "ctsql_parser.h"
#include "ctsql_service.h"
#include "srv_session.h"
#include "srv_instance.h"
#include "pl_executor.h"
#include "dml_executor.h"
#include "mes_func.h"
#include "dtc_drc.h"
#include "gdv_stmt.h"
#include "gdv_context.h"
#include "dtc_view.h"
#include "cms_interface.h"

static status_t drc_info_fetch(knl_handle_t se, knl_cursor_t *cursor);
static status_t drc_buf_info_fetch(knl_handle_t se, knl_cursor_t *cursor);
status_t drc_local_lock_info_fetch(knl_handle_t se, knl_cursor_t *cursor);
static status_t drc_res_ratio_fetch(knl_handle_t se, knl_cursor_t *cursor);
static status_t drc_global_res_fetch(knl_handle_t se, knl_cursor_t *cursor);
static status_t drc_res_map_fetch(knl_handle_t se, knl_cursor_t *cursor);
static status_t drc_buf_ctrl_fetch(knl_handle_t se, knl_cursor_t *cursor);

char g_drc_res_name[][CT_DYNVIEW_NORMAL_LEN] = {
    {"PAGE_BUF"},
    {"GLOBAL_LOCK"},
    {"LOCAL_LOCK"},
    {"LOCAL_TXN"},
    {"GLOBAL_TXN"},
    {"LOCK_ITEM"},
};

char g_drc_global_res_name[][CT_DYNVIEW_NORMAL_LEN] = {
    { "GLOBAL_BUF_RES" },
    { "GLOBAL_LOCK_RES" },
};

char g_drc_res_map_name[][CT_DYNVIEW_NORMAL_LEN] = {
    { "LOCAL_LOCK_MAP" },
    { "TXN_RES_MAP" },
    { "LOCAL_TXN_MAP" },
};

char g_dls_type_name[][CT_DYNVIEW_NORMAL_LEN] = {
    {"INVALID"},
    {"DATABASE"},
    {"TABLE SPACE"},
    {"TABLE"},
    {"DDL"},
    {"SEQENCE"},
    {"SERIAL"},
    {"ROLE"},
    {"USER"},
    {"DC"},
    {"INDEX"},
    {"TRIGGER"},
    {"HEAP"},
    {"HEAP_PART"},
    {"HEAP_LATCH"},
    {"HEAP_PART_LATCH"},
    {"BTREE_LATCH"},
    {"BRTEE_PART_LATCH"},
    {"INTERVAL_PART_LATCH"},
    {"LOB_LATCH"},
    {"LOB_PART_LATCH"},
    {"PROFILE"},
    {"UNDO"},
    {"PROC"},
    {"GDV"},
};
status_t drc_info_open(knl_handle_t session, knl_cursor_t *cursor)
{
    cursor->rowid.vmid = 0;
    cursor->rowid.vm_slot = 0;
    cursor->rowid.vm_tag = 0;
    return CT_SUCCESS;
}

static knl_column_t g_drc_info_columns[] = {
    { 0, "DRC_INFO_NAME", 0, 0, CT_TYPE_VARCHAR, CT_DYNVIEW_NORMAL_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "COUNT", 0, 0, CT_TYPE_BIGINT, sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_drc_buf_info_columns[] = {
    { 0, "IDX", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "FILE_ID", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 2, "PAGE_ID", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 3, "OWNER_ID", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 4, "OWNER_LOCK", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 5, "CONVERTING_INST", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 6, "CONVERTING_CUR_LOCK", 0, 0, CT_TYPE_VARCHAR, CT_DYNVIEW_NORMAL_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 7, "CONVERTING_REQ_LOCK", 0, 0, CT_TYPE_VARCHAR, CT_DYNVIEW_NORMAL_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 8, "CONVERTQ_LEN", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 9, "EDP_MAP", 0, 0, CT_TYPE_BIGINT, sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
    { 10, "CONVERTING_REQ_SID", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 11, "CONVERTING_REQ_RSN", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 12, "PART_ID", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 13, "READONLY_COPIES", 0, 0, CT_TYPE_BIGINT, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_drc_res_ratio_columns[] = {
    { 0, "DRC_RESOURCE", 0, 0, CT_TYPE_VARCHAR, CT_DYNVIEW_NORMAL_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "USED", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 2, "TOTAL", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 3, "RATIO", 0, 0, CT_TYPE_VARCHAR, CT_DYNVIEW_NORMAL_LEN, 0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_drc_global_res_colums[] = {
    { 0, "DRC_RESOURCE", 0, 0, CT_TYPE_VARCHAR, CT_DYNVIEW_NORMAL_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "BUCKET_NUM", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 2, "POOL_RECYCLE_POS", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 3, "POOL_FREE_LIST", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 4, "BUCKETS_COUNT", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 5, "BUCKETS_FIRST", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_drc_res_map_colums[] = {
    { 0, "DRC_RESOURCE", 0, 0, CT_TYPE_VARCHAR, CT_DYNVIEW_NORMAL_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "BUCKET_NUM", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 2, "POOL_RECYCLE_POS", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 3, "POOL_FREE_LIST", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 4, "BUCKETS_COUNT", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 5, "BUCKETS_FIRST", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_buf_ctrl_info_columns[] = {
    { 0, "POOL_ID", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "FILE_ID", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 2, "PAGE_ID", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 3, "LATCH_SHARE_COUNT", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 4, "LATCH_STAT", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 5, "LATCH_SID", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 6, "LATCH_XSID", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 7, "IS_READONLY", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 8, "IS_DIRTY", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 9, "IS_REMOTE_DIRTY", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 10, "IS_MARKED", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 11, "LOAD_STATUS", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 12, "IN_OLD", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 13, "IN_CKPT", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 14, "LOCK_MODE", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 15, "IS_EDP", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 16, "REF_NUM", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 17, "LASTEST_LFN", 0, 0, CT_TYPE_BIGINT, sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
    { 18, "EDP_SCN", 0, 0, CT_TYPE_BIGINT, sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_drc_local_lock_info_columns[] = {
    { 0, "IDX", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "DRID_TYPE", 0, 0, CT_TYPE_VARCHAR, CT_DYNVIEW_NORMAL_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 2, "DRID_UID", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 3, "DRID_ID", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 4, "DRID_IDX", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 5, "DRID_PART", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 6, "DRID_PARENTPART", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 7, "IS_OWNER", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 8, "IS_LOCKED", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 9, "COUNT", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 10, "LATCH_SHARE_COUNT", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 11, "LATCH_STAT", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 12, "LATCH_SID", 0, 0, CT_TYPE_UINT32, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
};

#define DRC_INFO_COLS (ELEMENT_COUNT(g_drc_info_columns))
#define DRC_BUF_INFO_COLS (ELEMENT_COUNT(g_drc_buf_info_columns))
#define DRC_RES_RATIO_COLS (ELEMENT_COUNT(g_drc_res_ratio_columns))
#define DRC_GLOBAL_RES_COLS (ELEMENT_COUNT(g_drc_global_res_colums))
#define DRC_RES_MAP_COLS (ELEMENT_COUNT(g_drc_res_map_colums))
#define BUF_CTRL_INFO_COLS (ELEMENT_COUNT(g_buf_ctrl_info_columns))
#define DRC_LOCAL_LOCK_INFO_COLS (ELEMENT_COUNT(g_drc_local_lock_info_columns))

VW_DECL g_drc_info = { "SYS", "DV_DRC_INFO", DRC_INFO_COLS, g_drc_info_columns, drc_info_open, drc_info_fetch };
VW_DECL g_drc_buf_info = { "SYS",         "DV_DRC_BUF_INFO", DRC_BUF_INFO_COLS, g_drc_buf_info_columns,
                           drc_info_open, drc_buf_info_fetch };
VW_DECL g_drc_res_ratio = { "SYS",         "DV_DRC_RES_RATIO", DRC_RES_RATIO_COLS, g_drc_res_ratio_columns,
                            drc_info_open, drc_res_ratio_fetch };
// for global_buf_res and global_lock_res
VW_DECL g_drc_global_res = { "SYS",         "DV_DRC_GLOBAL_RES", DRC_GLOBAL_RES_COLS, g_drc_global_res_colums,
                             drc_info_open, drc_global_res_fetch };
// for txn_res_map/local_txn_map/local_lock_map
VW_DECL g_drc_res_map = { "SYS",         "DV_DRC_RES_MAP", DRC_RES_MAP_COLS, g_drc_res_map_colums,
                          drc_info_open, drc_res_map_fetch };

VW_DECL g_buf_ctrl_info = { "SYS",         "DV_BUF_CTRL_INFO", BUF_CTRL_INFO_COLS, g_buf_ctrl_info_columns,
                            drc_info_open, drc_buf_ctrl_fetch };
VW_DECL g_drc_local_lock_info = {
    "SYS",         "DV_DRC_LOCAL_LOCK_INFO", DRC_LOCAL_LOCK_INFO_COLS, g_drc_local_lock_info_columns,
    drc_info_open, drc_local_lock_info_fetch
};

dynview_desc_t *vw_describe_dtc_local(uint32 id)
{
    switch ((dynview_id_t)id) {
        case DYN_VIEW_DRC_INFO:
            return &g_drc_info;
        case DYN_VIEW_DRC_BUF_INFO:
            return &g_drc_buf_info;
        case DYN_VIEW_DRC_RES_RATIO:
            return &g_drc_res_ratio;
        case DYN_VIEW_DRC_GLOBAL_RES:
            return &g_drc_global_res;
        case DYN_VIEW_DRC_RES_MAP:
            return &g_drc_res_map;
        case DYN_VIEW_BUF_CTRL_INFO:
            return &g_buf_ctrl_info;
        case DYN_VIEW_DRC_LOCAL_LOCK_INFO:
            return &g_drc_local_lock_info;
        default:
            return NULL;
    }
}

static status_t drc_buf_info_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    drc_res_ctx_t *drc_ctx = &g_drc_res_ctx;
    drc_global_res_t *global_buf_res = &drc_ctx->global_buf_res;
    drc_res_pool_t *buf_pool = &global_buf_res->res_map.res_pool;

    drc_buf_res_t *buf_res_begin = (drc_buf_res_t *)buf_pool->addr;

    uint32 item_id = (uint32)cursor->rowid.vmid;

    if (item_id >= buf_pool->item_num) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    drc_buf_res_t *tmp_buf_res = buf_res_begin + item_id;

    while (1) {
        if (tmp_buf_res->is_used == CT_TRUE) {
            break;
        }

        item_id++;

        if (item_id >= buf_pool->item_num) {
            cursor->eof = CT_TRUE;
            return CT_SUCCESS;
        }

        tmp_buf_res = buf_res_begin + item_id;
    }

    row_assist_t ra;
    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, DRC_BUF_INFO_COLS);
    CT_RETURN_IFERR(row_put_uint32(&ra, (int32)tmp_buf_res->idx));
    CT_RETURN_IFERR(row_put_uint32(&ra, (int32)tmp_buf_res->page_id.file));
    CT_RETURN_IFERR(row_put_uint32(&ra, (int32)tmp_buf_res->page_id.page));
    CT_RETURN_IFERR(row_put_uint32(&ra, (int32)tmp_buf_res->claimed_owner));
    CT_RETURN_IFERR(row_put_uint32(&ra, (int32)tmp_buf_res->lock));
    CT_RETURN_IFERR(row_put_uint32(&ra, (int32)tmp_buf_res->converting.req_info.inst_id));
    CT_RETURN_IFERR(row_put_str(&ra, drc_get_buf_lock_mode_str(tmp_buf_res->converting.req_info.curr_mode)));
    CT_RETURN_IFERR(row_put_str(&ra, drc_get_buf_lock_mode_str(tmp_buf_res->converting.req_info.req_mode)));
    CT_RETURN_IFERR(row_put_uint32(&ra, (int32)tmp_buf_res->convert_q.count));
    CT_RETURN_IFERR(row_put_uint32(&ra, (int64)tmp_buf_res->edp_map));
    CT_RETURN_IFERR(row_put_uint32(&ra, (int32)tmp_buf_res->converting.req_info.inst_sid));
    CT_RETURN_IFERR(row_put_uint32(&ra, (int32)tmp_buf_res->converting.req_info.rsn));
    CT_RETURN_IFERR(row_put_uint32(&ra, (int32)tmp_buf_res->part_id));
    CT_RETURN_IFERR(row_put_uint32(&ra, (int32)tmp_buf_res->readonly_copies));

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);

    cursor->rowid.vmid = item_id;
    cursor->rowid.vmid++;

    return CT_SUCCESS;
}

static status_t drc_info_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    drc_res_ctx_t *drc_ctx = &g_drc_res_ctx;
    drc_master_info_row *stat_row = drc_ctx->stat.stat_info;

    uint32 id;
    id = (uint32)cursor->rowid.vmid;
    if (id >= drc_ctx->stat.master_info_row_cnt) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    row_assist_t ra;
    stat_row += id;
    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, DRC_INFO_COLS);
    CT_RETURN_IFERR(row_put_str(&ra, stat_row->name));
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)stat_row->cnt));
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);

    cursor->rowid.vmid++;

    return CT_SUCCESS;
}

static status_t get_local_lock_res_view(row_assist_t *ra, drc_local_lock_res_t *local_lock_res)
{
    CT_RETURN_IFERR(row_put_uint32(ra, (uint32)local_lock_res->idx));
    CT_RETURN_IFERR(row_put_str(ra, g_dls_type_name[(uint32)local_lock_res->res_id.type]));
    CT_RETURN_IFERR(row_put_uint32(ra, (uint32)local_lock_res->res_id.uid));
    CT_RETURN_IFERR(row_put_uint32(ra, (uint32)local_lock_res->res_id.id));
    CT_RETURN_IFERR(row_put_uint32(ra, (uint32)local_lock_res->res_id.idx));
    CT_RETURN_IFERR(row_put_uint32(ra, (uint32)local_lock_res->res_id.part));
    CT_RETURN_IFERR(row_put_uint32(ra, (uint32)local_lock_res->res_id.parentpart));
    CT_RETURN_IFERR(row_put_uint32(ra, (uint32)local_lock_res->is_owner));
    CT_RETURN_IFERR(row_put_uint32(ra, (uint32)local_lock_res->is_locked));
    CT_RETURN_IFERR(row_put_uint32(ra, (uint32)local_lock_res->count));
    CT_RETURN_IFERR(row_put_uint32(ra, (uint32)local_lock_res->latch_stat.shared_count));
    CT_RETURN_IFERR(row_put_uint32(ra, (uint32)local_lock_res->latch_stat.stat));
    CT_RETURN_IFERR(row_put_uint32(ra, (uint32)local_lock_res->latch_stat.sid));
    return CT_SUCCESS;
}

status_t drc_local_lock_info_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    row_assist_t ra;
    drc_res_ctx_t *ctx = &g_drc_res_ctx;
    drc_local_lock_res_t *local_lock_res = NULL;
    drc_res_bucket_t *bucket = NULL;
    uint64 index = 0;
    uint32 i = 0;
    uint32 lock_idx = 0;

    if (cursor->rowid.vmid >= ctx->local_lock_map.bucket_num) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    bucket = &ctx->local_lock_map.buckets[cursor->rowid.vmid];

    while (bucket->count == 0 && cursor->rowid.vmid < ctx->local_lock_map.bucket_num) {
        cursor->rowid.vmid++;
        cursor->rowid.vm_slot = 0;
        bucket = &ctx->local_lock_map.buckets[cursor->rowid.vmid];
    }

    if (cursor->rowid.vmid >= ctx->local_lock_map.bucket_num) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }
    drc_lock_remaster_mngr();
    index = cursor->rowid.vm_slot;
    lock_idx = bucket->first;
    for (i = 0; i < bucket->count; i++) {
        local_lock_res = (drc_local_lock_res_t *)DRC_GET_RES_ADDR_BY_ID(&ctx->local_lock_map.res_pool, lock_idx);
        if (index == 0) {
            break;
        } else {
            index--;
            lock_idx = local_lock_res->next;
        }
    }

    drc_unlock_remaster_mngr();

    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, DRC_LOCAL_LOCK_INFO_COLS);
    status_t ret = get_local_lock_res_view(&ra, local_lock_res);
    if (ret != CT_SUCCESS) {
        return ret;
    }
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);

    cursor->rowid.vm_slot++;
    if (i == bucket->count - 1) {
        cursor->rowid.vmid++;
        cursor->rowid.vm_slot = 0;
    }
    return CT_SUCCESS;
}

status_t drc_res_ratio_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    uint32 id = (uint32)cursor->rowid.vmid;
    uint32 row_cnt = sizeof(g_drc_res_name) / sizeof(g_drc_res_name[0]);
    if (id >= row_cnt) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    uint32 used_num = 0;
    uint32 item_num = 0;
    char ratio[CT_DYNVIEW_NORMAL_LEN];

    row_assist_t ra;
    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, DRC_RES_RATIO_COLS);
    drc_get_res_num((drc_res_type_e)(id + 1), &used_num, &item_num); // The first res type is invalid.
    CT_RETURN_IFERR(row_put_str(&ra, g_drc_res_name[id]));           // res name
    CT_RETURN_IFERR(row_put_uint32(&ra, used_num));                  // used
    CT_RETURN_IFERR(row_put_uint32(&ra, item_num));                  // total
    if (item_num == 0) {
        CT_RETURN_IFERR(row_put_str(&ra, "0.0")); // ratio
    } else {
        sprintf_s(ratio, CT_DYNVIEW_NORMAL_LEN, "%.5f", (float)used_num / item_num);
        CT_RETURN_IFERR(row_put_str(&ra, ratio));
    }

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid++;

    return CT_SUCCESS;
}

status_t drc_global_res_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    drc_res_ctx_t *drc_ctx = &g_drc_res_ctx;
    uint32 id = (uint32)cursor->rowid.vmid;
    uint32 row_cnt = sizeof(g_drc_global_res_name) / sizeof(g_drc_global_res_name[0]);
    if (id >= row_cnt) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    drc_global_res_t *global_res = NULL;
    switch ((drc_global_res_type_e)(id)) {
        case DRC_GLOBAL_BUF_RES_TYPE:
            global_res = &drc_ctx->global_buf_res;
            break;
        case DRC_GLOBAL_LOCK_RES_TYPE:
            global_res = &drc_ctx->global_lock_res;
            break;
        default:
            break;
    }
    drc_res_pool_t *buf_pool = &global_res->res_map.res_pool;
    drc_res_bucket_t *buckets = global_res->res_map.buckets;

    row_assist_t ra;
    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, DRC_GLOBAL_RES_COLS);
    CT_RETURN_IFERR(row_put_str(&ra, g_drc_global_res_name[id]));
    CT_RETURN_IFERR(row_put_uint32(&ra, (int32)global_res->res_map.bucket_num));
    CT_RETURN_IFERR(row_put_uint32(&ra, (int32)buf_pool->recycle_pos));
    CT_RETURN_IFERR(row_put_uint32(&ra, (int32)buf_pool->free_list));
    CT_RETURN_IFERR(row_put_uint32(&ra, (int32)buckets->count));
    CT_RETURN_IFERR(row_put_uint32(&ra, (int32)buckets->first));

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid++;
    return CT_SUCCESS;
}


status_t drc_res_map_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    drc_res_ctx_t *drc_ctx = &g_drc_res_ctx;
    uint32 id = (uint32)cursor->rowid.vmid;
    uint32 row_cnt = sizeof(g_drc_res_map_name) / sizeof(g_drc_res_map_name[0]);
    if (id >= row_cnt) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    drc_res_map_t *res_map = NULL;
    switch ((drc_res_map_type_e)(id)) {
        case DRC_LOCAL_LOCK_MAP_TYPE:
            res_map = &drc_ctx->local_lock_map;
            break;
        case DRC_TXN_RES_MAP_TYPE:
            res_map = &drc_ctx->txn_res_map;
            break;
        case DRC_LOCAL_TXN_MAP:
            res_map = &drc_ctx->local_txn_map;
            break;
        default:
            break;
    }
    drc_res_pool_t *buf_pool = &res_map->res_pool;
    drc_res_bucket_t *buckets = res_map->buckets;

    row_assist_t ra;
    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, DRC_RES_MAP_COLS);
    CT_RETURN_IFERR(row_put_str(&ra, g_drc_res_map_name[id]));
    CT_RETURN_IFERR(row_put_uint32(&ra, (int32)res_map->bucket_num));
    CT_RETURN_IFERR(row_put_uint32(&ra, (int32)buf_pool->recycle_pos));
    CT_RETURN_IFERR(row_put_uint32(&ra, (int32)buf_pool->free_list));
    CT_RETURN_IFERR(row_put_uint32(&ra, (int32)buckets->count));
    CT_RETURN_IFERR(row_put_uint32(&ra, (int32)buckets->first));

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid++;
    return CT_SUCCESS;
}

static status_t drc_buf_ctrl_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    row_assist_t ra;
    buf_ctrl_t *ctrl = NULL;

    buf_context_t *ctx = &g_dtc->kernel->buf_ctx;

    while (cursor->rowid.slot < ctx->buf_set_count) {
        buf_set_t *buf_set = &ctx->buf_set[cursor->rowid.slot];
        if (cursor->rowid.vmid >= buf_set->hwm) {
            cursor->rowid.vmid = 0;
            cursor->rowid.slot++;
            continue;
        }
        ctrl = &buf_set->ctrls[cursor->rowid.vmid];
        if (ctrl == NULL || (ctrl->page == NULL) || (ctrl->bucket_id == CT_INVALID_ID32)) {
            cursor->rowid.vmid++;
            continue;
        }

        row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, BUF_CTRL_INFO_COLS);
        CT_RETURN_IFERR(row_put_int32(&ra, (int32)(cursor->rowid.slot)));
        CT_RETURN_IFERR(row_put_uint32(&ra, (uint32)ctrl->page_id.file));
        CT_RETURN_IFERR(row_put_uint32(&ra, ctrl->page_id.page));
        CT_RETURN_IFERR(row_put_uint32(&ra, (uint32)ctrl->latch.shared_count));
        CT_RETURN_IFERR(row_put_uint32(&ra, (uint32)ctrl->latch.stat));
        CT_RETURN_IFERR(row_put_uint32(&ra, (uint32)ctrl->latch.sid));
        CT_RETURN_IFERR(row_put_uint32(&ra, (uint32)ctrl->latch.xsid));
        CT_RETURN_IFERR(row_put_uint32(&ra, (uint32)ctrl->is_readonly));
        CT_RETURN_IFERR(row_put_uint32(&ra, (uint32)ctrl->is_dirty));
        CT_RETURN_IFERR(row_put_uint32(&ra, (uint32)ctrl->is_remote_dirty));
        CT_RETURN_IFERR(row_put_uint32(&ra, (uint32)ctrl->is_marked));
        CT_RETURN_IFERR(row_put_uint32(&ra, (uint32)ctrl->load_status));
        CT_RETURN_IFERR(row_put_uint32(&ra, (uint32)ctrl->in_old));
        CT_RETURN_IFERR(row_put_uint32(&ra, (uint32)ctrl->in_ckpt));
        CT_RETURN_IFERR(row_put_uint32(&ra, (uint32)ctrl->lock_mode));
        CT_RETURN_IFERR(row_put_uint32(&ra, (uint32)ctrl->is_edp));
        CT_RETURN_IFERR(row_put_uint32(&ra, (uint32)ctrl->ref_num));
        CT_RETURN_IFERR(row_put_int64(&ra, (int64)ctrl->lastest_lfn));
        CT_RETURN_IFERR(row_put_int64(&ra, (int64)ctrl->edp_scn));
        cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);

        cursor->rowid.vmid++;
        return CT_SUCCESS;
    }
    if (cursor->rowid.slot >= ctx->buf_set_count) {
        cursor->eof = CT_TRUE;
    }
    return CT_SUCCESS;
}

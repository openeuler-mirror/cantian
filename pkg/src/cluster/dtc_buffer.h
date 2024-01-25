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
 * dtc_buffer.h
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_buffer.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DTC_BUFFER_H__
#define __DTC_BUFFER_H__
#include "cm_defs.h"
#include "knl_session.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct st_buf_ctrl buf_ctrl_t;

// pack read page parameters together
typedef struct st_buf_read_assist {
    page_id_t       page_id;
    knl_scn_t       query_scn;  // if not invalid, try edp, check edp scn with query_scn
    latch_mode_t    mode;
    uint8           options;
    bool8           try_edp;    // check edp if local page not usable
    uint16          read_num;   // == 1 no prefetch, > 1 prefetch multiple pages
} buf_read_assist_t;

#define DTC_BUF_READ_ONE 1                          // read only one, no prefetch
#define DTC_BUF_PREFETCH_EXT_NUM CT_INVALID_ID16    // prefetch by space extent_size
                                                    // others, prefetch by given read_num

#define DTC_BUF_NO_PREFETCH(read_num) ((read_num) == DTC_BUF_READ_ONE)
#define DTC_BUF_PREFETCH_EXTENT(read_num) ((read_num) == DTC_BUF_PREFETCH_EXT_NUM)

static inline uint64 dtc_get_ctrl_lsn(buf_ctrl_t *ctrl)
{
    return IS_SAME_PAGID(ctrl->page_id, AS_PAGID(ctrl->page->id)) ? ctrl->page->lsn : 0;
}

static inline uint64 dtc_get_ctrl_latest_lsn(buf_ctrl_t *ctrl)
{
    return (ctrl->load_status == BUF_IS_LOADED) ? ctrl->page->lsn : 0;
}

static inline void dtc_read_init(buf_read_assist_t *ra, page_id_t page_id, latch_mode_t mode, uint8 options,
                                 knl_scn_t query_scn, uint16 read_num)
{
    ra->page_id = page_id;
    ra->query_scn = query_scn;
    ra->mode = mode;
    ra->options = options;
    ra->try_edp = (query_scn == CT_INVALID_ID64 ? CT_FALSE : CT_TRUE);
    ra->read_num = read_num;
}

status_t dtc_read_page(knl_session_t *session, buf_read_assist_t *ra);
status_t dtc_get_share_owner_pages(knl_session_t *session, buf_ctrl_t **ctrl_array, buf_ctrl_t *ctrl, uint32 count);

bool32 dtc_dcs_readable(knl_session_t *session);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif

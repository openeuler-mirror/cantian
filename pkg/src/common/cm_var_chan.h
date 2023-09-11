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
 * cm_var_chan.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_var_chan.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __CM_VAR_CHAN_H__
#define __CM_VAR_CHAN_H__

#include "cm_chan.h"
#include "cm_list.h"

#define MAX_BUF_COUNT 64
typedef struct {
    uint8 *bufs[MAX_BUF_COUNT];      // every buf's start pos
    uint8 *bufs_end[MAX_BUF_COUNT];  // every buf's end pos
    uint8 *data_end[MAX_BUF_COUNT];  // the last pos of data stored of every buf
    uint32 buf_count;
    uint32 available;  // length of all available bufs
    uint32 total;      // total length of all bufs
    uint32 beg_buf_id;
    uint32 end_buf_id;
} chan_buf_ctrl_t;

typedef struct st_var_chan {
    chan_t ori_chan;
    chan_buf_ctrl_t buf_ctrl;
} var_chan_t;

var_chan_t *cm_var_chan_new(uint64 total, void *owner, ga_alloc_func_t alloc_func);
status_t cm_var_chan_send(var_chan_t *chan, const void *elem, uint32 len);
status_t cm_var_chan_send_timeout(var_chan_t *chan, const void *elem, uint32 len, uint32 timeout_ms);
status_t cm_var_chan_recv(var_chan_t *chan, void *elem, uint32 *len);
status_t cm_var_chan_recv_timeout(var_chan_t *chan, void *elem, uint32 *len, uint32 timeout_ms);
void cm_var_chan_close(var_chan_t *chan);
void cm_var_chan_free(var_chan_t *chan);
bool32 cm_var_chan_empty(var_chan_t *chan);

#endif


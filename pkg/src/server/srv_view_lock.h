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
 * srv_view_lock.h
 *
 *
 * IDENTIFICATION
 * src/server/srv_view_lock.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SRV_VIEW_LOCK_H__
#define __SRV_VIEW_LOCK_H__
#include "srv_view.h"

dynview_desc_t *vw_describe_lock(uint32 id);
#define ALCK_TEXTBUF_APPEND_RESERVE 4

typedef struct st_vw_alocks_assist {
    uint32 se_pool_itemcnts;
    uint32 tx_pool_itemcnts;
} vw_alocks_assist_t;

#endif

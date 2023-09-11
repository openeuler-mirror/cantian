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
 * srv_view_stat.h
 *
 *
 * IDENTIFICATION
 * src/server/srv_view_stat.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SRV_VIEW_STAT_H__
#define __SRV_VIEW_STAT_H__

#include "srv_view.h"
#include "rc_reform.h"

dynview_desc_t *vw_describe_stat(uint32 id);
extern reform_ctx_t *g_rc_ctx;
#endif

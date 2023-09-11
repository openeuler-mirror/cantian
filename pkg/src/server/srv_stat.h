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
 * srv_stat.h
 *
 *
 * IDENTIFICATION
 * src/server/srv_stat.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SRV_STAT_H__
#define __SRV_STAT_H__

#include "srv_session.h"

void stat_pool_init(stat_pool_t *pool);
status_t server_alloc_stat(uint16 *stat_id);
void server_release_stat(uint16 *stat_id);

#endif

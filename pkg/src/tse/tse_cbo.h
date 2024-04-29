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
 * tse_cbo.h
 *
 *
 * IDENTIFICATION
 * src/tse/tse_cbo.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __TSE_CBO_H__
#define __TSE_CBO_H__

#include "ostat_load.h"
#include "tse_srv.h"

#define DEFAULT_RANGE_DENSITY 0.5
#define PREFER_RANGE_DENSITY 0.8

status_t get_cbo_stats(knl_handle_t handle, dc_entity_t *entity, tianchi_cbo_stats_t *stats, tse_cbo_stats_table_t *tse_cbo_stats_table, uint32_t first_partid, uint32_t num_part_fetch);

#endif // __TSE_CBO_H__
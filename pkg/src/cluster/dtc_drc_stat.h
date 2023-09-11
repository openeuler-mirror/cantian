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
 * dtc_drc_stat.h
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_drc_stat.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef DTC_DRC_STAT_LOCAL_H
#define DTC_DRC_STAT_LOCAL_H

#ifdef __cplusplus
extern "C" {
#endif

status_t drc_stat_init(void);
void drc_stat_res_destroy(void);

typedef struct st_drc_master_info_row {
    char *name;
    uint64 cnt;
} drc_master_info_row;

typedef enum en_drc_stat_type {
    R_PO_TOTAL = 0,  // total count for request page owner. REQ_PAGE_OWNER_TOTAL
    R_PO_CONVETED,
    R_PO_FIRST, // fist request, need to construct buf_res struct for page. REQ_PAGE_OWNER_FIRST_REQ
    R_PO_TRY, // try to request page owner. REQ_PAGE_OWNER_TRY_REQ
    R_PO_CVTING_TOTAL, // total page cnt that need to converting. REQ_PAGE_OWNER_CONVERTING_TOTAL
    R_PO_CVTING_CURR, // current page cnt that converring. REQ_PAGE_OWNER_CONVETING_CURR
    R_PO_CVTQ_TOTAL, // total page cnt in queue. REQ_PAGE_OWNER_CONVERTQ_TOTAL
    R_PO_CVTQ_CURR, // current page cnt in queue. REQ_PAGE_OWNER_CONVERTQ_CURR
    R_PO_CONFLICT_TOTAL, // conflict count.  REQ_PAGE_OWNER_CONFLICT_TOTAL
} drc_stat_type_e;

#ifdef __cplusplus
}
#endif

#endif

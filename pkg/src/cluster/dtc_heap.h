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
 * dtc_heap.h
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_heap.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DTC_HEAP_H__
#define __DTC_HEAP_H__
#include "pcr_heap.h"

status_t dtc_heap_prefetch_cr_page(knl_session_t *session, knl_cursor_t *cursor, knl_scn_t query_scn,
                                   char *page_buf, bool8 *fb_buf);
status_t dtc_heap_enter_cr_page(knl_session_t *session, knl_cursor_t *cursor, knl_scn_t query_scn, rowid_t rowid);
status_t dtc_heap_check_current_visible(knl_session_t *session, cr_cursor_t *cursor,
                                        heap_page_t *page, bool32 *is_found);

#endif
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
 * knl_sort_page.h
 *
 *
 * IDENTIFICATION
 * src/kernel/common/knl_sort_page.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_SORT_PAGE_H__
#define __KNL_SORT_PAGE_H__

#include "mtrl_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MTRL_GET_DIR(page, id) (uint32 *)((char *)(page) + CT_VMEM_PAGE_SIZE - ((id) + 1) * sizeof(uint32))
#define MTRL_GET_ROW(page, id) ((char *)(page) + *MTRL_GET_DIR((page), (id)))
#define MTRL_DIR_SIZE(page) ((page)->rows * sizeof(uint32))
#define MTRL_PAGE_FREE_SIZE(page) (CT_VMEM_PAGE_SIZE - MTRL_DIR_SIZE(page) - ((page)->free_begin))

status_t mtrl_sort_page(mtrl_context_t *ctx, mtrl_segment_t *segment, mtrl_page_t *page);
status_t mtrl_adaptive_sort_page(mtrl_context_t *ctx, mtrl_segment_t *segment, mtrl_page_t *page);
status_t mtrl_insert_sorted_page(mtrl_context_t *ctx, mtrl_segment_t *segment, mtrl_page_t *page, char *row,
                                 uint16 row_size, uint32 *slot);

#ifdef __cplusplus
}
#endif

#endif

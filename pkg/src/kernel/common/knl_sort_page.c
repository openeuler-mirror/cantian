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
 * knl_sort_page.c
 *
 *
 * IDENTIFICATION
 * src/kernel/common/knl_sort_page.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_sort_page.h"
#include "knl_common.h"

#define MTRL_PRINT_PAGE(ctx, segment, page)                  \
    if ((ctx)->print_page != NULL) {                      \
        (ctx)->print_page (segment, (char *)(page));      \
    }

#define MTRL_ADAPTIVE_SORT_THRESHOLD 47  // The optimal value obtained by testing
#define MAX_QSORT_STACK_DEPTH 4000

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_qsort_span {
    int32 left;
    int32 right;
} qsort_span_t;

typedef struct st_qsort_stack {
    uint32 depth;
    qsort_span_t spans[MAX_QSORT_STACK_DEPTH];
} qsort_stack_t;

#define QSORT_PUSH(stack, l, r)                     \
    do {                                            \
        (stack)->spans[(stack)->depth].left = (l);  \
        (stack)->spans[(stack)->depth].right = (r); \
        (stack)->depth++;                           \
    } while (0)

#define QSORT_POP(stack)  \
    do {                  \
        (stack)->depth--; \
    } while (0)
#define QSORT_CURR(stack) ((stack)->spans[(stack)->depth - 1])

static status_t mtrl_sort_move_left(mtrl_context_t *ctx, mtrl_segment_t *segment, mtrl_page_t *page,
    char *pivot, int32 r_ind, int32 *l_ind)
{
    char *row_l = NULL;
    int32 result;

    while (*l_ind <= r_ind) {
        row_l = MTRL_GET_ROW(page, *l_ind);
        if (ctx->sort_cmp(segment, row_l, pivot, &result) != GS_SUCCESS) {
            return GS_ERROR;
        }
        if (result > 0) {
            break;
        }

        (*l_ind)++;
    }

    return GS_SUCCESS;
}

static status_t mtrl_sort_move_right(mtrl_context_t *ctx, mtrl_segment_t *segment, mtrl_page_t *page,
    char *pivot, int32 l_ind, int32 *r_ind)
{
    char *row_r = NULL;
    int32 result;

    while (l_ind < *r_ind) {
        row_r = MTRL_GET_ROW(page, *r_ind);
        if (ctx->sort_cmp(segment, row_r, pivot, &result) != GS_SUCCESS) {
            return GS_ERROR;
        }
        if (result <= 0) {
            break;
        }

        (*r_ind)--;
    }

    return GS_SUCCESS;
}

static inline void mtrl_swap_dir(mtrl_page_t *page, int32 id1, int32 id2)
{
    uint32 *dir1, *dir2, tmp;
    dir1 = MTRL_GET_DIR(page, id1);
    dir2 = MTRL_GET_DIR(page, id2);
    tmp = *dir1;
    *dir1 = *dir2;
    *dir2 = tmp;
}

//  pivot
//        <= pivot            unknown            > pivot
//  | _______________|_ _ _ _ _ _ _ _ _ _ _|__________________|
//  ^                 ^                   ^                   ^
//  left            l_ind                r_ind               right
//  ARRAY[left + 1, l_ind - 1] <= pivot
//  ARRAY[r_ind + 1, right] > pivot
static status_t mtrl_sort_span(mtrl_context_t *ctx, mtrl_segment_t *segment, mtrl_page_t *page,
    qsort_span_t *span, int32 *new_ind)
{
    char *pivot = NULL;
    int32 l_ind, r_ind;

    MTRL_PRINT_PAGE(ctx, segment, page);

    pivot = MTRL_GET_ROW(page, span->left);
    l_ind = span->left + 1;
    r_ind = span->right;

    while (l_ind <= r_ind) {
        if (mtrl_sort_move_left(ctx, segment, page, pivot, r_ind, &l_ind) != GS_SUCCESS) {
            return GS_ERROR;
        }
        if (l_ind >= r_ind) {
            break;
        }

        if (mtrl_sort_move_right(ctx, segment, page, pivot, l_ind, &r_ind) != GS_SUCCESS) {
            return GS_ERROR;
        }
        if (l_ind >= r_ind) {
            break;
        }

        mtrl_swap_dir(page, l_ind, r_ind);
        l_ind++;
        r_ind--;
        MTRL_PRINT_PAGE(ctx, segment, page);
    }

    *new_ind = l_ind - 1;
    if (l_ind == span->left + 1) {
        return GS_SUCCESS;
    }

    mtrl_swap_dir(page, *new_ind, span->left);
    MTRL_PRINT_PAGE(ctx, segment, page);

    return GS_SUCCESS;
}

// quick sort by Double-End Scanning and Swapping
status_t mtrl_sort_page(mtrl_context_t *ctx, mtrl_segment_t *segment, mtrl_page_t *page)
{
    int32 new_ind;
    qsort_stack_t stack;
    qsort_span_t span;

    if (page->rows <= 1) {
        return GS_SUCCESS;
    }

    stack.depth = 0;
    QSORT_PUSH(&stack, 0, page->rows - 1);

    while (stack.depth > 0) {
        span = QSORT_CURR(&stack);
        if (mtrl_sort_span(ctx, segment, page, &span, &new_ind) != GS_SUCCESS) {
            return GS_ERROR;
        }
        QSORT_POP(&stack);

        if (span.left < new_ind - 1) {
            QSORT_PUSH(&stack, span.left, new_ind - 1);
        }

        if (new_ind + 1 < span.right) {
            QSORT_PUSH(&stack, new_ind + 1, span.right);
        }
    }

    return GS_SUCCESS;
}

//         Sorted              unknown
//  |___________________|_ _ _ _ _ _ _ _ _ _ _|
//  ^                   ^                     ^
//  tmp_left        tmp_right                right
static status_t mtrl_binary_insert_sort(mtrl_context_t *ctx, mtrl_segment_t *segment, mtrl_page_t *page, int32 left,
    int32 right)
{
    int32 tmp_left, tmp_right, mid;
    int32 cmp;
    char *row_i = NULL;
    char *row_mid = NULL;
    char *row_right = NULL;
    char *dst = NULL;
    char *src = NULL;
    uint32 *dir = NULL;
    uint32 dir_i;
    errno_t ret;

    for (int32 i = left + 1; i <= right; i++) {
        tmp_left = left;
        tmp_right = i - 1;
        row_i = MTRL_GET_ROW(page, i);
        row_right = MTRL_GET_ROW(page, tmp_right);
        if (ctx->sort_cmp(segment, row_right, row_i, &cmp) != GS_SUCCESS) {
            return GS_ERROR;
        }
        if (cmp <= 0) {
            continue;
        }

        while (tmp_left <= tmp_right) {
            mid = (tmp_left + tmp_right) / 2;
            row_mid = MTRL_GET_ROW(page, mid);
            if (ctx->sort_cmp(segment, row_mid, row_i, &cmp) != GS_SUCCESS) {
                return GS_ERROR;
            }
            if (cmp > 0) {
                tmp_right = mid - 1;
            } else {
                tmp_left = mid + 1;
            }
        }

        if (i <= tmp_left) {
            continue;
        }
        dst = (char *)MTRL_GET_DIR(page, i);
        dir_i = *((uint32 *)dst);
        src = dst + sizeof(uint32);
        ret = memmove_s(dst, i * sizeof(uint32), src, (i - tmp_left) * sizeof(uint32));
        knl_securec_check(ret);
        dir = MTRL_GET_DIR(page, tmp_left);
        *dir = dir_i;
    }
    return GS_SUCCESS;
}

static status_t mtrl_five_points_check_equal(mtrl_context_t *ctx, mtrl_segment_t *segment, mtrl_page_t *page,
    int32 e1, int32 e2, int32 e3, int32 e4, int32 e5, bool8 *equal)
{
    int32 cmp = 0;
    char *row_l = MTRL_GET_ROW(page, e1);
    char *row_r = MTRL_GET_ROW(page, e2);
    if (ctx->sort_cmp(segment, row_l, row_r, &cmp) != GS_SUCCESS) { // e1 & e2
        return GS_ERROR;
    }
    if (cmp == 0) {
        *equal = GS_TRUE;
        return GS_SUCCESS;
    }

    row_l = MTRL_GET_ROW(page, e3);
    if (ctx->sort_cmp(segment, row_l, row_r, &cmp) != GS_SUCCESS) { // e2 & e3
        return GS_ERROR;
    }
    if (cmp == 0) {
        *equal = GS_TRUE;
        return GS_SUCCESS;
    }

    row_r = MTRL_GET_ROW(page, e4);
    if (ctx->sort_cmp(segment, row_l, row_r, &cmp) != GS_SUCCESS) { // e3 & e4
        return GS_ERROR;
    }
    if (cmp == 0) {
        *equal = GS_TRUE;
        return GS_SUCCESS;
    }

    row_l = MTRL_GET_ROW(page, e5);
    if (ctx->sort_cmp(segment, row_l, row_r, &cmp) != GS_SUCCESS) { // e4 & e5
        return GS_ERROR;
    }
    if (cmp == 0) {
        *equal = GS_TRUE;
    }
    return GS_SUCCESS;
}

static status_t mtrl_adaptive_dual_pivots_swap(mtrl_context_t *ctx, mtrl_segment_t *segment, mtrl_page_t *page,
    char *pivot1, char *pivot2, int32 *less, int32 *great)
{
    char *row_k = NULL;
    char *row_g = NULL;
    int32 cmp1, cmp2;

    for (int32 k = *less; k <= *great; k++) {
        row_k = MTRL_GET_ROW(page, k);
        if (ctx->sort_cmp(segment, row_k, pivot1, &cmp1) != GS_SUCCESS) {
            return GS_ERROR;
        }
        if (cmp1 < 0) {
            mtrl_swap_dir(page, k, *less);
            (*less)++;
            continue;
        }

        if (ctx->sort_cmp(segment, row_k, pivot2, &cmp2) != GS_SUCCESS) {
            return GS_ERROR;
        }
        if (cmp2 <= 0) {
            continue;
        }

        row_g = MTRL_GET_ROW(page, *great);
        if (ctx->sort_cmp(segment, row_g, pivot2, &cmp2) != GS_SUCCESS) {
            return GS_ERROR;
        }
        while (cmp2 > 0) {
            if ((*great)-- == k) {
                return GS_SUCCESS;
            }
            row_g = MTRL_GET_ROW(page, *great);
            if (ctx->sort_cmp(segment, row_g, pivot2, &cmp2) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
        if (ctx->sort_cmp(segment, row_g, pivot1, &cmp1) != GS_SUCCESS) {
            return GS_ERROR;
        }
        mtrl_swap_dir(page, k, *great);
        if (cmp1 < 0) {
            mtrl_swap_dir(page, k, *less);
            (*less)++;
        }

        (*great)--;
    }
    return GS_SUCCESS;
}

static status_t mtrl_adaptive_dual_pivots_center_swap(mtrl_context_t *ctx, mtrl_segment_t *segment, mtrl_page_t *page,
    char *pivot1, char *pivot2, int32 *less, int32 *great)
{
    char *row_k = NULL;
    char *row_g = NULL;
    int32 cmp1, cmp2;

    for (int32 k = *less; k <= *great; k++) {
        row_k = MTRL_GET_ROW(page, k);
        if (ctx->sort_cmp(segment, row_k, pivot1, &cmp1) != GS_SUCCESS) {
            return GS_ERROR;
        }
        if (cmp1 == 0) {
            mtrl_swap_dir(page, k, *less);
            (*less)++;
            continue;
        }

        if (ctx->sort_cmp(segment, row_k, pivot2, &cmp2) != GS_SUCCESS) {
            return GS_ERROR;
        }
        if (cmp2 != 0) {
            continue;
        }

        row_g = MTRL_GET_ROW(page, *great);
        if (ctx->sort_cmp(segment, row_g, pivot2, &cmp2) != GS_SUCCESS) {
            return GS_ERROR;
        }
        while (cmp2 == 0) {
            if ((*great)-- == k) {
                return GS_SUCCESS;
            }
            row_g = MTRL_GET_ROW(page, *great);
            if (ctx->sort_cmp(segment, row_g, pivot2, &cmp2) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
        if (ctx->sort_cmp(segment, row_g, pivot1, &cmp1) != GS_SUCCESS) {
            return GS_ERROR;
        }

        mtrl_swap_dir(page, k, *great);
        if (cmp1 == 0) {
            mtrl_swap_dir(page, k, *less);
            (*less)++;
        }
        (*great)--;
    }
    return GS_SUCCESS;
}

static status_t mtrl_adaptive_dual_pivots_center(mtrl_context_t *ctx, mtrl_segment_t *segment, mtrl_page_t *page,
    char *pivot1, char *pivot2, int32 *less, int32 *great)
{
    char *row_less = NULL;
    char *row_great = NULL;
    int32 cmp1, cmp2;

    row_less = MTRL_GET_ROW(page, *less);
    if (ctx->sort_cmp(segment, row_less, pivot1, &cmp1) != GS_SUCCESS) {
        return GS_ERROR;
    }
    while (cmp1 == 0) {
        (*less)++;
        row_less = MTRL_GET_ROW(page, *less);
        if (ctx->sort_cmp(segment, row_less, pivot1, &cmp1) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    row_great = MTRL_GET_ROW(page, *great);
    if (ctx->sort_cmp(segment, row_great, pivot2, &cmp2) != GS_SUCCESS) {
        return GS_ERROR;
    }
    while (cmp2 == 0) {
        (*great)--;
        row_great = MTRL_GET_ROW(page, *great);
        if (ctx->sort_cmp(segment, row_great, pivot2, &cmp2) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }
    return mtrl_adaptive_dual_pivots_center_swap(ctx, segment, page, pivot1, pivot2, less, great);
}

//  pivot1                                                         pivot2
//   left part           center part                   right part
//  +------------------------------------------------------------- +
//  | < pivot1 | pivot1 <= && <= pivot2 |  unknown  |  > pivot2    |
//  +------------------------------------------------------------- +
//  ^           ^                        ^         ^               ^
//  left        less                      k        great           right
//  ARRAY[left + 1, less - 1] < pivot1
//  pivot1 <= ARRAY[less, k - 1] <= pivot2
//  ARRAY[k, great] are unknown
//  ARRAY[great + 1, right - 1] > pivot2
static status_t mtrl_adaptive_sort_dual_pivots(mtrl_context_t *ctx, mtrl_segment_t *segment, mtrl_page_t *page,
    qsort_span_t *span, qsort_stack_t *stack, int32 e2, int32 e4)
{
    int32 less = span->left;
    int32 great = span->right;
    int32 seventh = (e4 - e2) / 2;
    int32 cmp1, cmp2;
    char *row_less = NULL;
    char *row_great = NULL;
    char *pivot1 = MTRL_GET_ROW(page, e2);
    char *pivot2 = MTRL_GET_ROW(page, e4);
    mtrl_swap_dir(page, span->left, e2);
    mtrl_swap_dir(page, span->right, e4);

    do {
        row_less = MTRL_GET_ROW(page, ++less);
        if (ctx->sort_cmp(segment, row_less, pivot1, &cmp1) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } while (cmp1 < 0);

    do {
        row_great = MTRL_GET_ROW(page, --great);
        if (ctx->sort_cmp(segment, row_great, pivot2, &cmp2) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } while (cmp2 > 0);

    if (mtrl_adaptive_dual_pivots_swap(ctx, segment, page, pivot1, pivot2, &less, &great) != GS_SUCCESS) {
        return GS_ERROR;
    }

    mtrl_swap_dir(page, span->left, less - 1);
    mtrl_swap_dir(page, span->right, great + 1);
    QSORT_POP(stack);
    // [less - 1] and [great + 1] are pivots, no longer need to participate in sorting.
    if (span->left < less - 2) {
        QSORT_PUSH(stack, span->left, less - 2);
    }
    if (great + 2 < span->right) {
        QSORT_PUSH(stack, great + 2, span->right);
    }

    if (less < e2 - seventh && e4 + seventh < great) {  // If center part is too large (comprises > 4/7 of the array)
        if (mtrl_adaptive_dual_pivots_center(ctx, segment, page, pivot1, pivot2, &less, &great) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }
    if (less < great) {
        QSORT_PUSH(stack, less, great);
    }
    return GS_SUCCESS;
}

//        < pivot               = pivot             unknown        > pivot
//  | _______________|_________________________|_ _ _ _ _ _ _ _|_____________|
//  ^                 ^                         ^             ^              ^
//  left              i                         k             j             right
//  ARRAY[left, i - 1] < pivot
//  ARRAY[i, k - 1] = pivot
//  ARRAY[k, j] are unknown
//  ARRAY[j + 1, right] > pivot
static status_t mtrl_three_ways_qsort_swap(mtrl_context_t *ctx, mtrl_segment_t *segment, mtrl_page_t *page,
    int32 *i, int32 *j)
{
    char *pivot = MTRL_GET_ROW(page, *i);
    char *row_k = NULL;
    char *row_j = NULL;
    int32 cmp_k, cmp_j;

    for (int32 k = (*i) + 1; k <= *j; k++) {
        row_k = MTRL_GET_ROW(page, k);
        if (ctx->sort_cmp(segment, row_k, pivot, &cmp_k) != GS_SUCCESS) {
            return GS_ERROR;
        }
        if (cmp_k == 0) {
            continue;
        }
        if (cmp_k < 0) {
            mtrl_swap_dir(page, *i, k);
            (*i)++;
            continue;
        }

        row_j = MTRL_GET_ROW(page, *j);
        if (ctx->sort_cmp(segment, row_j, pivot, &cmp_j) != GS_SUCCESS) {
            return GS_ERROR;
        }
        while (cmp_j > 0) {
            if (--(*j) < k) {
                return GS_SUCCESS;
            }
            row_j = MTRL_GET_ROW(page, *j);
            if (ctx->sort_cmp(segment, row_j, pivot, &cmp_j) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
        if (cmp_j < 0) {
            mtrl_swap_dir(page, *i, *j);
            (*i)++;
        }
        mtrl_swap_dir(page, k, *j);
        (*j)--;
    }
    return GS_SUCCESS;
}

static status_t mtrl_adaptive_sort_three_ways(mtrl_context_t *ctx, mtrl_segment_t *segment, mtrl_page_t *page,
    qsort_span_t *span, qsort_stack_t *stack)
{
    int32 i = span->left;
    int32 j = span->right;
    if (mtrl_three_ways_qsort_swap(ctx, segment, page, &i, &j) != GS_SUCCESS) {
        return GS_ERROR;
    }
    QSORT_POP(stack);
    if (span->left < i - 1) {
        QSORT_PUSH(stack, span->left, i - 1);
    }

    if (j + 1 < span->right) {
        QSORT_PUSH(stack, j + 1, span->right);
    }
    return GS_SUCCESS;
}

#define MOVE_FIVE_POINTS(page, left, e1, e2, e3, e4, e5) \
    do {                                                 \
        mtrl_swap_dir((page), (left), e1);               \
        mtrl_swap_dir((page), (left) + 1, e2);           \
        mtrl_swap_dir((page), (left) + 2, e3);           \
        mtrl_swap_dir((page), (left) + 3, e4);           \
        mtrl_swap_dir((page), (left) + 4, e5);           \
    } while (0)

static status_t mtrl_adaptive_sort_span(mtrl_context_t *ctx, mtrl_segment_t *segment, mtrl_page_t *page,
    qsort_span_t *span, qsort_stack_t *stack)
{
    int32 left = span->left;
    int32 right = span->right;
    int32 len = right - left + 1;
    if (len < MTRL_ADAPTIVE_SORT_THRESHOLD) {  // if len >= 4 * 7, e1 - left >= 5
        QSORT_POP(stack);
        return mtrl_binary_insert_sort(ctx, segment, page, left, right);
    }
    int32 seventh = (len / 8) + (len / 64) + 1;  // leng / 8 + len / 64 + 1 �� len / 7
    int32 e3 = (left + right) / 2;
    int32 e2 = e3 - seventh;
    int32 e1 = e2 - seventh;
    int32 e4 = e3 + seventh;
    int32 e5 = e4 + seventh;
    bool8 equal = GS_FALSE;
    // Use [left, left + 4] to temporarily store the values of five sampling points and restore them after sorting.
    MOVE_FIVE_POINTS(page, left, e1, e2, e3, e4, e5);
    if (mtrl_binary_insert_sort(ctx, segment, page, left, left + 4) != GS_SUCCESS) {
        return GS_ERROR;
    }
    MOVE_FIVE_POINTS(page, left, e1, e2, e3, e4, e5);

    if (mtrl_five_points_check_equal(ctx, segment, page, e1, e2, e3, e4, e5, &equal) != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (!equal) {
        return mtrl_adaptive_sort_dual_pivots(ctx, segment, page, span, stack, e2, e4);
    }
    mtrl_swap_dir(page, left, e3);
    return mtrl_adaptive_sort_three_ways(ctx, segment, page, span, stack);
}

// It combines Binary-Insertion SORT, Dual-Pivot QSORT and Three-Way QSORT.
status_t mtrl_adaptive_sort_page(mtrl_context_t *ctx, mtrl_segment_t *segment, mtrl_page_t *page)
{
    qsort_stack_t stack;
    qsort_span_t span;
    if (page->rows <= 1) {
        return GS_SUCCESS;
    }

    stack.depth = 0;
    QSORT_PUSH(&stack, 0, page->rows - 1);
    while (stack.depth > 0) {
        span = QSORT_CURR(&stack);
        if (mtrl_adaptive_sort_span(ctx, segment, page, &span, &stack) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

static status_t mtrl_binsearch(mtrl_context_t *ctx, mtrl_segment_t *segment, mtrl_page_t *page, char *row,
                               uint32 *slot)
{
    int32 result;
    int32 begin, end, curr;
    char *cmp_row = NULL;

    if (page->rows == 0) {
        *slot = 0;
        return GS_SUCCESS;
    }

    result = 0;
    // if >= the last row, put at the end directly
    cmp_row = MTRL_GET_ROW(page, page->rows - 1);
    if (ctx->sort_cmp(segment, row, cmp_row, &result) != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (result >= 0) {
        *slot = page->rows;
        return GS_SUCCESS;
    }

    // search the correct position
    curr = 0;
    begin = 0;
    end = page->rows - 1;

    while (begin < end) {
        curr = (end + begin) / 2;
        cmp_row = MTRL_GET_ROW(page, curr);
        if (ctx->sort_cmp(segment, row, cmp_row, &result) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (result == 0) {
            *slot = curr + 1;
            return GS_SUCCESS;
        }

        if (result < 0) {
            end = curr;
        } else {
            begin = curr + 1;
        }
    }

    if (result >= 0) {
        *slot = curr + 1;
    } else {
        *slot = curr;
    }

    return GS_SUCCESS;
}

static inline void mtrl_shift_slots(mtrl_page_t *page, uint32 pos)
{
    char *dst = NULL;
    char *src = NULL;
    errno_t ret;

    if (pos >= page->rows) {
        return;
    }

    dst = (char *)MTRL_GET_DIR(page, page->rows);
    src = dst + sizeof(uint32);
    ret = memmove_s(dst, (page->rows + 1) * sizeof(uint32), src, (page->rows - (uint16)pos) * sizeof(uint32));
    knl_securec_check(ret);
}

status_t mtrl_insert_sorted_page(mtrl_context_t *ctx, mtrl_segment_t *segment, mtrl_page_t *page,
                                 char *row, uint16 row_size, uint32 *slot)
{
    uint32 pos;
    char *ptr = NULL;
    uint32 *dir = NULL;
    errno_t ret;

    if (mtrl_binsearch(ctx, segment, page, row, &pos) != GS_SUCCESS) {
        return GS_ERROR;
    }

    mtrl_shift_slots(page, pos);
    ptr = (char *)page + page->free_begin;
    dir = MTRL_GET_DIR(page, pos);
    *dir = page->free_begin;
    // sizeof(uint32) means insert row's dir size
    ret = memcpy_sp(ptr, MTRL_PAGE_FREE_SIZE(page) - sizeof(uint32), row, row_size);
    knl_securec_check(ret);

    if (slot != NULL) {
        *slot = pos;
    }

    page->rows++;
    page->free_begin += row_size;
    return GS_SUCCESS;
}

#ifdef __cplusplus
}
#endif

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
 * var_aggr.h
 *
 *
 * IDENTIFICATION
 * src/common/variant/var_aggr.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __VAR_AGGR_H__
#define __VAR_AGGR_H__

#include "var_defs.h"

typedef struct st_mtrl_types_varea {
    uint32 sid;  // for mtrl data
    char  *buf;  // for mtrl datatype of columns
} mtrl_resource_t;

typedef struct st_aggr_stddev {
    variant_t extra; /* extra variant_t for storing some special data which is not used by one group of data */
    uint64 ex_count;
} aggr_stddev_t;

typedef struct st_aggr_covar {
    variant_t extra; /* extra and extra_1 variant_t for storing some special
                     data which is not used by one group of data */
    variant_t extra_1;
    uint64 ex_count;
} aggr_covar_t;

#define CORR_VAR_SUM_X 0
#define CORR_VAR_SUM_Y 1
#define CORR_VAR_SUM_XX 2
#define CORR_VAR_SUM_YY 3

#define APPX_BITS     (uint32)13
#define APPX_MAP_SIZE (uint32)8192
#define APPX_ALPHA_MM (double)(0.7213 / (1 + 1.079 / APPX_MAP_SIZE) * APPX_MAP_SIZE * APPX_MAP_SIZE)
#define APPX_MIN_VAL  (double)(2.5 * APPX_MAP_SIZE)
#define APPX_MAX_VAL  (double)143165576.533333333

typedef struct st_aggr_corr {
    variant_t extra[4]; /* extra variant_t for storing some special data which is not used by one group of data */
    uint64 ex_count;
} aggr_corr_t;

typedef struct st_aggr_str {
    /* size of aggr buffer for the non-numeric intermediate result of max(str)/min(str)/group_concat() */
    uint32 aggr_bufsize;
    mtrl_rowid_t str_result;
} aggr_str_t;

typedef struct st_aggr_group_concat {
    aggr_str_t aggr_str;  // must be the first element,the reason is that aggr_str is accessed by aggr_var.aggr_str
    variant_t extra;
    mtrl_rowid_t sort_rid; /* rowid of sort segment in vm */
    uint32 total_len;
    char *type_buf;
} aggr_group_concat_t;

typedef struct st_aggr_fir_val {
    bool32 ex_has_val;
} aggr_fir_val_t;

typedef struct st_aggr_avg {
    uint64 ex_avg_count;
} aggr_avg_t;

typedef struct st_aggr_mae {
    uint64 ex_mae_count;
} aggr_mae_t;

typedef struct st_aggr_rmse {
    uint64 ex_rmse_count;
} aggr_rmse_t;

typedef struct st_aggr_median {
    uint64 median_count;
    mtrl_rowid_t sort_rid; /* rowid of sort segment in vm */
    char *type_buf;
} aggr_median_t;

typedef struct st_aggr_appx_cntdis {
    uint8 *bitmap;
} aggr_appx_cntdis_t;

typedef struct st_aggr_var {
    variant_t var;            /* variant_to to store intermediate result while aggregating one group of data */
    uint32 extra_offset : 18; /* max value is 256K,vm page size */
    uint32 extra_size : 9;    /* max value is 512,great than sizeof(aggr_group_concat_t) */
    uint32 aggr_type : 5;     /* max value is 32,great than AGGR_TYPE_MAX */
} aggr_var_t;

#define GET_AGGR_VAR_COVAR(aggr_var)                                              \
    (                                                                              \
        (aggr_covar_t *)(((aggr_var)->extra_offset == 0 ||  \
                              (aggr_var)->extra_offset >= GS_VMEM_PAGE_SIZE ||  \
                              (aggr_var)->extra_size != sizeof(aggr_covar_t) ||  \
                              ((aggr_var)->aggr_type != AGGR_TYPE_COVAR_POP&& \
                                  (aggr_var)->aggr_type != AGGR_TYPE_COVAR_SAMP)) \
							  ? NULL                                               \
                              : ((char *)(aggr_var) + (aggr_var)->extra_offset)))

#define GET_AGGR_VAR_CORR(aggr_var)                                              \
    (                                                                              \
        (aggr_corr_t *)(((aggr_var)->extra_offset == 0 ||  \
                              (aggr_var)->extra_offset >= GS_VMEM_PAGE_SIZE ||  \
                              (aggr_var)->extra_size != sizeof(aggr_corr_t) ||  \
                              (aggr_var)->aggr_type != AGGR_TYPE_CORR)       \
                              ? NULL                                               \
                              : ((char *)(aggr_var) + (aggr_var)->extra_offset)))

#define GET_AGGR_VAR_STDDEV(aggr_var)                                              \
    (                                                                              \
        (aggr_stddev_t *)(((aggr_var)->extra_offset == 0 ||  \
                              (aggr_var)->extra_offset >= GS_VMEM_PAGE_SIZE ||  \
                              (aggr_var)->extra_size != sizeof(aggr_stddev_t) ||  \
                              ((aggr_var)->aggr_type != AGGR_TYPE_STDDEV &&        \
                                  (aggr_var)->aggr_type != AGGR_TYPE_STDDEV_POP && \
                                  (aggr_var)->aggr_type != AGGR_TYPE_STDDEV_SAMP && \
                                  (aggr_var)->aggr_type != AGGR_TYPE_VARIANCE &&        \
                                  (aggr_var)->aggr_type != AGGR_TYPE_VAR_POP && \
                                  (aggr_var)->aggr_type != AGGR_TYPE_VAR_SAMP)) \
                              ? NULL                                               \
                              : ((char *)(aggr_var) + (aggr_var)->extra_offset)))

#define GET_AGGR_VAR_GROUPCONCAT(aggr_var)                                                   \
    (                                                                                        \
        (aggr_group_concat_t *)(((aggr_var)->extra_offset == 0 ||  \
                                    (aggr_var)->extra_offset >= GS_VMEM_PAGE_SIZE ||  \
                                    (aggr_var)->extra_size != sizeof(aggr_group_concat_t) ||  \
                                    (aggr_var)->aggr_type != AGGR_TYPE_GROUP_CONCAT)         \
                                    ? NULL                                                   \
                                    : ((char *)(aggr_var) + (aggr_var)->extra_offset)))

#define GET_AGGR_VAR_STR(aggr_var)                                          \
    (                                                                       \
        (aggr_str_t *)(((aggr_var)->extra_offset == 0 ||  \
                           (aggr_var)->extra_offset >= GS_VMEM_PAGE_SIZE ||  \
                           (aggr_var)->extra_size != sizeof(aggr_str_t) ||  \
                           ((aggr_var)->aggr_type != AGGR_TYPE_MIN &&       \
                               (aggr_var)->aggr_type != AGGR_TYPE_MAX))     \
                           ? NULL                                           \
                           : ((char *)(aggr_var) + (aggr_var)->extra_offset)))

#define GET_AGGR_VAR_STR_EX(aggr_var) ((aggr_var)->aggr_type == AGGR_TYPE_GROUP_CONCAT ?  \
    &(GET_AGGR_VAR_GROUPCONCAT(aggr_var)->aggr_str) : GET_AGGR_VAR_STR(aggr_var))

#define GET_AGGR_VAR_AVG(aggr_var)                                              \
    (                                                                           \
        (aggr_avg_t *)(((aggr_var)->extra_offset == 0 ||  \
                           (aggr_var)->extra_offset >= GS_VMEM_PAGE_SIZE ||  \
                           (aggr_var)->extra_size != sizeof(aggr_avg_t) ||  \
                           ((aggr_var)->aggr_type != AGGR_TYPE_AVG &&           \
                               (aggr_var)->aggr_type != AGGR_TYPE_AVG_COLLECT && \
                               (aggr_var)->aggr_type != AGGR_TYPE_CUME_DIST)) \
                           ? NULL                                               \
                           : ((char *)(aggr_var) + (aggr_var)->extra_offset)))

#define GET_AGGR_VAR_MEDIAN(aggr_var)                                                \
    (                                                                              \
        (aggr_median_t *)(((aggr_var)->extra_offset == 0 ||  \
                            (aggr_var)->extra_offset >= GS_VMEM_PAGE_SIZE ||    \
                            (aggr_var)->extra_size != sizeof(aggr_median_t) ||  \
                            ((aggr_var)->aggr_type != AGGR_TYPE_MEDIAN))        \
                            ? NULL                                              \
                            : ((char *)(aggr_var) + (aggr_var)->extra_offset)))

#define GET_AGGR_VAR_DENSE_RANK(aggr_var) \
    ( \
        (aggr_dense_rank_t *)(((aggr_var)->extra_offset == 0 ||  \
                            (aggr_var)->extra_offset >= GS_VMEM_PAGE_SIZE ||    \
                            (aggr_var)->extra_size != sizeof(aggr_dense_rank_t) ||  \
                            ((aggr_var)->aggr_type != AGGR_TYPE_DENSE_RANK))        \
                            ? NULL                                              \
                            : ((char *)(aggr_var) + (aggr_var)->extra_offset)))

#define GET_AGGR_VAR_FIR_VAL(aggr_var)                                              \
    ((aggr_fir_val_t *)(((aggr_var)->extra_offset == 0 ||                           \
                         (aggr_var)->extra_offset >= GS_VMEM_PAGE_SIZE ||           \
                         (aggr_var)->extra_size != sizeof(aggr_fir_val_t) ||        \
                         (aggr_var)->aggr_type != AGGR_TYPE_FIRST_VALUE)            \
                        ? NULL                                                      \
                        : ((char *)(aggr_var) + (aggr_var)->extra_offset)))

#define GET_AGGR_VAR_APPX_CDIST(aggr_var)                                           \
    ((aggr_appx_cntdis_t *)(((aggr_var)->extra_offset == 0 ||                       \
                         (aggr_var)->extra_offset >= GS_VMEM_PAGE_SIZE ||           \
                         (aggr_var)->extra_size != sizeof(aggr_appx_cntdis_t) ||    \
                         (aggr_var)->aggr_type != AGGR_TYPE_APPX_CNTDIS)            \
                        ? NULL                                                      \
                        : ((char *)(aggr_var) + (aggr_var)->extra_offset)))
#endif

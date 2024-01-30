// Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
#ifndef __CTSQL_INPUT_BIND_PARAM_H__
#define __CTSQL_INPUT_BIND_PARAM_H__

#include "cm_defs.h"
#include "cm_text.h"
#include "cm_date.h"

#ifdef __cplusplus
extern "C" {
#endif

uint32 ctsql_get_param_count(const char *sql);
status_t ctsql_bind_params(ctconn_stmt_t stmt, uint32 param_count /* , uint32 *batch_count */);
status_t ctsql_bind_param_init(uint32 param_count);
void ctsql_bind_param_uninit(uint32 param_count);

/** @} */  // end group CTSQL_CMD

#ifdef __cplusplus
}
#endif

#endif  // end __CTSQL_INPUT_BIND_PARAM_H__
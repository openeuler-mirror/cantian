// Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
#ifndef __CTSQL_LOAD_H__
#define __CTSQL_LOAD_H__

#include "ctsql.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
* @addtogroup CTSQL_CMD
* @brief The API of `ctsql` command interface
* @{ */
void ctsql_show_loader_opts(void);
status_t ctsql_load(text_t *cmd_text);

/** @} */  // end group CTSQL_CMD

#ifdef __cplusplus
}
#endif

#endif  // end __CTSQL_LOAD_H__
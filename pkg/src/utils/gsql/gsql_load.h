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
 * gsql_load.h
 *
 *
 * IDENTIFICATION
 * src/utils/gsql/gsql_load.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __GSQL_LOAD_H__
#define __GSQL_LOAD_H__

#include "gsql.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
* @addtogroup GSQL_CMD
* @brief The API of `gsql` command interface
* @{ */
void gsql_show_loader_opts(void);
status_t gsql_load(text_t *cmd_text);

/** @} */  // end group GSQL_CMD

#ifdef __cplusplus
}
#endif

#endif  // end __GSQL_LOAD_H__
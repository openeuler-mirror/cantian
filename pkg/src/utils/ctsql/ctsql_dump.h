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
 * ctsql_dump.h
 *
 *
 * IDENTIFICATION
 * src/utils/ctsql/ctsql_dump.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CTSQL_DUMP_H__
#define __CTSQL_DUMP_H__

#include "ctsql.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Dump data to file.
 * + The syntax for dumping a table of data is
 *    dump table to D:\dd.csv
 * + The syntax for dumping a query is
 *    dump "select * from table where id > 0" to D:\dd.csv

 */
status_t ctsql_dump(text_t *cmd_text);

/** @} */  // end group CTSQL_CMD

#ifdef __cplusplus
}
#endif

#endif  // end __CTSQL_DUMP_H__
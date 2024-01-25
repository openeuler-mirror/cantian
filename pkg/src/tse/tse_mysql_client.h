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
 * tse_mysql_client.h
 *
 *
 * IDENTIFICATION
 * src/tse/tse_mysql_client.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __TSE_MYSQL_CLIENT_H__
#define __TSE_MYSQL_CLIENT_H__
#include <stdint.h>
#include <stdbool.h>
#include "tse_srv.h"
int mysql_execute_ddl_sql(uint32_t thd_id, tse_ddl_broadcast_request *broadcast_req, bool *allow_fail);
#endif
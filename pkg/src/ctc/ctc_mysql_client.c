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
 * ctc_mysql_client.c
 *
 *
 * IDENTIFICATION
 * src/ctc/ctc_mysql_client.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctc_module.h"
#include "ctc_srv.h"
#include "cm_log.h"
#include "knl_common.h"

int mysql_execute_ddl_sql(uint32_t thd_id, ctc_ddl_broadcast_request *broadcast_req,
                          bool *allow_fail)
{
    size_t len = strlen(broadcast_req->sql_str);
    if (len == 0) {
        CT_LOG_RUN_ERR("[CTC_DDL]:sql_str length is invalid");
    }
    int ret = ctc_ddl_execute_update_intf(thd_id, broadcast_req, allow_fail);
    return ret;
}

int mysql_execute_set_opt(uint32_t thd_id, ctc_set_opt_request *broadcast_req, bool allow_fail)
{
    int ret = ctc_ddl_execute_set_opt_intf(thd_id, broadcast_req, allow_fail);
    return ret;
}

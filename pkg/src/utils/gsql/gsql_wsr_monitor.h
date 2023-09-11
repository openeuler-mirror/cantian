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
 * gsql_wsr_monitor.h
 *
 *
 * IDENTIFICATION
 * src/utils/gsql/gsql_wsr_monitor.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __GSQL_WSR_MONITOR_H__
#define __GSQL_WSR_MONITOR_H__

#ifdef __cplusplus
extern "C" {
#endif

status_t gsql_monitor(text_t *cmd_text);

#ifdef __cplusplus
}
#endif

#endif
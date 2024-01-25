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
 * ctbackup_factory.h
 *
 *
 * IDENTIFICATION
 * src/utils/ctbackup/ctbackup_factory.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CANTIANDB_100_CTBACKUP_FACTORY_H
#define CANTIANDB_100_CTBACKUP_FACTORY_H

#include "ctbackup_info.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef ctbak_cmd_t* (* ctbak_cmd_generate_interface)(void);

ctbak_cmd_t* ctbak_factory_generate_cmd(ctbak_topic_t ctbak_topic);

#ifdef __cplusplus
}
#endif

#endif // CANTIANDB_100_CTBACKUP_FACTORY_H

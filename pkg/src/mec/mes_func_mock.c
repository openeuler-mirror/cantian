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
 * mes_func_mock.c
 *
 *
 * IDENTIFICATION
 * src/mec/mes_func_mock.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_defs.h"
#include "cm_thread.h"
#include "cm_timer.h"
#include "cs_pipe.h"
#include "cs_listener.h"
#include "mes_func_mock.h"
#include "mes_func.h"

void mes_set_msg_enqueue2(mes_command_t command, bool32 is_enqueue, mes_profile_t *profile)
{
    cm_assert(0);
    return;
}

bool32 mes_connection_ready2(uint32 inst_id, mes_mod_t module)
{
    cm_assert(0);
    return GS_TRUE;
}

void mes_destory_inst(mes_mod_t module)
{
    cm_assert(0);
}

void mes_lock_channel(mes_mod_t module)
{
    cm_assert(0);
}

void mes_unlock_channel(mes_mod_t module)
{
    cm_assert(0);
}

void mes_reset_channels(mes_mod_t module)
{
    cm_assert(0);
}

status_t mes_create_inst(mes_profile_t *profile)
{
    cm_assert(0);
    return GS_SUCCESS;
}

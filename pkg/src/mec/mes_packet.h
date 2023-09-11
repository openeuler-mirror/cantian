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
 * mes_packet.h
 *
 *
 * IDENTIFICATION
 * src/mec/mes_packet.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef MES_PACKET_H__
#define MES_PACKET_H__

#include "cm_defs.h"
#include "cs_packet.h"
#include "mes_func.h"
#ifdef __cplusplus
extern "C" {
#endif

static inline void mes_init_get(mes_message_ex_t *pack)
{
    cm_assert(0);
}

static inline void mes_init_set(mes_message_ex_t *pack, char *buf, uint32 buf_size)
{
    cm_assert(0);
}

/*
   reserve a space with size "size" in the pack
   and use CS_RESERVE_SPACE_ADDR to get the address of reserve space.
*/
static inline status_t mes_reserve_space(mes_message_ex_t *pack, uint32 size, void **buff)
{
    cm_assert(0);
    return GS_SUCCESS;
}

static inline status_t mes_put_str(mes_message_ex_t *pack, const char *str)
{
    cm_assert(0);
    return GS_SUCCESS;
}

static inline status_t mes_put_text2str(mes_message_ex_t *pack, text_t *text)
{
    cm_assert(0);
    return GS_SUCCESS;
}

static inline status_t mes_put_data(mes_message_ex_t *pack, const void *data, uint32 size)
{
    cm_assert(0);
    return GS_SUCCESS;
}

static inline status_t mes_put_int64(mes_message_ex_t *pack, uint64 value)
{
    cm_assert(0);
    return GS_SUCCESS;
}

static inline status_t mes_put_int32(mes_message_ex_t *pack, uint32 value)
{
    cm_assert(0);
    return GS_SUCCESS;
}

static inline status_t mes_put_int16(mes_message_ex_t *pack, uint16 value)
{
    cm_assert(0);
    return GS_SUCCESS;
}

static inline status_t mes_put_double(mes_message_ex_t *pack, double value)
{
    cm_assert(0);
    return GS_SUCCESS;
}

static inline status_t mes_put_date(mes_message_ex_t *pack, date_t value)
{
    cm_assert(0);
    return GS_SUCCESS;
}

static inline status_t mes_put_text(mes_message_ex_t *pack, text_t *text)
{
    cm_assert(0);
    return GS_SUCCESS;
}

static inline status_t mes_put_scn(mes_message_ex_t *pack, uint64 *scn)
{
    cm_assert(0);
    return mes_put_int64(pack, *scn);
}

static inline status_t mes_inc_head_size(mes_message_ex_t *pack, uint32 size)
{
    cm_assert(0);
    return GS_SUCCESS;
}

static inline status_t mes_get_data(mes_message_ex_t *pack, uint32 size, void **buf)
{
    cm_assert(0);
    return GS_SUCCESS;
}

static inline status_t mes_get_str(mes_message_ex_t *pack, char **buf)
{
    cm_assert(0);
    return GS_SUCCESS;
}

static inline status_t mes_get_int64(mes_message_ex_t *pack, int64 *value)
{
    cm_assert(0);
    return GS_SUCCESS;
}

static inline status_t mes_get_int32(mes_message_ex_t *pack, int32 *value)
{
    cm_assert(0);
    return GS_SUCCESS;
}

/* need keep 4-byte align by the caller */
static inline status_t mes_get_int16(mes_message_ex_t *pack, int16 *value)
{
    cm_assert(0);
    return GS_SUCCESS;
}

static inline status_t mes_get_double(mes_message_ex_t *pack, double *value)
{
    cm_assert(0);
    return GS_SUCCESS;
}

static inline status_t mes_get_text(mes_message_ex_t *pack, text_t *text)
{
    cm_assert(0);
    return mes_get_data(pack, text->len, (void **)&(text->str));
}

static inline status_t mes_get_scn(mes_message_ex_t *pack, uint64 *scn)
{
    cm_assert(0);
    return mes_get_int64(pack, (int64 *)scn);
}

#ifdef __cplusplus
}
#endif

#endif

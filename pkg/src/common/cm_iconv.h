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
 * cm_iconv.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_iconv.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_ICONV_H__
#define __CM_ICONV_H__

#include "cm_defs.h"
#ifdef WIN32
#include <windows.h>
#include <ctype.h>
#else
#include <iconv.h>
#include <wctype.h>
#include <wchar.h>
#include <errno.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define ICONV_END   0
#define ICONV_ERR   (-1)

int32 gbk2ucs2(char *gbk, uint32 gbk_len, uint16 *ucs2);
int32 cm_gbk_to_utf8(const void *src, uint32 *src_len, void *dst, uint32 dst_len, bool32 *eof);
int32 cm_utf8_to_gbk(const void *src, uint32 *src_len, void *dst, uint32 dst_len, bool32 *eof);

int32 cm_utf8_to_utf16(const void *src, uint32 *src_len, void *dst, uint32 dst_length, bool32 *eof);
int32 cm_utf16_to_utf8(const void *src, uint32 *src_len, void *dst, uint32 dst_length, bool32 *eof);

int32 cm_gbk_to_utf16(const void *src, uint32 *src_len, void *dst, uint32 dst_length, bool32 *eof);
int32 cm_utf16_to_gbk(const void *src, uint32 *src_len, void *dst, uint32 dst_length, bool32 *eof);

#ifdef WIN32
status_t cm_multibyte_to_widechar(uint32 cp_id, const char* src_c, size_t src_c_size, wchar_t* dest_w,
                                  size_t dest_w_size, size_t* num_of_wchar);
status_t cm_widechar_to_multibyte(uint32 cp_id, const wchar_t* src_w, size_t src_w_size, char* dest_c,
                                  size_t dest_c_size, size_t* num_of_char);
#else
status_t cm_multibyte_to_widechar(iconv_t agent_env, const char* src_c,
                                  size_t src_c_size, wchar_t* dest_w, size_t dest_w_size, size_t* num_of_wchar);
status_t cm_widechar_to_multibyte(iconv_t agent_env, const wchar_t* src_w,
                                  size_t src_w_size, char* dest_c, size_t dest_c_size, size_t* num_of_char);
#endif

#ifdef __cplusplus
}

#endif

#endif

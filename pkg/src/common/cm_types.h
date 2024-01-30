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
 * cm_types.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_types.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_TYPES_H__
#define __CM_TYPES_H__

#ifndef CT_TYPES_DEFINED
#define CT_TYPES_DEFINED 1

typedef unsigned char uchar;
typedef unsigned long ulong;
typedef unsigned int bool32;

#ifndef HAVE_INT8
#define HAVE_INT8
typedef char int8;
typedef short int16;
typedef int int32;
#endif

#ifndef HAVE_UINT8
#define HAVE_UINT8
typedef unsigned char uint8;
typedef unsigned char bool8;
typedef unsigned int uint32;
typedef unsigned short uint16;
#endif

#ifdef WIN32
typedef __int64 int64;
typedef unsigned __int64 uint64;
#ifdef _WIN64
typedef unsigned __int64 socket_t;
#else
typedef unsigned int socket_t;
typedef int pid_t;
#endif

#else
#ifndef HAVE_INT64
#define HAVE_INT64
typedef long long int64;
#endif
#ifndef HAVE_UINT64
#define HAVE_UINT64
typedef unsigned long long uint64;
#endif
typedef int socket_t;
#endif

typedef void *pointer_t;
typedef void *handle_t;

#define UINT64_BITS 64
#define UINT32_BITS 32
#define UINT16_BITS 16
#define UINT8_BITS 8

#endif /* CT_TYPES_DEFINED */

#endif /* __CM_TYPES_H__ */


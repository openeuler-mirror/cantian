 /*
 * Copyright Notice:
 * Copyright(C), 2014 - 2014, Huawei Tech. Co., Ltd. ALL RIGHTS RESERVED. \n
 */

 /**
* @file    dpax_typedef.h
* @brief   基本数据类型定义头文件
* @verbatim
  功能描述: 基本数据类型定义头文件
  目标用户: 用户
  使用约束: NA
  升级影响: no
@endverbatim
*/

#ifndef __DPAX_TYPEDEF_H__
#define __DPAX_TYPEDEF_H__

/**
 *@defgroup  osax_datatype 基本数据类型
 *@ingroup osax
*/
#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#include <stddef.h>
#endif
#ifdef WIN32//winsim
#include "lvos_type.h"
#ifndef __WORDSIZE
#define __WORDSIZE (64)
#endif
#endif

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

/**
 * 函数返回值
 */
#ifndef RET_OK
#define RET_OK                  (0)
#endif
#ifndef RET_ERR
#define RET_ERR                 (-1)
#endif

#ifndef NULL
#define NULL ((void *)0)
#endif

#ifndef inline
#define inline __inline
#endif

#ifndef __inline__
#define __inline__ inline
#endif

/**
 * 基本数据类型,
 * 以下s8,u8,s16,u16,s32,u32,s64,u64,内核态中asm-generic/int-ll64.h已经定义。
 */
//#if !defined(__KERNEL__) && !defined(__KAPI__)
#ifndef __KERNEL__
#if !defined(_BASIC_TYPEDEF_)
#define _BASIC_TYPEDEF_
typedef char                   s8;
typedef unsigned char          u8;

typedef short                  s16;
typedef unsigned short         u16;

typedef int                    s32;
typedef unsigned int           u32;

typedef int64_t               s64;
typedef uint64_t              u64;
#endif /* _BASIC_TYPEDEF_ */
#endif

/**
 * CPU字长
 */
typedef long int               slong;
/**
*   内核态下linux/types.h已经定义了ulong
*/
#ifndef __KERNEL__
typedef unsigned long int      ulong;
#endif

/**
*   cpu字长的bit数,内核态下bitsperlong.h中已经定义，
*   只需定义用户态
*/
#ifndef __KERNEL__
#ifndef BITS_PER_LONG
#define BITS_PER_LONG  __WORDSIZE
#endif
#endif

/**
 * 在检测到极端异常且无法恢复时, 立即触发进程崩溃, 产生coredump
 */
#ifndef __KERNEL__
#include   <signal.h>

#ifndef BUG
#define BUG()  \
    do { \
        raise(SIGILL); \
        exit(-1);      \
    } while (0)
#endif

#ifndef BUG_ON
#define BUG_ON(condition) \
    do { \
        if (unlikely(condition)) BUG(); \
    } while (0)
#endif
#endif

/**
*  bool定义，只需定义用户态，
*  内核态在linux/types.h中已经定义。
*/
#ifndef __KERNEL__
#ifndef __cplusplus
#ifndef _BOOL_TYPEDEF_
#define _BOOL_TYPEDEF_
#ifndef bool
#if defined(_PCLINT_) || defined(WIN32)
typedef int  bool;
#else
typedef char bool;
#endif
#endif
#define true 1
#define false 0
#endif
#endif
#endif

/**
 * OSP开始的是兼容性定义，后续不要使用
 */
#ifndef _OSP_TYPES_
#define _OSP_TYPES_

/**
 * OSP_VOID类型定义
 */
typedef void            OSP_VOID;
/**
 * OSP_BOOL类型定义
 */
typedef  int            OSP_BOOL;
/**
 * OSP_ULONG类型定义
 * Linux, 在32位下是32位，在64位下是64位
 * Windows 32和64位环境都是32位
 */
typedef unsigned long   OSP_ULONG;
/**
 * OSP_LONG类型定义
 * Linux, 在32位下是32位，在64位下是64位
 * Windows 32和64位环境都是32位
 */
typedef long            OSP_LONG;
/**
 * OSP_CHAR类型定义
 */
typedef char            OSP_CHAR;


typedef int8_t   OSP_S8;
typedef int16_t  OSP_S16;
typedef int32_t  OSP_S32;
typedef int64_t  OSP_S64;

typedef uint8_t   OSP_U8;
typedef uint16_t  OSP_U16;
typedef uint32_t  OSP_U32;
typedef uint64_t  OSP_U64;

#endif

#ifndef OPS_TYPE
#define OPS_TYPE
typedef size_t    OSP_SIZE_T;

typedef ptrdiff_t OSP_PTR_DIFF;

/**
 * 节点号类型，即: 板号
 */
typedef uint16_t nid_t;
/**
 * 模块 PID对于的类型
 */
typedef uint16_t moduleid_t;

#ifndef WIN32
typedef int SOCKET;
#endif
#endif

#ifndef WIN32
#ifndef INVALID_SOCKET
#define INVALID_SOCKET  (-1)
#endif
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef B_TRUE
#define B_TRUE 1
#endif

#ifndef B_FALSE
#define B_FALSE 0
#endif

#ifndef INVALID_VALUE64
#define INVALID_VALUE64     0xFFFFFFFFFFFFFFFFULL
#endif

#ifndef INVALID_VALUE_ULONG
#define INVALID_VALUE_ULONG ((OSP_ULONG)(-1))
#endif

#ifndef INVALID_VALUE32
#define INVALID_VALUE32     0xFFFFFFFF
#endif

#ifndef INVALID_VALUE16
#define INVALID_VALUE16     0xFFFF
#endif

#ifndef INVALID_VALUE8
#define INVALID_VALUE8      0xFF
#endif

#define __user

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* __DPAX_TYPEDEF_H__ */

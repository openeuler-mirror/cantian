/******************************************************************************

                  版权所有 (C) 2008-2008 华为赛门铁克科技有限公司

 ******************************************************************************
  文 件 名   : lvos_macro.h
  版 本 号   : 初稿
  作    者   : x00001559
  生成日期   : 2008年7月8日
  最近修改   :
  功能描述   : 一些通用的宏定义
  函数列表   :
  修改历史   :
  1.日    期   : 2008年7月8日
    作    者   : x00001559
    修改内容   : 创建文件

******************************************************************************/
/**
    \file  lvos_macro.h
    \brief 一些通用的宏定义

    \date 2008-08-19
*/

/** \addtogroup VOS_MACRO 公共宏定义
    @{ 
*/

#ifndef __LVOS_MACRO_H__
#define __LVOS_MACRO_H__

#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
#endif

#if defined(LINUX_VERSION_CODE) && LINUX_VERSION_CODE > KERNEL_VERSION(2,6,26)
#define __LINUX_VERSION_SUSE11__ 1
#define __LINUX_VERSION_SUSE10__ 1
#elif defined(LINUX_VERSION_CODE) && LINUX_VERSION_CODE > KERNEL_VERSION(2,6,5)
#define __LINUX_VERSION_SUSE10__ 1
#endif

#ifndef _WARN_FIXME
#define FIXME(desc)
#else
#ifdef WIN32
void __declspec(deprecated("must be fixed.")) FIXME(char *);
#else
void __attribute__((deprecated)) FIXME(char *);
#endif /* WIN32 */
#endif /* _WARN_FIXME */

#ifndef unlikely
#define unlikely(x) (x)
#endif

#ifndef likely
#define likely(x) (x)
#endif

#define LVOS_LITTLE_ENDIAN 0x1234
#define LVOS_BIG_ENDIAN    0x4321

#ifdef WIN32
    #if LITTLEENDIAN
        #define LVOS_BYTE_ORDER LVOS_LITTLE_ENDIAN
    #else
        #define LVOS_BYTE_ORDER LVOS_BIG_ENDIAN
    #endif
#elif defined(__KERNEL__)
    #if defined(__LITTLE_ENDIAN) && __LITTLE_ENDIAN
        #define LVOS_BYTE_ORDER LVOS_LITTLE_ENDIAN
    #else
        #define LVOS_BYTE_ORDER LVOS_BIG_ENDIAN
    #endif
#else
    #if __BYTE_ORDER == __LITTLE_ENDIAN
        #define LVOS_BYTE_ORDER LVOS_LITTLE_ENDIAN
    #else
        #define LVOS_BYTE_ORDER LVOS_BIG_ENDIAN
    #endif
#endif

/** \brief 计算结构体成员大小 */
#define ST_MEMBER_SIZE(st, member) (sizeof(((st *)(0))->member))

/** \brief 结构体成员是数组时计算数组元素个数 */
#define ST_MEMBER_ARRAY_LEN(st, member) (ST_MEMBER_SIZE(st, member) / ST_MEMBER_SIZE(st, member[0]))

/** \brief 根据结构成员地址找到结构首地址 */
#ifndef container_of
#define container_of(ptr, type, member) \
    ((type *)(void *)((char *)(ptr) - offsetof(type, member)))
#endif

/** \brief 计算数组的元素个数 */
#ifndef ARRAY_LEN
#define ARRAY_LEN(x) (sizeof(x) / sizeof((x)[0]))
#endif

/** \brief 取两个数较大的数 */
#ifndef MAX
#define MAX(x,y)  ((x) > (y) ? (x) : (y))
#endif

/** \brief 取两个数较小的数 */
#ifndef MIN
#define MIN(x,y)  ((x) < (y) ? (x) : (y))
#endif

/* 下面两个 align必须是2的n次方 */
#ifndef ROUND_UP
#define ROUND_UP(x, align)    (((x)+ (align) - 1) & ~((align) - 1))
#endif
#ifndef ROUND_DOWN
#define ROUND_DOWN(x, align)  ((x) & ~((align) - 1))
#endif

/** \brief 未使用参数申明 
    \note  一些函数原型要求的参数但实际可能不使用，不使用的参数使用此宏定义消除PC-Lint和编译告警
*/
#ifndef UNREFERENCE_PARAM
#define UNREFERENCE_PARAM(x) ((void)(x))
#endif

#if defined(WIN32) || defined(_PCLINT_) || defined(__LINUX_USR__)


#define EXPORT_SYMBOL(x)
#define module_init(x)
#define module_exit(x)
#define MODULE_AUTHOR(x)
#define MODULE_LICENSE(x)
#define dump_stack()    /* pengshufeng 90003000. 2008/12/22 */

#ifndef __init
#define __init
#endif

#ifndef __exit
#define __exit
#endif

#ifndef __initdata
#define __initdata
#endif

#elif defined(__KERNEL__)
#else
#error "platform not specify"
#endif

/** \brief 申明模块PID，用于\ref LVOS_Malloc, \ref DBG_LogError 等接口自动传入参数 */
#define MODULE_ID(x)        \
            static OSP_U32 MY_PID = (x)
#ifdef _PCLINT_
#define MODULE_NAME(x) int _pclint_module_name
#else
#define MODULE_NAME(x)
#endif

#ifndef MAX_PATH_NAME
#define MAX_PATH_NAME 256
#endif

/** \brief 内部使用的名称长度定义 */
#define MAX_NAME_LEN 128
#define MAX_DESC_LEN 256

/** \brief 保存IP地址字符串的最大长度 */
#define MAX_IP_STR_LEN      16
#define MAX_IPV6_STR_LEN    64

/** \brief 保存数字的最大字符串长度， 2^64只有20字节长，24字节足够 */
#define MAX_NUMBER_STR_LEN  24

/* 开关状态--开 */
#define SWITCH_ON   1

/* 开关状态--关 */
#define SWITCH_OFF  0

/* 容量转换 */
#define BYTE_PER_SECTOR     (512)
#define BYTE_PER_PAGE       (4096)
#define SECTOR_PER_PAGE     (BYTE_PER_PAGE / BYTE_PER_SECTOR)

/** 
*   支持PI(Protection Information)的扇区及页面大小定义
*   PI扇区由512字节数据+8字节DIF(Data Integrity Field)组成
*   PI页面由8个PI扇区组成
*
*   当屏蔽DIF时，DIF字节变成0。用_NO_DIF_这个全局宏来识别DIF屏蔽
*/
#ifdef _NO_DIF_
#define BYTES_PER_DIF          (0)
#else
#define BYTES_PER_DIF          (8)
#endif
#define BYTES_PER_SECTOR_PI    (BYTE_PER_SECTOR + BYTES_PER_DIF)
#define SECTORS_PER_PAGE_PI    (8)
#define BYTES_PER_PAGE_PI      (BYTES_PER_SECTOR_PI * SECTORS_PER_PAGE_PI)

#define BITS_PER_BYTE   8
#ifndef BITS_PER_LONG
#define BITS_PER_LONG   (BITS_PER_BYTE*sizeof(long))
#endif
#ifndef PAGE_SIZE
#define PAGE_SIZE       4096
#endif
#define SECTOR_SIZE     512
#define PAGE_SHIFT      12
#define SECTOR_SHIFT    9

#define KB_TO_SECTOR(x)   ((x)<<1)
#define PAGE_TO_SECTOR(x) ((x)<<3)
#define MB_TO_SECTOR(x)   ((x)<<11)
#define GB_TO_SECTOR(x)   ((x)<<21)

#define SECTOR_TO_KB(x)   ((x)>>1)
#define SECTOR_TO_PAGE(x) ((x)>>3)
#define SECTOR_TO_MB(x)   ((x)>>11)
#define SECTOR_TO_GB(x)   ((x)>>21)

#define TB_TO_GB(x) ((x)<<10)
#define TB_TO_MB(x) ((x)<<20)
#define GB_TO_MB(x) ((x)<<10)
#define GB_TO_KB(x) ((x)<<20)
#define MB_TO_KB(x) ((x)<<10)

#define KB_TO_MB(x) ((x)>>10)
#define KB_TO_GB(x) ((x)>>20)
#define MB_TO_GB(x) ((x)>>10)
#define MB_TO_TB(x) ((x)>>20)
#define GB_TO_TB(x) ((x)>>10)


/* 判断指针合法性的宏 */
#define POINTER_VALID(p) (NULL != (p))
#define POINTER_VALID2(p1, p2) (POINTER_VALID(p1) && POINTER_VALID(p2))
#define POINTER_VALID3(p1, p2, p3) (POINTER_VALID2(p1, p2) && POINTER_VALID(p3))
#define POINTER_VALID4(p1, p2, p3, p4) (POINTER_VALID3(p1, p2, p3) && POINTER_VALID(p4))
#define POINTER_VALID5(p1, p2, p3, p4, p5) (POINTER_VALID4(p1, p2, p3, p4) && POINTER_VALID(p5))


#endif  /* __LVOS_MACRO_H__ */

/** @} */


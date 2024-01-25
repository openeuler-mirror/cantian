/******************************************************************************

                  版权所有 (C) 2008-2008 华为赛门铁克科技有限公司

 ******************************************************************************
  文 件 名   : lvos_lib.h
  版 本 号   : 初稿
  作    者   : x00001559
  生成日期   : 2008年8月19日
  最近修改   :
  功能描述   : 对编译器（操作系统）提供的库函数的适配。
  函数列表   :
  修改历史   :
  1.日    期   : 2008年8月19日
    作    者   : x00001559
    修改内容   : 创建文件

******************************************************************************/

/**
    \file  lvos_lib.h
    \brief 公共函数。其中和动态库相关的函数支持windows和linux用户态，其余支持windows、linux内核态、linux用户态

    \date 2008-08-19
*/

/** \addtogroup VOS_LIB  杂项库函数
    对于标准库函数: memcpy, memset, strcpy, strcmp, sprintf, snprintf 直接使用库函数原型，接口层不再封装(头文件在接口层头文件中已经包含)
    @{ 
*/

#ifndef __LVOS_LIB_H__
#define __LVOS_LIB_H__

#if defined(WIN32) || defined(_PCLINT_)

/* VC下编译时使用VC建议的函数 */
#define snprintf    _snprintf
#define vsnprintf   _vsnprintf
#define filelength  _filelength
#define chsize      _chsize
#define fileno      _fileno
#define stricmp     _stricmp
#define strnicmp     _strnicmp
#define ftruncate   _chsize
#define unlink      _unlink
#define strncasecmp  _strnicmp
static inline unsigned int copy_from_user(void *dst, const void *src, unsigned int size)
{
    memcpy(dst, src, size);
    return 0;
}
static inline unsigned int copy_to_user(void *dst, const void *src, unsigned int size)
{
    memcpy(dst, src, size);
    return 0;
}







#elif defined(__KERNEL__) /* Linux内核态  */
#include <linux/math64.h>

/* 长度限制为4096，如果以后有更长得再修改 */
#define stricmp(s1, s2) strnicmp(s1 ,s2, 4096)


#elif defined(__LINUX_USR__) /* Linux用户态  */

typedef void* HMODULE;  /* 定义装载动态库时返回的句柄类型 */
typedef void* FARPROC;

#define stricmp strcasecmp
#define strnicmp strncasecmp

/** \brief 装载动态库
    \note  支持windows和linux用户态
    \param[in] v_szLibPathName 动态库的路径、名称
    \return 打开的动态库的句柄，装载失败时返回为 NULL
*/
HMODULE LVOS_LoadLibrary(const OSP_CHAR *v_szLibPathName);

/** \brief 查询动态库中的符号地址
    \note  支持windows和linux用户态
    \param[in] v_hModule 指向打开的动态库的句柄
    \param[in] v_szSymbolName   需要查询的符号名称
    \return 指向该符号的指针，如果查询失败，则返回NULL
*/
FARPROC LVOS_GetSymbolAddress(HMODULE v_hModule, const OSP_CHAR *v_szSymbolName);

/** \brief 查询动态库中的符号地址
    \note  支持windows和linux用户态
    \param[in] v_hModule 指向打开的动态库的句柄
    \retval RETURN_OK       关闭成功
    \retval RETURN_ERROR    关闭失败
*/
OSP_S32 LVOS_FreeLibrary(HMODULE v_hModule);

#endif


#ifndef memzero
#define memzero(s,n)    memset ((s),0,(n))
#endif

/* 为了兼容32为内核的Linux内核态开发定义64位除法运算 */
/** \brief 64位除法运算
    \note  支持windows、linux用户态、linux内核态
    \param[in] n       被除数
    \param[in] base    除数
    \param[out] puiMod 指向存放商值的指针
    \retval 商
*/
static inline OSP_U64 LVOS_div64(OSP_U64 n, OSP_U32 base, OSP_U32 *puiMod)
{
#if !defined(__KERNEL__) || defined(_PCLINT_)
    if (NULL != puiMod)
    {
        *puiMod = (OSP_U32)(n % base);
    }

    return (OSP_U64)(n / base);

#else /* 内核态 */
    OSP_U32 uiMod;

    if (NULL == puiMod)
    {
        return div_u64_rem(n, base, &uiMod);
    }
    else
    {
        return div_u64_rem(n, base, puiMod);
    }
#endif
}

static inline OSP_U64 UnSignedDivide64(OSP_U64  v_ullDvidend, OSP_U64  v_ullDivisor)
{
#if !defined(__KERNEL__) || defined(_PCLINT_)
    return v_ullDvidend / v_ullDivisor;
#else /* 内核态 */
    return div64_u64(v_ullDvidend, v_ullDivisor);
#endif
}

static inline OSP_U64 UnSignedRemain64(OSP_U64  v_ullDvidend, OSP_U64  v_ullDivisor)
{
#if !defined(__KERNEL__) || defined(_PCLINT_)
        return v_ullDvidend % v_ullDivisor;
#else /* 内核态 */
    #ifdef __x86_64__
        return v_ullDvidend % v_ullDivisor;

    #else
        return v_ullDvidend - v_ullDivisor * div64_u64(v_ullDvidend, v_ullDivisor);
    #endif
#endif
}

/** \brief strncpy函数，增加尾部填0的功能 */
#define LVOS_strncpy(s1, s2, n) do { \
    /* s1可以为指针或者数组，是数组时必须保证大小 >= n 或者等于0 */ \
    DBG_ASSERT((sizeof(s1) == 0) || (sizeof(s1) == sizeof(void *)) || (sizeof(s1) >= (n))); \
    strncpy((s1), (s2), (n)); \
    ((char *)(s1))[(n) - 1] = '\0'; \
 } while(0)

/** \brief 字符串转S64
    \note  支持windows、linux用户态、linux内核态
    \param[in] szStr 需要转换的字符串
    \return 成功时返回转换结果，szStr为NULL返回0，否则返回已转换的部分
    \note 仅支持十进制，无调用上下文限制
    \see  LVOS_StrToU64
*/
OSP_S64 LVOS_StrToS64(const OSP_CHAR *szStr);

/** \brief 字符串转U64
    \param[in] szStr 需要转换的字符串
    \return 成功时返回转换结果，szStr为NULL返回0，否则返回已转换的部分
    \note 支持十进制和十六进制，无调用上下文限制
    \see  LVOS_StrToS64
*/
OSP_U64 LVOS_StrToU64(const OSP_CHAR *szStr);

/** \brief 字符串转小写字符
    \param[in] v_pszStr 需要转换的字符串
*/
void LVOS_StrToLower(OSP_CHAR *v_pszStr);

/** \brief 判断是否是无符号整数
    \retval RETURN_OK 是
    \retval RETURN_ERROR  不是
*/
OSP_S32 LVOS_IsUnsignedNumbericStr(const OSP_CHAR *v_szStr);

/** 
    \brief 执行系统命令
    \param[in] v_szCommand 需要执行的命令
    \retval  0    执行成功
    \retval  其他 执行失败
*/
OSP_S32 LVOS_Execute(const OSP_CHAR*v_szCommand);

#ifdef WIN32 /* 内核和Linux用户态都有这个函数直接用内置的 */
char *strsep(char **s, const char *ct);
#endif

#endif /* __LVOS_LIB_H__ */
/** @} */



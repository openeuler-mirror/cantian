/******************************************************************************

                  版权所有 (C), 2001-2011, 华为赛门铁克科技有限公司

 ******************************************************************************
  文 件 名   : lvos_mem.h
  版 本 号   : 初稿

  生成日期   : 2008年11月13日
  最近修改   :
  功能描述   : 内存管理的头文件
  函数列表   :
  修改历史   :
  1.日    期   : 2008年11月13日

    修改内容   : 创建文件

******************************************************************************/

/**
    \file  lvos_mem.h
    \brief 操作系统内存管理接口封装
    \note  支持windows/linux_kernel/linux_user

    \date 2008-05-27
*/

/** \addtogroup MEM  内存管理模块
    操作系统内存管理接口封装
    @{ 
*/
#ifndef _LVOS_MEM_H__
#define _LVOS_MEM_H__

#if defined(__KERNEL__) && !defined(_PCLINT_)
    #define MEM_FUN_CALLER (OSP_U64)__builtin_return_address(0)
#else
    #define MEM_FUN_CALLER (OSP_U64)NULL
#endif

#if defined(__KERNEL__)
#ifdef _PCLINT_
#define GFP_ATOMIC 0
#endif

#define LVOS_MallocSub(pid, v_uiByte, MEM_FUN_CALLER) \
    LVOS_MallocSubStandard(pid, v_uiByte, MEM_FUN_CALLER,__FUNCTION__, __LINE__)
/** \brief windows、linux内核态和linux用户态统一的内存申请
    \param[in] v_uiByte 需要申请的内存长度
    \return 申请失败时返回NULL, 成功时返回申请到的内存地址
    \note 请不要直接使用函数\ref LVOS_MallocSub申请。本函数调用可能导致调用者阻塞
    \see  LVOS_MallocGfp, LVOS_Free
*/
#define LVOS_Malloc(v_uiByte) LVOS_MallocSub(MY_PID, v_uiByte, MEM_FUN_CALLER)

/** \brief linux内核态GFP方式的内存申请，windows和linux用户态直接使用了LVOS_Malloc方式申请
    \param[in] v_uiByte     需要申请的内存长度
    \param[in] v_uiGfpMask  申请方式
    \return 申请失败时返回NULL, 成功时返回申请到的内存地址
    \note 请不要直接使用函数\ref LVOS_MallocGfpSub 申请。本函数调用中非GFP_ATOMIC方式可能导致调用者阻塞
    \see  LVOS_Malloc, LVOS_Free
*/
#define LVOS_MallocGfp(v_uiByte, v_uiGfpMask) \
    LVOS_MallocGfpSub(MY_PID, v_uiByte, v_uiGfpMask, MEM_FUN_CALLER)

/** \brief windows、linux内核态和linux用户态统一的内存释放
    \param[in] v_ptr 需要释放的内存首地址
    \return 申请失败时返回NULL, 成功时返回申请到的内存地址
    \note 请不要直接使用函数\ref LVOS_MallocSub申请。本函数调用无调用上下文限制
    \see  LVOS_Malloc, LVOS_MallocGfp
*/
#define LVOS_Free(v_ptr)            \
    {                               \
        LVOS_FreeSub(v_ptr, __FUNCTION__, __LINE__);  \
        v_ptr = NULL;               \
    }


/* 下面的接口不对外开放，仅供宏定义使用 */
/*lint -function(realloc(0), LVOS_MallocSubStandard) */
/*lint -function(malloc(1), LVOS_MallocSubStandard(2)) */
/*lint -function(malloc(r), LVOS_MallocSubStandard(r)) */
/** \brief windows、linux内核态和linux用户态统一的内存释放
    \param[in] v_uiPid 申请内存的模块PID
    \param[in] v_uiByte 申请内存的大小
    \param[in] v_pcFunction 申请内存的函数名   
    \param[in] v_uiLine 申请内存的行号
    \return 申请失败时返回NULL, 成功时返回申请到的内存地址
*/
OSP_VOID *LVOS_MallocSubStandard(OSP_U32 v_uiPid, OSP_U32 v_uiByte, OSP_U64 v_ulCaller, 
                       OSP_CHAR const *v_pcFunction, OSP_U32 v_uiLine);


/*lint -function(realloc(0), LVOS_MallocGfpSub) */
/*lint -function(malloc(1), LVOS_MallocGfpSub(2)) */
/*lint -function(malloc(r), LVOS_MallocGfpSub(r)) */
/** \brief linux内核态非阻塞方式申请内存
    \param[in] v_uiPid 申请内存的模块PID
    \param[in] v_uiByte 申请内存的大小
    \param[in] v_uiGfpMask 内存申请方式
    \param[in] v_pcFunction 申请内存的函数名   
    \param[in] v_uiLine 申请内存的行号
    \return 申请失败时返回NULL, 成功时返回申请到的内存地址
*/
void *LVOS_MallocGfpSub(OSP_U32 v_uiPid, OSP_U32 v_uiByte, OSP_U32 v_uiGfpMask, OSP_U64 v_ulCaller);

/*lint -function(free, LVOS_FreeSub) */
void LVOS_FreeSub(void *v_ptr, 
    OSP_CHAR const *v_pcFunction, OSP_U32 v_uiLine);
#elif defined(__LINUX_USR__)
#define LVOS_MallocSub(pid, v_uiByte, MEM_FUN_CALLER) \
    LVOS_MallocSubStandard(pid, v_uiByte, MEM_FUN_CALLER,__FUNCTION__, __LINE__)
#define LVOS_Malloc(v_uiByte)  LVOS_MallocSub(MY_PID, v_uiByte, MEM_FUN_CALLER)
#define LVOS_MallocGfp(v_uiByte, v_uiGfpMask) malloc(v_uiByte)
#define LVOS_Free(v_ptr)         \
    {                            \
        LVOS_FreeSub(v_ptr, __FUNCTION__, __LINE__);            \
        v_ptr = NULL;            \
    }
OSP_VOID *LVOS_MallocSubStandard(OSP_U32 v_uiPid, OSP_U32 v_uiByte, OSP_U64 v_ulCaller, 
                       OSP_CHAR const *v_pcFunction, OSP_U32 v_uiLine);
void LVOS_FreeSub(void *v_ptr, 
    OSP_CHAR const *v_pcFunction, OSP_U32 v_uiLine);

#else
#define LVOS_Malloc(v_uiByte)  malloc(v_uiByte)
#define LVOS_MallocGfp(v_uiByte, v_uiGfpMask) malloc(v_uiByte)
#define LVOS_Free(v_ptr)         \
    {                            \
        free(v_ptr);             \
        v_ptr = NULL;            \
    }

#ifndef PCLINT_VOS_MEM
#define LVOS_MallocSub(v_uiPid, v_uiByte, v_ulCaller)  malloc(v_uiByte),(void)(v_ulCaller), (void)(v_uiPid)
#endif

#endif /* __KERNEL__ */

/* 兼容驱动的传入pid的方式的定义 */
#ifdef DECLARE_FOR_DRV_COMPAT
#undef LVOS_Malloc
#undef LVOS_MallocGfp
#if defined(__KERNEL__)
#define LVOS_Malloc(pid, size)  LVOS_MallocSub(pid, size, MEM_FUN_CALLER)
#define LVOS_MallocGfp(pid, size, gfp) LVOS_MallocGfpSub(pid, size, gfp, MEM_FUN_CALLER)
#elif defined(__LINUX_USR__)
#define LVOS_Malloc(pid, size)  LVOS_MallocSub(pid, size, MEM_FUN_CALLER)
#define LVOS_MallocGfp(pid, size, gfp) malloc(size)
#else
#define LVOS_Malloc(pid, size)  malloc(size)
#define LVOS_MallocGfp(pid, size, gfp) malloc(size)
#endif
#endif  /* UN_MEM */


#endif /* _LVOS_MEM_H__ */
/** @} */


/******************************************************************************
     版权所有 (C) 2010 - 2010  华为赛门铁克科技有限公司
*******************************************************************************
* 版 本 号: 初稿
* 作    者: x00001559
* 生成日期: 2010年6月26日
* 功能par 描述：
	 : TracePoint功能头文件
* 备    注: 
* 修改记录: 
*         1)时间    : 
*          修改人  : 
*          修改内容: 
******************************************************************************/
/**
    \lvos_tracepoint.h
    \VOS_TRACEP TracePoint功能
*/

/* VOS_TRACEP TracePoint(new)
    @{ 
    \example tracepoint_example.c
    TracePoint功能使用例子
*/

/** @defgroup VOS_TRACEP TracePoint */

#ifndef __LVOS_TRACEPOINT_H__
#define __LVOS_TRACEPOINT_H__

#include <stdlib.h>

#ifdef WIN32
#include "lvos_tracepoint.h"
#define LVOS_HVS_doTracePointPause		doTracePointPause
#define LVOS_HVS_getTracePoint			getTracePoint
#define LVOS_HVS_regTracePoint			regTracePoint
#define LVOS_HVS_unregTracePoint		unregTracePoint
#define LVOS_HVS_activeTracePoint		activeTracePoint
#define LVOS_HVS_deactiveTracePoint		deactiveTracePoint
#define LVOS_HVS_deactiveTracePointAll	deactiveTracePointAll

#ifndef DPAX_PANIC

#define DPAX_PANIC() \
do {\
    abort(); \
} while(0)
#endif

#endif

#define LVOS_MAX_HOOK_PER_TRACEP  16

#define LVOS_TRACEP_STAT_DELETED   0
#define LVOS_TRACEP_STAT_ACTIVE    1
#define LVOS_TRACEP_STAT_DEACTIVE  2

#define LVOS_TRACEP_PARAM_SIZE     32UL

/*HVS新框架*/
typedef enum tagLVOS_TP_TYPE_E
{
	LVOS_TP_TYPE_CALLBACK = 0,	/*回调*/
	LVOS_TP_TYPE_RESET,	    /*复位*/
	LVOS_TP_TYPE_PAUSE,         /*暂停*/
	LVOS_TP_TYPE_ABORT,
	LVOS_TP_TYPE_BUTT
}LVOS_TP_TYPE_E;

/** \brief 每个TracePoint的自定义参数区 */
typedef struct
{
    OSP_CHAR achParamData[LVOS_TRACEP_PARAM_SIZE]; /**<  自定义参数数据区 */
} LVOS_TRACEP_PARAM_S;

#ifdef DOXYGEN
/** \brief 定义一个不带参数的TracePoint */
#define LVOS_TRACEP_DEF0(tracep_name)

/** \brief 定义一个带参数的TracePoint 
    \param[in] tracep_name TracePoint的名称
    \param[in] ...  回调函数的自定义参数列表，如  :  OSP_S32 *, OSP_U64 *
    \note  名称只能是合法的变量名称，不要加引号，后面调用的时候也不能加引号
*/
#define LVOS_TRACEP_DEFN(tracep_name, ...)

/** \brief 调用不带参数的TracePoint回调函数
    \note  不要在业务代码中调用测试代码注册的TracePoint
*/
#define LVOS_TRACEP_CALL0(tracep_name)

/** \brief 调用带参数的TracePoint回调函数
    \note     \note  不要在业务代码中调用测试代码注册的TracePoint
*/
#define LVOS_TRACEP_CALLN(tracep_name, ...)

/** \brief 调用不带参数的TracePoint回调函数
    \note  不要在业务代码中调用测试代码注册的TracePoint
*/
#define LVOS_TRACEPHOOK_CALL0(tracep_name)

/** \brief 调用带参数的TracePoint回调函数
    \note     \note  不要在业务代码中调用测试代码注册的TracePoint
*/
#define LVOS_TRACEPHOOK_CALLN(tracep_name, ...)

/** \brief 注册一个TracePoint 
    \param[in] tracep_name TracePoint的名称，和定义时一致，不要加引号
    \param[in] desc 简要描述信息
    \param[in] flag 初始是激活还是去激活, FALSE表示去激活，其他表示激活
    \note  业务代码中调用的TracePoint必须在业务代码中注册，测试代码可以调用业务代码注册的TracePoint但是反过来不要这样使用
*/
#define LVOS_TRACEP_REG_POINT(tracep_name, desc, flag)

/** \brief 注销一个TracePoint */
#define LVOS_TRACEP_UNREG_POINT(tracep_name)

/** \brief 激活/去激活一个TracePoint 
    \param[in] tracep_name TracePoint名称
    \param[in] flag FALSE表示去激活，其他值表示激活
*/
#define LVOS_TRACEP_ACTIVE(tracep_name, flag)

/** \brief 向TracePoint添加回调函数 
    \param[in] tracep_name TracePoint的名称，和定义时一致，不要加引号
    \param[in] fn 回调函数
    \param[in] desc 简要描述信息
    \param[in] flag 初始是激活还是去激活, FALSE表示去激活，其他表示激活
*/
#define LVOS_TRACEP_ADD_HOOK(tracep_name, fn, desc, flag)

/** \brief 从TracePoint删除一个回调函数 */
#define LVOS_TRACEP_DEL_HOOK(tracep_name, fn)

/** \brief 激活/去激活一个回调函数 */
#define LVOS_TRACEP_HOOK_ACTIVE(tracep_name, fn, flag)

/** \brief 定义一个不带参数的TracePoint (仅调试版本) */
#define LVOS_TRACEP_DEF0_D(tracep_name)

/** \brief 定义一个带参数的TracePoint (仅调试版本)
    \param[in] tracep_name TracePoint的名称
    \param[in] ...  回调函数的自定义参数列表，如  :  OSP_S32 *, OSP_U64 *
    \note  名称只能是合法的变量名称，不要加引号，后面调用的时候也不能加引号
*/
#define LVOS_TRACEP_DEFN_D(tracep_name, ...)

/** \brief 调用不带参数的TracePoint回调函数 (仅调试版本)
    \note  不要在业务代码中调用测试代码注册的TracePoint
*/
#define LVOS_TRACEP_CALL0_D(tracep_name)

/** \brief 调用带参数的TracePoint回调函数 (仅调试版本)
    \note     \note  不要在业务代码中调用测试代码注册的TracePoint
*/
#define LVOS_TRACEP_CALLN_D(tracep_name, ...)

/** \brief 调用不带参数的TracePoint回调函数 (仅调试版本)
    \note  不要在业务代码中调用测试代码注册的TracePoint
*/
#define LVOS_TRACEPHOOK_CALL0(tracep_name)

/** \brief 调用带参数的TracePoint回调函数 (仅调试版本)
    \note     \note  不要在业务代码中调用测试代码注册的TracePoint
*/
#define LVOS_TRACEPHOOK_CALLN(tracep_name, ...)

/** \brief 注册一个TracePoint (仅调试版本)
    \param[in] tracep_name TracePoint的名称，和定义时一致，不要加引号
    \param[in] desc 简要描述信息
    \param[in] flag 初始是激活还是去激活, FALSE表示去激活，其他表示激活
    \note  业务代码中调用的TracePoint必须在业务代码中注册，测试代码可以调用业务代码注册的TracePoint但是反过来不要这样使用
*/
#define LVOS_TRACEP_REG_POINT_D(tracep_name, desc, flag)

/** \brief 注销一个TracePoint (仅调试版本) */
#define LVOS_TRACEP_UNREG_POINT_D(tracep_name)

/** \brief 激活/去激活一个TracePoint (仅调试版本)
    \param[in] tracep_name TracePoint名称
    \param[in] flag FALSE表示去激活，其他值表示激活
*/
#define LVOS_TRACEP_ACTIVE_D(tracep_name, flag)

/** \brief 向TracePoint添加回调函数 (仅调试版本)
    \param[in] tracep_name TracePoint的名称，和定义时一致，不要加引号
    \param[in] fn 回调函数
    \param[in] desc 简要描述信息
    \param[in] flag 初始是激活还是去激活, FALSE表示去激活，其他表示激活
*/
#define LVOS_TRACEP_ADD_HOOK_D(tracep_name, fn, desc, flag)

/** \brief 从TracePoint删除一个回调函数 (仅调试版本) */
#define LVOS_TRACEP_DEL_HOOK_D(tracep_name, fn)

/** \brief 激活/去激活一个回调函数 (仅调试版本) */
#define LVOS_TRACEP_HOOK_ACTIVE_D(tracep_name, fn, flag)

/*HVS新框架*/
#define LVOS_TP_REG(name, desc, fn)
#define LVOS_TP_UNREG(name)
#define LVOS_TP_START(name, ...) 
#define LVOS_TP_NOPARAM_START(name)
#define LVOS_TP_END

#else

typedef void (*FN_TRACEP_COMMON_T)(LVOS_TRACEP_PARAM_S *, ...);

/**
 \ingroup VOS_TRACEP 
 *用于保存每个回调函数相关信息的数据结构。
 */
typedef struct
{
    OSP_CHAR  szName[MAX_NAME_LEN];  /**< 存放hook的名字。 */
    OSP_CHAR  szDesc[MAX_DESC_LEN]; /**< 存放hook的描述字段。 */
    OSP_S32   iId;    /**< 唯一标识，如果被删除则该标识会增加。 */
    OSP_S32   iActive;  /**< 用于识别该hook是否激活。*/
    OSP_S32   iDbgOnly; /**< 保留。*/
    FN_TRACEP_COMMON_T fnHook; /**< 回调函数。*/
} LVOS_TRACEP_HOOK_S;

/**
   \ingroup VOS_TRACEP 
 *用于保存每个tracepint相关信息的数据结构。
 */
typedef struct
{
    OSP_CHAR  szName[MAX_NAME_LEN]; /**< 存放tracepoint的名字。 */
    OSP_CHAR  szDesc[MAX_DESC_LEN]; /**< 存放tracepoint的描述字段。 */
    OSP_U32   uiPid; /**< 模块ID号。*/
    OSP_S32   iId;     /**< 作为标识，在增加或删除Hook时都会做自增1的操作。 */
    OSP_S32   iActive;  /**< 用于识别该tracepoint 是否激活*/
    OSP_S32   iDbgOnly; /**< 保留。*/
    LVOS_TRACEP_PARAM_S stParam;  /**< 用于存放回调函数的自定义参数。*/
    LVOS_TRACEP_HOOK_S  stHooks[LVOS_MAX_HOOK_PER_TRACEP]; /**< 存放每个tracepoint上的回调函数。*/
} LVOS_TRACEP_S;

/*HVS新框架*/
typedef struct tagLVOS_TRACEP_NEW_S
{
    char szName[MAX_NAME_LEN];
    char szDesc[MAX_DESC_LEN];
    uint32_t uiPid;
    int32_t iActive;
    int32_t type;
    uint32_t timeAlive;
    uint32_t timeCalled;
    FN_TRACEP_COMMON_T fnHook;
    LVOS_TRACEP_PARAM_S stParam;
}LVOS_TRACEP_NEW_S;

/** \ingroup VOS_TRACEP 
    \par 描述：
	 定义一个TracePoint，不带参数，与\ref LVOS_TRACEP_DEFN功能相同，但\ref LVOS_TRACEP_DEFN可带参数。
    \attention  名称只能是合法的变量名称，不要加引号，后面调用的时候也不能加引号。
    \param tracep_name [in] TracePoint的名称，取值：长度小于128字节。
    \par依赖:  
	 lvos_tracepoint.h
	\since V100R001C00
*/
#define LVOS_TRACEP_DEF0(tracep_name) \
    typedef void (*FN_TRACEP_T_##tracep_name)(LVOS_TRACEP_PARAM_S *);

/** \ingroup VOS_TRACEP 
    \par 描述：
	  定义一个TracePoint，可带参数，与\ref LVOS_TRACEP_DEF0功能相同，但\ref LVOS_TRACEP_DEF0不能带参数。
    \attention  名称只能是合法的变量名称，不要加引号，后面调用的时候也不能加引号。
    \param tracep_name [in] TracePoint的名称，取值：长度小于128字节。
    \param ...  [in] 回调函数的自定义参数列表，如：OSP_S32 *, OSP_U64 *。
    \par依赖:  
	 lvos_tracepoint.h
	\since V100R001C00
*/
#define LVOS_TRACEP_DEFN(tracep_name, ...) \
    typedef void (*FN_TRACEP_T_##tracep_name)(LVOS_TRACEP_PARAM_S *, __VA_ARGS__);

#define LVOS_TRACEP_CALL(tracep_name, ...)                                             \
do                                                                              \
{                                                                               \
    static LVOS_TRACEP_S *_pstTp = NULL;                                        \
    static OSP_S32   _iId = 0;                                                  \
    OSP_U32   _i;                                                               \
    if (unlikely(NULL == _pstTp || _pstTp->iId != _iId))                       \
    {                                                                           \
        _pstTp = LVOS_FindTracePoint(MY_PID, #tracep_name);                            \
        if (NULL == _pstTp)                                                     \
        {                                                                       \
            DBG_LogWarning(DBG_LOGID_BUTT, "tracepoint `%s` not register", #tracep_name);    \
            break;                                                              \
        }                                                                       \
        else                                                                    \
        {                                                                       \
            _iId = _pstTp->iId;                                                 \
        }                                                                       \
    }                                                                           \
    if (_pstTp->iActive != LVOS_TRACEP_STAT_ACTIVE)                             \
    {                                                                           \
        break;                                                                  \
    }                                                                           \
    for (_i = 0; _i < LVOS_MAX_HOOK_PER_TRACEP; _i++)                           \
    {                                                                           \
        if ((_pstTp->stHooks[_i].iActive == LVOS_TRACEP_STAT_ACTIVE)            \
            && (NULL != _pstTp->stHooks[_i].fnHook))                            \
        {                                                                       \
            FN_TRACEP_T_##tracep_name fn = (FN_TRACEP_T_##tracep_name)_pstTp->stHooks[_i].fnHook;     \
            fn(__VA_ARGS__);                                                    \
        }                                                                       \
    }                                                                           \
}while(0)

        
#define LVOS_TRACEPHOOK_CALL(tracep_name, fn, ...)                              \
do                                                                              \
{                                                                               \
    static LVOS_TRACEP_S *_pstTp = NULL;                                        \
    static LVOS_TRACEP_HOOK_S *_pstHook = NULL;                                 \
    static OSP_S32   _iId = 0;                                                  \
    static OSP_S32   _iHookId = 0;                                              \
    if (unlikely(NULL == _pstTp || _pstTp->iId != _iId))                       \
    {                                                                           \
        _pstTp = LVOS_FindTracePoint(MY_PID, #tracep_name);                     \
        if (NULL == _pstTp)                                                     \
        {                                                                       \
            DBG_LogWarning(DBG_LOGID_BUTT, "tracepoint `%s` not register", #tracep_name);    \
            break;                                                              \
        }                                                                       \
        else                                                                    \
        {                                                                       \
            _iId = _pstTp->iId;                                                 \
        }                                                                       \
    }                                                                           \
    if (_pstTp->iActive != LVOS_TRACEP_STAT_ACTIVE)                             \
    {                                                                           \
        break;                                                                  \
    }                                                                           \
    if (unlikely(NULL == _pstHook || _pstHook->iId != _iHookId))               \
    {                                                                           \
        _pstHook = LVOS_FindTraceHook(_pstTp, #fn);                             \
        if (NULL == _pstHook)                                                   \
        {                                                                       \
            DBG_LogWarning(DBG_LOGID_BUTT, "hook `%s`not found", #fn);        \
            break;                                                              \
        }                                                                       \
        else                                                                    \
        {                                                                       \
            _iHookId = _pstHook->iId;                                           \
        }                                                                       \
    }                                                                           \
    if ((_pstHook->iActive == LVOS_TRACEP_STAT_ACTIVE)                          \
        && (NULL != _pstHook->fnHook))                                          \
    {                                                                           \
        FN_TRACEP_T_##tracep_name _fn = (FN_TRACEP_T_##tracep_name)_pstHook->fnHook; \
        _fn(__VA_ARGS__);                                                       \
    }                                                                           \
}while(0)

/** \ingroup VOS_TRACEP 
    \par 描述：
	  通过参数tracep_name指定TracePoint，执行该TracePoint所有激活了的回调函数。 
    \attention  不要在业务代码中调用测试代码注册的TracePoint。
    \param tracep_name [in] TracePoint的名称，取值：长度小于128字节。    
    \par依赖:  
	 lvos_tracepoint.h
	\since V100R001C00
*/
#define LVOS_TRACEP_CALL0(tracep_name)  LVOS_TRACEP_CALL(tracep_name, &_pstTp->stParam)

/** \ingroup VOS_TRACEP 
    \par 描述：
	  通过参数tracep_name指定TracePoint，执行该TracePoint所有激活了的回调函数，并且可通过“…”指定回调函数的参数。 
    \attention  不要在业务代码中调用测试代码注册的TracePoint。
    \param tracep_name [in] TracePoint的名称，取值：长度小于128字节。
    \param ... [in] 回调函数的自定义参数。     
    \par依赖:  
	 lvos_tracepoint.h
	\since V100R001C00
*/
#define LVOS_TRACEP_CALLN(tracep_name, ...)  LVOS_TRACEP_CALL(tracep_name, &_pstTp->stParam, __VA_ARGS__)

/** \ingroup VOS_TRACEP 
    \par 描述：
	 通过参数tracep_name指定TracePoint，执行参数fn指定的回调函数。与\ref LVOS_TRACEP_CALL0的区别是：LVOS_TRACEP_CALL0会执行所有在tracep_name这个tracepoint点的回调函数。
    \attention  不要在业务代码中调用测试代码注册的TracePoint。
    \param tracep_name [in] TracePoint的名称，取值：长度小于128字节。  
    \param fn [in] 回调函数。 
    \par依赖:  
	 lvos_tracepoint.h
	\since V100R001C00
*/
#define LVOS_TRACEPHOOK_CALL0(tracep_name, fn)      LVOS_TRACEPHOOK_CALL(tracep_name, fn, &_pstTp->stParam)

/** \ingroup VOS_TRACEP 
    \par 描述：
	 通过参数tracep_name指定TracePoint，执行参数fn指定的回调函数，并且可通过“…”指定回调函数的参数。与\ref LVOS_TRACEP_CALLN的区别是：LVOS_TRACEP_CALLN会执行所有在tracep_name这个tracepoint点的回调函数。
    \attention  不要在业务代码中调用测试代码注册的TracePoint。
    \param tracep_name [in] TracePoint的名称，取值：长度小于128字节。  
    \param fn [in] 回调函数。
    \param ... [in] 回调函数的自定义参数。     
    \par依赖:  
	 lvos_tracepoint.h
	\since V100R001C00
*/
#define LVOS_TRACEPHOOK_CALLN(tracep_name, fn, ...) LVOS_TRACEPHOOK_CALL(tracep_name, fn, &_pstTp->stParam, __VA_ARGS__)

/** \ingroup VOS_TRACEP 
    \par 描述：
	   TracePoint注册接口，通过此接口用户可以注册一个tracePoint。
    \attention  业务代码中调用的TracePoint必须在业务代码中注册，测试代码可以调用业务代码注册的TracePoint。
    \param tracep_name [in] TracePoint的名称，不要加引号，取值：长度小于128字节。  
    \param desc [in] 注册接口相关的简要描述信息，取值：长度小于256字节。
    \param flag [in] 设置初始是激活还是去激活, FALSE表示去激活，TURE表示激活。
    \par依赖:  
	 lvos_tracepoint.h
	\since V100R001C00
*/
#define LVOS_TRACEP_REG_POINT(tracep_name, desc, flag)   LVOS_RegTracePoint(MY_PID, #tracep_name, desc, flag, FALSE)

/** \ingroup VOS_TRACEP 
    \par 描述：
	   TracePoint注销接口，与\ref LVOS_TRACEP_REG_POINT注册接口相对应。
    \param tracep_name [in] TracePoint的名称，取值：长度小于128字节。  
     \par依赖:  
	 lvos_tracepoint.h
	\since V100R001C00
*/
#define LVOS_TRACEP_UNREG_POINT(tracep_name)       LVOS_UnRegTracePoint(MY_PID, #tracep_name)

/** \ingroup VOS_TRACEP  
    \par 描述：
	  激活/去激活一个TracePoint，TracePoint共有三种：LVOS_TRACEP_STAT_ACTIVE（激活）、LVOS_TRACEP_STAT_DEACTIVE（去激活）、LVOS_TRACEP_STAT_DELETED（注销，与此函数无关）。
    \param tracep_name [in] TracePoint名称，取值：长度小于128字节。  
    \param flag [in] FALSE表示去激活，其他值表示激活。
    \par依赖:  
	 lvos_tracepoint.h
	\since V100R001C00
*/
#define LVOS_TRACEP_ACTIVE(tracep_name, flag)      LVOS_ActiveTracePoint(MY_PID, #tracep_name, flag)

/** \ingroup VOS_TRACEP 
    \par 描述：
	  向tracep_name指定的tracepoint点添加一个回调函数。
    \param tracep_name [in] TracePoint的名称，不要加引号，取值：长度小于128字节。  
    \param fn [in] 回调函数，取值：非空。
    \param desc [in] 简要描述信息，取值：长度小于256字节。  
    \param flag [in] 初始化回调函数的激活状态，取值：FALSE表示去激活，其它值表示激活。
    \par依赖:  
	 lvos_tracepoint.h
	\since V100R001C00
*/
#define LVOS_TRACEP_ADD_HOOK(tracep_name, fn, desc, flag)                              \
    do                                                                          \
    {                                                                           \
        FN_TRACEP_T_##tracep_name _Hookfn = fn;                                        \
        LVOS_AddTracePointHook(MY_PID, #tracep_name, #fn, (FN_TRACEP_COMMON_T)_Hookfn, desc, flag, FALSE);\
    } while(0) 
    
/** \ingroup VOS_TRACEP 
    \par 描述：
	   通过参数tracep_name指定相应的tracepoint，删除该tracepoint上回调函数是fn的函数。
    \param tracep_name [in] TracePoint的名称，取值：长度小于128字节。 
    \param fn [in] 回调函数，取值：非空。
    \par依赖:  
	 lvos_tracepoint.h
	\since V100R001C00
*/
#define LVOS_TRACEP_DEL_HOOK(tracep_name, fn)                                          \
    do                                                                          \
    {                                                                           \
        FN_TRACEP_T_##tracep_name _Hookfn = fn;  /* 参数检查 */                        \
        UNREFERENCE_PARAM(_Hookfn);                                           \
        LVOS_DelTracePointHook(MY_PID, #tracep_name, #fn);                             \
    } while (0)

/** \ingroup VOS_TRACEP 
    \par 描述：
	   激活/去激活一个回调函数。通过参数tracep_name指定相应的tracepoint，修改该tracepoint上回调函数是fn的函数的活动状态。
    \param tracep_name [in] TracePoint的名称，取值：长度小于128字节。  
    \param fn [in] 回调函数，取值：非空。
    \param flag [in] 修改回调函数的活动状态，取值：FALSE表示去激活，其它值表示激活。
    \par依赖:  
	 lvos_tracepoint.h
	\since V100R001C00
*/    
#define LVOS_TRACEP_HOOK_ACTIVE(tracep_name, fn, flag) LVOS_ActiveTracePointHook(MY_PID, #tracep_name, #fn, flag)


#ifdef _DEBUG

/** \ingroup VOS_TRACEP 
    \par 描述：
	  定义一个TracePoint，不带参数，与LVOS_TRACEP_DEFN功能相同，但LVOS_TRACEP_DEFN可带参数(仅调试版本，非调试版本为空)。
    \attention  名称只能是合法的变量名称，不要加引号，后面调用的时候也不能加引号。
    \param tracep_name [in] TracePoint的名称，取值：长度小于128字节。
    \par依赖:  
	 lvos_tracepoint.h
	\since V100R001C00
*/
#define LVOS_TRACEP_DEF0_D(tracep_name)                LVOS_TRACEP_DEF0(tracep_name)

/** \ingroup VOS_TRACEP 
    \par 描述：
	  定义一个TracePoint，可带参数，与LVOS_TRACEP_DEF0功能相同，但LVOS_TRACEP_DEF0不能带参数(仅调试版本，非调试版本为空)。
    \attention  名称只能是合法的变量名称，不要加引号，后面调用的时候也不能加引号。
    \param tracep_name [in] TracePoint的名称，取值：长度小于128字节。
    \param ...  [in] 回调函数的自定义参数，如：OSP_S32 *，OSP_U64 *。
    \par依赖:  
	 lvos_tracepoint.h
	\since V100R001C00
*/
#define LVOS_TRACEP_DEFN_D(tracep_name, ...)           LVOS_TRACEP_DEFN(tracep_name, __VA_ARGS__)

/** \ingroup VOS_TRACEP 
    \par 描述：
	  回调函数的执行，该回调函数不带参数(仅调试版本，非调试版本为空)。
    \attention  不要在业务代码中调用测试代码注册的TracePoint。
    \param tracep_name [in] TracePoint的名称，取值：长度小于128字节。     
    \par依赖:  
	 lvos_tracepoint.h
	\since V100R001C00
*/
#define LVOS_TRACEP_CALL0_D(tracep_name)               LVOS_TRACEP_CALL0(tracep_name)

/** \ingroup VOS_TRACEP 
    \par 描述：
	  回调函数的执行，该回调函数可带参数(仅调试版本，非调试版本为空)。  
    \attention  不要在业务代码中调用测试代码注册的TracePoint。
    \param tracep_name [in] TracePoint的名称，取值：长度小于128字节。
    \param ... [in] 回调函数的自定义参数，如：OSP_S32 *，OSP_U64 *。  
    \par依赖:  
	 lvos_tracepoint.h
	\since V100R001C00
*/
#define LVOS_TRACEP_CALLN_D(tracep_name, ...)          LVOS_TRACEP_CALLN(tracep_name, __VA_ARGS__)

/** \ingroup VOS_TRACEP 
    \par 描述：
	  回调函数的执行，该回调函数不带参数。与\ref LVOS_TRACEP_CALL0的区别是：LVOS_TRACEP_CALL0函数会执行参数tracep_name指定的tracepoint点所有的回调函数(仅调试版本，非调试版本为空)。
    \attention  不要在业务代码中调用测试代码注册的TracePoint。
    \param tracep_name [in] TracePoint的名称，取值：长度小于128字节。  
    \param fn [in] 回调函数，取值：非空。 
    \par依赖:  
	 lvos_tracepoint.h
	\since V100R001C00
*/
#define LVOS_TRACEPHOOK_CALL0_D(tracep_name, fn)       LVOS_TRACEPHOOK_CALL0(tracep_name, fn)

/** \ingroup VOS_TRACEP 
    \par 描述：
	  回调函数的执行，该回调函数可带参数。与\ref LVOS_TRACEP_CALLN的区别是：LVOS_TRACEP_CALLN函数会执行参数tracep_name指定的tracepoint点所有的回调函数(仅调试版本，非调试版本为空)。
    \attention  不要在业务代码中调用测试代码注册的TracePoint。
    \param tracep_name [in] TracePoint的名称，取值：长度小于128字节。  
    \param fn [in] 回调函数，取值：非空。
    \param ... [in] 回调函数的自定义参数，如：OSP_S32 *，OSP_U64 *。    
    \par依赖:  
	 lvos_tracepoint.h
	\since V100R001C00
*/
#define LVOS_TRACEPHOOK_CALLN_D(tracep_name, fn, ...)  LVOS_TRACEPHOOK_CALLN(tracep_name, fn, __VA_ARGS__)

/** \ingroup VOS_TRACEP 
    \par 描述：
	   TracePoint注册接口，用于注册一个tracePoint(仅调试版本，非调试版本为空)。
    \attention  业务代码中调用的TracePoint必须在业务代码中注册，测试代码可以调用业务代码注册的TracePoint。
    \param tracep_name [in] TracePoint的名称，和定义时一致，不要加引号，取值：长度小于128字节。  
    \param desc [in] 简要描述信息，取值：长度小于256字节。  
    \param flag [in] 初始是激活还是去激活, FALSE表示去激活，其它值表示激活。
    \par依赖:  
	 lvos_tracepoint.h
	\since V100R001C00
*/
#define LVOS_TRACEP_REG_POINT_D(tracep_name, desc, flag)     LVOS_RegTracePoint(MY_PID, #tracep_name, desc, flag, TRUE)

/** \ingroup VOS_TRACEP 
    \par 描述：
	   TracePoint注销接口，与\ref LVOS_TRACEP_REG_POINT对应(仅调试版本，非调试版本为空)。
    \param tracep_name [in] TracePoint的名称，取值：长度小于128字节。
     \par依赖:  
	 lvos_tracepoint.h
	\since V100R001C00
*/
#define LVOS_TRACEP_UNREG_POINT_D(tracep_name)         LVOS_TRACEP_UNREG_POINT(tracep_name)

/** \ingroup VOS_TRACEP  
    \par 描述：
	  激活/去激活一个TracePoint。TracePoint共有三种状态：LVOS_TRACEP_STAT_ACTIVE（激活）、LVOS_TRACEP_STAT_DEACTIVE（去激活）、LVOS_TRACEP_STAT_DELETED（注销，与此函数无关）。仅适用于调试版本。
    \param tracep_name [in] TracePoint名称，取值：长度小于128字节  
    \param flag [in] 回调函数的激活状态，FALSE表示去激活，其他值表示激活。
    \par依赖:  
	 lvos_tracepoint.h
	\since V100R001C00
*/
#define LVOS_TRACEP_ACTIVE_D(tracep_name, flag)        LVOS_TRACEP_ACTIVE(tracep_name, flag)

/** \ingroup VOS_TRACEP 
    \par 描述：
	  向对应名称是tracep_name的tracepoint点添加一个回调函数(仅调试版本，非调试版本为空)。
    \param tracep_name TracePoint的名称，不要加引号，取值：长度小于128字节。  
    \param fn [in] 回调函数，取值：非空。
    \param desc [in] 简要描述信息，取值：长度小于256字节。  
    \param flag [in] 初始化回调函数的激活状态，取值：FALSE表示去激活，其它值表示激活。
    \par依赖:  
	 lvos_tracepoint.h
	\since V100R001C00
*/
#define LVOS_TRACEP_ADD_HOOK_D(tracep_name, fn, desc, flag)                            \
    do                                                                          \
    {                                                                           \
        FN_TRACEP_T_##tracep_name _Hookfn = fn;                                        \
        LVOS_AddTracePointHook(MY_PID, #tracep_name, #fn, (FN_TRACEP_COMMON_T)_Hookfn, desc, flag, TRUE);\
    } while(0) 

 /** \ingroup VOS_TRACEP 
    \par 描述：
	   通过参数tracep_name指定tracepoint，删除回调函数是fn的函数(仅调试版本，非调试版本为空)。
    \param tracep_name [in] TracePoint的名称，取值：长度小于128字节。  
    \param fn [in]  回调函数，取值：非空。
    \par依赖:  
	 lvos_tracepoint.h
	\since V100R001C00
*/
#define LVOS_TRACEP_DEL_HOOK_D(tracep_name, fn)        LVOS_TRACEP_DEL_HOOK(tracep_name, fn)

/** \ingroup VOS_TRACEP 
    \par 描述：
	   激活/去激活一个回调函数，修改名称是tracep_name的tracepoint上回调函数fn的活动状态(仅调试版本，非调试版本为空)。
    \param tracep_name [in] TracePoint的名称，取值：长度小于128字节。
    \param fn [in] 回调函数，取值：非空。
    \param flag [in] 修改回调函数的活动状态，取值：FALSE表示去激活，其它值表示激活。
    \par依赖:  
	 lvos_tracepoint.h
	\since V100R001C00
*/  
#define LVOS_TRACEP_HOOK_ACTIVE_D(tracep_name, fn, flag)  LVOS_TRACEP_HOOK_ACTIVE(tracep_name, fn, flag)

/*HVS新框架*/

/*注册Tracepoint*/
/** \ingroup VOS_TRACEP 
    \par 描述：
	   HVS新框架的注册接口，用于注册一个tracePoint到HASH表中。
    \param name [in] TracePoint的名称，和定义时一致，不要加引号，取值：长度小于128字节。  
    \param desc [in] 简要描述信息，取值：长度小于256字节。  
    \param fn [in] 回调函数，取值：非空。
    \par依赖:  
	 lvos_tracepoint.h
	\since V100R001C00
*/
#define LVOS_TP_REG(name, desc, fn)    LVOS_HVS_regTracePoint(MY_PID, #name, desc, (FN_TRACEP_COMMON_T)fn)
/*卸载Tracepoint*/  
/** \ingroup VOS_TRACEP 
    \par 描述：
	   HVS新框架的注销接口，用于从HASH表中注销一个tracePoint。
    \param name [in] TracePoint的名称，和定义时一致，不要加引号，取值：长度小于128字节。  
    \par依赖:  
	 lvos_tracepoint.h
	\since V100R001C00
*/  
#define LVOS_TP_UNREG(name)                      LVOS_HVS_unregTracePoint(PID_OSP_NULL, #name)
/*插入故障点*/
/** \ingroup VOS_TRACEP 
    \par 描述：
	   HVS新框架的插入故障点功能。
    \param name [in] TracePoint的名称，和定义时一致，不要加引号，取值：长度小于128字节。
    \param ... [in] 跟回调函数对应的参数信息。
    \par依赖:  
	 lvos_tracepoint.h
	\since V100R001C00
*/ 
#define LVOS_TP_START(name, ...)                                 \
    do                                                                                          \
    {                                                                                           \
        static LVOS_TRACEP_NEW_S *_pstTp = NULL;                      \
        if (unlikely(NULL == _pstTp))                                             \
        {                                                                                       \
            (void)LVOS_HVS_getTracePoint(PID_OSP_NULL, #name, &_pstTp);     \
            if (NULL == _pstTp)                                                     \
            {                                                                                 \
                DBG_LogWarning(DBG_LOGID_BUTT, "tracepoint `%s` not registered", #name);    \
            }                                                                                   \
        }                                                                                       \
        if (NULL != _pstTp && LVOS_TRACEP_STAT_ACTIVE == _pstTp->iActive && LVOS_TP_TYPE_CALLBACK == _pstTp->type)              \
        {                                                                                       \
            _pstTp->fnHook(&_pstTp->stParam, __VA_ARGS__);  \
            _pstTp->timeCalled++;                                   \
            if (_pstTp->timeAlive > 0 && 0 == --(_pstTp->timeAlive))                                                \
            {                                                                                                           \
                LVOS_HVS_deactiveTracePoint(PID_OSP_NULL, #name);                                            \
            }                                                                                           \
        }                                                                                       \
        else                                                                                   \
        {                                                                                       \
            if (NULL != _pstTp && LVOS_TRACEP_STAT_ACTIVE == _pstTp->iActive && LVOS_TP_TYPE_ABORT == _pstTp->type)               \
            {                                                                                   \
                DPAX_PANIC();              \
            }                      \
            if (NULL != _pstTp && LVOS_TRACEP_STAT_ACTIVE == _pstTp->iActive && LVOS_TP_TYPE_RESET == _pstTp->type)               \
            {                                                                                   \
                system("reboot");                \
            }                                           \
            else if (NULL != _pstTp && LVOS_TRACEP_STAT_ACTIVE == _pstTp->iActive && LVOS_TP_TYPE_PAUSE == _pstTp->type)        \
            {                                           \
                LVOS_HVS_doTracePointPause(_pstTp);               \
                _pstTp->timeCalled++;                                   \
                if (_pstTp->timeAlive > 0 && 0 == --(_pstTp->timeAlive))                                                \
                {                                                                                                           \
                    LVOS_HVS_deactiveTracePoint(PID_OSP_NULL, #name);                                            \
                }                                                                           \
            }
/*插入故障点(当无回调函数或回调函数只有用户参数时)*/
/** \ingroup VOS_TRACEP 
    \par 描述：
	   HVS新框架的插入故障点功能(当无回调函数或回调函数只有用户参数时)。
    \param name [in] TracePoint的名称，和定义时一致，不要加引号，取值：长度小于128字节。
    \par依赖:  
	 lvos_tracepoint.h
	\since V100R001C00
*/ 
#define LVOS_TP_NOPARAM_START(name)                                 \
    do                                                                                          \
    {                                                                                           \
        static LVOS_TRACEP_NEW_S *_pstTp = NULL;                      \
        if (unlikely(NULL == _pstTp))                                             \
        {                                                                                       \
            (void)LVOS_HVS_getTracePoint(PID_OSP_NULL, #name, &_pstTp);     \
            if (NULL == _pstTp)                                                     \
            {                                                                                 \
                DBG_LogWarning(DBG_LOGID_BUTT, "tracepoint `%s` not registered", #name);    \
            }                                                                                   \
        }                                                                                       \
        if (NULL != _pstTp && LVOS_TRACEP_STAT_ACTIVE == _pstTp->iActive && LVOS_TP_TYPE_CALLBACK == _pstTp->type)              \
        {                                                                                       \
            _pstTp->fnHook(&_pstTp->stParam);                               \
            _pstTp->timeCalled++;                                   \
            if (_pstTp->timeAlive > 0 && 0 == --(_pstTp->timeAlive))                                                \
            {                                                                                                           \
                LVOS_HVS_deactiveTracePoint(PID_OSP_NULL, #name);                                            \
            }                                                                                           \
        }                                                                                       \
        else                                                                                   \
        {                                                                                       \
            if (NULL != _pstTp && LVOS_TRACEP_STAT_ACTIVE == _pstTp->iActive && LVOS_TP_TYPE_ABORT == _pstTp->type)               \
            {                                                                                   \
                DPAX_PANIC();              \
            }                      \
            if (NULL != _pstTp && LVOS_TRACEP_STAT_ACTIVE == _pstTp->iActive && LVOS_TP_TYPE_RESET == _pstTp->type)               \
            {                                                                                   \
                system("reboot");                \
            }                                           \
            else if (NULL != _pstTp && LVOS_TRACEP_STAT_ACTIVE == _pstTp->iActive && LVOS_TP_TYPE_PAUSE == _pstTp->type)        \
            {                                           \
                LVOS_HVS_doTracePointPause(_pstTp);               \
                _pstTp->timeCalled++;                                   \
                if (_pstTp->timeAlive > 0 && 0 == --(_pstTp->timeAlive))                                                \
                {                                                                                                           \
                    LVOS_HVS_deactiveTracePoint(PID_OSP_NULL, #name);                                            \
                }                                                                           \
            }

/*插入故障点结束*/
/** \ingroup VOS_TRACEP 
    \par 描述：
	   HVS新框架插入故障点结束。
    \par依赖:  
	 lvos_tracepoint.h
	\since V100R001C00
*/ 
#define LVOS_TP_END     \
        }                              \
    }while(0);
       
#else
#define LVOS_TRACEP_DEF0_D(tracep_name)
#define LVOS_TRACEP_DEFN_D(tracep_name, ...)
#define LVOS_TRACEP_CALL0_D(tracep_name)
#define LVOS_TRACEP_CALLN_D(tracep_name, ...)
#define LVOS_TRACEPHOOK_CALL0_D(tracep_name, fn)
#define LVOS_TRACEPHOOK_CALLN_D(tracep_name, fn, ...)
#define LVOS_TRACEP_REG_POINT_D(tracep_name, desc, flag)
#define LVOS_TRACEP_UNREG_POINT_D(tracep_name)
#define LVOS_TRACEP_ACTIVE_D(tracep_name, flag)
#define LVOS_TRACEP_ADD_HOOK_D(tracep_name, fn, desc, flag)
#define LVOS_TRACEP_DEL_HOOK_D(tracep_name, fn)
#define LVOS_TRACEP_HOOK_ACTIVE_D(tracep_name, fn, flag)

#define LVOS_TP_REG(name, desc, fn)  
#define LVOS_TP_UNREG(name)
#define LVOS_TP_START(name, ...) 
#define LVOS_TP_NOPARAM_START(name)
#define LVOS_TP_END


#endif

LVOS_TRACEP_S *LVOS_FindTracePoint(OSP_U32 v_uiPid, const OSP_CHAR *v_szName);


void LVOS_RegTracePoint(OSP_U32 v_uiPid, const OSP_CHAR *v_szName, const OSP_CHAR *v_szDesc, OSP_S32 v_iInitState, OSP_S32 v_iDbgOnly);
void LVOS_UnRegTracePoint(OSP_U32 v_uiPid, const OSP_CHAR *v_szName);

void LVOS_AddTracePointHook(OSP_U32 v_uiPid, const OSP_CHAR *v_szName, const OSP_CHAR *v_szHookName, FN_TRACEP_COMMON_T fnHook, const OSP_CHAR *v_szDesc, OSP_S32 v_iInitState, OSP_S32 v_iDbgOnly);
void LVOS_DelTracePointHook(OSP_U32 v_uiPid, const OSP_CHAR *v_szName, const OSP_CHAR *v_szHookName);

void LVOS_ActiveTracePoint(OSP_U32 v_uiPid, const OSP_CHAR *v_szName, OSP_S32 v_iFlag);
void LVOS_ActiveTracePointHook(OSP_U32 v_uiPid, const OSP_CHAR *v_szName, const OSP_CHAR *v_szHookName, OSP_S32 v_iFlag);
LVOS_TRACEP_HOOK_S *LVOS_FindTraceHook(LVOS_TRACEP_S *v_pstTp, const OSP_CHAR *v_szName);

/*HVS新框架*/
void LVOS_HVS_doTracePointPause(LVOS_TRACEP_NEW_S *tracepoint);
int32_t LVOS_HVS_getTracePoint(uint32_t pid, const char *name, LVOS_TRACEP_NEW_S **tracepoint);
int32_t LVOS_HVS_regTracePoint(uint32_t pid, const char *name, const char *desc, FN_TRACEP_COMMON_T fnHook);
int32_t LVOS_HVS_unregTracePoint(uint32_t pid, const char *name);
int32_t LVOS_HVS_activeTracePoint(uint32_t pid, const char *name, int32_t type, uint32_t time, LVOS_TRACEP_PARAM_S userParam);
int32_t LVOS_HVS_deactiveTracePoint(uint32_t pid, const char *name);
int32_t LVOS_HVS_deactiveTracePointAll(void);

#endif

#endif
/** @} */


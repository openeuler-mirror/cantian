/******************************************************************************

                  版权所有 (C), 2008-2008, 华为赛门铁克科技有限公司

 ******************************************************************************
  文 件 名   : debug.h
  版 本 号   : 初稿

  生成日期   : 2008年5月31日
  最近修改   :
  功能描述   : 调试模块头文件
  函数列表   :
  修改历史   :

  2.日    期   : 2008年11月13日

    修改内容   : 增加模块PID作输入和判断条件
  1.日    期   : 2008年5月31日

    修改内容   : 创建文件

******************************************************************************/
/**
    \file  lvos_debug.h
    \brief 调试打印模块对外接口, 该头文件已在lvos.h中包含，不需要自行包含
    \note  支持windows/linux_kernel/linux_user，异步接口，无调用上下文限制

    \date 2008-11-13
*/

/** \addtogroup DEBUG  调试打印
    @{ 
*/

#ifndef __DEBUG_H__
#define __DEBUG_H__
#if defined(__KERNEL__) && !defined(_PCLINT_)
#include <linux/kdb.h>
#endif

#include "lvos_diag.h"

#ifndef KDB_ENTER
#define KDB_ENTER()
#endif

#ifndef BUG
#define BUG()
#endif

/* 打印级别枚举 */
/** \brief 分为5个级别，致命，错误，普通异常，信息，调试信息
    \see MSG_SendSyncMsg, MSG_PostAsyncMsg
*/
typedef enum tagDBG_LOG_TYPE
{
    DBG_LOG_EMERG = 1,  /**< 致命(如非法参数、非法指针) */
    DBG_LOG_ERROR,      /**< 错误(如资源不足等) */
    DBG_LOG_WARNING,    /**< 普通异常情况，可正常处理 */
    DBG_LOG_EVENT,      /**< 信息 */
    DBG_LOG_INFO = DBG_LOG_EVENT,
    DBG_LOG_TRACE,      /**< 开发、调试信息，仅在开发可用记录 */
    DBG_LOG_DEBUG = DBG_LOG_TRACE,

    DBG_LOG_BUTT
} DBG_LOG_TYPE;

/*****************************************************************************
 函 数 名  : DBG_SetDefLogLevel
 功能描述  : 设定 默认的打印级别
 输入参数  : v_iLogLevel    请求打印的消息级别
 输出参数  : 无
 返 回 值  : TRUE   设置成功
             FALSE  设置失败
 调用函数  : DBG_GetSharedMem()
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2009年10月30日


*****************************************************************************/
OSP_BOOL DBG_SetDefLogLevel(OSP_U8 v_iLogLevel);

OSP_U8 DBG_GetPidLevel(OSP_U32 v_uiPid);

/** \brief 设置PID的名称 
    \param[in] v_uiPid PID的值
    \param[in] v_szName  PID的名称
    \note 内部会直接使用v_szName传入的地址，不会拷贝字符串，所以传入的名称不能是局部变量的地址
*/
void DBG_SetPidName(OSP_U32 v_uiPid, OSP_CHAR *v_szName);

/** \brief 获取PID对应的名称，如果未知则返回 "<pid>"
    \param[in] v_uiPid 输入PID
    \return 返回字符串指针
*/
OSP_CHAR *DBG_GetPidName(OSP_U32 v_uiPid);

/** \brief 记录调试消息，不要调用该函数，使用其他宏定义接口代替
    \param[in] v_uiPid          调用模块的PID
    \param[in] v_iLogLevel      调试打印的级别, \ref DBG_LOG_TYPE
    \param[in] v_pszFuncName    调用者的函数名
    \param[in] v_iLine          调用该接口的源代码所在行号
    \param[in] v_uiLogId        日志编号，便于自动化日志分析工具分析
    \param[in] v_pszFormat      用于控制输出内容的格式化字符串
    \param[in] ...              用于填充输出内容中格式化控制符的内容项
    \retval    无
    \attention 输出的函数名最多只有16个字符，输出的格式化字符串(含填充好的内容)最长为159个字符(不含结束符)
    \see DBG_LogEmerg, DBG_LogError, DBG_LogWarning, DBG_LogEvent, DBG_LogTrace
*/
/*lint -printf(6,DBG_Log)*/
void DBG_Log(OSP_U32 v_uiPid,
                 OSP_S32 v_iLogLevel,
                 const OSP_CHAR *v_pszFuncName,
                 OSP_S32 v_iLine,
                 OSP_U32 v_uiLogId,
                 const OSP_CHAR *v_pszFormat,
                 ...);

/****************************************************************************
以下几个宏对DEBUG对外提供的接口进行了封装，增加了易用性，
并让新的DEBUG模块对以前的调用方式兼容。
不过由于参数的变化，要求增加一个模块号 PID 作为输入参数，为避免烦琐的输入，
要求每个使用这些宏的源文件须在文件开头作如下语句:

MODULE_ID(__PID__);

其中“__PID__”为该文件所属的模块号。执行此语句需要包含 "lvos.h" 或 "lvos_macro.h"
******************************************************************************/
/** \brief 记录紧急级别调试日志
    \param[in] LogID  日志编号
    \param[in] ...    格式化输出字符串和用于填充输出内容中格式化控制符的内容项
    \retval    无
    \attention 输出的格式化字符串(含填充好的内容)最长为159个字符(不含结束符)
*/
#define DBG_LogCritical(LogID,...)    \
    DBG_Log(MY_PID, DBG_LOG_EMERG,  \
        __FUNCTION__, __LINE__, \
        (LogID), __VA_ARGS__)
#define DBG_LogEmerg  DBG_LogCritical

/** \brief 以DBG_LOG_ERROR级别记录调试信息
    \param[in] LogID  日志编号
    \param[in] ...  格式化输出字符串和用于填充输出内容中格式化控制符的内容项
    \retval    无
    \attention 输出的格式化字符串(含填充好的内容)最长为159个字符(不含结束符)
    \see DBG_Log()
*/
#define DBG_LogError(LogID, ...)                                               \
    DBG_Log(MY_PID, DBG_LOG_ERROR,  \
        __FUNCTION__, __LINE__, \
        (LogID), __VA_ARGS__)

/** \brief 以DBG_LOG_WARNING级别记录调试信息
    \param[in] LogID  日志编号
    \param[in] ...  格式化输出字符串和用于填充输出内容中格式化控制符的内容项
    \retval    无
    \attention 输出的格式化字符串(含填充好的内容)最长为159个字符(不含结束符)
    \see DBG_Log()
*/
#define DBG_LogWarning(LogID, ...)   \
    DBG_Log(MY_PID, DBG_LOG_WARNING,  \
        __FUNCTION__, __LINE__,   \
        (LogID), __VA_ARGS__)

/** \brief 以DBG_LOG_EVENT级别记录调试信息
    \param[in] LogID  日志编号
    \param[in] ...  格式化输出字符串和用于填充输出内容中格式化控制符的内容项
    \retval    无
    \attention 输出的格式化字符串(含填充好的内容)最长为159个字符(不含结束符)
    \see DBG_Log()
*/
#define DBG_LogInfo(LogID, ...)   \
    DBG_Log(MY_PID, DBG_LOG_EVENT,  \
        __FUNCTION__, __LINE__, \
        (LogID), __VA_ARGS__)
 #define DBG_LogEvent  DBG_LogInfo

/** \brief 以DBG_LOG_TRACE级别记录调试信息，同\ref DBG_LogTrace但不需要输入日志ID号
    \param[in] ...  格式化输出字符串和用于填充输出内容中格式化控制符的内容项
    \retval    无
    \attention 输出的格式化字符串(含填充好的内容)最长为159个字符(不含结束符)
    \see DBG_LogTrace
*/
#define DBG_LogDebug(LogID, ...)   \
    DBG_Log(MY_PID, DBG_LOG_TRACE,  \
        __FUNCTION__, __LINE__, \
        (LogID), __VA_ARGS__)
#define DBG_LogTrace DBG_LogDebug

#define DBG_LogIntf(level, logid, ...)  DBG_Log(MY_PID, level, __FUNCTION__, __LINE__, (OSP_U32)(logid), __VA_ARGS__)


enum tagOSP_DEBUG_LEVEL_E
{
    OSP_DBL_CRITICAL = 0,  /*致命（比如空指针、非法参数）*/
    OSP_DBL_MAJOR,        /*严重（比如系统资源不足、镜像链路故障）*/
    OSP_DBL_MINOR,       /*一般（比如命令超时）*/
    OSP_DBL_INFO,          /*信息*/
    OSP_DBL_DATA,       /*请求或响应包内容*/
    OSP_DBL_ALL,        /*命令处理经过的所有函数，以及一般以上的错误信息*/
    OSP_DBL_BUTT
};


#define OSP_TRACE(pid, loglevel, ...)

#ifdef _DEBUG

#if defined(WIN32) /* Windows下直接使用Windows定义的_ASSERT */
/** \brief ASSERT功能, Linux下面只记录
    \param[in] (表达式)  用于判断真、假的表达式
    \retval    无
    \attention 输出的格式化字符串(含填充好的内容)最长为159个字符(不含结束符)，该词句仅在_DEBUG被定义时有效
    \see DBG_Log()
*/
#if defined(_PCLINT)  /* Windows Debug模式下PC-LINT检查，直接定义  */
#define DBG_ASSERT(exp)
#define DBG_ASSERT_EXPR(expr, ...)
#define DBG_ASSERT_LIMIT(exp, interval, times)
#else
#define DBG_ASSERT(exp)     if (unlikely(!(exp))) \
                            { \
                                DBG_Log(MY_PID, DBG_LOG_EMERG, __FUNCTION__, __LINE__, 0, "Assert fail: (%s)", #exp); \
                            } \
                            _ASSERT(exp)

#define DBG_ASSERT_EXPR(expr, ...) \
            (void) ((!!(expr)) || \
                    (1 != _CrtDbgReport(_CRT_ASSERT, __FILE__, __LINE__, NULL, __VA_ARGS__)) || \
                    (_CrtDbgBreak(), 0))

#define DBG_ASSERT_LIMIT(exp, interval, times) DBG_ASSERT(exp)

#endif
#else

/** \brief ASSERT功能, Linux下面只记录
    \param[in] exp  用于判断真、假的表达式
    \retval    无
    \attention 输出的格式化字符串(含填充好的内容)最长为159个字符(不含结束符)，该词句仅在_DEBUG被定义时有效
    \see DBG_Log()
*/
#define DBG_ASSERT(exp)     if (unlikely(!(exp))) \
                            {\
                                DBG_Log(MY_PID, DBG_LOG_EMERG, __FUNCTION__, __LINE__, 0, "Assert fail: (%s)", #exp); \
                                KDB_ENTER(); \
                                BUG(); \
                            }

#define DBG_ASSERT_EXPR(exp, ...)     if (unlikely(!(exp))) \
                            { \
                                DBG_Log(MY_PID, DBG_LOG_EMERG, __FUNCTION__, __LINE__, 0, __VA_ARGS__); \
                                KDB_ENTER(); \
                                BUG(); \
                            }

#define DBG_ASSERT_LIMIT(exp, interval, times) \
do \
{ \
    OSP_BOOL bCanPrint = FALSE; \
    if (unlikely(!(exp))) \
    { \
	    PRINT_LIMIT(DBG_LOG_ERROR, DBG_LOGID_BUTT, interval, times, bCanPrint); \
        if (TRUE == bCanPrint) \
        { \
		    DBG_Log(MY_PID, DBG_LOG_EMERG, __FUNCTION__, __LINE__, 0, "Assert fail: (%s)", #exp); \
            KDB_ENTER(); \
        } \
    } \
}while(0)

#endif /* WIN32 */

#else
/** \brief ASSERT功能, Linux下面只记录
    \param[in] exp  用于判断真、假的表达式
    \retval    无
    \attention 输出的格式化字符串(含填充好的内容)最长为159个字符(不含结束符)，该词句仅在_DEBUG被定义时有效
    \see DBG_Log()
*/
#define DBG_ASSERT(exp)
#define DBG_ASSERT_EXPR(expr, ...)
#define DBG_ASSERT_LIMIT(exp, interval, times)

#endif  /* _DEBUG */

#define ASSERT(p) DBG_ASSERT(p)
#define ASSERT_LIMIT(exp, interval, times) DBG_ASSERT_LIMIT(exp, interval, times)

/* 定义统一的便于编码 */
#define DBG_LOGID_BUTT   0  /* 兼容以前的 */
#define NO_LOGID         0  /* 代表该条日志没有日志ID */
#define DBG_LOGID_NEW    0 /*HVS新增未分配日志ID*/
#ifdef WIN32
void DBG_SetWin32LogDir(OSP_CHAR *szDir);
#endif

/* 打印频率限制功能，先拿过来，后面再看如何优化 */
#if defined(WIN32) || defined(_PCLINT_)
/* WIN32下不支持使用该功能，下面的定义是为了PC_lint能通过 */
#define PRINT_LIMIT_PERIOD( level, logid, interval, burst, can)             \
do                                                                                              \
{                                                                                                \
    static int print_times = burst;                                                 \
    static int missed = 0;                                                              \
    if (0 < print_times)                                                                \
    {                                                                                           \
    (can) = TRUE;                                                                  \
        print_times--;                                                                   \
    }                                                                                           \
    else                                                                                      \
    {                                                                                           \
        (can) = FALSE;                                                                   \
        missed++;                                                                          \
        if (burst <= missed)                                                           \
        {                                                                                        \
            print_times = burst;                                                        \
            missed = 0;                                                                     \
        }                                                                                        \
    }                                                                                           \
}while(0)

#define PRINT_LIMIT( level, logid, interval, burst, can)                     \
do                                                                                              \
{                                                                                                \
    static int print_times = burst;                                                 \
    static int missed = 0;                                                              \
    if (0 < print_times)                                                                \
    {                                                                                           \
    (can) = TRUE;                                                                  \
        print_times--;                                                                   \
    }                                                                                           \
    else                                                                                      \
    {                                                                                           \
        (can) = FALSE;                                                                   \
        missed++;                                                                          \
        if (burst <= missed)                                                           \
        {                                                                                        \
            print_times = burst;                                                        \
            missed = 0;                                                                     \
        }                                                                                        \
    }                                                                                           \
}while(0)

#elif defined(__KERNEL__) 
/************************************************************************
 * 宏名称: PRINT_LIMINT_PERIOD
 *
 * 功能: 周期性的打印频率控制，第一次允许打印busrt次，
 *             后面每interval的时间最多打印一次
 *
 * 输入参数: interval: 时间周期长度,每隔interval可打印一次
 *                        burst: 初始打印次数
 *
 * 输出参数: can: 布尔值表示是否允许打印
 *
 *************************************************************************/
#define PRINT_LIMIT_PERIOD( level, logid, interval, burst, can)                \
do                                                      \
{                                                       \
    /*使用静态变量保存最大配额，减少运算*/  \
    static OSP_U64 ulMaxToks = (burst) * (interval);                    \
    static OSP_U64 ulToks = (burst) * (interval);                       \
    static OSP_U32 uiMissed = 0;                                    \
    static OSP_U64 ulLast = 0;                                  \
    OSP_U64 ulNow = jiffies;                                    \
                                                        \
    /*更新当前配额*/                                    \
    ulToks += ulNow - ulLast;                                   \
    ulToks = (ulToks > ulMaxToks)?ulMaxToks:ulToks;                 \
    /*如果当前配额大于每次消耗的时间*/          \
    if (ulToks >= (interval))                                   \
    {                                                       \
        if (uiMissed)                                           \
        {                                                   \
            DBG_LogIntf(level, logid,                           \
                    "%d messages suppressed. %s,line=%d.\n",     \
                    uiMissed,__FUNCTION__,__LINE__);          \
        }                                                   \
        /*允许打印，同时配额消耗*/                  \
        ulToks -= (interval);                                       \
        uiMissed = 0;                                           \
        (can) = TRUE;                                           \
    }                                                       \
    else                                                    \
    {                                                       \
        uiMissed++;                                         \
        (can) = FALSE;                                          \
    }                                                       \
    /*更新上一次触发的时间*/                        \
    ulLast = ulNow;                                         \
}while(0)

/************************************************************************
 * 宏名称: PRINT_LIMIT
 *
 * 功能: 打印频率控制，冷却时间大于interval时
 *             就允许打印busrt次
 *
 * 输入参数: interval: 冷却时间
 *                        burst: 每次可打印的次数
 *
 * 输出参数: can: 布尔值表示是否允许打印
 *
 *************************************************************************/
#define PRINT_LIMIT( level, logid, interval, burst, can)                       \
do                                                          \
{                                                           \
    static OSP_U32 uiPrinted = 0;                                   \
    static OSP_U32 uiMissed = 0;                                        \
    static OSP_ULONG ulLast = 0;                                      \
    OSP_ULONG ulNow = jiffies;                                        \
                                                            \
    /*如果两次触发的时间间隔大于设定时间*/           \
    if (time_after_eq(ulNow, ulLast + (interval)))                      \
    {                                                           \
        if (uiMissed)                                               \
        {                                                       \
            DBG_LogIntf(level, logid,                                    \
                    "%d messages suppressed.%s,line=%d.\n",         \
                    uiMissed,__FUNCTION__,__LINE__);              \
        }                                                       \
        /*打印次数清零*/                                    \
        uiPrinted = 0;                                              \
        uiMissed = 0;                                               \
    }                                                           \
                                                            \
    /*打印次数最多为burst次*/                                    \
    if ((burst) > uiPrinted)                                            \
    {                                                           \
        uiPrinted++;                                                \
        (can) = TRUE;                                                    \
    }                                                           \
    else                                                        \
    {                                                           \
        uiMissed++;                                             \
        (can) = FALSE;                                          \
    }                                                           \
    /*更新上一次触发的时间*/                            \
    ulLast = ulNow;                                                 \
}while(0)
#elif defined(__LINUX_USR__) 
#define PRINT_LIMIT_PERIOD( level, logid, interval, burst, can)           \
do                                                                                            \
{                                                                                              \
    (can) = TRUE;                                                                \
}while(0)

#define PRINT_LIMIT( level, logid, interval, burst, can)                   \
do                                                                                            \
{                                                                                              \
    (can) = TRUE;                                                                \
}while(0)

#endif



#endif

/** @} */



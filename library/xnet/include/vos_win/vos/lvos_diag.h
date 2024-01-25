/******************************************************************************
     版权所有 (C) 2010 - 2010  华为赛门铁克科技有限公司
*******************************************************************************
* 版 本 号: 初稿
* 生成日期: 2010年6月21日
* 功能描述: 调试命令行头文件
* 备    注: 
* 修改记录: 
*         1)时间    : 
*          修改人  : 
*          修改内容: 
******************************************************************************/
/**
    \file  lvos_diag.h
    \brief 调试命令行功能
*/

/** \addtogroup VOS_DIAG 调试命令行(new)
    新的调试命令行机制，替代MML, 规范命令格式，提供交互式输入(确认)功能。

    @{
    \example diagnose_example.c 调试命令行使用例子
*/
#ifndef __LVOS_DIAGNOSE_H__
#define __LVOS_DIAGNOSE_H__

#define DBG_RET_UNKNOWN_ARG   1

#define DBG_MAX_COMMAND_LEN   20
#define DBG_MAX_CMD_DESC_LEN  64

#define DBG_MAX_ERR_MSG_LEN   80

typedef void (*FN_DBG_CMD_PROC)(OSP_S32 v_iArgc, OSP_CHAR *v_szArgv[]);
typedef void (*FN_DBG_CMD_HELP_PROC)(OSP_CHAR *v_szCommand, OSP_S32 iShowDetail);

/** \brief 调试命令注册结构 */
typedef struct
{
    OSP_CHAR szCommand[DBG_MAX_COMMAND_LEN];              /**< 命令字, 长度[1,15] */
    OSP_CHAR szDescription[DBG_MAX_CMD_DESC_LEN];         /**< 命令的简要描述 */
    FN_DBG_CMD_PROC fnCmdDo;             /**< 命令执行函数,  v_szArgv[0] 是命令字 */
    FN_DBG_CMD_HELP_PROC fnPrintCmdHelp; /**< 命令打印帮助的函数 */
} DBG_CMD_S;

/** \brief 调试命令参数解析时使用的结构 */
typedef struct
{
    OSP_CHAR *szOptArg; /**< 当选项包含参数内容时，该项指向参数内容 */
    OSP_S32  iOptIndex; /**< 当前处理的argc索引 */
    OSP_CHAR chOpt;     /**< 当发现无效选项的时候该值包含无效的选项字符 */
    OSP_CHAR szErrMsg[DBG_MAX_ERR_MSG_LEN]; /**< 出错时传出错误信息 */
} DBG_OPT_S;

/** 
    \brief 调试命令打印输出接口, 不能在自旋锁中使用
    \param[in] v_pchFormat 输入参数同标准库函数printf
    \param[in] ...         输入参数同标准库函数printf
    \note 该函数只能在调试模块调用fnCmdDo的线程上下文调用，不能在其他线程调用
    \note 该函数不能在自旋锁加锁范围中调用, 需要在加锁中调用请使用\ref DBG_PrintBuf
    \note 该函数和DBG_Log不一样，不会自动在后面加换行
*/
/*lint -printf(1,DBG_Print)*/
void DBG_Print(const OSP_CHAR *v_pchFormat, ...);

/** 
    \brief 调试命令打印输出接口，输出到临时缓冲区，可以在自旋锁中使用
    \param[in] v_pchFormat 输入参数同标准库函数printf
    \param[in] ...         输入参数同标准库函数printf
    \note 该函数只能在调试模块调用fnCmdDo的线程上下文调用，不能在其他线程调用
    \note 由于缓冲区有限制(<2K)，超过缓冲区就会丢失，需要使用者注意
    \note 调用\ref DBG_Print或者处理函数返回会自动将缓冲区中的内容传回客户端
*/
/*lint -printf(1,DBG_PrintBuf)*/
void DBG_PrintBuf(const OSP_CHAR *v_pchFormat, ...);

/** 
    \brief 调试命令打印输出接口, 将指定的缓冲区输出到客户端
    \param[in] v_pchBuf 缓冲区地址
    \param[in] v_uiSize 缓冲区长度
    \note 该函数只能在调试模块调用fnCmdDo的线程上下文调用，不能在其他线程调用
    \note 该函数不能在自旋锁加锁范围中调用
*/
void DBG_SendBuf(const OSP_CHAR *v_pchBuf, OSP_U32 v_uiSize);

/** 
    \brief 输出错误信息和命令简要用法
    \param[in] v_pchFormat 输入参数同标准库函数printf, pchFormat为NULL时仅输出简要用法信息
    \param[in] ...         输入参数同标准库函数printf
    \note 该函数只能在调试模块调用fnCmdDo的线程上下文调用，不能在其他线程调用
*/
void DBG_ShowUsageAndErrMsg(const OSP_CHAR *v_pchFormat, ...);

/** \brief  获取交互式输入
    \param[in]  v_szPrompt      交互式输入的提示符
    \param[out] v_szInput       保存获取到的交互式输入字符串
    \param[in]  v_uiMaxInputLen 获取交互式输入的缓冲区长度, 目前支持的最大长度为63有效字符(不包含'\\0')
    \retval     RETURN_OK     正确获取到用户输入
    \retval     RETURN_ERROR  没有获取到输入(比如客户端退出了)
    \note 该函数只能在调试模块调用fnCmdDo的线程上下文调用，不能在其他线程调用
    \note 该函数会一直阻塞直到客户端退出或者有用户输入为止
*/
OSP_S32 DBG_GetInput(OSP_CHAR *v_szPrompt, OSP_CHAR *v_szInput, OSP_U32 v_uiMaxInputLen);

/** 
    \brief 命令注册接口
    \param[in]  v_pstCmd    注册命令的描述，参考\ref DBG_CMD_S
    \note 该函数内部没有做互斥保护，请尽量在init函数中调用，保证是串行调用的
*/
OSP_S32 DBG_RegCmd(DBG_CMD_S *v_pstCmd);

OSP_S32 DBG_RegCmdToCLI(DBG_CMD_S *v_pstCmd);


/** 
    \brief 注销命令接口
    \param[in]  v_szCommand  注销的命令
*/
void DBG_UnRegCmd(OSP_CHAR *v_szCommand);

void DBG_UnRegCmdToCLI(OSP_CHAR *v_szCommand);



/** 
    \brief 参数解析接口
    \param[in]  v_iArgc         传入调用fnCmdDo时的参数
    \param[in]  v_szArgv        传入调用fnCmdDo时的参数
    \param[in]  v_szOptString   合法的选项列表，如果选项需要参数则在后面加':', 如: "a:bi:dl"，表示合法的选项有abidl，其中a和i需要附加的参数值
    \param[out] v_pstOpt        输出当前解析的附加数据，参考\ref DBG_OPT_S
    \retval  -1     选项处理完成
    \retval  '?'    当前的选项字符不再合法选项列表中
    \retval  DBG_RET_UNKNOWN_ARG      发现非选项字符串
    \retval  其他   返回当前的选项字符
    \attention 该函数只能在调试模块调用fnCmdDo的线程上下文调用，不能在其他线程调用
*/
OSP_S32 DBG_GetOpt(OSP_S32 v_iArgc, OSP_CHAR *v_szArgv[], const OSP_CHAR *v_szOptString, DBG_OPT_S *v_pstOpt);

/** \brief 设置参数包含某个参数
    \param[out] v_puiOptBits 用于保存参数位标识的变量
    \param[in]  iOpt  参数只能是小写字母
*/
void DBG_SetOpt(OSP_U32 *v_puiOptBits, OSP_S32 iOpt);

/** \brief 测试参数是否包含某个参数
    \param[in] uiOptBits 用于保存参数位标识的变量
    \param[in] iOpt 参数只能是小写字母
    \return    不包含返回0, 否则返回非0(注意: 非0不是1)
*/
OSP_S32 DBG_TestOpt(OSP_U32 uiOptBits, OSP_S32 iOpt);

/** \brief 获取U64无符号整数
    \param[in]  pszParam    参数字符串
    \param[out] pullData    传出转换以后的值
    \retval RETURN_OK       转换成功
    \retval RETURN_ERROR    转换失败
*/
OSP_S32 DBG_GetParamU64(const OSP_CHAR *pszParam, OSP_U64 *pullData);

/** \brief 获取U32无符号整数
    \param[in]  pszParam    参数字符串
    \param[out] pullData    传出转换以后的值
    \retval RETURN_OK       转换成功
    \retval RETURN_ERROR    转换失败
*/
OSP_S32 DBG_GetParamU32(const OSP_CHAR *pszParam, OSP_U32 *puiData);

/** \brief 获取指针参数
    \param[in]  pszParam    参数字符串
    \param[out] pullData    传出转换以后的值
    \retval RETURN_OK       转换成功
    \retval RETURN_ERROR    转换失败
*/
OSP_S32 DBG_GetParamPointer(const OSP_CHAR *pszParam, void **ppPointer);

/** \brief 打印地址的内容
    \param[in] v_pvAddr    打印的地址
    \param[in] v_uiLen     打印的长度
*/
void DBG_PrintMemContext(void *v_pvAddr, OSP_U32 v_uiLen);

#endif

/** @} */


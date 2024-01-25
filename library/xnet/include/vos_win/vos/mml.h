/******************************************************************************

                  版权所有 (C), 2008-2010, 华为赛门铁克科技有限公司

 ******************************************************************************
  文 件 名   : mml.h
  版 本 号   : 初稿

  生成日期   : 2008年12月19日
  最近修改   :
  功能描述   : mml的对外接口头文件
  函数列表   :
  修改历史   :
  1.日    期   : 2008年12月19日

    修改内容   : 创建文件

******************************************************************************/
/**
    \file  mml.h
    \brief 调试命令行对外接口描述
    \date 2008-12-19
*/

/** \addtogroup MML  调试命令行MML
    注意: MML功能迭代0以后会取消，请大家不要再使用
    @{ 
*/

#ifndef __MML_H__
#define __MML_H__

/** \brief 注册命令的最大长度(不含结束符) */
#define MML_MAX_CMD_LEN 7       /* 注册命令的最大长度(不含结束符) */

/** \brief 注册命令的结构体 */
typedef struct stDebugMML
{
    OSP_S32     iPid;/**< 模块的PID */

    /* MML将分析用户输入的第一个单词，如果跟achName匹配，则调用本模块的DoMML函数 */
    OSP_CHAR    achName[MML_MAX_CMD_LEN + 1];   /**< 本模块的命令单词。最多8 个字符，不能有空格 */
    
    OSP_S32     iNameNChar;                     /**< 命令单词 的字符个数 */

    OSP_CHAR    *pchModuleName;                 /**< 本模块的名字 */

    /* 处理MML命令的函数，输入是一个字符串，就是用户输入的字符串
       开头的iNameNChar + 1个字符已经被跳过了
       例如用户输入trgt xx，则调用此函数时从xx处传入参数
       在这个函数里面，如果要打印输出，请调用MML_Print()
     */
    void (*DoMML)(OSP_CHAR * v_pchInStr);   /**< 处理MML命令的函数 */
} MML_REG_S;


/** \brief 注册MML命令行处理接口
    \param[in] v_arg  注册结构指针
    \return 无
*/
#ifdef WIN32
__declspec(deprecated("This function will be deleted for future, please use 'DBG_RegCmd' instead."))
#endif
void MML_Register(MML_REG_S *v_arg);

/** \brief 反注册MML命令行处理接口
    \param[in] v_uiPid  模块PID
    \return 无
*/
void MML_UnRegister(OSP_U32 v_uiPid);

/** \brief MML的调试信息输出接口
    \param[in] pcfmt  参数格式和printf一样
    \param[in] ...  参数格式和printf一样
    \return 无
*/
void MML_Print(OSP_CHAR * pcfmt, ...);

#endif  /* __MML_H__ */
/** @} */


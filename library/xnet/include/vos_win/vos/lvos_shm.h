/******************************************************************************

                  版权所有 (C), 2008-2008, 华为赛门铁克科技有限公司

 ******************************************************************************
  文 件 名   : lvos_shm.h
  版 本 号   : 初稿

  生成日期   : 2008年12月23日
  最近修改   :
  功能描述   : 共享内存封装，提供Windows和Linux(用户态)下通用的共享内存使用接口
  函数列表   :
              LVOS_shmget
  修改历史   :
  1.日    期   : 2008年12月22日

    修改内容   : 创建文件

******************************************************************************/
/**
    \file  lvos_shm.h
    \brief Windows下和Linux下统一使用共享内存的接口
    \date 2008-12-24
*/

/** \addtogroup VOS_SHM 共享内存
    注意: 内核态使用限制太大，不建议内核态使用
    @{ 
*/

#ifndef __LVOS_SHM_H__
#define __LVOS_SHM_H__

/*
 * 定义共享内存的读写、执行权限，由于Linux下不支持执行共享内存中的代码，
 * 为了统一，这里不提供执行权限
 */

/** \brief 指定创是创建还是取得，以及读写的权限 */
typedef enum
{
    SHM_READONLY = 1,   /* 以只读方式获取共享内存(不创建) */
    SHM_READWRITE,      /* 以读、写方式获取共享内存(不创建) */
    SHM_CR_READONLY,    /* 创建共享内存，设为只读 */
    SHM_CR_READWRITE    /* 创建共享内存，设为读、写 */
}SHM_FLAG_E;

/*****************************************************************************
 函 数 名  : LVOS_shmget
 功能描述  : 创建、取得一片共享内存
 输入参数  : v_iKey     KEY, 作为创建、取得共享内存的标识
             v_iSize    需要创建的共享内存的大小
             v_iFlag    创建的共享内存的创建和读写权限设置
                        如果没有明确指定创建，则只是用名字来查询取得，但得到的共享内存长度
                        只是它创建时指定的长度，与v_iSize无关
 输出参数  : 无
 返 回 值  : 成功则返回共享内存映射到本进程的地址, 失败则返回 NULL
 调用函数  : 
 被调函数  : 

 注    意  : 在Windows下，进程退出时，如果没有其他进程使用该共享内存，它会被系统自动删除!
 
 修改历史      :
  1.日    期   : 2008年12月23日

    修改内容   : 新生成函数

*****************************************************************************/
/** \brief 创建、取得共享内存
    \note  支持windows/linux_user/linux_kernel, Kernel下只能调用该函数获取的线程能访问共享内存
    \note  同步接口，可能会导致调用者阻塞，不适用于不允许阻塞的调用上下文(如中断处理程序等)
    \param[in] v_iKey 用以标识共享内存的KEY值
    \param[in] v_iSize 共享内存的大小，如果是取得而不是创建，则最终大小以最初创建时的大小为准
    \param[in] v_iFlag 对共享内存的读写权限及创建标记，详见 \ref SHM_FLAG_E
    \return 成功则返回共享内存映射到本进程的地址, 失败则返回 NULL
    \note 在Windows下，进程退出时，如果没有其他进程使用该共享内存，它会被系统自动删除!。 而Linux下不会。
    \see  MSG_FreeMsg
*/
void *LVOS_shmget(OSP_S32 v_iKey, OSP_S32 v_iSize, SHM_FLAG_E v_iFlag);

#if DESC("内存映射文件")
#ifdef __LINUX_USR__
#include <sys/mman.h>
#define FILE_MAP_WRITE  (PROT_READ | PROT_WRITE)
#define FILE_MAP_READ   (PROT_READ)
#endif

/**
    \brief 将文件映射到内存(仅用户态可用)
    \param[in] fd     使用 \ref LVOS_open 打开的文件描述
    \param[in] prot   映射模式, FILE_MAP_WRITE, FILE_MAP_READ
    \param[in] offset 映射偏移地址，各操作系统对偏移地址有限制，如Windows下必须是64K的整数倍
    \param[in] len    映射的长度
    \return    返回映射的地址，NULL标识失败
*/
 void *LVOS_mmap(OSP_S32 fd, OSP_S32 prot, off_t offset, size_t len);

/** 
    \brief 取消文件映射内存(仅用户态可用)
    \param[in] addr LVOS_mmap返回的地址
    \retval RETURN_OK     成功取消
    \retval RETURN_ERROR  失败
*/
 OSP_S32 LVOS_munmap(void *addr);

#endif

#endif /* __LVOS_SHM_H__ */

/** @} */


/******************************************************************************

                  版权所有 (C), 2008-2008, 华为赛门铁克科技有限公司

 ******************************************************************************
  文 件 名   : lvos_file.h
  版 本 号   : 初稿

  生成日期   : 2008年12月29日
  最近修改   :
  功能描述   : 文件操作接口头文件
  函数列表   :
  修改历史   :
  1.日    期   : 2008年12月29日

    修改内容   : 创建文件

******************************************************************************/
/**
    \file  lvos_file.h
    \brief 文件操作对外接口，支持windows、linux内核态和linux用户态。文件操作接口可能会导致调用者阻塞。

    \date 2008-12-29
*/

/** \addtogroup VOS_FILE 文件操作
    @{ 
*/


#ifndef __LVOS_FILE_H__
#define __LVOS_FILE_H__

#define INVALID_FD (-1)

/* 文件路径的最大长度 */
#define MAX_FILE_PATH_LENTH 1024

/* 文件操作中拼接命令的最大长度 命令最多由2个路径和几个字符组成 */
#define MAX_FILE_SHELL_CMD_LEN 4096

/* tar命令需要的操作模式 */
typedef enum tagLVOS_TAR_TYPE_E
{
    LVOS_TAR_TYPE_ARCHIVE = 0, /* 打包 */
    LVOS_TAR_TYPE_EXTRACT,     /* 解包 */
    LVOS_TAR_TYPE_BUTT
} LVOS_TAR_TYPE_E;

#ifdef __KERNEL__
#define NAME_OFFSET(de) ((int) ((de)->d_name - (char __user *) (de)))

struct linux_dirent {
unsigned long    d_ino;      
unsigned long    d_off;      
unsigned short   d_reclen;     
char             d_name[1]; 
}; 


struct getdents_callback {
struct linux_dirent * current_dir;
struct linux_dirent * previous;
int                   count;      
int                   error;
};
#endif

#ifdef WIN32
/* windows下适配unix下的文件权限位，定义下列宏 */
/* 所有者权限 */
#define S_IRUSR S_IREAD
#define S_IWUSR S_IWRITE
#define S_IXUSR S_IEXEC
#define S_IRWXU (S_IRUSR | S_IWUSR | S_IXUSR)

/* windows下暂时这里统一模拟为所有者 */
#define S_IRGRP S_IREAD
#define S_IWGRP S_IWRITE
#define S_IXGRP S_IEXEC
#define S_IRWXG (S_IRGRP | S_IWGRP | S_IXGRP)

#define S_IROTH S_IREAD
#define S_IWOTH S_IWRITE
#define S_IXOTH S_IEXEC
#define S_IRWXO (S_IROTH | S_IWOTH | S_IXOTH)
#else
#define O_TEXT   0  /* Linux下不区分是否是文本 */
#define O_BINARY 0
#endif  /* __KERNEL__ */

/* 检查文件是否存在及是否拥有权限 */
#define MODE_EXIST  00      /* 文件是否存在 */
#define MODE_READ   02      /* 是否拥有读权限 */
#define MODE_WRITE  04      /* 是否拥有写权限 */
#define MODE_RW     06      /* 是否拥有读写权限 */

/** 
    \brief 检查文件是否存在及拥有权限
    \param[in] v_szFilePath 需要检查的文件路径及文件名
    \param[in] v_iMode          需要检查的模式
    \return  检查成功返回 RETURN_OK, 检查失败返回 RETURN_ERROR
    \attention 支持的模式为 MODE_EXIST, MODE_READ, MODE_WRITE, MODE_RW
*/


OSP_S32 LVOS_access(const OSP_CHAR *v_szFilePath, OSP_S32 v_iMode);

/** 
    \brief 打开文件
    \note  同步接口，有可能导致调用者阻塞
    \param[in] v_pcPath     需要打开的文件路径及文件名
    \param[in] v_iFlag      需要打开的文件的属性
    \param[in] v_iMode      需要打开的文件的权限
    \retval    正确打开，返回文件的文件描述符；否则，返回RETURN_ERROR
*/

OSP_S32 LVOS_open(const OSP_CHAR *v_pcPath, OSP_S32 v_iFlag, OSP_S32 v_iMode );

/** 
    \brief 从文件中读取数据
    \note  同步操作接口，从磁盘读取过程中，可能会导致调用者阻塞
    \param[in] v_iFd        需要读取的文件的文件描述符
    \param[in] v_pBuf       用户提供的读入缓冲区
    \param[in] v_ulCount    用户希望读取的字节数
    \retval    正确读取到的字节数，错误返回RETURN_ERROR
*/
OSP_LONG LVOS_read( OSP_S32 v_iFd, void *v_pBuf, OSP_ULONG v_ulCount );

/** 
    \brief 从文件中读取一行数据
    \note  同步操作接口，从磁盘读取过程中，可能会导致调用者阻塞
    \param[in] v_iFd        需要读取的文件的文件描述符
    \param[in] v_pBuf       用户提供的读入缓冲区
    \param[in] v_iMaxSize   最大读取的长度
    \retval    没有读取到返回NULL, 其他情况返回v_pBuf的值
*/
OSP_CHAR *LVOS_readline( OSP_S32 v_iFd, void *v_pBuf, OSP_S32 v_iMaxSize);

/** 
    \brief 向一个文件写入数据
    \note  根据open时传入v_iFlag文件属性的不同，决定是否等待实际的物理I/O完成后返回，但均有可能导致调用者阻塞
    \param[in] v_iFd        需要写入的文件的文件描述符
    \param[in] v_pBuf       用户提供的写入缓冲区
    \param[in] v_ulCount    用户希望写入的字节数
    \retval    正确写入的字节数，错误返回RETURN_ERROR
*/
OSP_LONG LVOS_write( OSP_S32 v_iFd, const void *v_pBuf, OSP_ULONG v_ulCount );

/** 
    \brief 重定位文件指针
    \param[in] v_iFd        需要重定位的文件的文件描述符
    \param[in] v_lOffset    新的文件指针偏移
    \param[in] v_iWhence    文件指针起始位置
    \retval    正确重定位则返回相对于文件起始位置的文件偏移，否则返回RETURN_ERROR
*/
OSP_LONG LVOS_lseek( OSP_S32 v_iFd, OSP_LONG v_lOffset, OSP_S32 v_iWhence );

/** 
    \brief 刷指定的文件缓冲区内容到磁盘
    \note  同步操作接口，实际数据写到磁盘上后返回，因此可能导致调用者阻塞
    \param[in] v_iFd      需要执行刷盘操作的文件的文件描述符 
    \retval RETURN_OK     函数调用成功
    \retval RETURN_ERROR  函数调用失败
*/
OSP_S32 LVOS_sync (OSP_S32 v_iFd);

/** 
    \brief 关闭打开的文件
    \param[in] v_iFd      需要关闭的文件的文件描述符
    \retval RETURN_OK     关闭文件成功
    \retval RETURN_ERROR  关闭文件失败
*/
OSP_S32 LVOS_close( OSP_S32 v_iFd );

/** 
    \brief 拷贝文件
    \param[in] v_pcSrcfile      源文件名
    \param[in] v_pcDestfile     目的文件名
    \retval RETURN_OK     拷贝文件成功
    \retval RETURN_ERROR  拷贝文件失败
*/

OSP_S32 LVOS_copy(const OSP_CHAR * v_pcSrcfile, const OSP_CHAR * v_pcDestfile);




#if DESC("文件锁接口")
/** \brief 文件锁类型定义 */
enum LVOS_FLOCK_TYPE_E
{
    LVOS_FLOCK_TYPE_RDW,   /**< 获取读锁，如果被其他的进程锁了则会等待 */
    LVOS_FLOCK_TYPE_RWW,   /**< 获取读写锁，如果被其他的进程锁了则会等待 */
    LVOS_FLOCK_TYPE_RDNW,  /**< 获取读锁，如果被其他的进程锁了则会立即返回错误 */
    LVOS_FLOCK_TYPE_RWNW   /**< 获取读写锁，如果被其他的进程锁了则会立即返回错误 */
} ;

/** \brief 文件锁描述信息 */
typedef struct
{
    OSP_LONG l_type;    /**< 参考 \ref LVOS_FLOCK_TYPE_E 定义*/
    OSP_LONG l_offset;  /**< 需要锁的内容的偏移地址 */
    OSP_LONG l_len;     /**< 需要锁的内容的长度 */
} LVOS_FLOCK_S;

/** 
    \brief 文件锁加锁
    \param[in] v_iFd      使用\ref LVOS_open打开的文件描述符
    \param[in] v_pstFlock 锁描述信息，参考\ref LVOS_FLOCK_S，如果传入非法之，默认为同步获取读锁
    \note 目前只实现了用户态(Linux和Windows)，文件加锁只在多个使用文件锁的进程之间有效，加锁并不代表其他进程无法访问该文件, 仅在多个加锁操作之间做互斥
    \retval RETURN_OK     成功
    \retval RETURN_ERROR  失败
*/
 OSP_S32 LVOS_LockFile(OSP_S32 v_iFd, LVOS_FLOCK_S *v_pstFlock);

/** 
    \brief 文件锁解锁
    \param[in] v_iFd      使用\ref LVOS_open打开的文件描述符
    \param[in] v_pstFlock 锁描述信息，参考\ref LVOS_FLOCK_S
    \note 目前只实现了用户态(Linux和Windows)
    \retval RETURN_OK     成功
    \retval RETURN_ERROR  失败
*/
 OSP_S32 LVOS_UnLockFile(OSP_S32 v_iFd, LVOS_FLOCK_S *v_pstFlock);

#endif



/*****************************************************************************
 函 数 名  : LVOS_CmdCp
 功能描述  : 文件或目录的拷贝操作
 输入参数  : const OSP_CHAR *v_pcSrcfile   
             const OSP_CHAR *v_pcDestfile  
             OSP_BOOL v_bIsDir             
 输出参数  : 无
 返 回 值  : OSP_S32
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2010年7月1日

    修改内容   : 新生成函数

*****************************************************************************/
/** 
    \brief 文件命令
    \param[in] v_pcSrcfile      源文件
    \param[in] v_pcDestfile     目的文件
    \param[in] v_bIsDir         是否是目录
    \retval RETURN_OK           拷贝文件成功
    \retval RETURN_ERROR        拷贝文件失败
*/

OSP_S32 LVOS_CmdCp(const OSP_CHAR *v_pcSrcfile, const OSP_CHAR *v_pcDestfile, OSP_BOOL v_bIsDir);

/*****************************************************************************
 函 数 名  : LVOS_CmdRm
 功能描述  : 文件或目录的移除操作
 输入参数  : const OSP_CHAR *v_pcfile  
             OSP_BOOL v_bIsDir         
 输出参数  : 无
 返 回 值  : OSP_S32
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2010年7月1日

    修改内容   : 新生成函数

*****************************************************************************/
/** 
    \brief 文件命令
    \param[in] v_pcfile         需要移除的文件或目录
    \param[in] v_bIsDir         是否是目录
    \retval RETURN_OK           移除成功
    \retval RETURN_ERROR        移除失败
*/

OSP_S32 LVOS_CmdRm(const OSP_CHAR *v_pcfile, OSP_BOOL v_bIsDir);

/*****************************************************************************
 函 数 名  : LVOS_CmdTar
 功能描述  : 打包解包命令
 输入参数  : const OSP_CHAR *v_pcfile  
             const OSP_CHAR *v_pcDir   
             OSP_U32 v_uiMode          
 输出参数  : 无
 返 回 值  : OSP_S32
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2010年7月1日

    修改内容   : 新生成函数

*****************************************************************************/
/** 
    \brief 文件命令
    \param[in] v_pcfile         包名
    \param[in] v_pcDir          打包操作: 需要打包的文件(目录);解包操作: 解包目的目录
    \param[in] v_uiMode         打包类型(解包或者打包)
    \retval RETURN_OK           打包成功
    \retval RETURN_ERROR        打包失败
*/

OSP_S32 LVOS_CmdTar(const OSP_CHAR *v_pcfile, const OSP_CHAR *v_pcDir, OSP_U32 v_uiMode);

/*****************************************************************************
 函 数 名  : LVOS_CmdTouch
 功能描述  : 创建文件或修改文件的时间戳(修改文件的时间戳暂不实现)
 输入参数  : const OSP_CHAR *v_pcfile  
             OSP_U32 v_uiMode          
 输出参数  : 无
 返 回 值  : OSP_S32
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2010年7月1日

    修改内容   : 新生成函数

*****************************************************************************/
/** 
    \brief 文件命令
    \param[in] v_pcfile         文件名
    \param[in] v_uiMode         创建文件或修改文件的时间戳
    \retval RETURN_OK           成功
    \retval RETURN_ERROR        失败
*/

OSP_S32 LVOS_CmdTouch(const OSP_CHAR *v_pcfile, OSP_U32 v_uiMode);

/*****************************************************************************
 函 数 名  : LVOS_CmdMv
 功能描述  : 重命名或移动命令
 输入参数  : const OSP_CHAR *v_pcSrcfile   
             const OSP_CHAR *v_pcDestfile  
             OSP_BOOL v_bIsDir             
 输出参数  : 无
 返 回 值  : OSP_S32
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2010年7月1日

    修改内容   : 新生成函数

*****************************************************************************/
/** 
    \brief 文件命令
    \param[in] v_pcSrcfile         源文件名或源目录名
    \param[in] v_pcDestfile        目的文件名或目的目录名
    \param[in] v_bIsDir            是否是目录
    \retval RETURN_OK              成功
    \retval RETURN_ERROR           失败
*/

OSP_S32 LVOS_CmdMv(const OSP_CHAR *v_pcSrcfile, const OSP_CHAR *v_pcDestfile, OSP_BOOL v_bIsDir);

/*****************************************************************************
 函 数 名  : LVOS_CmdMkdir
 功能描述  : 创建目录的命令
 输入参数  : OSP_CHAR *v_pcfile  
 输出参数  : 无
 返 回 值  : OSP_S32
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2010年6月18日

    修改内容   : 新生成函数

*****************************************************************************/
/** 
    \brief 文件命令
    \param[in] v_pcSrcfile         需要创建的目录名
    \retval RETURN_OK              成功
    \retval RETURN_ERROR           失败
*/

OSP_S32 LVOS_CmdMkdir(OSP_CHAR *v_pcfile);

#ifndef _PCLINT_

#ifdef __KERNEL__
/*****************************************************************************
 函 数 名  : LVOS_readdir
 功能描述  : 获取目录内容
 输入参数  : OSP_CHAR *v_pcPath 
             filldir_t filler 回调函数
             void * buf  传进的内存空间
 输出参数  : 无
 返 回 值  : OSP_S32
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2013年3月5日

    修改内容   : 新生成函数

*****************************************************************************/
/** 
    \brief 文件命令
    \param[in] v_pcSrcfile         需要创建的目录名
    \retval RETURN_OK              成功
    \retval RETURN_ERROR           失败
*/

OSP_S32 LVOS_readdir(const OSP_CHAR * v_pcPath, filldir_t filler, void * buf);



/*****************************************************************************
 函 数 名  : LVOS_stat
 功能描述  : 获取文件属性
 输入参数  : OSP_CHAR *v_pcPath 
             struct kstat* buf  返回文件内容
 输出参数  : 无
 返 回 值  : OSP_S32
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2013年3月5日

    修改内容   : 新生成函数

*****************************************************************************/
/** 
    \brief 文件命令
    \param[in] v_pcSrcfile         需要创建的目录名
    \retval RETURN_OK              成功
    \retval RETURN_ERROR           失败
*/

OSP_S32 LVOS_stat(const char* v_pcPath, struct kstat* buf);



/*****************************************************************************
 函 数 名  : LVOS_statfs
 功能描述  : 获取文件系统属性
 输入参数  : OSP_CHAR *v_pcPath 
             struct kstat* buf  返回文件内容
 输出参数  : 无
 返 回 值  : OSP_S32
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2013年3月5日

    修改内容   : 新生成函数

*****************************************************************************/
/** 
    \brief 文件命令
    \param[in] v_pcSrcfile         需要创建的目录名
    \retval RETURN_OK              成功
    \retval RETURN_ERROR           失败
*/

OSP_S32 LVOS_statfs(const char* v_pcPath, struct kstatfs* buf);

#endif
#endif

#endif /* __LVOS_FILE_H__ */

/** @} */



#ifndef _LVOS_PUB_H_
#define _LVOS_PUB_H_

/* 定义操作系统相关宏, 默认为LINUX用户态代码  */
#if defined(WIN32) || defined(_PCLINT_)

#ifndef DESC
#define DESC(x) 1 /* 文件分段描述宏  */
#endif

#ifndef _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE
#endif

#ifdef _PCLINT_
#undef _DEBUG   /* PC-Lint按照Release版本标准进行 */
#endif

#ifndef BUILD_WITH_ACE
#define _CRTDBG_MAP_ALLOC
#endif

#define _WIN32_WINNT 0x0600
#define WIN32_LEAN_AND_MEAN /* windows.h中不包含winsock.h, 下面单独使用winsock2.h */

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winsock2.h>
#include <stddef.h>
#include <io.h>
#include <crtdbg.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <share.h>

/* 自定义头文件  */
#include "vos_win/vos/lvos_version.h"
#include "vos_win/vos/lvos_type.h"          /* 基本类型定义  */
#include "vos_win/vos/return.h"             /* 公共返回码定义  */
#include "vos_win/vos/pid.h"                /* 定义系统的所有PID */
#include "vos_win/vos/lvos_macro.h"         /* 全局宏定义 */
#include "vos_win/vos/lvos_atomic.h"        /* Linux内核的atomic功能仿真 */
#include "vos_win/vos/lvos_bitops.h"        /* 位操作头文件 */
#include "vos_win/vos/lvos_list.h"          /* 链表操作宏定义 */
#include "vos_win/vos/lvos_hash.h"          /* 移植自linux/hash.h, 快速HASH数转换 */
#include "vos_win/vos/lvos_mb.h"            /* 内存屏障 */
#include "vos_win/vos/lvos_lock.h"          /* 信号量、锁等相关定义  */
#include "vos_win/vos/lvos_byteorder.h"     /* 进行字节序转换的功能 */
#include "vos_win/vos/lvos_sched.h"         /* 线程调度头文件 */
#include "vos_win/vos/lvos_debug.h"         /* 调试模块头文件 */
#include "vos_win/vos/lvos_diag.h"
#include "vos_win/vos/lvos_mem.h"           /* 内存管理头文件 */
#include "vos_win/vos/lvos_tracepoint.h"
#include "vos_win/vos/lvos_lib.h"           /* 标准库的封装 */
#include "vos_win/vos/lvos_time.h"          /* 时间功能 */
#include "vos_win/vos/lvos_thread.h"        /* 线程管理相关定义  */
#include "vos_win/vos/lvos_socket.h"        /* socket功能 */
#include "vos_win/vos/lvos_file.h"          /* 进行文件相关操作 */
#include "vos_win/vos/lvos_shm.h"           /* 内存共享头文件 */
#include "vos_win/vos/lvos_wait.h"          /* 等待队列头文件 */
#include "vos_win/vos/lvos_completion.h"    /* 完成变量头文件 */
#include "vos_win/vos/lvos_sysinfo.h"       /* 系统基本信息查询 */
#include "vos_win/vos/lvos_timer.h"         /* 定时器 */
#include "vos_win/vos/lvos_timer2.h"
#include "vos_win/vos/lvos_sched_work.h"    /* 异步调度执行接口 */
#include "vos_win/vos/lvos_syscall.h"       /* VOS层提供的系统调用机制接口 */
#include "vos_win/vos/os_intf.h"            /* OS提供的和硬件强相关的接口 */
#include "vos_win/vos/lvos_stub.h"

/* 上层业务的返回码，为方便使用在这里包含 */
#include "return.h"

/* LINUX_KERNEL  */
#elif defined(__KERNEL__)  
#include <vos/lvos.h>
#include <vos/lvos_callback.h>
#include <vos/lvos_crypt.h>
#include <vos/lvos_file.h>
#include <vos/lvos_hash.h>
#include <vos/lvos_hrtimer.h>
#include <vos/lvos_lib.h>
#include <vos/lvos_list.h>
#include <vos/lvos_lock.h>
#include <vos/lvos_logid.h>
#include <vos/lvos_mem.h>
#include <vos/lvos_sched.h>
#include <vos/lvos_shm.h>
#include <vos/lvos_socket.h>
#include <vos/lvos_syscall.h>
#include <vos/lvos_sysinfo.h>
#include <vos/lvos_thread.h>
#include <vos/lvos_time.h>
#include <vos/lvos_timer.h>
#include <vos/lvos_tracepoint.h>
#include <vos/lvos_version.h>
#include <vos/lvos_wait.h>
#include <vos/lvos_aio.h>
#include <vos/lvos_blk.h>
#include <vos/lvos_zlib.h>
#include <vos/lvos_reboot.h>
#include <vos/os_intf.h>
#include "return.h"

#elif defined(__DPAX_LINUX_USR__) || defined(__DPAX_LINUX__) 
#include "dpax_lvos.h"
#include "return.h"


/* LINUX_USER  */
#else
#if !defined(__KAPI__) && !defined(__KAPI_USR__)
//#define __LINUX_USR__
#endif
//#include <vos/lvos.h>
#endif 
 
#endif /* _LVOS_PUB_H_ */

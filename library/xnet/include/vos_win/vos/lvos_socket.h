/******************************************************************************

                  版权所有 (C), 2008-2008, 华为赛门铁克科技有限公司

 ******************************************************************************
  文 件 名   : lvos_socket.h
  版 本 号   : 初稿
  作    者   : x00001559
  生成日期   : 2008年5月27日
  最近修改   :
  功能描述   : socket功能头文件
  函数列表   :
  修改历史   :
  1.日    期   : 2008年5月27日
    作    者   : x00001559
    修改内容   : 创建文件

******************************************************************************/
/**
    \file  lvos_socket.h
    \brief socket功能头文件
    \note  支持windows/linux_kernel/linux_user，使用过程中可能会导致调用者阻塞，因此不适用于中断等不允许阻塞的上下文

    \date 2008-12-24
*/

/** \addtogroup VOS_SOCKET Socket库
    socket库的接口和标准接口一致，请直接参考标准接口的函数说明
    @{ 
*/

#ifndef _LVOS_SOCKET_H_
#define _LVOS_SOCKET_H_

/* Windows环境下的Vista以下版本不支持 IPv6 */
#if !defined(WIN32) || (_WIN32_WINNT >= 0x0600)
#define IS_OS_SUPPORT_IPV6  1
#else
#define IS_OS_SUPPORT_IPV6  0
#endif


/* 对KSOCKET实现本省做PCLINT时不能使用WIN32的定义 */
#if (defined(WIN32) || defined(_PCLINT_)) && !defined(_PCLINT_KSOCKET_) /* WIN32, link Ws2_32.lib  */

#define SHUT_RD     0
#define SHUT_WR     1
#define SHUT_RDWR   2
#define ADDR_LEN 16

typedef int socklen_t;

/** \brief Windows需要初始化socket库，这里提供相关函数，该函数在linux下为空
    \return 无
*/
static inline void LVOS_SocketInit(void)
{
    WSADATA wsaData;

    /* Windows需要初始化socket库 */
    int iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != NO_ERROR)
    {
        printf("Error at WSAStartup");
    }
}

static inline void LVOS_SocketExit(void)
{
    return;
}

/** \brief socket函数封装 */
#define LVOS_socket       socket
/** \brief bind函数封装 */
#define LVOS_bind         bind
/** \brief listen函数封装 */
#define LVOS_listen       listen
/** \brief accept函数封装 */
#define LVOS_accept       accept
/** \brief connect函数封装 */
#define LVOS_connect      connect
/** \brief sendto函数封装 */
#define LVOS_sendto       sendto
/** \brief send函数封装 */
#define LVOS_send         send
/** \brief recvfrom函数封装 */
#define LVOS_recvfrom     recvfrom
/** \brief recv函数封装 */
#define LVOS_recv         recv
/** \brief closesocket函数封装 */
#define LVOS_closesocket  closesocket
/** \brief inet_addr函数封装 */
#define LVOS_inet_addr(x) (OSP_U32)inet_addr(x)
/** \brief getpeername函数封装 */
#define LVOS_getpeername  getpeername
/** \brief select函数封装 */
#define LVOS_select       select
/** \brief ioctlsocket函数封装 */
#define LVOS_ioctlsocket  ioctlsocket
/** \brief setsockopt函数封装 */
#define LVOS_setsockopt   setsockopt
/** \brief getsockopt函数封装 */
#define LVOS_getsockopt   getsockopt
/** \brief shutdown函数封装 */
#define LVOS_shutdown     shutdown

#elif defined(__LINUX_USR__)
/* Linux用户态  */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netdb.h>

#define LVOS_SocketInit()
#define LVOS_SocketExit()

#define LVOS_socket       socket
#define LVOS_bind         bind
#define LVOS_listen       listen
#define LVOS_accept(s, addr, paddrlen)       accept(s, addr, (socklen_t *)(paddrlen))
#define LVOS_connect      connect
/* Linux用户态统一设置MSG_NOSIGNAL标志，避免由于socket对端非法退出导致进程非法退出 */
#define LVOS_sendto(s, buf, len, flags, to, tolen)  sendto((s), (buf), (len), ((flags) | MSG_NOSIGNAL), (to), (tolen))
#define LVOS_send(s, buf, len, flags)               send((s), (buf), (len), ((flags) | MSG_NOSIGNAL))
#define LVOS_recvfrom     recvfrom
#define LVOS_recv         recv
#define LVOS_closesocket  close
#define LVOS_inet_addr    inet_addr
#define LVOS_getpeername(s, addr, paddrlen)  getpeername(s, addr, (socklen_t *)(paddrlen))
#define LVOS_select       select
#define LVOS_ioctlsocket  ioctl
#define LVOS_setsockopt(s, level, optname, optvalue, optlen)   setsockopt(s, level, optname, optvalue, (socklen_t)(optlen))
#define LVOS_getsockopt(s, level, optname, optvalue, poptlen)   getsockopt(s, level, optname, optvalue, (socklen_t *)(poptlen))
#define LVOS_shutdown     shutdown

#elif defined(__KERNEL__)
#ifndef _PCLINT_
#include <linux/in.h>
#endif

#define SHUT_RD     0
#define SHUT_WR     1
#define SHUT_RDWR   2

typedef int socklen_t;

/* 暂时没有实现select */
void LVOS_SocketInit(void);
void LVOS_SocketExit(void);
int LVOS_socket(int family, int type, int protocol);
int LVOS_bind(int iSocket, struct sockaddr *myaddr, int addrlen);
int LVOS_listen(int iSocket, int backlog);
int LVOS_accept(int iSocket, struct sockaddr *upeer_sockaddr, int *upeer_addrlen);
int LVOS_connect(int iSocket, struct sockaddr *srvraddr, int addrlen);
int LVOS_sendto(int iSocket, void *buff, size_t len, int flags, struct sockaddr *addr, int addr_len);
int LVOS_send(int iSocket, void *buff, size_t len, int flags);
int LVOS_recvfrom(int iSocket, void *buff, size_t size, int flags, struct sockaddr *addr, int *addr_len);
int LVOS_recv(int iSocket, void *buff, size_t size, int flags);
int LVOS_closesocket(int iSocket);
int LVOS_getpeername(int iSocket, struct sockaddr *addr, int *sockaddr_len);
int LVOS_setsockopt(int iSocket, int level, int optname, char *optval, int optlen);
int LVOS_getsockopt(int iSocket, int level, int optname, char *optval, int *optlen);
int LVOS_ioctlsocket(int iSocket, long cmd, unsigned long *argp);
OSP_U32 LVOS_inet_addr(const char *sipaddr);
int LVOS_shutdown(int iSocket, int how);

#else
#error "platform not specify"
#endif




/** \brief 获取管理网口的ipv6地址; 临时方案,该方案会造成os要去感知管理口的存在
    \param[out]  v_szIPString  用于存储取得到管理网口的IP地址字符串的buffer，要求保证有至少40个字节的空间
    \retval RETURN_OK  成功
    \retval RETURN_ERROR 失败
*/
OSP_S32 LVOS_GetMngtIPAddr6(OSP_CHAR *v_szIPString);

/** \brief 根据网络设备名称获取IP地址
    \param[in]  v_szEthName  网络设备名称
    \param[out] v_puiIpAddr  IP地址
    \param[out] v_puiMask    子网掩码，该参数可以为NULL表示不取该项
    \retval RETURN_OK  成功
    \retval RETURN_ERROR 失败
*/
OSP_S32 LVOS_GetEthIPAddr(const OSP_CHAR *v_szEthName, OSP_U32 *v_puiIpAddr, OSP_U32 *v_puiMask);

/** \brief 将OSP_U32 类型的IP 地址转换为字符串型
    \param[in]  stAddr  IP 地址
    \param[out] pszBuf  用于保存转换以后的IP地址的字符串
    \retval IP的字符串地址，如果pszBuf为NULL则返回内部静态变量缓冲区，否则返回pszBuf
*/
OSP_CHAR * LVOS_inet_ntoa(OSP_U32 stAddr, OSP_CHAR *pszBuf);

/** \brief 将设置网口绑定
    \param[in] v_pszBondPortName 绑定名
    \param[in] v_ppszPortName    要绑定的端口名数组
    \param[in] v_uiPortNum       要绑定的端口个数
    \retval RETURN_OK  成功
    \retval RETURN_ERROR 失败
*/
OSP_S32 LVOS_SetBond(OSP_CHAR * v_pszBondPortName, OSP_CHAR * v_ppszPortName[], 
                                                OSP_U32 v_uiPortNum);

/** \brief 将取消网口绑定
    \param[in] v_pszBondPortName  绑定名
    \param[in] v_ppszPortName     要取消绑定的端口名数组
    \param[in] v_uiPortNum        要取消绑定的端口个数
    \retval RETURN_OK  成功
    \retval RETURN_ERROR 失败
*/
OSP_S32 LVOS_CancelBond(OSP_CHAR * v_pszBondPortName,
                                            OSP_CHAR * v_ppszPortName[], OSP_U32 v_uiPortNum);

OSP_S32 LVOS_InitBond(OSP_CHAR *v_pszBondName);
/** \brief 临时设置端口IP，不写入配置文件
    \param[in] v_pszPortName  端口名
    \param[in] v_pIpAddr      IP
    \param[in] v_pNetMask     掩码
    \retval RETURN_OK  成功
    \retval RETURN_ERROR 失败
*/
OSP_S32 LVOS_SetPortIP(OSP_CHAR * v_pszPortName , OSP_CHAR *v_pIpAddr,
                                                OSP_CHAR *v_pNetMask);

/** \brief 获取端口IP
    \param[in] v_pszPortName  端口名
    \param[in] v_pIpAddr      IP
    \param[in] v_pNetMask     掩码
    \retval RETURN_OK  成功
    \retval RETURN_ERROR 失败
*/
OSP_S32 LVOS_GetPortIP(OSP_CHAR * v_pszPortName , OSP_CHAR *v_pIpAddr,
                                                OSP_CHAR *v_pNetMask);

/** \brief 删除端口IP
    \param[in] v_pszPortName  端口名
    \param[in] v_pIpAddr      IP
    \param[in] v_pNetMask     掩码
    \retval RETURN_OK  成功
    \retval RETURN_ERROR 失败
*/
OSP_S32 LVOS_DelPortIP(OSP_CHAR * v_pszPortName , OSP_CHAR *v_pIpAddr,
                                                OSP_CHAR *v_pNetMask);												


/** \brief 添加路由信息到操作系统内核，不写入配置文件
    \param[in] v_pszPortName  端口名
    \param[in] v_pDestAddr    目的IP
    \param[in] v_pDestMask    掩码
    \param[in] v_pGateWay     网关
    \retval RETURN_OK  成功
    \retval RETURN_ERROR 失败
*/
OSP_S32 LVOS_AddPortRoute(OSP_CHAR * v_pszPortName, OSP_CHAR * v_pDestAddr, 
                                                         OSP_CHAR * v_pDestMask, OSP_CHAR * v_pGateWay);

/** \brief 从操作系统内核删除路由信息，不写入配置文件
    \param[in] v_pszPortName 端口名
    \param[in] v_pDestAddr 目的IP
    \param[in] v_pDestMask 掩码
    \param[in] v_pGateWay  网关
    \retval RETURN_OK  成功
    \retval RETURN_ERROR 失败
*/
OSP_S32 LVOS_DelPortRoute(OSP_CHAR * v_pszPortName, OSP_CHAR * v_pDestAddr, 
                                                OSP_CHAR * v_pDestMask, OSP_CHAR * v_pGateWay);

/** \brief 临时设置端口IP，不写入配置文件
    \param[in] 端口名
    \param[in] IP
    \param[in] 掩码长度
    \retval RETURN_OK  成功
    \retval RETURN_ERROR 失败
*/
OSP_S32 LVOS_SetPortIP6(OSP_CHAR * v_pszPortName , OSP_CHAR *v_pIp6Addr,
                                                OSP_U32 iNetMaskLen);

/** \brief 临时删除端口IP，不写入配置文件
    \param[in] 端口名
    \param[in] IP
    \param[in] 掩码长度
    \retval RETURN_OK  成功
    \retval RETURN_ERROR 失败
*/
OSP_S32 LVOS_DelPortIP6(OSP_CHAR * v_pszPortName , OSP_CHAR *v_pIp6Addr,
                                                OSP_U32 iNetMaskLen);

/** \brief 临时添加路由信息，不写入配置文件
    \param[in] 端口名
    \param[in] 目的IP
    \param[in] 掩码长度
    \param[in] 网关
    \retval RETURN_OK  成功
    \retval RETURN_ERROR 失败
*/
OSP_S32 LVOS_AddPortRoute6(OSP_CHAR * v_pszPortName, OSP_CHAR * v_pDestAddr, 
                                                         OSP_S32 iDestMaskLen, OSP_CHAR * v_pGateWay);

/** \brief 临时删除路由信息，不写入配置文件
    \param[in] 端口名
    \param[in] 目的IP
    \param[in] 掩码长度
    \param[in] 网关
    \retval RETURN_OK  成功
    \retval RETURN_ERROR 失败
*/
OSP_S32 LVOS_DelPortRoute6(OSP_CHAR * v_pszPortName, OSP_CHAR * v_pDestAddr, 
                                                OSP_S32 iDestMaskLen, OSP_CHAR * v_pGateWay);

/** \brief 比较两个IP 是否冲突
    \param[in] IP地址1
    \param[in] 掩码
    \param[in] IP地址2
    \param[in] 掩码
    \retval TRUE  冲突
    \retval FALSE 不冲突
*/
OSP_BOOL LVOS_IfIpConflict(OSP_CHAR *v_pIpAddr1, OSP_CHAR * v_pNetMask1, 
                                OSP_CHAR *v_pIpAddr2, OSP_CHAR * v_pNetMask2);

/** \brief 比较两个IPv6 是否冲突
    \param[in] IP地址1
    \param[in] 掩码
    \param[in] IP地址2
    \param[in] 掩码
    \retval TRUE  冲突
    \retval FALSE 不冲突
*/
OSP_BOOL LVOS_IfIpV6Conflict(OSP_CHAR *v_pIpAddr1, OSP_U32 v_uiPrefixLen1, 
                                   OSP_CHAR *v_pIpAddr2, OSP_U32 v_uiPrefixLen2);


/* R2 IPV6 added by f00004188 2011/03/01 begin */
#define LVOS_IN6_IS_ADDR_LINKLOCAL(a)       \
        ((((OSP_U8*)(a))[0] == 0xfe) && (((OSP_U8*)(a))[1] & 0xc0 == 0x80))

#define LVOS_IN6_IS_ADDR_SITELOCAL(a)        \
        ((((OSP_U8*)(a))[0] == 0xfe) && (((OSP_U8*)(a))[1] & 0xc0 == 0xc0))
     

#define LVOS_IN6_IS_ADDR_MULTICAST(a)        \
        (((OSP_U8*)(a))[0] == 0xff)

#define LVOS_IN6_IS_ADDR_LOOPBACK(a)         \
         ((*(OSP_U32 *)(&(a[0])) == 0) &&  \
           (*(OSP_U32 *)(&(a[4])) == 0) &&  \
           (*(OSP_U32 *)(&(a[8])) == 0) &&  \
           (*(OSP_U32 *)(&(a[12])) == 0x01000000))
           
#define LVOS_IN6_ARE_ADDR_EQUAL(a, b)                        \
        (memcmp((OSP_U8*)a, (OSP_U8*)b, sizeof(OSP_U8)*16) == 0)

#define LOVS_IN6_IS_ADDR_UNSPECIFIED(a)         \
        ((*(OSP_U32 *)(&(a[0])) == 0) &&    \
          (*(OSP_U32 *)(&(a[4])) == 0) &&     \
          (*(OSP_U32 *)(&(a[8])) == 0) &&    \
          (*(OSP_U32 *)(&(a[12])) == 0) )

/*suse 对IPV6的网关有限制*/
/*有效的IPV6网关地址的最高八位的二进制区间(00100000-11011111)*/
#define LVOS_IN6_GW_ISVALID(a)                   \
        ((*(OSP_U8*)(&(a[0]))) >= 32 &&   \
        (*(OSP_U8*)(&(a[0]))) <= 223)

#if 1
 /**% INT16 Size */ 
 #define NS_INT16SZ   2  
 /**% IPv4 Address Size */ 
 #define NS_INADDRSZ  4  
 /**% IPv6 Address Size */ 
 #define NS_IN6ADDRSZ    16  

OSP_S32 LVOS_inet_pton4(const char *src, void *dst);     
OSP_S32 LVOS_inet_pton6(const char *src, void *dst);
OSP_S32 LVOS_inet_pton(int af, const char *src, void *dst);
#endif

#endif
/** @} */


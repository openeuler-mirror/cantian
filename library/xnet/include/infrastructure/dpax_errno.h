/*
 * Copyright Notice:
 * Copyright(C), 2014 - 2014, Huawei Tech. Co., Ltd. ALL RIGHTS RESERVED. \n
 */


#ifndef __DPAX_ERRNO_H__
#define __DPAX_ERRNO_H__


#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define MAX_ERRNO       4095


#define DP_TRUE                   (1)

#define DP_FALSE                  (0)

#define DP_ERROR                  (~0)

#define DP_OK                     (0)

#define DP_FAIL                   (~0)

#define DP_ERRNO_PERM             (1)  /* Operation not permitted */

#define DP_ERRNO_NOENT            (2)  /* No such file or directory */

#define DP_ERRNO_SRCH             (3)  /* No such process */

#define DP_ERRNO_INTR             (4)  /* Interrupted system call */

#define DP_ERRNO_IO               (5)  /* I/O error */

#define DP_ERRNO_NXIO             (6)  /* No such device or address */

#define DP_ERRNO_2BIG             (7)  /* Argument list too long */

#define DP_ERRNO_NOEXEC           (8)  /* DP_ERRNO_xec format error */

#define DP_ERRNO_BADF             (9)  /* Bad file number */

#define DP_ERRNO_CHILD           (10)  /* No child processes */

#define DP_ERRNO_AGAIN           (11)  /* Try again */

#define DP_ERRNO_NOMEM           (12)  /* Out of memory */

#define DP_ERRNO_ACCES           (13)  /* Permission denied */

#define DP_ERRNO_FAULT           (14)  /* Bad address */

#define DP_ERRNO_NOTBLK          (15)  /* Block device required */

#define DP_ERRNO_BUSY            (16)  /* Device or resource busy */

#define DP_ERRNO_EXIST           (17)  /* File exists */

#define DP_ERRNO_XDEV            (18)  /* Cross-device link */

#define DP_ERRNO_NODEV           (19)  /* No such device */

#define DP_ERRNO_NOTDIR          (20)  /* Not a directory */

#define DP_ERRNO_ISDIR           (21)  /* Is a directory */

#define DP_ERRNO_INVAL           (22)  /* Invalid argument */

#define DP_ERRNO_NFILE           (23)  /* File table overflow */

#define DP_ERRNO_MFILE           (24)  /* Too many open files */

#define DP_ERRNO_NOTTY           (25)  /* Not a typewriter */

#define DP_ERRNO_TXTBSY          (26)  /* Text file busy */

#define DP_ERRNO_FBIG            (27)  /* File too large */

#define DP_ERRNO_NOSDP           (28)  /* No space left on device */

#define DP_ERRNO_SPIPE           (29)  /* Illegal seek */

#define DP_ERRNO_ROFS            (30)  /* Read-only file system */

#define DP_ERRNO_MLINK           (31)  /* Too many links */

#define DP_ERRNO_PIPE            (32)  /* Broken pipe */

#define DP_ERRNO_DOM             (33)  /* Math argument out of domain of func */

#define DP_ERRNO_RANGE           (34)  /* Math result not representable */

#define DP_ERRNO_DEADLK          (35)             /* Resource deadlock would occur */

#define DP_ERRNO_DEADLOCK        DP_ERRNO_DEADLK /* Resource deadlock would occur */

#define DP_ERRNO_NAMETOOLONG     (36)  /* File name too long */

#define DP_ERRNO_NOLCK           (37)  /* No record locks available */

#define DP_ERRNO_NOSYS           (38)  /* Function not implemented */

#define DP_ERRNO_NOTEMPTY        (39)  /* Directory not empty */

#define DP_ERRNO_LOOP            (40)  /* Too many symbolic links encountered */

#define DP_ERRNO_WOULDBLOCK      (41)  /* Operation would block */

#define DP_ERRNO_NOMSG           (42)  /* No message of desired type */

#define DP_ERRNO_IDRM            (43)  /* Identifier removed */

#define DP_ERRNO_CHRNG           (44)  /* Channel number out of range */

#define DP_ERRNO_L2NSYNC         (45)  /* Level 2 not synchronized */

#define DP_ERRNO_L3HLT           (46)  /* Level 3 halted */

#define DP_ERRNO_L3RST           (47)  /* Level 3 reset */

#define DP_ERRNO_LNRNG           (48)  /* Link number out of range */

#define DP_ERRNO_UNATCH          (49)  /* Protocol driver not attached */

#define DP_ERRNO_NOCSI           (50)  /* No CSI structure available */

#define DP_ERRNO_L2HLT           (51)  /* Level 2 halted */

#define DP_ERRNO_BADE            (52)  /* Invalid exchange */

#define DP_ERRNO_BADR            (53)  /* Invalid request descriptor */

#define DP_ERRNO_XFULL           (54)  /* DP_ERRNO_xchange full */

#define DP_ERRNO_NOANO           (55)  /* No anode */

#define DP_ERRNO_BADRQC          (56)  /* Invalid request code */

#define DP_ERRNO_BADSLT          (57)  /* Invalid slot */

#define DP_ERRNO_BFONT           (58)  /* Bad font file format */

#define DP_ERRNO_NOSTR           (59)  /* Device not a stream */

#define DP_ERRNO_NODATA          (60)  /* No data available */

#define DP_ERRNO_TIME            (61)  /* Timer expired */

#define DP_ERRNO_NOSR            (62)  /* Out of streams resources */

#define DP_ERRNO_NONET           (63)  /* Machine is not on the network */

#define DP_ERRNO_NOPKG           (64)  /* Package not installed */

#define DP_ERRNO_REMOTE          (65)  /* Object is remote */

#define DP_ERRNO_NOLINK          (66)  /* Link has been severed */

#define DP_ERRNO_ADV             (67)  /* Advertise error */

#define DP_ERRNO_SRMNT           (68)  /* Srmount error */

#define DP_ERRNO_COMM            (69)  /* Communication error on send */

#define DP_ERRNO_PROTO           (70)  /* Protocol error */

#define DP_ERRNO_MULTIHOP        (71)  /* Multihop attempted */

#define DP_ERRNO_DOTDOT          (72)  /* RFS specific error */

#define DP_ERRNO_BADMSG          (73)  /* Not a data message */

#define DP_ERRNO_OVERFLOW        (74)  /* Value too large for defined data type */

#define DP_ERRNO_NOTUNIQ         (75)  /* Name not unique on network */

#define DP_ERRNO_BADFD           (76)  /* File descriptor in bad state */

#define DP_ERRNO_REMCHG          (77)  /* Remote address changed */

#define DP_ERRNO_LIBACC          (78)  /* Can not access a needed shared library */

#define DP_ERRNO_LIBBAD          (79)  /* Accessing a corrupted shared library */

#define DP_ERRNO_LIBSCN          (80)  /* .lib section in a.out corrupted */

#define DP_ERRNO_LIBMAX          (81)  /* Attempting to link in too many shared libraries */

#define DP_ERRNO_LIBEXEC         (82)  /* Cannot exec a shared library directly */

#define DP_ERRNO_ILSEQ           (83)  /* Illegal byte sequence */

#define DP_ERRNO_RESTART         (84)  /* Interrupted system call should be restarted */

#define DP_ERRNO_STRPIPE         (85)  /* Streams pipe error */

#define DP_ERRNO_USERS           (86)  /* Too many users */

#define DP_ERRNO_NOTSOCK         (87)  /* Socket operation on non-socket */

#define DP_ERRNO_DESTADDRREQ     (88)  /* Destination address required */

#define DP_ERRNO_MSGSIZE         (89)  /* Message too long */

#define DP_ERRNO_PROTOTYPE       (90)  /* Protocol wrong type for socket */

#define DP_ERRNO_NOPROTOOPT      (91)  /* Protocol not available */

#define DP_ERRNO_PROTONOSUPPORT  (92)  /* Protocol not supported */

#define DP_ERRNO_SOCKTNOSUPPORT  (93)  /* Socket type not supported */

#define DP_ERRNO_OPNOTSUPP       (94)  /* Operation not supported on transport endpoint */

#define DP_ERRNO_PFNOSUPPORT     (95)  /* Protocol family not supported */

#define DP_ERRNO_AFNOSUPPORT     (96)  /* Address family not supported by protocol */

#define DP_ERRNO_ADDRINUSE       (97)  /* Address already in use */

#define DP_ERRNO_ADDRNOTAVAIL    (98)  /* Cannot assign requested address */

#define DP_ERRNO_NETDOWN         (99) /* Network is down */

#define DP_ERRNO_NETUNREACH      (100) /* Network is unreachable */

#define DP_ERRNO_NETRESET        (101) /* Network dropped connection because of reset */

#define DP_ERRNO_CONNABORTED     (102) /* Software caused connection abort */

#define DP_ERRNO_CONNRESET       (103) /* Connection reset by peer */

#define DP_ERRNO_NOBUFS          (104) /* No buffer space available */

#define DP_ERRNO_ISCONN          (105) /* Transport endpoint is already connected */

#define DP_ERRNO_NOTCONN         (106) /* Transport endpoint is not connected */

#define DP_ERRNO_SHUTDOWN        (107) /* Cannot send after transport endpoint shutdown */

#define DP_ERRNO_TOOMANYREFS     (108) /* Too many references: cannot splice */

#define DP_ERRNO_TIMEDOUT        (109) /* Connection timed out */

#define DP_ERRNO_CONNREFUSED     (110) /* Connection refused */

#define DP_ERRNO_HOSTDOWN        (111) /* Host is down */

#define DP_ERRNO_HOSTUNREACH     (112) /* No route to host */

#define DP_ERRNO_ALREADY         (113) /* Operation already in progress */

#define DP_ERRNO_INPROGRESS      (114) /* Operation now in progress */

#define DP_ERRNO_STALE           (115) /* Stale NFS file handle */

#define DP_ERRNO_UCLEAN          (116) /* Structure needs cleaning */

#define DP_ERRNO_NOTNAM          (117) /* Not a XENIX named type file */

#define DP_ERRNO_NAVAIL          (118) /* No XENIX semaphores available */

#define DP_ERRNO_ISNAM           (119) /* Is a named type file */

#define DP_ERRNO_REMOTEIO        (120) /* Remote I/O error */

#define DP_ERRNO_DQUOT           (121) /* Quota exceeded */

#define DP_ERRNO_NOMEDIUM        (122) /* No medium found */

#define DP_ERRNO_MEDIUMTYPE      (123) /* Wrong medium type */

#define DP_ERRNO_NOTINIT         (124) /* module not init */

#define DP_ERRNO_OPFAIL          (125)

#define DP_ERRNO_UNAVAILABLE     (126)

#define DP_ERRNO_SVC_NOT_EXIST   (127)

#define DP_ERRNO_REQ_QUEUE_FULL  (128)

#define DP_ERRNO_UNKNOWN         0x1000     /* Unkown reason */


#define DP_ERRNO_MK_USERNO(n)    (0x1000 + (n))
#define DP_ERRNO_MK_COMMNO(n)    (0x2000 + (n))
#define DP_MID_MK_HI16(MID)      ((MID) << 16)


#define DPAX_ERRNO_XML_MULTI_NODE (DP_MID_MK_HI16(DPAX_MID_XML_CFG) | DP_ERRNO_MK_USERNO(1))

#define DPAX_ERRNO_XML_NODE_NOT_EXIST (DP_MID_MK_HI16(DPAX_MID_XML_CFG) | DP_ERRNO_MK_USERNO(2))

#define DPAX_ERRNO_XML_OPEN_FAIL (DP_MID_MK_HI16(DPAX_MID_XML_CFG) | DP_ERRNO_MK_USERNO(3))

#define DPAX_ERRNO_XML_ATTR_NOT_EXIST (DP_MID_MK_HI16(DPAX_MID_XML_CFG) | DP_ERRNO_MK_USERNO(4))

#define DPAX_ERRNO_XML_NOT_LEAF_NODE (DP_MID_MK_HI16(DPAX_MID_XML_CFG) | DP_ERRNO_MK_USERNO(5))

#define DPAX_ERRNO_XML_PARAM_RELOAD (DP_MID_MK_HI16(DPAX_MID_XML_CFG) | DP_ERRNO_MK_USERNO(6))


#define DP_ERRNO_SPINLOCK_EXIST (DP_MID_MK_HI16(DPAX_MID_SPINLOCK) | DP_ERRNO_MK_USERNO(1))

#define DP_ERRNO_SPINLOCK_NOT_EXIST (DP_MID_MK_HI16(DPAX_MID_SPINLOCK) | DP_ERRNO_MK_USERNO(2))

#define DP_ERRNO_SPINLOCK_NO_FREE (DP_MID_MK_HI16(DPAX_MID_SPINLOCK) | DP_ERRNO_MK_USERNO(3))

#define DP_ERRNO_SPINLOCK_CRT_PARTITION_FAILED (DP_MID_MK_HI16(DPAX_MID_SPINLOCK) | DP_ERRNO_MK_USERNO(4))

#define DP_ERRNO_SPINLOCK_RESERVED_ALLOCED (DP_MID_MK_HI16(DPAX_MID_SPINLOCK) | DP_ERRNO_MK_USERNO(5))

#define DP_ERRNO_SPINLOCK_CORRUPT (DP_MID_MK_HI16(DPAX_MID_SPINLOCK) | DP_ERRNO_MK_USERNO(6))

#define DP_ERRNO_SPINLOCK_SHM_NOT_EXIST (DP_MID_MK_HI16(DPAX_MID_SPINLOCK) | DP_ERRNO_MK_USERNO(7))



#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif /* __DPAX_ERRNO_H__ */

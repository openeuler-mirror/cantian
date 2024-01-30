/******************************************************************************

                  版权所有 (C), 2008-2008, 华为赛门铁克科技有限公司

 ******************************************************************************
  文 件 名   : pid.h
  版 本 号   : 初稿

  生成日期   : 2008年6月16日
  最近修改   :
  功能描述   : 定义系统的所有PID
  函数列表   :
  修改历史   :
  1.日    期   : 2008年6月16日

    修改内容   : 创建文件

  2.日    期   : 2008年11月12日

    修改内容   : 删除_PID_宏
******************************************************************************/

#ifndef __PID_H__
#define __PID_H__

/*模块ID定义*/
/* 系统内最大容量为1024个PID，有效值为1--1023 */
/* 现有的PID不做改动，平台从后往前增加，产品从前往后增加 */
typedef enum tagPID_E
{ 
    PID_OSP_NULL = 0,           /*无效值*/
    PID_OSP_DEBUG = 1,
    PID_RESOURCE = 2,
    PID_MODULE_INTERFACE = 3,
    PID_IBC = 4,
    PID_MML = 5,                /* MML */
    
    /* Begin s2600添加 */
    PID_PRODUCT = 6,
    /* End s2600添加 */
    
    PID_DRV_BIOS = 7,    /*BIOS升级模块*/
    PID_DRV_API = 8,     /*驱动接口层*/

    PID_FC_EVENT = 9,           /* 为驱动定义 */
    
    PID_TSDK = 10,
    PID_TSDK_FRONT = 11,
    PID_TSDK_INI   = 12,        /*TSDK 启动器*/
    PID_TGT_MIDDLE = 13,        /*目标器*/
    PID_SCSI    = 14,           /* SCSI层*/
    PID_SAS_INI = 15,           /* SAS 启动器*/
    PID_IBS_SENDER   = 16,      /* 板间通道模块*/
    PID_IBS_RECEIVER = 17,
    PID_SAS_TGT = 18,           /*SAS目标器helinzhi59137*/
    PID_IBS_MAN = 19,           /* IBS管理模块lixuhui 65736, 20070709*/

    PID_HMP    = 20,            /* 主机多路径*/
    PID_4KPOOL = 21,            /* 4K池模块*/
    PID_CACHE  = 22,            /* CACHE模块*/

    /* Begin s2600添加 */
    PID_APPCM  = 23,            /*典型业务配置模块*/
    /* End s2600添加 */

    PID_RAID_CONTROL = 25,          /*RAID 主控*/
    PID_RP_CACHE_INTERFACE = 26,    /*Cache接口模块*/
    PID_RP_DISK_INTERFACE  = 27,    /*硬盘接口模块*/
    PID_RP_READ  = 28,              /*CACHE读模块*/
    PID_RP_WRITE = 29,              /*CACHE写模块*/
    PID_RP_RECONSTRUCT = 30,        /*重构模块*/
    PID_RP_COPYBACK    = 31,        /*Copyback模块*/
    PID_RP_LUN_FORMAT  = 32,        /* LUN格式化模块*/
    PID_RP_XOR     = 33,            /* XOR模块*/
    PID_RP_MAP     = 34,            /* Map模块*/
    PID_RP_MUTEX   = 35,            /* 互斥模块*/
    PID_RP_LUN_VERIFY =36,

    PID_RP_PRIOSCHED = 37,      /* RAID优先级调度模块 */
    PID_RP_PS = 38 ,            /* RAID磁盘休眠模块 */
    PID_DMP = 39,

    PID_DB = 40,
    PID_ISCSI   = 41,           /* ISCSI*/
    PID_SAFEBOX_CACHE = 42,     /* 保险箱*/
    PID_SAFEBOX_ALARM = 43,     /* 保险箱*/
    PID_SAFEBOX_DB = 44,        /* 保险箱*/

    PID_WEB = 45,            
    OSP_CLI = 46,
    OSP_SYS = 47,       /* 系统管理模块*/

    OSP_DEV = 48,       /* 产品化设备适配管理，为实现在线升级，需要使用原来设备管理的PID*/

    OSP_ALM = 49,       /* 告警日志*/

    OSP_USR   = 50,     /* 用户鉴权*/
    OSP_MLIB  = 51,     /* 通用消息解析*/
    OSP_AGENT = 52,     /* SNMP AGENT*/
    PID_AGENT_CTRL = 53, /* SNMP AGENT 控制模块 */

    OSP_BSP = 55,
    OSP_OS  = 56,
    OSP_MT  = 57,

    /* Begin s2600添加 */
    PID_POWERSAVE_CONTROL = 58,
    PID_SAFEBOX_OS = 59,                   /*OS 保险箱*/
    PID_RAMDISK = 60,                      /*装备测试*/
    /* End s2600添加 */

    PID_NET = 61,                      /*装备测试*/

    PID_DCM_PRE = 62,       /* DCM的预处理 */
    PID_DCM_CMD = 63,       /* DCM的命令解析 */
    PID_DCM_ROUTINE = 64,   /* DCM的例测 */

    PID_SATA_DRV = 65,     /* sata驱动 */
    PID_PCIE_CARD = 66,	/* PCIe驱动 */

    PID_TOE = 67,         /* 网络组TOE */  
    PID_IWARP = 68,       /* 网络组IWARP */


    PID_ISCSI_INI = 70,         /* ISCSI启动器 */
                                
    PID_IB = 71,         /* 交换组IB */  
    PID_ACC = 72,       /* 交换组ACC */

    PID_VAULT = 75,             /* 保险箱 */
    PID_INBAND_AGENT = 76,      /* 带内管理阵列端 */

    PID_VAULT_NVRAM = 77,                  /* VAULT NVRAM模块 */ 

    /* 增值特性begin */
    PID_RSS = 80,               /* Replication Service Subsystem(增值特性子系统) */
    PID_RSF = 81,                    /* Replication Service Frame （增值特性框架） */
    PID_RPR = 82,                    /* Replication Public Resource (增值特性公共资源) */
    PID_BGR = 83,                    /* Background Replication (后台复制) */
    PID_CLN = 84,                    /* 分裂镜像 */
    PID_ECP = 85,                    /* 扩展拷贝模块 */
    PID_LM = 86,                     /* LUN迁移模块 */
    PID_RM = 87,                     /* 远程镜像 */
    PID_CPY = 88,                    /* LUN拷贝 */
    PID_SNAP = 89,                 /* 虚拟快照 */
    PID_TB = 90,         /* 三级跳 */
    PID_TP = 91,         /* Thin Provisioning(自动精简配置) */ 
    PID_TP_ASYNC_IBS = 92,  /* 异步IBS*/
    PID_RSS_UTILITY = 93,    /* 增值特性公共模块*/
    PID_LMR = 94,             /* 卷镜像 */

    PID_SBU_BACKUP = 95,	/*一体化备份*/

    PID_RIM = 96,                   /*复制IO中介模块*/
    PID_DCL = 97,                   /*复制DCL模块*/
    PID_IO_CTRL = 98,               /*复制IO_CTRL模块*/
    PID_REP_IO_UTILITY = 99,        /*复制IO公共模块*/
    
    /* 增值特性end */

    PID_RP_LUN_EXPAND = 100,        /* LUN扩展模块 */
    PID_RP_DYNAMIC = 101,           /* 动态特性模块 */
    PID_RP_COMMSRV = 102,           /* RAID公共服务 */
    PID_RP_RAID6ALGORITHM = 103,    /* RAID6算法 */
    PID_RP_IBC_PROXY = 104,         /* 异步IBC代理 */

    OSP_LICENSE = 105,
    PID_EPL = 110,                  /* 外部交互 external path&Lun  */
    PID_IMP = 111,                  /* 内部I/O转发 */
    PID_EBS_SENDER = 112,           /*EBS发送模块*/
    PID_EBS_RECEIVER = 113,         /*EBS接收模块*/
    PID_EBS_MAN = 114,              /*EBS管理模块*/
    PID_TESTMACHINE = 115,          /* 拷机模式PID */
    
    PID_EA = 116,                   /* 统一版本产品适配层 */
    PID_UG = 117,                   /* 统一版本产品升级 */
    PID_MT = 118,                   /* 统一版本产品烤机 */
    PID_ET = 119,                   /* 统一版本产品装备测试 */
    PID_DISKFAULT = 120,            /* 坏道修复 */
    PID_WS_BUSM = 121,    /* Wushan业务管理模块 */
    PID_WS_MDS = 122,    /* Wushan MDS模块 */
    PID_WS_OSN = 123,    /* Wushan OSN模块 */
    PID_WS_PERF = 124,   /* Wushan性能采集模块 */
    PID_WS_UPGRADE = 125,   /* Wushan升级模块 */
    PID_WS_DEV = 126,      /* Wushan设备管理模块 */
    PID_WS_DEPLOY = 127,      /* Wushan自动部署模块 */
    
    PID_AUTO_DISCOVERY = 128,       /* 开局部署模块，用于自动发现，OMM使用 */

    /* VIS Start */
    PID_SF_REXE_SERV = 130,         /* VIS SF SSHD 服务端 */
    PID_SF_REXE_CLIENT = 131,       /* VIS SF SSHD 客户端 */
    /* VIS end */
    PID_BST = 132,        /* 坏块标记 */
    PID_DHA_VAULT = 133,  /* DHA保险箱模块 */
    
    /* CR: xxxxxx SmartCache liangshangdong 00002039 20100506 add begin */
    PID_SSDC = 134,       /* Smart Cache */
    /* CR: xxxxxx SmartCache liangshangdong 00002039 20100506 add end */

    /*配合OS，保险箱新增512M  BootData空间added by z90003978  20101117 begin*/
    PID_BOOTDATA_VAULT = 135,
    /*配合OS，保险箱新增512M  BootData空间added by z90003978  20101117 end*/

    PID_UPGRADE_C99 = 136, /* c99升级模块 */
    PID_VSTORE = 137,      /* 多租户模块 */


    PID_DETECT_SLOWDISK = 138, /* 新增慢盘检测模块*/


    PID_OSP_BUTT,         /* 产品在此之前定义 */
    
    PID_ST  = 140,         /* 查找表模块 */
    PID_CMM = 21,          /* Cache Memory Management模块 */
    PID_IO_SCHED = 142,    /* IO调度框架模块 */
    PID_IO_PERF = 143,     /* IO性能统计模块 */

    PID_PCIE_IBS = 144,
    PID_PCIE_HP = 145,
    PID_PCIE_BASE = 146,
    PID_DDEV = 147,
    PID_DIO = 148,

    /*Claire Zhong*/
    PID_QUOTA = 149,
    PID_PAGEPOOL = 150,
    PID_BDM = 151,    
    PID_BDM_SD = 152,
    PID_BDM_LD = 153,   
    PID_BDM_HDM = 154,   
    PID_BDM_MP = 155,
    PID_BDM_SCHED = 156,
    PID_BDM_SIO = 157,
    PID_BDM_BA = 158,	
	PID_OVERLOAD_CTRL = 199,     /*过载控制模块id*/
    PID_DEV_LUN = 200,           /* DEV LUN */
    PID_QOS = 201,               /* Qos */
    PID_PAIR = 202,              /* 增值Pair */
    PID_VOLUME = 203,            /* Volume */
    PID_EXTENT = 204,            /* Extent */
    PID_CKG_IOF = 205,           /* CKG_IOF IO框架 */
    PID_CKG_BST = 206,           /* CKG_BST 坏块标记 */
    PID_CKG_DISKLOG = 207,       /* CKG_DISKLOG 硬盘日志 */
    PID_CKG_RESTORE = 208,       /* CKG_RESTORE 坏道修复 */
    PID_CKG_RAID10 = 209,        /* RAID10 raid10算法 */
    PID_CKG_RAID5 = 210,         /* RAID5 raid5算法 */
    PID_CKG_RAID6 = 211,         /* RAID6 raid6算法 */
    PID_CKG_WRITEHOLE = 212,     /* WRITEHOLE writehole处理 */
    PID_BACKSCAN = 213,          /* BACKSCAN 后台扫描 */
    PID_SPA_NODEMGR = 214,       /* SPA_NODEMGR spa节点管理 */
    PID_SPA_LAYOUT = 215,        /* SPA_LAYOUT spa布局管理 */
    PID_SPA_SPACEMGR = 216,      /* SPA_SPACEMGR spa空间管理 */
    PID_SPA_TXMGR = 217,         /* SPA_TXMGR spa事务管理 */
    PID_DISK_SELECT = 218,       /* DISK_SELECT 选盘算法 */
    PID_SPACEMAP = 219,          /* SPACE_MAP 空间图算法 */
    PID_BTREE = 220,             /* BTREE b+tree算法 */
    PID_RECON = 221,             /* RECON 重构模块 */
    PID_LEVELING = 222,          /* LEVELING 均衡模块 */
    PID_DST_MONITOR = 223,       /* DST_MONITOR dst i/o监控 */
    PID_DST_ANALYSE = 224,       /* DST_ANALYSE dst排布分析 */
    PID_DST_PREDICTION = 225,    /* DST_PREDICT dst性能预测 */
    PID_DST_MIGRATION = 226,     /* DST_MIGRATE dst数据迁移 */
    PID_PMGR = 227,              /* PMGR pool管理模块 */
    PID_XNET = 228,
    PID_XRB  = 229,
    PID_EXTENT_INIT = 230,
    PID_DSCP = 231,
    PID_XNET_ETH = 232,
    PID_XNET_PCIE = 233,
    PID_CLS_MSG_FILTER = 234,
    PID_UPGRADE_ATOM = 240,     /* 升级原子 */
    PID_LINK_CFG = 241,         /* 增值的链路配置模块 */
    PID_SYS_EVENT = 242,        /* 系统事件处理模块 */
    PID_HEAL = 243,             /* 自愈框架 */
    PID_SPA_BACKUP = 244,       /* 元数据备份*/
    PID_DIF = 250,              /* DIF公共模块 */
    PID_DISTR_TX_FRAME = 251,   /* 分布式事务框架 */
    PID_LOGZONE = 252,          /* 日志卷模块 */
    PID_CKG_TSF_UNDER = 253,    /* CKG IO转发(StripCache之下) */
    PID_CKG_TSF_ABOVE = 254,    /* CKG IO转发(StripCache之上) */
    PID_USER_POOL =255,           /* UserPoolMgr */

    PID_CLM = 256,               /* 集群分布式锁模块id */
    PID_THROUGH_WRITEHOLE = 257, /* 透写writehole模块id */
    
    PID_VOLUME_CACHE = 258,      /* 一层Cache模块 */
    PID_STRIPE_CACHE = 259,      /* 二层Cache模块 */
	
    PID_SPA_MCACHE = 260,       /* SPA_MCACHE spa元数据cache */

    PID_UPDA = 261,     /* 升级模块 Agent 的定义 */
    PID_CLIADAPTER = 262,     /* CLI命令框架 */
    PID_CKG_DISK = 263, /* CKG DISK IO、格式化 */

    PID_SPACE = 300,                /* space子系统 300 ~ 349 */
    PID_SPACE_PAL = 301,            /* PAL模块id */
    PID_SPACE_CONTROL = 302,        /* Space Control模块id */
    PID_SPACE_IO = 303,             /* Space IO模块id */
    PID_SPACE_TX = 304,
    PID_SPACE_SNAP = 305,  /* 文件系统快照模块id*/
    PID_CONTEXT = 306,              /* Context模块id */
    PID_KVDB = 307,                 /*KV DB模块id */
    PID_SPACE_NOTIFY = 308,         /* Notify模块id */
    PID_SPACE_FILE_COUNT = 309,
    

    PID_GRAIN = 310,                /* 变长分配器模块id */

    PID_SNAS = 311,                 /* 文件系统协议模块id */
    PID_SPACE_SCHED = 312,          /* 文件系统后台统一调度 */
    PID_PAL_FORWORD = 313,

    PID_SPACE_FLOW_CTRL = 314,   /* 文件系统过载控制模块id*/
    PID_SPACE_RAL = 315,         /* 文件系统RAL模块id*/
	PID_FS_AV = 316,
    PID_SPACE_UB  = 317,         /* 文件系统UB模块id*/

    PID_SPACE_ERR_3 = 347,          /* Space错误码专用id */
    PID_SPACE_ERR_2 = 348,          /* Space错误码专用id */
    PID_SPACE_ERR_1 = 349,          /* Space错误码专用id，从下往上使用 */
	
	PID_DDP = 350,  /* 重删压缩模块id */
	PID_CROSS_CLS = 599,  /* 跨站点集群管理id */
    
   	/* 集群新增模块 */
	PID_CLUSTER_MSG_FRAMEWORK = 600, /*消息适配、消息框架*/
	PID_CLUSTER_CAB = 601,    /*集群原子通信*/
	PID_CLUSTER_DLM = 602,    /*分布式锁管理*/
	PID_CLUSTER_CCDB_SERVER = 603, /*CCDB服务端*/
	PID_CLUSTER_CCDB_CLIENT = 604, /*CCDB客户端*/
	PID_CLUSTER_PAXOS = 605,    /*集群Paxos*/
	PID_CLUSTER_RPM = 606,		/*RPM消息处理*/
	PID_CLUSTER_EVENT = 607,    /*集群事件中心（适配用户态）*/
	PID_CLUSTER_LIB = 608, 		/*集群基础库*/
	PID_CLUSTER_CNM = 609,		/*集群节点管理*/
	PID_CLUSTER_MSG_BNET = 610,  /*集群通信封装模块*/

    /* 复制新增模块[630~649] */
    PID_TCP_LINK = 630,       /* 向EPL提供基于TCPIP的私有传输协议的通信链路 */
	PID_CPS = 631,           /* 双活仲裁模块*/
	PID_REP_HC = 632,        /* 双活特性控制模块*/
	PID_VMG = 633,        /* 租户迁移控制模块*/
	PID_REPRM = 634,        /* 文件远程复制控制模块*/
	PID_REPTMP = 635,      /* 复制模板 */
    PID_REPSVC = 636,        /* 复制服务控制模块*/
    PID_REPRPC = 637,        /* 复制RPC控制模块*/
    PID_SDD = 638,           /* 复制压缩模块*/
    PID_ARB = 639,           /* 双活仲裁模块*/
    PID_ARB_AGENT = 640,     /* 双活仲裁用户态模块PID */
    
	/* 协议新增模块650~699 */
	PID_PROTO_OMAGENT = 650,	/*NAS协议消息代理*/
	PID_PROTO_SYSCTRL = 651,  /*NAS协议系统控制模块*/
	
	
	
    /* PID 700-799区段分配给盘古平台新增模块 begin*/
    PID_SAS_INI_SAL = 705,	/*12g sas*/
    PID_FC_UNF = 710,		/*16G FC*/
    PID_BSPA = 715,             /*BSP适配层*/
    PID_DSWA = 720,             /*交换机适配层*/
    PID_ISCSI_TRANS_SW = 750, /*自研iSCSI传输层模块*/
    PID_FCOE = 770,

    PID_DMI = 730,              /*PANGEA设备管理框架*/


    /* PID 700-799区段分配给盘古平台新增模块 end*/
    
    /* 移植C3模块PID */
    PID_MSG_ADAPTER = 806,       /* 消息适配模块 */
    PID_TRANSFER_DEBUG = 807,    /* 消息调试模块 */

    PID_HAB = 808,               /*  heart beat */
    PID_MEMP = 809,               /*多控设备管理消息转发*/
    PID_FTDS = 900,         /* FTDS模块 */

    /* 平台定义的PID */
    PID_LOG_CBB = 948,
    PID_MSG_CHECK = 949,
    PID_UTOP_BEGIN = 950,
	
    PID_PERF_SAMPLE = PID_UTOP_BEGIN,   /* 性能统计采样端 */
    PID_PERF_MANAGE = 951,   /* 性能统计管理端 */

    PID_LOCK  = 952,       /* 全局锁模块 */
    PID_LOCK_CLIENT = 953, /* 全局锁模块 */
    PID_DAB  = 954,        /* 数据原子广播模块 */
    PID_MAST = 955,        /*主备管理用户态*/
    PID_DHA_SCHED = 956,   /* DHA调度器 */
    PID_SIMULATOR = 957, /* 仿真 */
    PID_DHA_COLLECTOR = 958, /* DHA 驱动采集器 */
    PID_SCM = 959,           /* SCM 主程序 */
    PID_SCM_KRN = 960,       /* SCM 内核程序 */
    PID_AA_KERNEL = 961,    /* AUTH 内核程序 */
    PID_OM_SYNC = 962,         /* SYNC 主进程 */
    PID_VMMS_KERNEL = 963,    /* VMMS内核代理 */
    PID_VMMS = 964,
    PID_ILOCK = 965,        /* IO范围锁 */
    PID_ASYNC_LOCK = 966,   /* 异步锁 */
    
    PID_VOS = 997,          /*vos*/
    PID_OS_TOOL = 998,      /* OS TOOL */
    PID_MC  = 999,          /* 消息兼容性转换 */
    PID_MSG = 1000,
    PID_MSG_SERVER = 1001,
    PID_MSG_CLIENT = 1002,

    PID_MMT = 1003,         /* 网管消息分发模块 */
    PID_MMT_KERNEL = 1004,  /* 网管消息分发模块内核态 */
    PID_MMT_NOTIFY  = 1005, /* 主动上报模块 */

    PID_AA = 1006,

    PID_LIC_KERNEL = 1007,  /* License模块内核态 */

    PID_LIB_STD = 1008,     /* 标准库 */

    PID_UPGRADE = 1009,     /* 升级模块的定义 */

    PID_PERF_KERNEL = 1010, /* 性能统计内核态 */
    PID_PERF_USER = 1011,   /* 性能统计用户态 */
    PID_DCM = 1012,         /* 物理通信模块 */
    PID_EVENT = 1013,       /* 事件中心模块 */
    PID_UPGRADE_KERNEL = 1014,
    PID_OS_SYNC_DISK = 1015, /*os 启动盘同步使用*/
    PID_OS_FIRE_HDD = 1016,  /* usb启动烧硬盘使用 */
    PID_OS_TEST = 1017,      /* OS模拟系统故障复位 */
    PID_OS_DEBUG = 1018,     /* OS Debug */
    PID_ECONF = 1019,        /* 可扩展的配置文件模块 */
    PID_EML = 1020,          /* 仿真pid */
    PID_GEM = 1021,
    PID_VERSION = 1022,    /* 用于查看各子模块版本号的MML命令 */
    PID_DEBUG = 1023,       /* 平台DBG模块 */


    PID_UTOP_BUTT = 1024    /* 最大PID */
} PID_E;


#ifndef INVALID_PID
#define INVALID_PID 0
#endif

#define MAX_PID_NUM 1024


#endif


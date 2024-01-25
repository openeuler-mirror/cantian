/**
 *          Copyright 2011 - 2015, Huawei Tech. Co., Ltd.
 *                      ALL RIGHTS RESERVED
 *
 * dsw_id.h
 *

 * @create: 2012-04-13
 *
 */

#ifndef __DSW_ID_H__
#define __DSW_ID_H__


#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

#ifdef __DFV_VERSION__
enum dsw_mod_id_definition 
{
    DSW_MID_CORE = 0,
    DSW_MID_MEM =1,
    DSW_MID_TIMER=2,
    DSW_MID_OSDDATANET=3,
    DSW_MID_VBSDATANET=4,
    DSW_MID_MDCDATANET=5,
    DSW_MID_OSDHBNET=6,
    DSW_MID_MSG=7,
    DSW_MID_MDC=8,
    DSW_MID_MDCHB=9,
    DSW_MID_RSM=10,
    DSW_MID_SNAP=11,
    DSW_MID_CACHE=12,
    DSW_MID_CLIENT=13,
    DSW_MID_VBS=14,
    DSW_MID_VBP=15,
    DSW_MID_AIO_DM=16,
    DSW_MID_SCSI=17,
    DSW_MID_SMARTCACHE=18,
    DSW_MID_OM=19,
    DSW_MID_VBSHB=20,
    DSW_MID_FLOWCTRL=21,
    DSW_MID_ISCSI=22,
    DSW_MID_FAULT=23,
    DSW_MID_VFS=24,
    DSW_MID_VFSDATANET=25,
    DSW_MID_VFSHB=26,
    DSW_MID_MDCCALC=27,

    //TODO: vbs multi_thead tmp -- del -- Multi thread
    DSW_MID_VBSDATANET1 = 28,
    DSW_MID_VBSDATANET2 = 29,
    DSW_MID_VBSDATANET3 = 30,
    DSW_MID_VBSDATANET4 = 31,
    DSW_MID_VBSDATANET5 = 32,    
    DSW_MID_VBSDATANET6  = 33,
    DSW_MID_VBSDATANET7 = 34,
    DSW_MID_VBSDATANET8 = 35,
    DSW_MID_VBSDATANET9 = 36,
    DSW_MID_VBSDATANET10 = 37,
    DSW_MID_VBSDATANET11 = 38,
    DSW_MID_VBSDATANET12 = 39,
    
    DSW_MID_INTERFACE = 40,
    DSW_MID_LIBCLIENT_DATANET = 41,
    DSW_MID_LIBCLIENT_DATANET1 = 42,
    DSW_MID_LIBCLIENT_DATANET2 = 43,
    DSW_MID_LIBCLIENT_DATANET3 = 44,
    DSW_MID_LIBCLIENT_DATANET4 = 45,
    DSW_MID_LIBCLIENT_DATANET5 = 46,
    DSW_MID_VBS_ASSIST         = 47,
    DSW_MID_DEBUG              = 48,    //insight tool mid
    
    DSW_MID_AGENT              = 200,   //agent mid, corresponding define is AGENT_DEFAULT_HEAD in agent
    DSW_MID_NR,
};
#else
enum dsw_mod_id_definition 
{
    DSW_MID_CORE = 0,
    DSW_MID_MEM =1,
    DSW_MID_TIMER=2,
    DSW_MID_OSDDATANET=3,
    DSW_MID_VBSDATANET=4,
    DSW_MID_MDCDATANET=5,
    DSW_MID_OSDHBNET=6,
    DSW_MID_MSG=7,
    DSW_MID_MDC=8,
    DSW_MID_MDCHB=9,
    DSW_MID_RSM=10,
    DSW_MID_SNAP=11,
    DSW_MID_CACHE=12,
    DSW_MID_CLIENT=13,
    DSW_MID_VBS=14,
    DSW_MID_VBP=15,
    DSW_MID_AIO_DM=16,
    DSW_MID_SCSI=17,
    DSW_MID_SMARTCACHE=18,
    DSW_MID_OM=19,
    DSW_MID_VBSHB=20,
    DSW_MID_FLOWCTRL=21,
    DSW_MID_ISCSI=22,
    DSW_MID_FAULT=23,
    DSW_MID_VFS=24,
    DSW_MID_VFSDATANET=25,
    DSW_MID_VFSHB=26,
    DSW_MID_MDCCALC=27,

    //TODO: vbs multi_thead tmp -- del -- Multi thread
    DSW_MID_VBSDATANET1 = 28,
    DSW_MID_VBSDATANET2 = 29,
    DSW_MID_VBSDATANET3 = 30,
    DSW_MID_VBSDATANET4 = 31,
    DSW_MID_VBSDATANET5 = 32,    
    //replication
    DSW_MID_REP_SPLITTER = 33,
    DSW_MID_REP_ADAPTER = 34,
    
    //KVS
    DSW_MID_KVS                 = 35,
    DSW_MID_KVSDATANET   =36,
    DSW_MID_KVSHB             =37,
    DSW_MID_KVSDATANET1 = 38,
    DSW_MID_KVSDATANET2 = 39,
    DSW_MID_KVSDATANET3 = 40,
    DSW_MID_KVSDATANET4 = 41,
    DSW_MID_KVSDATANET5 = 42,
    DSW_MID_VBS_ASSIST    = 43,

    DSW_MID_MDCCFM = 44,
    //DGW
    DSW_MID_DGW         = 45,
    DSW_MID_DGWDATANET  = 46,

    //LLD
    DSW_MID_LOCK = 47,
    
    DSW_MID_EC_RSM = 48,
    DSW_MID_ECCACHE_RSM = 49,
    DSW_MID_ECC_SNAP = 50,
    DSW_MID_OSDDATANET1 = 51,

    DSW_MID_HC   = 52,
    //LINKER
    DSW_MID_LINKER      = 53,
    DSW_MID_LINKERDATANET=54,    

    DSW_MID_PLOGCLIENT_CLIENT    = 60,
    DSW_MID_PLOGCLIENT           = 61,
    DSW_MID_PLOGCLIENTHB         = 62,
    
    DSW_MID_PLOGCLIENT_DATANET   = 63,
    DSW_MID_PLOGCLIENT_DATANET1  = 64,
    DSW_MID_PLOGCLIENT_DATANET2  = 65,
    DSW_MID_PLOGCLIENT_DATANET3  = 66,
    DSW_MID_PLOGCLIENT_DATANET4  = 67,
    DSW_MID_PLOGCLIENT_DATANET5  = 68,
    DSW_MID_PLOGCLIENT_DATANET6  = 69,
    DSW_MID_PLOGCLIENT_DATANET7  = 70,
    DSW_MID_PLOGCLIENT_DATANET8  = 71,
    DSW_MID_PLOGCLIENT_DATANET9  = 72,
    DSW_MID_PLOGCLIENT_DATANET10 = 73,
    DSW_MID_PLOGCLIENT_DATANET11 = 74,
    DSW_MID_PLOGCLIENT_DATANET12 = 75,

    DSW_MID_REP_RSF            = 81, /* Replication RSF module, reserved for upgrade. */ 
    DSW_MID_INTERFACE          = 82,
    DSW_MID_DEBUG              = 83,    //insight tool mid
/*
    DSW_MID_VBSDATANET6  = 84,
    DSW_MID_VBSDATANET7 = 85,
    DSW_MID_VBSDATANET8 = 86,
    DSW_MID_VBSDATANET9 = 87,
    DSW_MID_VBSDATANET10 = 88,
    DSW_MID_VBSDATANET11 = 89,
    DSW_MID_VBSDATANET12 = 90,
*/
    DSW_MID_XNET               = 91,
    
    DSW_MID_REP_UTILITY        = 93, /* Replication UTITLITY module, reserved for upgrade. */ 
/*
    DSW_MID_OSDDATANET2       = 92,
    DSW_MID_OSDDATANET3       = 93,
    DSW_MID_OSDDATANET4       = 94,
    DSW_MID_OSDDATANET5       = 95,
    DSW_MID_OSDDATANET6       = 96,
    DSW_MID_OSDDATANET7       = 97,
    DSW_MID_OSDDATANET8       = 98,
    DSW_MID_OSDDATANET9       = 99,
    DSW_MID_OSDDATANET10      = 100,
*/
    DSW_MID_MDC_STUB             = 101,

    DSW_MID_XNETDATANET1         = 102,
    DSW_MID_XNETDATANET2         = 103,
    DSW_MID_XNETDATANET3         = 104,
    DSW_MID_XNETDATANET4         = 105,
    DSW_MID_QOS                  = 106,

    DSW_MID_UC_LOCAL_MEM         = 107,
    DSW_MID_REP_NGW              = 110, /* Replication NGW module, reserved for upgrade. */ 
    
    DSW_MID_LIBCLIENT_DATANET  = 111,
    DSW_MID_LIBCLIENT_DATANET1 = 112,
    DSW_MID_LIBCLIENT_DATANET2 = 113,
    DSW_MID_LIBCLIENT_DATANET3 = 114,
    DSW_MID_LIBCLIENT_DATANET4 = 115,
    DSW_MID_LIBCLIENT_DATANET5 = 116,

    DSW_MID_AGENT                = 200,   //agent mid, corresponding define is AGENT_DEFAULT_HEAD in agent
    DSW_MID_REP_DMSAGENT         = 200, /* Replication DMS_AGENT module, reserved for upgrade. Both AGENT and DMS_AGENT 
                                                use the same value 200 for legacy code. NOTICE that these two module should not
                                                be in the same process.*/
    DSW_MID_NR
};
#endif


#define DSW_MID_GLOBAL DSW_MID_NR
#define DSW_MID_POOL (DSW_MID_NR + 1)

#define GLOBAL_AND_POOL 2

#define DSW_MID_VDB   DSW_MID_SNAP
#define DSW_OSD_PID   666   //temp define for use infr libs


static inline dsw_bool check_is_libclient_mid(dsw_u32 mid)
{
    return (DSW_MID_INTERFACE <= mid && mid <= DSW_MID_LIBCLIENT_DATANET5) ? DSW_TRUE : DSW_FALSE;
}

static dsw_u16 g_file_id = DSW_NULL_WORD;

inline static dsw_u16 get_file_id(const char *file_name)
{
    extern dsw_u16 dsw_om_get_file_id(const char* file_name);

    if (DSW_NULL_WORD == g_file_id)
    {
        g_file_id = dsw_om_get_file_id(file_name);
    }

    return g_file_id;
}
inline static void file_id_init()
{
    extern dsw_u16 dsw_om_get_file_id(const char* file_name);
    g_file_id = dsw_om_get_file_id(__FILE__);
}

#ifdef __cplusplus
}
#endif /* __cpluscplus */

#endif /* __DSW_ID_H__ */

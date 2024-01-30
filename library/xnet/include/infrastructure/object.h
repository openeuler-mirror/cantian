/**************************************************************************

    (C) 2007 ~2019   华为赛门铁克科技有限公司  版权所有，保留一切权利。

***************************************************************************
 版 本 号:  初稿
 作    者:  zhaowang+00000895
 完成日期:  2011年8月15日
 功能描述:  业务公共对象定义
 备    注:
 修改记录:
        1.时    间 :
          修 改 人 :
          修改内容 :
**************************************************************************/
#ifndef XVE_OBJECT_H
#define XVE_OBJECT_H


typedef uint16_t vnodeid_t;
#define INVALID_VNODE_ID (INVALID_VALUE16) 

typedef uint32_t lunid_t;
typedef uint32_t filesystemid_t;
#define INVALID_LUN_ID 0xffffffff
#define INVALID_FS_ID 0xffffffff
#define GET_LUN_TYPE(lunId) ((((lunid_t)(lunId)) >> 28) & 0x0F)
#define SET_LUN_TYPE(lunId, lunType) \
    (((((lunid_t)(lunType)) << 28) & 0xF0000000) ^ (lunId))

#define GET_LUN_INDEX(lunId) ((lunid_t)(lunId) & 0xFFFFF)

typedef enum tagLUN_TYPE_E
{
    LUN_TYPE_INNER = 0,
    LUN_TYPE_EXT_PRIVATE = 1,
    LUN_TYPE_EXT_3RD = 2,
    LUN_TYPE_VIRTUAL = 3,

    LUN_TYPE_BUTT
} LUN_TYPE_E;

#define SET_INTERNAL_LUNID(lunId)        ((lunid_t)(lunId))

#define SET_EXT_PRIVATE_LUNID(arrayId, devLunId) \
    ((((lunid_t)LUN_TYPE_EXT_PRIVATE << 28) & 0xF0000000) | (((lunid_t)(arrayId) << 20) & 0x0FF00000) | ((lunid_t)(devLunId)))

#define SET_EXT_3RD_LUNID(thdLunId) \
    ((((lunid_t)LUN_TYPE_EXT_3RD << 28) & 0xF0000000) | ((lunid_t)(thdLunId)))

#define SET_VIRTUAL_LUNID(devLunId) \
    ((((lunid_t)LUN_TYPE_VIRTUAL << 28) & 0xF0000000) | ((lunid_t)(devLunId)))

#define GET_LUN_TYPE_BY_LUNID(lunId)    (((lunid_t)(lunId) >> 28) & (0x0F))

#define GET_ARRAY_ID_BY_PRIVATE_LUNID(lunId)    (((lunid_t)(lunId) >> 20) & (0xFF))

#define GET_DEVLUN_ID_BY_PRIVATE_LUNID(lunId)   (((lunid_t)(lunId)) & (0xFFFFF))

#define GET_THDLUN_ID_BY_3RD_LUNID(lunId)   (((lunid_t)(lunId)) & (0xFFFFFFF))

#define GET_DEVLUN_ID_BY_VIRTUAL_LUNID(lunId)   (((lunid_t)(lunId)) & (0xFFFFFFF))

typedef uint32_t poolid_t;

#define INVALID_POOL_ID 0xffffffff

typedef uint32_t diskid_t;

#define INVALID_DISK_ID 0xffffffff

typedef uint64_t volumeid_t;

#define INVALID_VOLUME_ID 0xffffffffffffffff
#define GET_VOL_PARENT_TYPE(volId) ((((volumeid_t)(volId)) >> 60) & 0x0F)
#define SET_VOL_PARENT_TYPE(volId, parentType) \
    (((((volumeid_t)(parentType)) << 60) & 0xF000000000000000) ^ (volId))
typedef enum
{
    VOL_PARENT_TYPE_LUN = 0,
    VOL_PARENT_TYPE_POOL,
    VOL_PARENT_TYPE_LOG_VOL = VOL_PARENT_TYPE_POOL,
    VOL_PARENT_TYPE_BUTT
} VOL_PARENT_TYPE_E;

#define GET_VOL_PARENT_ID(volId) (((volumeid_t)(volId)) & 0xFFFFFFFF)
#define SET_VOL_PARENT_ID(volId, parentId) \
    ((((volumeid_t)(parentId)) & 0xFFFFFFFF) ^ (volId))

typedef uint32_t ckgid_t;

#define INVALID_CKG_ID 0xffffffff

#define GENERATE_CKG_ID(tierType, pairId, appType, index) \
    (((index) & 0x1ffffffU) ^ (((appType) &0x1U) << 25) ^ (((pairId) & 0xfU) << 26) ^ (((tierType) & 0x3U) << 30))

#define GET_CKG_TIER_TYPE(ckgId) ((((ckgid_t)(ckgId)) >> 30) & 0x03)

#define GET_CKG_PAIR_ID(ckgId) ((((ckgid_t)(ckgId)) >> 26) & 0x0f)

#define GET_CKG_APP_TYPE(ckgId) ((((ckgid_t)(ckgId)) >> 25) & 0x01)

#define GET_CKG_INDEX(ckgId) (((ckgid_t)(ckgId))  & 0x01ffffff)

#define SET_CKG_INDEX(ckgId, index) \
    (((ckgId) & (0xfe000000)) ^ ((index) & 0x01ffffff))

#define INVALID_EXTENT_ID 0xffffffffffffffff

typedef uint64_t extentid_t;

typedef enum
{
    EXTENT_TYPE_ROOT,
    EXTENT_TYPE_META,
    EXTENT_TYPE_DATA_THICK,
    EXTENT_TYPE_DST,
    EXTENT_TYPE_DATA_THIN,
    EXTENT_TYPE_DATA_COW,
    EXTENT_TYPE_DATA_WITH_MAP
} EXTENT_ID_TYPE_E;

#define EXTENT_ZONE_INDEX_SHIFT   53
#define EXTENT_ZONE_INDEX_BITS    11
#define EXTENT_ZONE_INDEX_MASK    ((((uint64_t)1) << EXTENT_ZONE_INDEX_BITS) - 1)
#define GET_EXTENT_ZONE_INDEX(extentId) \
    (((extentId) >> EXTENT_ZONE_INDEX_SHIFT) & EXTENT_ZONE_INDEX_MASK)
#define SET_EXTENT_ZONE_INDEX(extentId, index) \
    (((extentId) & ~(EXTENT_ZONE_INDEX_MASK << EXTENT_ZONE_INDEX_SHIFT)) \
     | (((index) & EXTENT_ZONE_INDEX_MASK) << EXTENT_ZONE_INDEX_SHIFT))



#define EXTENT_TYPE_SHIFT   12
#define EXTENT_TYPE_BITS    3
#define EXTENT_TYPE_MASK    ((((uint64_t)1) << EXTENT_TYPE_BITS) - 1)
#define GET_EXTENT_TYPE(extentId) \
    (((extentId) >> EXTENT_TYPE_SHIFT) & EXTENT_TYPE_MASK)
#define SET_EXTENT_TYPE(extentId, type) \
    (((extentId) & ~(EXTENT_TYPE_MASK << EXTENT_TYPE_SHIFT)) \
     | (((type) & EXTENT_TYPE_MASK) << EXTENT_TYPE_SHIFT))

#define EXTENT_HIGN_INDEX_SHIFT 4
#define THIN_COW_EXTENT_INDEX_SHIFT 28
#define EXTENT_HIGH_INDEX_MASK ((((uint64_t)1) << EXTENT_HIGN_INDEX_SHIFT) - 1)

#define CHANGE_EXTENT_INDEX(fullIdx) \
    ((((fullIdx) >> (THIN_COW_EXTENT_INDEX_SHIFT+EXTENT_TYPE_SHIFT)) & EXTENT_HIGH_INDEX_MASK)\
    | ((((fullIdx)>>EXTENT_TYPE_SHIFT) & (EXTENT_CKGID_MASK))<<EXTENT_HIGN_INDEX_SHIFT))

#define EXTENT_CKGID_SHIFT   16
#define EXTENT_CKGID_BITS    32
#define EXTENT_CKGID_MASK    ((((uint64_t)1) << EXTENT_CKGID_BITS) - 1)
#define GET_EXTENT_CKGID(extentId) \
            (((extentId) >> EXTENT_CKGID_SHIFT) & EXTENT_CKGID_MASK)

#define GET_THIN_COW_EXTENT_INDEX(extentId)\
    (((((extentId)>>EXTENT_CKGID_SHIFT) & EXTENT_HIGH_INDEX_MASK) << THIN_COW_EXTENT_INDEX_SHIFT)\
     | (((extentId) >> (EXTENT_CKGID_SHIFT+EXTENT_HIGN_INDEX_SHIFT))))

#define SET_EXTENT_CKGID(extentId, id) \
    (((extentId) & ~(EXTENT_CKGID_MASK << EXTENT_CKGID_SHIFT)) \
     | (((id) & EXTENT_CKGID_MASK) << EXTENT_CKGID_SHIFT))
#define GET_EXTENT_SEQUENCE(extentId) \
        GET_EXTENT_CKGID(extentId)

#define EXTENT_INDEX_SHIFT   0
#define EXTENT_INDEX_BITS    12
#define EXTENT_INDEX_MASK    ((((uint64_t)1) << EXTENT_INDEX_BITS) - 1)
#define GET_EXTENT_INDEX(extentId) \
    (((extentId) >> EXTENT_INDEX_SHIFT) & EXTENT_INDEX_MASK)
#define SET_EXTENT_INDEX(extentId, index) \
    (((extentId) & ~(EXTENT_INDEX_MASK << EXTENT_INDEX_SHIFT)) \
     | (((index) & EXTENT_INDEX_MASK) << EXTENT_INDEX_SHIFT))

static inline extentid_t generateExtentId(ckgid_t ckgId, uint64_t extentIdx, uint32_t type)
{
    extentid_t extentId = 0;
    uint32_t id;
    uint32_t index;

    switch (type)
    {
        case EXTENT_TYPE_DATA_THICK:
            id = extentIdx & 0xFFFFFFFFU;
            index = 0xFEF;
            break;
        case EXTENT_TYPE_ROOT:
        case EXTENT_TYPE_META:
        case EXTENT_TYPE_DATA_WITH_MAP:
            id = ckgId;
            index = extentIdx & 0xFFFU;
            break;
        case EXTENT_TYPE_DST:
        case EXTENT_TYPE_DATA_THIN:
        case EXTENT_TYPE_DATA_COW:
            id = (uint32_t)CHANGE_EXTENT_INDEX(extentIdx);
            index = extentIdx & 0xFFFU;
            break;
        default:
            return INVALID_VALUE64;
    }

    extentId = SET_EXTENT_CKGID(extentId, id);
    extentId = SET_EXTENT_TYPE(extentId, type);
    extentId = SET_EXTENT_INDEX(extentId, index);
    return extentId;
}
#define GENERATE_FATLUN_EXTENTID(extentIdx) (generateExtentId(0, extentIdx, EXTENT_TYPE_DATA_THICK))

typedef enum
{
    TIER_TYPE_SSD,
    TIER_TYPE_SAS,
    TIER_TYPE_NLSAS,
    TIER_TYPE_BUTT
} TIER_TYPE_E;
#define TIER_TYPE_SATA (TIER_TYPE_NLSAS)
#define TIER_TYPE_FC (TIER_TYPE_SAS)

typedef uint32_t tierid_t;

#define INVALID_GLOBAL_TIER_ID 0xffffffff
#define GET_TIER_TIER_TYPE(tierId) ((((tierid_t)(tierId)) >> 30) & 0x03)
#define SET_TIER_TIER_TYPE(tierId, tierType) \
    (((((tierid_t)(tierType)) << 30) & 0xc0000000) ^ (tierId & 0x3fffffff))

#define GET_TIER_POOL_ID(tierId) (((tierid_t)(tierId)) & 0x3fffffff)
#define SET_TIER_POOL_ID(tierId, poolId) \
    ((((poolid_t)(poolId)) & 0x3fffffff) ^ (tierId & 0xc0000000))

#define SET_TIER_TIER_TYPE_AND_POOL_ID(tierId, tierType, poolId) \
    (SET_TIER_POOL_ID(SET_TIER_TIER_TYPE(tierId, tierType), poolId))

#define GET_LUN_VOL_TYPE(volId) ((((volumeid_t)(volId)) >> 36) & 0xFF)

#if 0
#define GENERATE_VOL_ID_BY_LUN(lunId, genType) generateVolumeIdByLun(lunId, genType)
static inline volumeid_t generateVolumeIdByLun(lunid_t lunId, uint8_t genType)
{
    volumeid_t volumeId = 0;
    volumeId = SET_VOL_PARENT_TYPE(volumeId, VOL_PARENT_TYPE_LUN);
    volumeId = SET_VOL_PARENT_ID(volumeId, lunId);
    volumeId = volumeId ^ ((((volumeid_t)genType) << 36) & 0x00000FF000000000);
    return volumeId;
}
#endif

#define GET_POOL_VOL_TYPE(volId) ((((volumeid_t)(volId)) >> 32) & 0xFF)
#define GENERATE_VOL_ID_BY_POOL(poolId, genType) generateVolumeIdByPool(poolId, genType)
static inline volumeid_t generateVolumeIdByPool(poolid_t poolId, uint8_t genType)
{
    volumeid_t volumeId = 0;
    volumeId = SET_VOL_PARENT_TYPE(volumeId, VOL_PARENT_TYPE_POOL);
    volumeId = SET_VOL_PARENT_ID(volumeId, poolId);
    volumeId = volumeId ^ ((((volumeid_t)genType) << 32) & 0x000000FF00000000);
    return volumeId;
}

#define GET_TRANS_VOL_TYPE(volId) ((((volumeid_t)(volId)) >> 32) & 0xFF)
#define GENERATE_VOL_ID_BY_NID(NId) generateVolumeIdByNode(NId)
static inline volumeid_t generateVolumeIdByNode(uint32_t NId, uint8_t genType)
{
    volumeid_t volumeId = 0;
    volumeId = SET_VOL_PARENT_TYPE(volumeId, VOL_PARENT_TYPE_LOG_VOL);
    volumeId = SET_VOL_PARENT_ID(volumeId, NId);
    volumeId = volumeId ^ ((((volumeid_t)genType) << 32) & 0x000000FF00000000);
    return volumeId;
}

#define GET_VOL_VOL_TYPE(volId) ((((volumeid_t)(volId)) >> 32) & 0x0F)
#define GENERATE_VOL_ID_BY_VOL(volId, genType) generateVolumeIdByVol(volId, genType)
static inline volumeid_t generateVolumeIdByVol(volumeid_t volId, uint8_t genType)
{
    volumeid_t volumeId = 0;
    volumeId = volId ^ ((((volumeid_t)genType) << 32) & 0x0000000F00000000);
    return volumeId;
}
#define GET_VOL_PARENT_VOL(volId) ((volId) & (~(0x0000000F00000000)))

typedef enum
{
    LUN_DATA_VOL_GENTYPE = 0x00,
    LUN_DATA_META_VOL_GENTYPE = 0x01,
    LUN_OBS_MOS_VOL_GENTYPE = 0x02,
    LUN_OBS_DDUP_VOL_GENTYPE = 0x03,
    LUN_OBS_FS_VOL_GENTYPE = 0x04,
    LUN_OBS_DCL_VOL_GENTYPE = 0x05,
    LUN_GENTYPE_BUTT
} LUN_GENTYPE_E;

#define SPA_METADATA_VOL_GENTYPE 0x01
#define SPA_RECLAIM_VOL_GENTYPE 0x02

#define TRANS_LOG_VOL_GENTYPE 0x03

#define POOL_META_VOL_GENTYPE 0x2

typedef uint16_t zoneid_t;
#define INVALID_ZONE_ID 0xffff

#define GENERATE_ZONE_ID(tierType, index, appType) \
    (((appType) & 0x01) ^ (((index) & 0x07ff) << 1) ^ (((tierType) & 0x03) << 14))

#define GET_ZONE_TIER_TYPE(zoneId) (((zoneId) >> 14) & 0x03)

#define GET_ZONE_APP_TYPE(zoneId) ((zoneId) & 0x01)

#define GET_ZONE_INDEX(zoneId) (((zoneId) >> 1)  & 0x07ff)

typedef uint16_t dgid_t;

#define INVALID_DG_ID 0xffff

#if 1
#define GENERATE_DG_ID(tierType, pairId, index) \
    (((index) & 0x1fU) \
    ^ (((tierType) & 0x03U) << 5)\
    ^ (((pairId) & 0x0fU) << 10) \
    ^ (((tierType) & 0x03U) << 14))
#define GET_DG_INDEX_IN_TIER(dgId) ((dgId) & 0x1f)
#else
#define GENERATE_DG_ID(tierType, pairId, index) \
    (((index) & 0x3f) ^ (((pairId) & 0x0f) << 6) ^ (((tierType) & 0x03) << 14))
#define GET_DG_INDEX(dgId)      ((dgId) & 0x7f)
#endif

#define GET_DG_TIER_TYPE(dgId)  (((dgId) >> 14) & 0x03)
#define GET_DG_PAIR_ID(dgId)    (((dgId) >> 10) & 0x0f)


#define INVALID_CKG_OBJ_ID 0xffffffffffffffffULL

#define GENERATE_CKG_OBJ_ID(zoneId, ckgId) \
    (((ckgId) & 0xffffffffU)) ^ ((((uint64_t)(zoneId) & 0xffffU) << 32))

#define GET_CKG_OBJ_ZONE_ID(ckgObjId) \
    ((((uint64_t)(ckgObjId)) >> 32) & 0xffffU)

#define GET_CKG_OBJ_CKG_ID(ckgObjId) \
    (((uint64_t)(ckgObjId)) & 0xffffffffU)

#define SET_CKG_OBJ_ZONE_ID(ckgObjId, zoneId) \
    ((ckgObjId) ^ (((uint64_t)(zoneId) & 0xffffU) << 32))

#define SET_CKG_OBJ_CKG_ID(ckgObjId,ckgId) \
    ((ckgObjId) ^ ((ckgId) & 0xffffffffU))

static inline bool isMetaVolumeId(volumeid_t volumeId)
{        
    if (LUN_DATA_META_VOL_GENTYPE == GET_LUN_VOL_TYPE(volumeId))
    {
        return B_TRUE;
    }
    
    return B_FALSE;
}

#endif


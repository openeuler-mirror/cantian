/* -------------------------------------------------------------------------
 *  This file is part of the Cantian project.
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
 *
 * Cantian is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *          http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * -------------------------------------------------------------------------
 *
 * cm_scsi.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_scsi.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_SCSI_H__
#define __CM_SCSI_H__

#include "cm_defs.h"
#ifdef WIN32
#else
#include <scsi/scsi_ioctl.h>
#include <scsi/sg.h>
#endif

#define CM_SCSI_SENSE_LEN          64
#define CM_SCSI_XFER_DATA          512
#define CM_SCSI_TIMEOUT	           60  //secs
#define CM_DEF_BLOCK_SIZE          512
#define CM_MAX_VENDOR_LEN          64
#define CM_MAX_WWN_LEN             64
#define CM_MAX_PRODUCT_LEN         30
#define CM_MAX_ARRAY_SN_LEN        64
#define CM_MAX_LUNID_LEN           11
#define CM_HW_ARRAY_SN_LEN         21
#define CM_MAX_RKEY_COUNT          CT_MAX_INSTANCES

#define SAM_CHECK_CONDITION         0x02
#define SAM_RESERVATION_CONFLICT    0x18
#define SAM_COMMAND_TERMINATED      0x22

#define CM_SPC_SK_MISCOMPARE          0xe  //the sense key indicates that the source data did not match the data read from the medium

#define CM_DRIVER_MASK                0x0f
#define CM_DRIVER_SENSE               0x08

#define CM_SCSI_RESULT_GOOD           0
#define CM_SCSI_RESULT_STATUS         1       //other than GOOD and CHECK CONDITION
#define CM_SCSI_RESULT_SENSE          2
#define CM_SCSI_RESULT_TRANSPORT_ERR  3

#define CM_SCSI_ERR_MISCOMPARE        (-2)
#define CM_SCSI_ERR_CONFLICT          (-2)

typedef struct st_vendor_info {
    char vendor[CM_MAX_VENDOR_LEN];
    char product[CM_MAX_PRODUCT_LEN];
}vendor_info_t;

typedef struct st_array_info {
    char array_sn[CM_MAX_ARRAY_SN_LEN];
} array_info_t;

typedef struct st_lun_info {
    char lun_wwn[CM_MAX_WWN_LEN];
    int32 lun_id;
}lun_info_t;

typedef struct st_inquiry_data {
    vendor_info_t vendor_info;
    array_info_t array_info;
    lun_info_t lun_info;
}inquiry_data_t;

//SCSI sense header
typedef struct st_scsi_sense_hdr {
    uchar response_code;
    uchar sense_key;
    uchar asc;
    uchar ascq;
    uchar res4;
    uchar res5;
    uchar res6;
    uchar add_length;
}scsi_sense_hdr_t;

#ifdef WIN32
#else

//scsi2 reserve(6)/release(6)
status_t cm_scsi2_reserve(int32 fd);
status_t cm_scsi2_release(int32 fd);

//scsi3 register/reserve/release/clear/preempt
int32 cm_scsi3_register(int32 fd, int64 sark);
int32 cm_scsi3_unregister(int32 fd, int64 rk);
status_t cm_scsi3_reserve(int32 fd, int64 rk);
status_t cm_scsi3_release(int32 fd, int64 rk);
status_t cm_scsi3_clear(int32 fd, int64 rk);
status_t cm_scsi3_preempt(int32 fd, int64 rk, int64 sark);
//scsi3 vaai compare and write
//return : CT_TIMEDOUT/CT_SUCCESS/CT_ERROR/CM_SCSI_ERR_MISCOMPARE
int32 cm_scsi3_caw(int32 fd, int64 block_addr, char* buff, int32 buff_len);

//scsi3 read(10)/write(10)
status_t cm_scsi3_read(int32 fd, int32 block_addr, uint16 block_count,
    char* buff, int32 buff_len);
status_t cm_scsi3_write(int32 fd, int32 block_addr, uint16 block_count,
    char* buff, int32 buff_len);

//scsi inquiry(get lun info)
status_t cm_scsi3_inql(int32 fd, inquiry_data_t* inquiry_data);
status_t cm_scsi3_get_array(int32 fd, array_info_t* array_info);
status_t cm_scsi3_get_vendor(int32 fd, vendor_info_t* vendor_info);
status_t cm_scsi3_get_lun(int32 fd, lun_info_t* lun_info);

//scsi3 reserve in(get reservation keys and reservations)
//read register keys
status_t cm_scsi3_rkeys(int32 fd, int64* reg_keys, int32* key_count, uint32* generation);
//read reservation key
status_t cm_scsi3_rres(int32 fd, int64* rk, uint32* generation);

#endif //WIN32

#endif //__CM_SCSI_H__


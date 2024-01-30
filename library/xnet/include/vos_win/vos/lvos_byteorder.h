/******************************************************************************

                  版权所有 (C) 2008-2008 华为赛门铁克科技有限公司

 ******************************************************************************
  文 件 名   : byteorder.h
  版 本 号   : 初稿
  作    者   : x00001559
  生成日期   : 2008年7月26日
  最近修改   :
  功能描述   : 进行字节序转换的功能
  修改历史   :
  1.日    期   : 2008年7月26日
    作    者   : x00001559
    修改内容   : 创建文件

******************************************************************************/
/**
    \file  lvos_byteorder.h
    \brief 字节序转换对外接口

    \date 2008-07-26
*/


/** \addtogroup VOS_BYTEORDER  字节序转换
    @{ 
*/

#ifndef __BYTEORDER_H__
#define __BYTEORDER_H__

#ifdef __LINUX_USR__
//#include <byteswap.h>
#endif

/** \brief 16位整数从CPU序转换到小序
    \param[in] usData  需要转换的整数
    \return 转换后的整数
    \see CpuToLittleEndian32  CpuToLittleEndian64
*/
OSP_U16 CpuToLittleEndian16(OSP_U16 usData);

/** \brief 32位整数从CPU序转换到小序
    \param[in] usData  需要转换的整数
    \return 转换后的整数
    \see CpuToLittleEndian16  CpuToLittleEndian64
*/
OSP_U32 CpuToLittleEndian32(OSP_U32 usData);

/** \brief 64位整数从CPU序转换到小序
    \param[in] ulData  需要转换的整数
    \return 转换后的整数
    \see CpuToLittleEndian16  CpuToLittleEndian32
*/
OSP_U64 CpuToLittleEndian64(OSP_U64 ulData);

/** \brief 16位整数从CPU序转换到大序
    \param[in] usData  需要转换的整数
    \return 转换后的整数
    \see CpuToBigEndian32  CpuToBigEndian64
*/
OSP_U16 CpuToBigEndian16(OSP_U16 usData);

/** \brief 32位整数从CPU序转换到大序
    \param[in] usData  需要转换的整数
    \return 转换后的整数
    \see CpuToBigEndian16  CpuToBigEndian64
*/
OSP_U32 CpuToBigEndian32(OSP_U32 usData);

/** \brief 64位整数从CPU序转换到大序
    \param[in] ulData  需要转换的整数
    \return 转换后的整数
    \see CpuToBigEndian16  CpuToBigEndian32
*/
OSP_U64 CpuToBigEndian64(OSP_U64 ulData);

/** \brief 16位整数从小序转换到CPU序
    \param[in] usData  需要转换的整数
    \return 转换后的整数
    \see LittleEndianToCpu32  LittleEndianToCpu64
*/
OSP_U16 LittleEndianToCpu16(OSP_U16 usData);

/** \brief 32位整数从小序转换到CPU序
    \param[in] usData  需要转换的整数
    \return 转换后的整数
    \see LittleEndianToCpu32  LittleEndianToCpu64
*/
OSP_U32 LittleEndianToCpu32(OSP_U32 usData);

/** \brief 64位整数从小序转换到CPU序
    \param[in] ulData  需要转换的整数
    \return 转换后的整数
    \see LittleEndianToCpu32  LittleEndianToCpu64
*/
OSP_U64 LittleEndianToCpu64(OSP_U64 ulData);

/** \brief 16位整数从CPU序转换到大序
    \param[in] usData  需要转换的整数
    \return 转换后的整数
    \see BigEndianToCpu32  BigEndianToCpu64
*/
OSP_U16 BigEndianToCpu16(OSP_U16 usData);

/** \brief 32位整数从CPU序转换到大序
    \param[in] usData  需要转换的整数
    \return 转换后的整数
    \see BigEndianToCpu16  BigEndianToCpu64
*/
OSP_U32 BigEndianToCpu32(OSP_U32 usData);

/** \brief 64位整数从CPU序转换到大序
    \param[in] ulData  需要转换的整数
    \return 转换后的整数
    \see BigEndianToCpu16  BigEndianToCpu32
*/
OSP_U64 BigEndianToCpu64(OSP_U64 ulData);

#endif
/** @} */


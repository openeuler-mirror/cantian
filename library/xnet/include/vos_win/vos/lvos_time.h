/******************************************************************************

                  版权所有 (C) 2008-2008 华为赛门铁克科技有限公司

 ******************************************************************************
  文 件 名   : lvos_time.h
  版 本 号   : 初稿
  
  生成日期   : 2008年7月8日
  最近修改   :
  功能描述   : 时间功能
  函数列表   :
  修改历史   :
  1.日    期   : 2008年7月8日
    
    修改内容   : 创建文件

******************************************************************************/

/**
    \file  lvos_time.h
    \brief 时间功能

    \date 2008-12-24
*/

/** \addtogroup VOS_TIME  时间类接口
    @{ 
*/

#ifndef __LVOS_TIME_H__
#define __LVOS_TIME_H__

#define MAX_DATE_TIME            20

/** \brief 时间结构体 */
typedef struct 
{
    OSP_S32 iYear;          /**< 年, 1999年则为1999 */ 
    OSP_S32 iMonth;       /**< 月, 1-12*/
    OSP_S32 iMDay;        /**< 日, 1-31 */
    OSP_S32 iHour;         /**< 时, 0-23 */
    OSP_S32 iMinute;     /**< 分, 0-59 */
    OSP_S32 iSecond;     /**< 秒, 0-59 */
    OSP_S32 iWDay;      /**< 星期, 0-6:日~六 */
} TIME_S;

/** \brief 取得当前的本地时间，从1970-1-1 00:00:00 开始经过的秒数
    \note  支持windows/linux_kernel/linux_user，无调用上下文限制
    \param[in] llUtcTime  输入UTC time
    \return OSP_S64 返回local时间
*/
OSP_S64 LVOS_GetLocalTimeFromUtcTime(OSP_S64 llUtcTime);

/** \brief 取得当前的本地时间，从1970-1-1 00:00:00 开始经过的秒数
    \note  支持windows/linux_kernel/linux_user，无调用上下文限制
    \param[in] piTime  传出时间，为NULL时不传出
    \return OSP_S64 返回时间
*/
OSP_S64 LVOS_GetLocalTime(OSP_S64 *piTime);


/** \brief 取得当前的本地夏令时时间，从1970-1-1 00:00:00 开始经过的秒数
    \note  
    \param[in] v_pllTime  传出时间，为NULL时不传出
    \return OSP_S32   成功:RETURN_OK ;  失败:RETURN_ERROR
*/
OSP_S32 LVOS_GetDSTTime(OSP_S64 *v_pllTime);

/** \brief 根据传入的UTC 时间获取夏令时时间，从1970-1-1 00:00:00 开始经过的秒数
    \note  
    \param[in] 
    \return OSP_S64   返回时间,如果返回0表示获取失败
*/
OSP_S64 LVOS_GetDSTTimeFromUtcTime(OSP_S64 llUtcTime);



/** \brief 查询时间是否在夏令时区内
           支持两种：1、查询系统时间；2、查询输入utc时间；
    \note  
    \param[in]  OSP_U32 uiFlag 查询标志，0：查询系统时间，其他：查询输入时间
                OSP_S64 llUtcTime             输入的UTC时间，查询系统时间时输入0
    \return OSP_S64   RETURN_OK       时间在夏令时区内
                                RETURN_ERROR 时间不在夏令时区内
*/
OSP_S32 LVOS_CheckIsDSTTime(OSP_U32 uiFlag,OSP_S64 llUtcTime);


/** \brief 取得当前的时间，从1970-1-1 00:00:00 开始经过的秒数
    \note  支持windows/linux_kernel/linux_user，无调用上下文限制
    \param[in] piTime  传出时间，为NULL时不传出
    \return OSP_S64 返回时间
*/
OSP_S64 LVOS_GetTime(OSP_S64 *piTime);

/*lint -sem(TIME_GmTime, 2p) */
/** \brief 格式化时间为年、月、日、时、分、秒格式
    \note  支持windows/linux_kernel/linux_user，无调用上下文限制
    \param[in]  piTime   需要格式化的时间，为NULL时表示取当前时间
    \param[out] pstTime  格式化后的传出时间
    \return 无
*/
void LVOS_GmTime(const OSP_S64 *piTime, TIME_S *pstTime);

/*lint -sem(LVOS_mkTime, 1p) */
/** \brief 将年、月、日、时、分、秒格式的时间转换为秒数
    \param[in]  pstTime  需要转化的时间
    \return 转化后的时间
*/
OSP_S64 LVOS_mkTime(TIME_S *pstTime);

/*lint -sem(TIME_AscTime, 3n > 24 && 3n <= 2P) */
/** \brief 生成字符串形式的时间
    \note  支持windows/linux_kernel/linux_user，无调用上下文限制
    \param[in] piTime  输入需要转换的时间值，如果为NULL则转换当前时间
    \param[in] szBuffer  字符串缓存空间
    \param[in] uiBufferSize 字符串缓存大小
    \return 无
*/
void LVOS_AscTime(const OSP_S64 *piTime, OSP_CHAR *szBuffer, OSP_U32 uiBufferSize);

/** \brief 获取系统启动后经过的毫秒数
    \note  支持windows/linux_kernel/linux_user，同步接口，无调用上下文限制
    \return 系统启动后经过的毫秒数
*/
OSP_U64 LVOS_GetMilliSecond(void);

#ifdef WIN32
__declspec(deprecated("This function will be deleted for future, please use 'LVOS_GetMilliSecond' instead."))
#endif
static inline OSP_U32 LVOS_GetTickCount(void)
{
    return (OSP_U32)LVOS_GetMilliSecond();
}

/** \brief 获取系统启动后经过的纳秒数
    \note  支持windows/linux_kernel，同步接口，无调用上下文限制
    \return 获取系统启动后经过的纳秒数
*/
OSP_U64 LVOS_GetNanoSecond(void);

/** \brief 查询系统时区(windows下直接返回OK)
    \note  只支持linux用户态
    \param[in]  三种表示形式的时区信息
    \retval RETURN_OK       查询成功
    \retval RETURN_ERROR    查询失败
*/
OSP_S32 LVOS_GetTimeZone(OSP_CHAR *pTimeZoneUTC,OSP_CHAR *pTimeZoneName,OSP_CHAR *pTimeZoneStyle);

/** \brief 设置系统时区(windows下直接返回OK)
    \note  只支持linux用户态
    \param[in] OSP_CHAR *时区名称字符串
    \retval RETURN_OK       设置成功
    \retval RETURN_ERROR    设置失败
*/
OSP_S32 LVOS_SetTimeZone(OSP_CHAR *pTimeZoneName);

/** \brief 查询输入地区当年是否使用了夏令时(windows下直接返回OK)
    \note  只支持linux用户态
    \param[in]  OSP_CHAR * 夏令时开始时间
                OSP_CHAR * 结束时间 偏移时间
                OSP_U32 *  偏移时间
    \retval RETURN_OK       查询成功
    \retval RETURN_ERROR    查询失败
*/
OSP_S32 LVOS_QueryDstConfInfo(OSP_CHAR *pDstBegin,
                              OSP_CHAR *pDstEnd,OSP_U32 *DstMinOffset,OSP_U32 *DstConfMod);



OSP_S32 LVOS_QueryDstConfInfoForRegion(OSP_CHAR *pTimeZoneName, OSP_CHAR *pDstBegin,
                              OSP_CHAR *pDstEnd,OSP_U32 *DstMinOffset,OSP_U32 *DstConfMod);


OSP_S32 LVOS_QueryDstForRegion(OSP_CHAR *pTimeZoneName,OSP_U32 *pFlag);

/** \brief 设置UTC时间(windows下直接返回OK)
    \note  只支持linux用户态
    \param[in] const OSP_S64 *以秒为单位的UTC时间
    \retval RETURN_OK       设置成功
    \retval RETURN_ERROR    设置失败
*/
OSP_S32  LVOS_SetTime(const OSP_S64 *v_pllTime);

#endif
/** @} */


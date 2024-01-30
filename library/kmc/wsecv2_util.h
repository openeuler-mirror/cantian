/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2014-2020. All rights reserved.
 * Description: KMC internal interfaces are not open to external systems.

 * Create: 2014-06-16
 */

#ifndef KMC_SRC_COMMON_WSECV2_UTIL_H
#define KMC_SRC_COMMON_WSECV2_UTIL_H

#include "wsecv2_type.h"
#include "securec.h"
#include "wsecv2_ctx.h"

#ifdef __cplusplus
extern "C" {
#endif
/* 1.2 Either iPSI or OpenSSL or mbedtls can be specified. */
#ifdef WSEC_COMPILE_CAC_IPSI
#if defined(WSEC_COMPILE_CAC_OPENSSL) || defined(WSEC_COMPILE_CAC_MBEDTLS)
#error Cannot defined both 'WSEC_COMPILE_CAC_IPSI' and '(WSEC_COMPILE_CAC_OPENSSL' or 'WSEC_COMPILE_CAC_MBEDTLS)'
#endif
#endif

#ifdef WSEC_COMPILE_CAC_OPENSSL
#if defined(WSEC_COMPILE_CAC_MBEDTLS) || defined(WSEC_COMPILE_CAC_IPSI)
#error Cannot defined both 'WSEC_COMPILE_CAC_OPENSSL' and 'WSEC_COMPILE_CAC_MBEDTLS' or 'WSEC_COMPILE_CAC_IPSI'
#endif
#endif

#ifdef WSEC_COMPILE_CAC_MBEDTLS
#if defined(WSEC_COMPILE_CAC_IPSI) || defined(WSEC_COMPILE_CAC_OPENSSL)
#error Cannot defined both 'WSEC_COMPILE_CAC_MBEDTLS' and 'WSEC_COMPILE_CAC_IPSI' or 'WSEC_COMPILE_CAC_OPENSSL'
#endif
#endif

/* 2. Macro Definition */
/* 2.1 Constant Macro */
#define WSEC_LOG_BUFF_SIZE    512 /* Maximum length of a log. */

/* 2.3 Log Function Macro */
#define WSEC_LOG(kmcCtx, level, logText) WsecLog(kmcCtx, WSEC_KMC_FILE, __LINE__, level, "%s", logText)
#define WSEC_LOG1(kmcCtx, level, fmt, v1) WsecLog(kmcCtx, WSEC_KMC_FILE, __LINE__, level, fmt, v1)
#define WSEC_LOG2(kmcCtx, level, fmt, v1, v2) WsecLog(kmcCtx, WSEC_KMC_FILE, __LINE__, level, fmt, v1, v2)
#define WSEC_LOG3(kmcCtx, level, fmt, v1, v2, v3) WsecLog(kmcCtx, WSEC_KMC_FILE, __LINE__, level, fmt, v1, v2, v3)
#define WSEC_LOG4(kmcCtx, level, fmt, v1, v2, v3, v4) \
    WsecLog(kmcCtx, WSEC_KMC_FILE, __LINE__, level, fmt, v1, v2, v3, v4)
#define WSEC_LOG5(kmcCtx, level, fmt, v1, v2, v3, v4, v5) \
    WsecLog(kmcCtx, WSEC_KMC_FILE, __LINE__, level, fmt, v1, v2, v3, v4, v5)

/* 1) Error logs */
#define WSEC_LOG_E(kmcCtx, logText) WSEC_LOG(kmcCtx, WSEC_LOG_ERR, logText)
#define WSEC_LOG_E1(kmcCtx, fmt, v1) WSEC_LOG1(kmcCtx, WSEC_LOG_ERR, fmt, v1)
#define WSEC_LOG_E2(kmcCtx, fmt, v1, v2) WSEC_LOG2(kmcCtx, WSEC_LOG_ERR, fmt, v1, v2)
#define WSEC_LOG_E3(kmcCtx, fmt, v1, v2, v3) WSEC_LOG3(kmcCtx, WSEC_LOG_ERR, fmt, v1, v2, v3)
#define WSEC_LOG_E4(kmcCtx, fmt, v1, v2, v3, v4) WSEC_LOG4(kmcCtx, WSEC_LOG_ERR, fmt, v1, v2, v3, v4)
#define WSEC_LOG_E5(kmcCtx, fmt, v1, v2, v3, v4, v5) WSEC_LOG5(kmcCtx, WSEC_LOG_ERR, fmt, v1, v2, v3, v4, v5)

/* 2) Warning logs */
#define WSEC_LOG_W(kmcCtx, logText) WSEC_LOG(kmcCtx, WSEC_LOG_WARN, logText)
#define WSEC_LOG_W1(kmcCtx, fmt, v1) WSEC_LOG1(kmcCtx, WSEC_LOG_WARN, fmt, v1)
#define WSEC_LOG_W2(kmcCtx, fmt, v1, v2) WSEC_LOG2(kmcCtx, WSEC_LOG_WARN, fmt, v1, v2)
#define WSEC_LOG_W3(kmcCtx, fmt, v1, v2, v3) WSEC_LOG3(kmcCtx, WSEC_LOG_WARN, fmt, v1, v2, v3)
#define WSEC_LOG_W4(kmcCtx, fmt, v1, v2, v3, v4) WSEC_LOG4(kmcCtx, WSEC_LOG_WARN, fmt, v1, v2, v3, v4)
#define WSEC_LOG_W5(kmcCtx, fmt, v1, v2, v3, v4, v5) WSEC_LOG5(kmcCtx, WSEC_LOG_WARN, fmt, v1, v2, v3, v4, v5)

/* 3) Warning logs */
#define WSEC_LOG_I(kmcCtx, logText) WSEC_LOG(kmcCtx, WSEC_LOG_INFO, logText)
#define WSEC_LOG_I1(kmcCtx, fmt, v1) WSEC_LOG1(kmcCtx, WSEC_LOG_INFO, fmt, v1)
#define WSEC_LOG_I2(kmcCtx, fmt, v1, v2) WSEC_LOG2(kmcCtx, WSEC_LOG_INFO, fmt, v1, v2)
#define WSEC_LOG_I3(kmcCtx, fmt, v1, v2, v3) WSEC_LOG3(kmcCtx, WSEC_LOG_INFO, fmt, v1, v2, v3)
#define WSEC_LOG_I4(kmcCtx, fmt, v1, v2, v3, v4) WSEC_LOG4(kmcCtx, WSEC_LOG_INFO, fmt, v1, v2, v3, v4)
#define WSEC_LOG_I5(kmcCtx, fmt, v1, v2, v3, v4, v5) WSEC_LOG5(kmcCtx, WSEC_LOG_INFO, fmt, v1, v2, v3, v4, v5)

/* 4) Operation failure logs */
#define WSEC_LOG_E4MALLOC(kmcCtx, memSize) \
    WSEC_LOG_E1(kmcCtx, "Allocate Memory(size=%u) fail.", ((WsecUint32)(memSize))) /* Failed to allocate memory. */

#define WSEC_LOG_E4MEMCPY(kmcCtx) WSEC_LOG_E(kmcCtx, "copy memory fail.") /* Failed to copy the memory. */
#define WSEC_LOG_E4MEMSET(kmcCtx) WSEC_LOG_E(kmcCtx, "reset memory fail.") /* Failed to set the memory. */

/* 5. Debug trace */
#ifdef WSEC_DEBUG
    #define WSEC_TRACE(kmcCtx, traceText) WSEC_LOG_I(kmcCtx, traceText)
    #define WSEC_TRACE1(kmcCtx, fmt, v1) WSEC_LOG_I1(kmcCtx, fmt, v1)
    #define WSEC_TRACE2(kmcCtx, fmt, v1, v2) WSEC_LOG_I2(kmcCtx, fmt, v1, v2)
    #define WSEC_TRACE3(kmcCtx, fmt, v1, v2, v3) WSEC_LOG_I3(kmcCtx, fmt, v1, v2, v3)
    #define WSEC_TRACE4(kmcCtx, fmt, v1, v2, v3, v4) WSEC_LOG_I4(kmcCtx, fmt, v1, v2, v3, v4)
    #define WSEC_TRACE5(kmcCtx, fmt, v1, v2, v3, v4, v5) WSEC_LOG_I5(kmcCtx, fmt, v1, v2, v3, v4, v5)
#else
    #define WSEC_TRACE(kmcCtx, traceText)
    #define WSEC_TRACE1(kmcCtx, fmt, v1)
    #define WSEC_TRACE2(kmcCtx, fmt, v1, v2)
    #define WSEC_TRACE3(kmcCtx, fmt, v1, v2, v3)
    #define WSEC_TRACE4(kmcCtx, fmt, v1, v2, v3, v4)
    #define WSEC_TRACE5(kmcCtx, fmt, v1, v2, v3, v4, v5)
#endif

/* 6) Comparison result */
#define WSEC_CMP_RST_SMALL_THAN (-1)
#define WSEC_CMP_RST_EQUAL      0
#define WSEC_CMP_RST_BIG_THAN   1

#define WSEC_EVENT_PERIOD 400

#define DECLEAR_KMC_PERORMANCE WsecUint64 timeTick
#define KMC_PERFORMANCE_START(kmcCtx) WsecGetTimeTickStart(kmcCtx, &timeTick)
#define KMC_PERFORMANCE_END(kmcCtx, type) WsecGetTimeTickEnd(kmcCtx, timeTick, type, __FUNCTION__)
#define KMC_IS_PARAM_VALID(iter, min, max) (((min) <= (iter)) && ((iter) <= (max)))
#define KMC_IS_PERCONF_PARAM_VALID(iter, min, max) (((iter) == 0) || (((min) <= (iter)) && ((iter) <= (max))))
#define KMC_DEFAULT_PERF_TIME 60 // time performance default is 1 mins
#define KMC_MAX_PERF_TIME 600 // time performance max is 10 mins
#define KMC_MIN_PERF_TIME 5 //  time performance min is 5 s

/* TLV */
#pragma pack(1)
typedef struct TagWsecTlv {
    WsecUint32  tag;
    WsecUint32  len;
    void       *val;
} WsecTlv;
#pragma pack()

/* ksfParam */
#pragma pack(1)
typedef struct TagWsecKsfParam {
    WsecHandle ksf;         // fileHandle
    WsecHandle *hashCtx;
    WsecUint32 ctxNum;
    WsecUint32 startIndex;  // Indicates the start index of the array during hash calculation.
} WsecKsfParam;
#pragma pack()

/* 3. Enumeration */
/* Log Level */
typedef enum {
    WSEC_LOG_INFO,
    WSEC_LOG_WARN,
    WSEC_LOG_ERR
} WsecLogLevel;

/* Print logs. */
WsecVoid WsecLog(WsecHandle kmcCtx, const char *file, int line, int level, const char *fmt, ...)
    SECUREC_ATTRIBUTE(5, 6);

/* byte array converted to unsigned long long number */
unsigned long long WsecByteArrToBigInt(const unsigned char *byteArr, size_t len);
/* Encryption (software-layer root key or master key) */
unsigned long WsecKmcHwEncData(WsecHandle kmcCtx, WsecHandle handle, const unsigned char *plaintext,
    unsigned int plaintextLen, unsigned char *ciphertext, unsigned int *ciphertextLen);

/* Decryption (software-layer root key or master key) */
unsigned long WsecKmcHwDecData(WsecHandle kmcCtx, WsecHandle handle, const unsigned char *ciphertext,
    unsigned int ciphertextLen, unsigned char *plaintext, unsigned int *plaintextLen);

/* Count the number of elements whose values are 0 in the buffer. */
size_t GetZeroItemCount(const WsecVoid *data, size_t size, size_t itemSize);

WsecVoid WsecGetTimeTickStart(KmcCbbCtx *kmcCtx, WsecUint64 *timeTick);

WsecVoid WsecGetTimeTickEnd(KmcCbbCtx *kmcCtx, WsecUint64 timeTick, WsecUint32 opIndex, const char *callBy);

WsecBool WsecCheckPerConf(const WsecPerConf *perConf);

#ifdef __cplusplus
}
#endif  /* __cplusplus */

#endif /* KMC_SRC_COMMON_WSECV2_UTIL_H */

/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2014-2020. All rights reserved.
 * Description: This file requires app programmers to perform simple configuration on
 * compilation options.

 * Create: 2014-06-16

 */

#ifndef KMC_INCLUDE_WSECV2_CONFIG_H
#define KMC_INCLUDE_WSECV2_CONFIG_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef WSEC_COMPILE_ENABLE_TEE
#define WSEC_COMPILE_ENABLE_TEE  0
#endif

#if defined(__LINUX__) || defined(__linux__)
#ifndef WSEC_COMPILE_ENABLE_ASYM
#define WSEC_COMPILE_ENABLE_ASYM  1
#endif
#else
#define WSEC_COMPILE_ENABLE_ASYM  0
#endif

/*
 * Compilation Switch
 * #define WSEC_DEBUG
 * #define WSEC_TRACE_MEMORY It is used for CBB development and commissioning
 * and is ignored by the app.
 * #define WSEC_COMPILE_SDP Enable the SDP (sensitive data protection) sub CBB.
 * #define WSEC_COMPILE_CAC_IPSI Enable the iPSI-based CAC (encryption algorithm library adaptation) sub CBB.
 * #define WSEC_COMPILE_CAC_OPENSSL Enable the OpenSSL-based CAC (encryption algorithm lib adaptor) sub CBB.
 * If a new-line character is automatically added to the end of a log record,
 * this macro is defined. Otherwise, comment out the following content:
 * #define WSEC_WRI_LOG_AUTO_END_WITH_CRLF
 * Start error code reserved for the CBB, which must be explicitly defined by the application.
 * #define WSEC_ERR_CODE_BASE 0
 */
/* Endian Mode */
#define WSEC_CPU_ENDIAL_AUTO_CHK 0 /* Automatic program detection */
#define WSEC_CPU_ENDIAL_BIG      1 /* Big-endian alignment */
#define WSEC_CPU_ENDIAL_LITTLE   2 /* Little-endian alignment */

/* If this macro is not defined, the program automatically detects the value. */
#ifndef WSEC_CPU_ENDIAN_MODE
#define WSEC_CPU_ENDIAN_MODE    WSEC_CPU_ENDIAL_AUTO_CHK
#endif
#ifdef WSEC_CPU_ENDIAN_MODE
    #if !(((WSEC_CPU_ENDIAN_MODE) == (WSEC_CPU_ENDIAL_AUTO_CHK)) || \
        ((WSEC_CPU_ENDIAN_MODE) == (WSEC_CPU_ENDIAL_BIG)) || ((WSEC_CPU_ENDIAN_MODE) == (WSEC_CPU_ENDIAL_LITTLE)))
        #error "WSEC_CPU_ENDIAN_MODE must be WSEC_CPU_ENDIAL_AUTO_CHK, WSEC_CPU_ENDIAL_BIG or WSEC_CPU_ENDIAL_LITTLE"
    #endif
#endif

/* Other static parameters */
#define WSEC_DOMAIN_NUM_MAX          1024 /* Maximum number of domains */
#define WSEC_DOMAIN_KEY_TYPE_NUM_MAX 16   /* Maximum number of key types in a domain */
#define WSEC_MK_NUM_MAX              4096 /* Maximum number of MKs that can be stored in the Keystore file */
/* Time-consuming operation. The allowed continuous CPU occupation time (unit: ms) */
#define WSEC_ENABLE_BLOCK_MILSEC     10

#ifdef __cplusplus
}
#endif  /* __cplusplus */

#endif /* KMC_INCLUDE_WSECV2_CONFIG_H */

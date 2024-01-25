/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2014-2020. All rights reserved.
 * Description: error code

 * Create: 2014-06-16

 */

#ifndef KMC_INCLUDE_WSECV2_ERRORCODE_H
#define KMC_INCLUDE_WSECV2_ERRORCODE_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Note: Define this macro in the IDE project instead of in the wsecv2_config.h
 * file to ensure that the app provides the correct definition.
 */
#ifndef WSEC_ERR_CODE_BASE
#define WSEC_ERR_CODE_BASE 0
#endif

#if (WSEC_ERR_CODE_BASE == 0)
    #define WSEC_ERROR_CODE(seq) ((unsigned long)(seq))
    #define WSEC_BASE_ERROR_CODE(code) ((unsigned int)(code))
#else
    #define WSEC_ERROR_CODE(seq) ((unsigned long)(WSEC_ERR_CODE_BASE + seq))
    #define WSEC_BASE_ERROR_CODE(code) ((unsigned int)(code - WSEC_ERR_CODE_BASE))
#endif

#define WSEC_SUCCESS                                           (unsigned long)0    /* Success */
#define WSEC_FAILURE                                           WSEC_ERROR_CODE(1)   /* Common error. */

/* File operation error. */
#define WSEC_ERR_OPEN_FILE_FAIL                                WSEC_ERROR_CODE(11)   /* Failed to open the file. */
#define WSEC_ERR_READ_FILE_FAIL                                WSEC_ERROR_CODE(12)   /* Failed to read the file. */
#define WSEC_ERR_WRI_FILE_FAIL                                 WSEC_ERROR_CODE(13)   /* Failed to write the file. */
/* Failed to obtain the file length. */
#define WSEC_ERR_GET_FILE_LEN_FAIL                             WSEC_ERROR_CODE(14)
#define WSEC_ERR_FILE_FORMAT                                   WSEC_ERROR_CODE(15)   /* Incorrect file format. */
#define WSEC_ERR_FILE_COPY_FAIL                                WSEC_ERROR_CODE(16)   /* Failed to copy the file. */
#define WSEC_ERR_FILE_FLUSH_FAIL                               WSEC_ERROR_CODE(17)   /* Failed to synchronize files. */
#define WSEC_ERR_FILE_LEN_TOO_MAX                              WSEC_ERROR_CODE(18)   /* File is too max. */

/* Memory operation error. */
#define WSEC_ERR_MALLOC_FAIL                                   WSEC_ERROR_CODE(51)  /* Failed to allocate memory. */
#define WSEC_ERR_MEMCPY_FAIL                                   WSEC_ERROR_CODE(52)  /* Failed to copy the memory. */
#define WSEC_ERR_MEMCLONE_FAIL                                 WSEC_ERROR_CODE(53)  /* Failed to clone the memory. */
/* Failed to copy the character string. */
#define WSEC_ERR_STRCPY_FAIL                                   WSEC_ERROR_CODE(54)
#define WSEC_ERR_OPER_ARRAY_FAIL                               WSEC_ERROR_CODE(55)  /* Array operation failed. */
#define WSEC_ERR_MEMSET_FAIL                                   WSEC_ERROR_CODE(56)  /* Failed to set the memory. */
#define WSEC_ERR_ARRAY_ITEM_REPEAT                             WSEC_ERROR_CODE(57)  /* Element repeat in array. */
#define WSEC_ERR_MEMMOVE_FAIL                                  WSEC_ERROR_CODE(58)  /* Failed to move the memory. */

/* Security function processing error. */
/* Failed to operate the algorithm library (iPSI). */
#define WSEC_ERR_CRPTO_LIB_FAIL                                WSEC_ERROR_CODE(101)
/* Failed to generate the hash value. */
#define WSEC_ERR_GEN_HASH_CODE_FAIL                            WSEC_ERROR_CODE(102)
#define WSEC_ERR_HASH_NOT_MATCH                                WSEC_ERROR_CODE(103) /* The hash value does not match. */
#define WSEC_ERR_INTEGRITY_FAIL                                WSEC_ERROR_CODE(104) /* Integrity is damaged. */
#define WSEC_ERR_HMAC_FAIL                                     WSEC_ERROR_CODE(105) /* HMAC failure */
#define WSEC_ERR_HMAC_AUTH_FAIL                                WSEC_ERROR_CODE(106) /* HMAC verification failed. */
/* Failed to obtain the random number. */
#define WSEC_ERR_GET_RAND_FAIL                                 WSEC_ERROR_CODE(107)
#define WSEC_ERR_PBKDF2_FAIL                                   WSEC_ERROR_CODE(108) /* Failed to derive the key. */
#define WSEC_ERR_ENCRPT_FAIL                                   WSEC_ERROR_CODE(109) /* Failed to encrypt data. */
#define WSEC_ERR_DECRPT_FAIL                                   WSEC_ERROR_CODE(110) /* Failed to decrypt the data. */
/* Failed to obtain the security algorithm name. */
#define WSEC_ERR_GET_ALG_NAME_FAIL                             WSEC_ERROR_CODE(111)
/* KMC sync create dh keypair failed */
#define WSEC_ERR_KMC_DH_CREATE_KEYPAIR_FAILED                  WSEC_ERROR_CODE(112)
/* KMC sync dh derive share key failed */
#define WSEC_ERR_KMC_DH_DERIVE_FAILED                          WSEC_ERROR_CODE(113)
/* dlsym failed */
#define WSEC_ERR_KMC_GENERIC_SYMBOL_FAILED                     WSEC_ERROR_CODE(114)


/* Function invoking error. */
#define WSEC_ERR_INVALID_ARG                                   WSEC_ERROR_CODE(151) /* Invalid parameter. */
/* The output buffer is insufficient. */
#define WSEC_ERR_OUTPUT_BUFF_NOT_ENOUGH                        WSEC_ERROR_CODE(152)
/* The input buffer is insufficient. */
#define WSEC_ERR_INPUT_BUFF_NOT_ENOUGH                         WSEC_ERROR_CODE(153)
#define WSEC_ERR_CANCEL_BY_APP                                 WSEC_ERROR_CODE(154) /* Canceling an App Operation */
/* The app invoking sequence is incorrect. */
#define WSEC_ERR_INVALID_CALL_SEQ                              WSEC_ERROR_CODE(155)
/* The callback function is not registered. */
#define WSEC_ERR_CALLBACKS_NOT_REG                             WSEC_ERROR_CODE(156)
#define WSEC_ERR_INVALID_INSTANCE                              WSEC_ERROR_CODE(157) /* Using the instance flag wrong */
/* The callback and instance type do not match. */
#define WSEC_ERR_USE_WRONG_RANDOM_CALLBACK                     WSEC_ERROR_CODE(158)

/* System operation error. */
/* Failed to obtain the current time. */
#define WSEC_ERR_GET_CURRENT_TIME_FAIL                         WSEC_ERROR_CODE(201)
/* An error occurred when calculating the time difference. */
#define WSEC_ERR_CALC_DIFF_DAY_FAIL                            WSEC_ERROR_CODE(202)

/* KMC error */
/* Failed to obtain KMC configuration data. */
#define WSEC_ERR_KMC_CALLBACK_KMCCFG_FAIL                      WSEC_ERROR_CODE(251)
/* Invalid KMC configuration data. */
#define WSEC_ERR_KMC_KMCCFG_INVALID                            WSEC_ERROR_CODE(252)
/* Invalid configuration data exists in the Keystore. */
#define WSEC_ERR_KMC_KSF_DATA_INVALID                          WSEC_ERROR_CODE(253)
/* Initialization is invoked for multiple times. */
#define WSEC_ERR_KMC_INI_MUL_CALL                              WSEC_ERROR_CODE(254)
/* The file is not in the Keystore format. */
#define WSEC_ERR_KMC_NOT_KSF_FORMAT                            WSEC_ERROR_CODE(255)
/* Failed to read the key store file of another version. */
#define WSEC_ERR_KMC_READ_DIFF_VER_KSF_FAIL                    WSEC_ERROR_CODE(256)
#define WSEC_ERR_KMC_READ_MK_FAIL                              WSEC_ERROR_CODE(257) /* Failed to read the MK. */
#define WSEC_ERR_KMC_MK_LEN_TOO_LONG                           WSEC_ERROR_CODE(258) /* The MK key is too long. */
/* The MK to be registered is duplicate. */
#define WSEC_ERR_KMC_REG_REPEAT_MK                             WSEC_ERROR_CODE(259)
/* You are trying to add a duplicate domain (with the same ID). */
#define WSEC_ERR_KMC_ADD_REPEAT_DOMAIN                         WSEC_ERROR_CODE(260)
/* Duplicate key type (in the same domain). */
#define WSEC_ERR_KMC_ADD_REPEAT_KEY_TYPE                       WSEC_ERROR_CODE(261)
/* Duplicate KeyId (KeyId in the same domain) */
#define WSEC_ERR_KMC_ADD_REPEAT_MK                             WSEC_ERROR_CODE(262)
#define WSEC_ERR_KMC_DOMAIN_MISS                               WSEC_ERROR_CODE(263) /* The domain does not exist. */
/* The DOMAIN KeyType does not exist. */
#define WSEC_ERR_KMC_DOMAIN_KEYTYPE_MISS                       WSEC_ERROR_CODE(264)
/* The number of configured domains exceeds the upper limit. */
#define WSEC_ERR_KMC_DOMAIN_NUM_OVERFLOW                       WSEC_ERROR_CODE(265)
/* The number of configured key types exceeds the upper limit. */
#define WSEC_ERR_KMC_KEYTYPE_NUM_OVERFLOW                      WSEC_ERROR_CODE(266)
/* The number of MKs exceeds the threshold. */
#define WSEC_ERR_KMC_MK_NUM_OVERFLOW                           WSEC_ERROR_CODE(267)
#define WSEC_ERR_KMC_MK_MISS                                   WSEC_ERROR_CODE(268) /* The MK does not exist. */
#define WSEC_ERR_KMC_RECREATE_MK                               WSEC_ERROR_CODE(269) /* Failed to re-create the MK. */
/* The CBB has not been initialized. */
#define WSEC_ERR_KMC_CBB_NOT_INIT                              WSEC_ERROR_CODE(270)
/* The key automatically generated by the system cannot be registered. */
#define WSEC_ERR_KMC_CANNOT_REG_AUTO_KEY                       WSEC_ERROR_CODE(271)
/* The MK in the active state cannot be deleted. */
#define WSEC_ERR_KMC_CANNOT_RMV_ACTIVE_MK                      WSEC_ERROR_CODE(272)
/* The inactive MK cannot be set to expire. */
#define WSEC_ERR_KMC_CANNOT_SET_EXPIRETIME_FOR_INACTIVE_MK     WSEC_ERROR_CODE(273)
/* The RK generation mode does not support this operation. */
#define WSEC_ERR_KMC_RK_GENTYPE_REJECT_THE_OPER                WSEC_ERROR_CODE(274)
/* The MK generation mode does not support this operation. */
#define WSEC_ERR_KMC_MK_GENTYPE_REJECT_THE_OPER                WSEC_ERROR_CODE(275)
/* The domain to be added conflicts with the residual MK. */
#define WSEC_ERR_KMC_ADD_DOMAIN_DISCREPANCY_MK                 WSEC_ERROR_CODE(276)
/* The imported MK conflicts with the domain configuration. */
#define WSEC_ERR_KMC_IMPORT_MK_CONFLICT_DOMAIN                 WSEC_ERROR_CODE(277)
/* The private domain of the CBB cannot be accessed. */
#define WSEC_ERR_KMC_CANNOT_ACCESS_PRI_DOMAIN                  WSEC_ERROR_CODE(278)
#define WSEC_ERR_KMC_INVALID_ROLETYPE                          WSEC_ERROR_CODE(279) /* Invalid identity information. */
#define WSEC_ERR_KMC_ROLLBACK_FAIL                             WSEC_ERROR_CODE(280) /* Rollback failed. */
/* The hash length of the key entered for query is incorrect. */
#define WSEC_ERR_KMC_INVALID_KEYHASH_LEN                       WSEC_ERROR_CODE(281)
#define WSEC_ERR_KMC_CANNOT_FIND_ACTIVEKEY                     WSEC_ERROR_CODE(282) /* No valid key is found. */
#define WSEC_ERR_KMC_KEYSTOREMEM_NOTEXIST                      WSEC_ERROR_CODE(283) /* The keystore does not exist. */
#define WSEC_ERR_KMC_KEYCFGMEM_NOTEXIST                        WSEC_ERROR_CODE(284) /* keycfg does not exist. */
/* The key used for intra-domain registration is reversed. */
#define WSEC_ERR_KMC_MKID_OVERFLOW                             WSEC_ERROR_CODE(285)
#define WSEC_ERR_KMC_READMK_NOTCOMPLETE                        WSEC_ERROR_CODE(286) /* The MK is not completely read. */
#define WSEC_ERR_KMC_KSF_CORRUPT                               WSEC_ERROR_CODE(287) /* The KMC Ksf is damaged. */
/* The number of MK records exceeds the maximum. */
#define WSEC_ERR_LARGER_THAN_MAX_MK_RECORD_LEN                 WSEC_ERROR_CODE(288)
/* The KSF version number is incorrect. */
#define WSEC_ERR_KMC_KSF_VERSION_INVALID                       WSEC_ERROR_CODE(289)
/* The hardware root key does not exist. */
#define WSEC_ERR_KMC_HARDWARE_RK_NOT_FOUND                     WSEC_ERROR_CODE(290)
#define WSEC_ERR_KMC_SYNC_MK_FAILED                            WSEC_ERROR_CODE(291) /* Sync MK failed */
/* The MK domain type is incorrect. */
#define WSEC_ERR_KMC_DOMAIN_TYPE_ERROR                         WSEC_ERROR_CODE(292)
/* The MKs that meet the search criteria (domainId and domainType) are not filtered during import and export. */
#define WSEC_ERR_KMC_FILTER_MK_COUNT_ZERO                      WSEC_ERROR_CODE(293)
/* The number of MKs imported to the KSF exceeds the threshold. */
#define WSEC_ERR_KMC_IMPORT_MK_NUM_OVERFLOW                    WSEC_ERROR_CODE(294)
/* Import mk type is invalid, only support ADD and REPLACE mode currently. */
#define WSEC_ERR_KMC_INVALID_IMPORT_TYPE                       WSEC_ERROR_CODE(295)
/* The MK not support export or import. */
#define WSEC_ERR_KMC_MK_NOT_SUPPORT_EXP_IMP                    WSEC_ERROR_CODE(296)
#define WSEC_ERR_KMC_BATCH_DOAMIN_COUNT_EXCEED                 WSEC_ERROR_CODE(297) /* Batch domainId count is exceed */
/* Sync (send/recv) msg count failed */
#define WSEC_ERR_KMC_SYNC_CNF_COUNT_FAILED                     WSEC_ERROR_CODE(298)
/* Sync (send/recv) msg count invalid */
#define WSEC_ERR_KMC_SYNC_CNF_COUNT_INVALID                    WSEC_ERROR_CODE(299)
#define WSEC_ERR_KMC_SYNC_CNF_SEND_FAILED                      WSEC_ERROR_CODE(300) /* Sync msg count - send failed */
#define WSEC_ERR_KMC_SYNC_CNF_RECV_FAILED                      WSEC_ERROR_CODE(301) /* Sync msg count - recv failed */
/* Sync msg header failed - send/recv failed */
#define WSEC_ERR_KMC_SYNC_HEADER_SEND_FAILED                   WSEC_ERROR_CODE(302)
/* Sync msg header failed - send/recv failed */
#define WSEC_ERR_KMC_SYNC_HEADER_RECV_FAILED                   WSEC_ERROR_CODE(303)
/* Sync msg header failed - msg type invalid */
#define WSEC_ERR_KMC_SYNC_HEADER_MSGTYPE_INVALID               WSEC_ERROR_CODE(304)
/* Sync msg header failed - header version invalid */
#define WSEC_ERR_KMC_SYNC_HEADER_VER_INVALID                   WSEC_ERROR_CODE(305)
/* Sync msg header failed - msg length invalid */
#define WSEC_ERR_KMC_SYNC_HEADER_MSGLEN_INVALID                WSEC_ERROR_CODE(306)
#define WSEC_ERR_KMC_SYNC_AGENT_RESPONSE                       WSEC_ERROR_CODE(307) /* Sync agent response failed */
/* The algorithm does not exist or is not supported. */
#define WSEC_ERR_KMC_PRI_ALG_NOT_SUPPORTED                     WSEC_ERROR_CODE(320)
/* KMC does not support in NoKeyStore mode. */
#define WSEC_ERR_KMC_NOKEYSTORE_MODE_NOT_SUPPORTED             WSEC_ERROR_CODE(321)
/* KMC KSF VERSION NOT SAME */
#define WSEC_ERR_KMC_KSF_VERSION_NOT_SAME                      WSEC_ERROR_CODE(322)


/* SDP error. */
/* Failed to verify the password ciphertext. */
#define WSEC_ERR_SDP_PWD_VERIFY_FAIL                           WSEC_ERROR_CODE(351)
/* The configured data is inconsistent with the used data. */
#define WSEC_ERR_SDP_CONFIG_INCONSISTENT_WITH_USE              WSEC_ERROR_CODE(352)
/* The ciphertext format is incorrectly parsed. */
#define WSEC_ERR_SDP_INVALID_CIPHER_TEXT                       WSEC_ERROR_CODE(353)
/* The ciphertext version is incompatible with the current version. */
#define WSEC_ERR_SDP_VERSION_INCOMPATIBLE                      WSEC_ERROR_CODE(354)
/* The algorithm does not exist or is not supported. */
#define WSEC_ERR_SDP_ALG_NOT_SUPPORTED                         WSEC_ERROR_CODE(355)
/* The ciphertext is from an unexpected domain. */
#define WSEC_ERR_SDP_DOMAIN_UNEXPECTED                         WSEC_ERROR_CODE(356)
/* The length of the entered ciphertext is insufficient. */
#define WSEC_ERR_SDP_CIPHER_LENGTH_NOT_ENOUGH                  WSEC_ERROR_CODE(357)
/* During decryption, the ciphertext length in the ciphertext header is 0. */
#define WSEC_ERR_SDP_ZERO_CIPHER_LENGTH                        WSEC_ERROR_CODE(358)
/* Failed to initialize the random number RNG (DRBG). */
#define WSEC_ERR_SDP_RAND_INIT_FAILED                          WSEC_ERROR_CODE(359)
/* The number of iterations does not meet the expectation. */
#define WSEC_ERR_SDP_ITER_UNEXPECTED                           WSEC_ERROR_CODE(360)
#define WSEC_ERR_SDP_HEADER_CORRUPT                            WSEC_ERROR_CODE(361) /* The sdp header corrupt. */
#define WSEC_ERR_SDP_HEADER_TYPE                               WSEC_ERROR_CODE(362) /* The sdp header type err. */
#define WSEC_ERR_SDP_ARG_CIPHER_LEN                            WSEC_ERROR_CODE(363)
#define WSEC_ERR_SDP_ARG_PLAIN_LEN                             WSEC_ERROR_CODE(364)
#define WSEC_ERR_SDP_ARG_SALT_LEN                              WSEC_ERROR_CODE(365)
#define WSEC_ERR_SDP_ARG_IV_LEN                                WSEC_ERROR_CODE(366)

/* sdp asym err */
#define WSEC_ERR_SDP_SIGN_PLAIN_LEN_TOO_MAX                    WSEC_ERROR_CODE(450)
#define WSEC_ERR_SDP_SIGN_LEN_TOO_MAX                          WSEC_ERROR_CODE(451)
#define WSEC_ERR_SDP_ENC_PLAIN_LEN_TOO_MAX                     WSEC_ERROR_CODE(452)

/* TPM */
#define WSEC_ERR_TPM_CAPABILITY_NOT_GOT                        WSEC_ERROR_CODE(500)
#define WSEC_ERR_TPM_RESOURCE_NOT_ENOUGH                       WSEC_ERROR_CODE(501)
#define WSEC_ERR_KMC_NOT_HARDWARE                              WSEC_ERROR_CODE(502)


/* sync error */
/* KMC sync domain array is not enough. */
#define WSEC_ERR_KMC_SYNC_DOMAINARRAY_NOT_ENOUGH               WSEC_ERROR_CODE(550)
/* KMC sync has no intersect dh alg */
#define WSEC_ERR_KMC_SYNC_DH_ALG_NOT_INTERSECT                 WSEC_ERROR_CODE(551)
/* KMC sync has no available dh alg */
#define WSEC_ERR_KMC_SYNC_HASNO_AVAILABLE_DH_ALG               WSEC_ERROR_CODE(552)
/* KMC sync transform dh alg failed */
#define WSEC_ERR_KMC_SYNC_DH_ALG_TRANSFORM_FAILED              WSEC_ERROR_CODE(553)
/* KMC sync support dh cap nego failed */
#define WSEC_ERR_KMC_SYNC_DH_CAP_NOT_SUPPORT                   WSEC_ERROR_CODE(554)
/* KMC sync recv peer msg type error */
#define WSEC_ERR_KMC_SYNC_MSG_TYPE_ERROR                       WSEC_ERROR_CODE(555)
/* KMC sync dlsym failed, not support dh */
#define WSEC_ERR_KMC_SUPPORT_DH_FAILED                         WSEC_ERROR_CODE(556)
/* KMC sync recv msg body failed */
#define WSEC_ERR_KMC_SYNC_RECV_BODY_FAILED                     WSEC_ERROR_CODE(557)
/* do not need to sync asym key */
#define WSEC_ERR_KMC_SYNC_ASYM_KEY_FAILED                      WSEC_ERROR_CODE(558)


/* Memory information protection */
#define WSEC_ERR_MEMINFO_PROTECT_FAIL                          WSEC_ERROR_CODE(600)
/* Failed to initialize memory information protection. */
#define WSEC_ERR_MASK_INIT_FAIL                                WSEC_ERROR_CODE(601)
#define WSEC_ERR_KEYRING_REQKEY                                WSEC_ERROR_CODE(602)
#define WSEC_ERR_KEYRING_READKEY                               WSEC_ERROR_CODE(603)
#define WSEC_ERR_KEYRING_COMPAREKEY                            WSEC_ERROR_CODE(604)

/* TEE CA ERROR */
#define WSEC_ERR_CA_INTI_CONTEXT                               WSEC_ERROR_CODE(700)
#define WSEC_ERR_CA_OPEN_SESSION                               WSEC_ERROR_CODE(701)
#define WSEC_ERR_CA_INVALID_PARAM_FORMAT                       WSEC_ERROR_CODE(702) /* Data format is invalid. */
#define WSEC_ERR_CA_INVALID_ARG                                WSEC_ERROR_CODE(703) /* Invalid parameter */
/* Out buffer is not enough for current request */
#define WSEC_ERR_CA_BUFFER_NOT_ENOUGH                          WSEC_ERROR_CODE(704)
#define WSEC_ERR_CA_ACCESS_DENIED                              WSEC_ERROR_CODE(705) /* Permission check failed. */
/* Request operation is not supported */
#define WSEC_ERR_CA_OPERATION_NOT_SUPPORTED                    WSEC_ERROR_CODE(706)
#define WSEC_ERR_CA_GENERIC_ERROR                              WSEC_ERROR_CODE(707) /* Tee generic error occurs. */
#define WSEC_ERR_CA_INVALID_TA_PATH                            WSEC_ERROR_CODE(708) /* Invalid ta path. */
/* confilct occurs in concurrent access to data */
#define WSEC_ERR_CA_EXCEED_MAX_SESSION_NUM                     WSEC_ERROR_CODE(709)
#define WSEC_ERR_CA_BUFFER_TOO_LARGE                           WSEC_ERROR_CODE(710) /* Input buffer is toot large. */
#define WSEC_ERR_CA_INVALID_TA_PATH_SUFFIX                     WSEC_ERROR_CODE(711) /* Invalid ta path suffix. */
#define WSEC_ERR_CA_UNSUPPORT_TEE_MODE                         WSEC_ERROR_CODE(712) /* Not support tee mode. */
#define WSEC_ERR_CA_TEE_NOT_SUPPORT                            WSEC_ERROR_CODE(713)
#define WSEC_ERR_CA_RK_LEN_INVAILD                             WSEC_ERROR_CODE(714)
/* Failed to load Trusted Application */
#define WSEC_ERR_CA_TRUSTED_APP_LOAD_ERROR                     WSEC_ERROR_CODE(715)
/* TEE mod not support HardWare, TEE and hardware mode cannot coexist */
#define WSEC_ERR_CA_TEEMODE_NOT_SUPPORT_HW                     WSEC_ERROR_CODE(716)
/* TEEOS crash exception */
#define WSEC_ERR_CA_TEE_CRASH                                  WSEC_ERROR_CODE(717)

/* common tlv error */
#define WSEC_ERR_TLV_CORRUPT                                   WSEC_ERROR_CODE(800) /* The sdp header tlv corrupt. */
#define WSEC_ERR_MATCH_TLV_TAG                                 WSEC_ERROR_CODE(801) /* Not find match tlv tag. */
#define WSEC_ERR_MATCH_TLV_LEN                                 WSEC_ERROR_CODE(802) /* the tlv value len err. */
#define WSEC_ERR_FILL_TLV                                      WSEC_ERROR_CODE(803) /* fill tlv err. */

/* asymmetic error */
/* Create evp pkey context failed. */
#define WSEC_ERR_EVP_PKEY_CTX_NEW_ID_FAILED                    WSEC_ERROR_CODE(900)
/* Evp pkey context init failed. */
#define WSEC_ERR_EVP_PKEY_KEYGEN_INIT_FAILED                   WSEC_ERROR_CODE(901)
/* Evp pkey keygen failed. */
#define WSEC_ERR_EVP_PKEY_KEYGEN_FAILED                        WSEC_ERROR_CODE(902)
/* Get evp pkey raw public or private failed. */
#define WSEC_ERR_EVP_PKEY_GET_RAW_PUBPRI_KEY_FAILED            WSEC_ERROR_CODE(903)
/* Set rsa key bits failed. */
#define WSEC_ERR_RSA_PKEY_CTX_CTRL_FAILED                      WSEC_ERROR_CODE(904)
/* Evp pkey parameters init failed. */
#define WSEC_ERR_EVP_PKEY_PARAMGEN_INIT_FAILED                 WSEC_ERROR_CODE(905)
/* Create evp pkey ctx failed. */
#define WSEC_ERR_EVP_PKEY_CTX_NEW_FAILED                       WSEC_ERROR_CODE(906)
/* Set pkey paramgen curve nid failed. */
#define WSEC_ERR_EVP_PKEY_CTX_CTRL_FAILED                      WSEC_ERROR_CODE(907)
/* Ecc get public key x and y failed. */
#define WSEC_ERR_EC_POINT_GET_AFFINE_COORDINATES_FAILED        WSEC_ERROR_CODE(908)
/* Ecc keyParts Malloc failed. */
#define WSEC_ERR_ECC_KEYPARTS_MALLOC_FAILED                    WSEC_ERROR_CODE(909)
/* Bignum to binary with pad failed. */
#define WSEC_ERR_BN_BN2BINPAD_FAILED                           WSEC_ERROR_CODE(910)
/* Evp pkey assign failed. */
#define WSEC_ERR_EVP_PKEY_ASSIGN_FAILED                        WSEC_ERROR_CODE(911)
/* Create evp md ctx failed. */
#define WSEC_ERR_EVP_MD_CTX_NEW_FAILED                         WSEC_ERROR_CODE(912)
/* Evp sign init failed. */
#define WSEC_ERR_EVP_DIGEST_SIGN_INIT_FAILED                   WSEC_ERROR_CODE(913)
/* Evp digest sign update failed. */
#define WSEC_ERR_EVP_DIGEST_UPDATE_FAILED                      WSEC_ERROR_CODE(914)
/* Asym Key sign final failed */
#define WSEC_ERR_SIGN_FAILED                                   WSEC_ERROR_CODE(915)
/* Asym Key verify final failed */
#define WSEC_ERR_VERIFY_FAILED                                 WSEC_ERROR_CODE(916)
/* Get Ecc Sign MD by algo failed. */
#define WSEC_ERR_GET_ECC_SIGN_MD_BY_ALGO_FAILED                WSEC_ERROR_CODE(917)
/* Binary to bignum failed. */
#define WSEC_ERR_BN_BIN2BN_FAILED                              WSEC_ERROR_CODE(918)
/* Extract buff failed. */
#define WSEC_ERR_EXTRACT_BUFF_FAILED                           WSEC_ERROR_CODE(919)
/* Ecc key set public failed. */
#define WSEC_ERR_EC_KEY_SET_PUB_KEY_FAILED                     WSEC_ERROR_CODE(920)
/* Ecc key set private failed. */
#define WSEC_ERR_EC_KEY_SET_PRIVATE_KEY_FAILED                 WSEC_ERROR_CODE(921)
/* Evp pkey set ec key failed. */
#define WSEC_ERR_EVP_PKEY_SET1_EC_KEY_FAILED                   WSEC_ERROR_CODE(922)
/* Duplicate EVP_MD failed. */
#define WSEC_ERR_EVP_MD_METH_DUP_FAILED                        WSEC_ERROR_CODE(923)
/* Evp pkey sign set padding failed. */
#define WSEC_ERR_EVP_PKEY_CTX_SET_RSA_PADDING_FAILED           WSEC_ERROR_CODE(924)
/* Evp pkey set sign md failed. */
#define WSEC_ERR_EVP_PKEY_CTX_SET_SIGNATURE_MD_FAILED          WSEC_ERROR_CODE(925)
/* Create new evp pkey failed. */
#define WSEC_ERR_EVP_PKEY_NEW_FAILED                           WSEC_ERROR_CODE(926)
/* Rsa new failed. */
#define WSEC_ERR_RSA_NEW_FAILED                                WSEC_ERROR_CODE(927)
/* Rsa set parts failed. */
#define WSEC_ERR_RSA_SET0_KEY_FAILED                           WSEC_ERROR_CODE(928)
/* Not support algo. */
#define WSEC_ERR_GET_OP_PARAM_FAILED                           WSEC_ERROR_CODE(929)
/* Sign Compute digest failed. */
#define WSEC_ERR_COMPUTE_DIGEST_FAILED                         WSEC_ERROR_CODE(930)
/* Evp pkey sign init failed. */
#define WSEC_ERR_EVP_PKEY_SIGN_INIT_FAILED                     WSEC_ERROR_CODE(931)
/* Evp digest verify init failed. */
#define WSEC_ERR_EVP_DIGEST_VERIFY_INIT_FAILED                 WSEC_ERROR_CODE(932)
/* Evp pkey set alias type failed. */
#define WSEC_ERR_EVP_PKEY_SET_ALIAS_TYPE_FAILED                WSEC_ERROR_CODE(933)
/* Evp pkey encrypt init failed. */
#define WSEC_ERR_EVP_PKEY_ENCRYPT_INIT_FAILED                  WSEC_ERROR_CODE(934)
/* Evp pkey encrypt failed. */
#define WSEC_ERR_EVP_PKEY_ENCRYPT_FAILED                       WSEC_ERROR_CODE(935)
/* Evp pkey decrypt init failed. */
#define WSEC_ERR_EVP_PKEY_DECRYPT_INIT_FAILED                  WSEC_ERROR_CODE(936)
/* Evp pkey decrypt failed. */
#define WSEC_ERR_EVP_PKEY_DECRYPT_FAILED                       WSEC_ERROR_CODE(937)
/* KeyType is not support. */
#define WSEC_ERR_UNSUPPORTED_KEYTYPE                           WSEC_ERROR_CODE(938)
/* New raw evp pkey private failed. */
#define WSEC_ERR_EVP_PKEY_NEW_RAW_PRIVATE_KEY_FAILED           WSEC_ERROR_CODE(939)
/* New raw evp pkey public failed. */
#define WSEC_ERR_EVP_PKEY_NEW_RAW_PUBLIC_KEY_FAILED            WSEC_ERROR_CODE(940)
/* Evp pkey verify init failed. */
#define WSEC_ERR_EVP_PKEY_VERIFY_INIT_FAILED                   WSEC_ERROR_CODE(941)
/* i2d publickey failed. */
#define WSEC_ERR_I2D_PUBKEY_FAILED                             WSEC_ERROR_CODE(942)
/* d2I publickey failed. */
#define WSEC_ERR_D2I_PUBKEY_FAILED                             WSEC_ERROR_CODE(943)
/* create new EC_KEY by curve failed. */
#define WSEC_ERR_NEW_EC_BY_CURVE_FAILED                        WSEC_ERROR_CODE(945)
/* Asn1 get object failed. */
#define WSEC_ERR_ASN1_GET_OBJECT_FAILED                        WSEC_ERROR_CODE(946)
/* Pub key len error. */
#define WSEC_ERR_GET_PUB_KEY_LEN_FAILED                        WSEC_ERROR_CODE(947)
/* Evp pkey get bn param failed. */
#define WSEC_ERR_EVP_PKEY_GET_BN_PARAM_FAILED                  WSEC_ERROR_CODE(948)
/* Evp pkey ctx new from name failed. */
#define WSEC_ERR_EVP_PKEY_CTX_NEW_FROM_NAME_FAILED             WSEC_ERROR_CODE(949)
/* Evp pkey from data init failed. */
#define WSEC_ERR_EVP_PKEY_FROM_DATA_INIT_FAILED                WSEC_ERROR_CODE(950)
/* New ossl param bld failed. */
#define WSEC_ERR_OSSL_PARAM_BLD_NEW_FAILED                     WSEC_ERROR_CODE(951)
/* Ossl param push utf8string failed. */
#define WSEC_ERR_OSSL_PARAM_BLD_PUSH_UTF8STRING_FAILED         WSEC_ERROR_CODE(952)
/*  Ossl param push octstring failed. */
#define WSEC_ERR_OSSL_PARAM_BLD_PUSH_OCTTRING_FAILED           WSEC_ERROR_CODE(953)
/* Ossl param push bn failed. */
#define WSEC_ERR_OSSL_PARAM_BLD_PUSH_BN_FAILED                 WSEC_ERROR_CODE(954)
/* Build ossl bld to param failed. */
#define WSEC_ERR_OSSL_PARAM_BLD_TO_PARAM_FAILED                WSEC_ERROR_CODE(955)
/* Evp pkey from data failed. */
#define WSEC_ERR_EVP_PKEY_FROM_DATA_FAILED                     WSEC_ERROR_CODE(956)
/* Bignum to binary failed. */
#define WSEC_ERR_BN_BN2BIN_FAILED                              WSEC_ERROR_CODE(957)

/* asym key management error */
/* KMC ext ksf value len too large */
#define WSEC_ERR_KMC_EXT_KSF_VALUE_LEN_TOO_LARGE               WSEC_ERROR_CODE(2000)
/* KMC nova ksf repeat */
#define WSEC_ERR_KMC_ADD_NOVA_KSF_REPEAT                       WSEC_ERROR_CODE(2001)
/* KMC ext ksf tag invaild */
#define WSEC_ERR_KMC_EXT_KSF_TAG_INVAILD                       WSEC_ERROR_CODE(2002)
/* KMC ext ksf num too large */
#define WSEC_ERR_KMC_EXT_KSF_NUM_OVERFLOW                      WSEC_ERROR_CODE(2003)
/* KMC nova key tag not match */
#define WSEC_ERR_KMC_NOVA_KEY_TAG_NOT_MATCH                    WSEC_ERROR_CODE(2004)
/* nova key repeat */
#define WSEC_ERR_KMC_ADD_REPEAT_NOVA_KEY                       WSEC_ERROR_CODE(2005)
/* keyType not match */
#define WSEC_ERR_KMC_ADD_KEY_TYPE_NOT_MATCH                    WSEC_ERROR_CODE(2006)
/* nova key miss */
#define WSEC_ERR_KMC_NOVA_KEY_MISS                             WSEC_ERROR_CODE(2007)
/* nova ksf miss */
#define WSEC_ERR_KMC_NOVA_KSF_MISS                             WSEC_ERROR_CODE(2008)
/* kmc domain keyType not match */
#define WSEC_ERR_KMC_DOMAIN_KEYTYPE_NOT_MATCH                  WSEC_ERROR_CODE(2009)
/* kmc get nova ksf mem */
#define WSEC_ERR_KMC_GET_NOVA_KSF_MEM                          WSEC_ERROR_CODE(2010)
/* The nova key in the active state cannot be deleted. */
#define WSEC_ERR_KMC_CANNOT_RMV_ACTIVE_NOVA_KEY                WSEC_ERROR_CODE(2011)
/* The nova key can not add in domain 0 and 1 */
#define WSEC_ERR_KMC_CANNOT_ADD_ASYM_TO_DEFAULT                WSEC_ERROR_CODE(2012)
/* The asym keypair not a pair */
#define WSEC_ERR_KMC_ASYM_KEYPAIR_NOT_MATCH                    WSEC_ERROR_CODE(2013)
/* The ext ksf tag not match */
#define WSEC_ERR_KMC_EXT_TAG_NOT_MATCH                         WSEC_ERROR_CODE(2014)
/* The ext sub num too much */
#define WSEC_ERR_KMC_EXT_SUB_NUM_TOO_MUCH                      WSEC_ERROR_CODE(2015)
/* The key len is rollover in transmission */
#define WSEC_ERR_KMC_KEY_LEN_OVERFLOW                          WSEC_ERROR_CODE(2016)
/* The asym keySpec not match domain keyType */
#define WSEC_ERR_KMC_ASYM_KEYSPEC_NOT_MATCH_KEYTYPE            WSEC_ERROR_CODE(2017)
/* The asym keyLen too much */
#define WSEC_ERR_KMC_ASYM_KEY_LEN_TOO_MUCH                     WSEC_ERROR_CODE(2018)

#define WSEC_ERR_MAX                                           WSEC_ERROR_CODE(5000) /* Maximum CBB Error Code */

#ifdef __cplusplus
}
#endif  /* __cplusplus */

#endif /* KMC_INCLUDE_WSECV2_ERRORCODE_H */

/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2014-2020. All rights reserved.
 * Description: KMC internal interfaces are not open to external systems.

 * Create: 2014-06-16
 */

#ifndef KMC_SRC_COMMON_WSECV2_FILE_H
#define KMC_SRC_COMMON_WSECV2_FILE_H

#include "wsecv2_type.h"
#include "wsecv2_callbacks.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WSEC_FILE_IO_SIZE_MAX 4096 /* Maximum length of a file I/O. */
/* Ensure that the ciphertext size is less than 2 GB,
 * the maximum len that can be obtained for encrypted files.
 * ((1024 * 1024) * (2048 - 8))
 */
#define WSEC_ENCRYPT_MAX_FILE_LEN (1024 * 1024 * 2040)
/* Calculate the maximum decryption file length (the largest among all possible ciphertext files)
 * based on the maximum encrypted file length.
 * The maximum decryption file length is divided into five parts:
 * 1. Write file header: sizeof(SdpCipherFileHeader) + 2 x size(flag)
 * 2. Write the ciphertext header, sizeof(SdpCipherCtxEx) + max_tlv_len + 2 x size(flag).
 * 3. The file is encrypted in blocks, and each block is WSEC_FILE_IO_SIZE_MAX + 2*size(flag).
 * The value of WSEC_FILE_IO_SIZE_MAX is less than the value of SDP_SYM_MAX_BLOCK_SIZE plus 2 x size.
 * The part with more flags is encrypted later.
 * 4. Encrypt SDP_SYM_MAX_BLOCK_SIZE + 2*size(flag)
 * 5. Write hmac, SDP_SYM_MAX_BLOCK_SIZE + 2*size(flag)
 */
/* the maximum decryption file length,win long_max  */
#define WSEC_DECRYPT_MAX_FILE_LEN 0x7FFFFFFF

/* Check whether the file exists. */
WsecBool WsecCheckStatus(KmcCbbCtx *kmcCtx, const char *name);

/* Copying files */
WsecBool WsecCopyFile(KmcCbbCtx *kmcCtx, const char *srcFile, const char *destFile);

/* Obtains the file length. */
WsecBool WsecGetFileLen(KmcCbbCtx *kmcCtx, WsecHandle fd, long *fileLen);

/* Obtains the rest file length. */
WsecBool WsecGetRestFileLen(KmcCbbCtx *kmcCtx, WsecHandle fd, long *fileLen);

/* Securely delete files. For security consider, if the file length exceed the fileMaxLen,
 * the delete operation will not continue. The fileMaxLen is set according to actual needs,
 * and it will not check the file length if set fileMaxLen = 0.
 */
WsecBool WsecDeleteFileSafe(KmcCbbCtx *kmcCtx, const char *filePathName, long fileMaxLen);

/* Open the file to be read and written and obtain the length of the file to be read. */
unsigned long WsecReadWriteFilePrepare(KmcCbbCtx *kmcCtx, const char *readFile, const char *writeFile,
    WsecHandle *readStream, WsecHandle *writeStream,
    long *remainLen);

/* checke the encrypt or decrypt file len is OK. */
unsigned long WsecCheckEncDecFileLen(KmcCbbCtx *kmcCtx, long fileLen, WsecBool isEncrypt);

#define WSEC_FOPEN(kmcCtx, filePathName, mode)     (WsecFopen(kmcCtx, filePathName, mode))
#define WSEC_FCLOSE(kmcCtx, stream)                (((stream) != NULL) ? (void)WsecFclose(kmcCtx, stream) : (void)0)
#define WSEC_FREAD(kmcCtx, buffer, count, stream)  (WsecFread(kmcCtx, buffer, (size_t)(count), stream))
#define WSEC_FWRITE(kmcCtx, buffer, count, stream) (WsecFwrite(kmcCtx, buffer, (size_t)(count), stream))
#define WSEC_FREMOVE(kmcCtx, filePathName)         (WsecFremove(kmcCtx, filePathName))
#define WSEC_FFLUSH(kmcCtx, stream)                (WsecFflush(kmcCtx, stream))
#define WSEC_FTELL(kmcCtx, stream)                 (WsecFtell(kmcCtx, stream))
#define WSEC_FSEEK(kmcCtx, stream, offset, origin) (WsecFseek(kmcCtx, stream, (long)(offset), origin))
#define WSEC_FERRNO(kmcCtx, stream)                (WsecFerrno(kmcCtx, stream))
#define WSEC_FSTATUS(kmcCtx, name)                 (WsecCheckStatus(kmcCtx, name))

#define WSEC_FREAD_MUST(kmcCtx, buff, buffLen, stream)  (WSEC_FREAD(kmcCtx, buff, buffLen, stream) == WSEC_TRUE)
#define WSEC_FWRITE_MUST(kmcCtx, buff, buffLen, stream) (WSEC_FWRITE(kmcCtx, buff, buffLen, stream) == WSEC_TRUE)

#ifdef __cplusplus
}
#endif  /* __cplusplus */

#endif /* KMC_SRC_COMMON_WSECV2_FILE_H */

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
 * cm_string_uca.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_string_uca.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __CM_STRING_UCA_H__
#define __CM_STRING_UCA_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned long cm_wc_t;

#define CM_CS_ILSEQ 0
#define CM_CS_ILUNI 0
#define CM_CS_TOOSMALL  (-101)
#define CM_CS_TOOSMALL2 (-102)
#define CM_CS_TOOSMALL3 (-103)
#define CM_CS_TOOSMALL4 (-104)
#define CM_CS_TOOSMALL5 (-105)
#define CM_CS_TOOSMALL6 (-106)
#define CM_CS_TOOSMALLN(n) (-100 - (n))

#define CM_CS_REPLACEMENT_CHARACTER 0xFFFD

#define CM_UCA_900_CE_SIZE 3
#define UCA900_DISTANCE_BETWEEN_WEIGHTS (CM_UCA_900_CE_SIZE * 256)

#define CM_UCA_CNT_FLAG_SIZE 4096
#define CM_UCA_CNT_FLAG_MASK 4095

#define CM_UCA_CNT_HEAD (1 << 0)
#define CM_UCA_CNT_TAIL (1 << 1)
#define CM_UCA_CNT_MID1 (1 << 2)
#define CM_UCA_PREVIOUS_CONTEXT_HEAD (1 << 3)
#define CM_UCA_PREVIOUS_CONTEXT_TAIL (1 << 4)

#define CM_UCA_MAX_WEIGHT_SIZE 25

#define CM_MIN_VALUE(a, b) ((a) < (b) ? (a) : (b))

#define JA_KATA_QUAT_WEIGHT 0x08
#define JA_HIRA_QUAT_WEIGHT 0x02
#define HANGUL_JAMO_MAX_LENGTH 3

#define UCA900_NUM_OF_CE(page, subcode) ((page)[(subcode)])
#define UCA900_WEIGHT_ADDR(page, level, subcode) ((page) + 256 + (level) * 256 + (subcode))
#define UCA900_WEIGHT(page, level, subcode) (page)[256 + (level) * 256 + (subcode)]

int32 bincmp_utf8mb4(const uchar *s, const uchar *se, const uchar *t, const uchar *te);
void cm_tosort_unicode(const CM_UNICASE_INFO *uni_plane, cm_wc_t *cm_wc, uint flags);
int32 cm_mb_wc_utf8_prototype(cm_wc_t *pwc, const uchar *s, const uchar *e, bool32 range_check, bool32 support_mb4);
int32 cm_mb_wc_utf8mb4(cm_wc_t *pwc, const uchar *s, const uchar *e);
int32 cm_utf8mb4_general_ci_compare_collsp(const CHARSET_COLLATION *cs, text_t *text1, text_t *text2);
int32 cm_utf8mb4_bin_compare_collsp(const CHARSET_COLLATION *cs, text_t *text1, text_t *text2);
int32 cm_utf8mb4_0900_ai_ci_compare_coll(const CHARSET_COLLATION *cs, text_t *text1, text_t *text2);
int32 cm_utf8mb4_0900_bin_compare_collsp(const CHARSET_COLLATION *cs, text_t *text1, text_t *text2);
int32 cm_bin_compare_coll(const CHARSET_COLLATION *cs, text_t *text1, text_t *text2);
int32 uca_scanner_more_weight(scanner_t *scanner);
const uint16 *uca_scanner_previous_context_find(scanner_t *scanner, cm_wc_t wc0, cm_wc_t wc1);
const uint16 *uca_scanner_contraction_find(scanner_t *scanner, cm_wc_t wc0, size_t *chars_skipped);
void uca_scanner_cm_put_jamo_weights(scanner_t *scanner, cm_wc_t *hangul_jamo, int32 jamo_cnt);
int32 uca_scanner_next_implicit(uca_scanner_t *uca_scanner, cm_wc_t ch);
int32 uca_scanner_next(uca_scanner_t *uca_scanner, uint32 levels_for_compare);
extern uint16 *uca900_weight[4352];

#ifdef __cplusplus
}
#endif

#endif
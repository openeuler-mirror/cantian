/* -------------------------------------------------------------------------
 *  This file is part of the Cantian project.
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd.
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
 * cm_dec2.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_dec2.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_dec2.h"
#include "cm_text.h"
#include "cm_binary.h"

#ifdef __cplusplus
extern "C" {
#endif

#define GET_ZEROS_TAIL_CELL(u) (((u) % 10 == 0) ? 1 : 0)
#define GET_DIGITS_HEAD_CELL(u) (((u) >= 10) ? 2 : 1)
#define DEC2_HALF_MASK 50U

/* DEC2_POW2_MASK is 10^4 */
#define DEC2_POW2_MASK ((uint32)10000u)

/* DEC2_POW3_MASK is 10^6 */
#define DEC2_POW3_MASK ((uint64)1000000u)

/* DEC2_POW4_MASK is 10^8 */
#define DEC2_POW4_MASK ((uint64)100000000u)

/* DEC2_POW5_MASK is 10^10 */
#define DEC2_POW5_MASK ((uint64)10000000000u)

/* DEC2_POW6_MASK is 10^12 */
#define DEC2_POW6_MASK ((uint64)1000000000000u)

/* DEC2_POW7_MASK is 10^14 */
#define DEC2_POW7_MASK ((uint64)100000000000000u)

/* DEC2_POW8_MASK is 10^16 */
#define DEC2_POW8_MASK ((uint64)10000000000000000u)

/* DEC2_POW9_MASK is 10^18 */
#define DEC2_POW9_MASK ((uint64)1000000000000000000u)

static const uint64 g_pow100_u64[] = {
    1,               // 100^0
    DEC2_CELL_MASK,  // 100^1
    DEC2_POW2_MASK,  // 100^2
    DEC2_POW3_MASK,  // 100^3
    DEC2_POW4_MASK,  // 100^4
    DEC2_POW5_MASK,  // 100^5
    DEC2_POW6_MASK,  // 100^6
    DEC2_POW7_MASK,  // 100^7
    DEC2_POW8_MASK,  // 100^8
    DEC2_POW9_MASK,  // 100^9
};

/* decimal 0.5 50*10^-2 */
static const dec2_t DEC2_HALF_ONE = {
    .len = 2,
    .head = CONVERT_EXPN(-2, GS_FALSE),
    .cells = { 50 }
};

/* decimal 1 1.0*10^0 */
const dec2_t DEC2_ONE = {
    .len = 2,
    .head = CONVERT_EXPN(0, GS_FALSE),
    .cells = { 1 }
};

/* decimal pi/2 is 1.570796326794896619231321691639751442098584699687552910487472296153908 * 10 ^0 */
static const dec2_t DEC2_HALF_PI = {
    .len = DEC2_MAX_LEN,
    .head = CONVERT_EXPN(0, GS_FALSE),
    .cells = { 1,  57, 07, 96, 32, 67, 94, 89, 66, 19, 23, 13, 21, 69, 16, 39, 75, 14, 42, 9,  85, 84, 69, 96, 88 }
};

/* decimal pi is   3.1415926535897932384626433832795028841971693993751058209749445923078164 * 10 ^0 */
static const dec2_t DEC2_PI = {
    .len = DEC2_MAX_LEN,
    .head = CONVERT_EXPN(0, GS_FALSE),
    .cells = { 3,  14, 15, 92, 65, 35, 89, 79, 32, 38, 46, 26, 43, 38, 32, 79, 50, 28, 84, 19, 71, 69, 39, 93, 75 }
};

/* decimal 2*pi is 6.28318530717958647692528676655900576839433879875021164194988918461563281 * 10^0 */
static const dec2_t DEC2_2PI = {
    .len = DEC2_MAX_LEN,
    .head = CONVERT_EXPN(0, GS_FALSE),
    .cells = { 6,  28, 31, 85, 30, 71, 79, 58, 64, 76, 92, 52, 86, 76, 65, 59, 00, 57, 68, 39, 43, 38, 79, 87, 50 }
};

/* 1/(2pi) is 15.9154943091895335768883763372514362034459645740456448747667344058896797634226535 * 10^-2 */
static const dec2_t DEC2_INV_2PI = {
    .len = DEC2_MAX_LEN,
    .head = CONVERT_EXPN(-2, GS_FALSE),
    .cells = { 15, 91, 54, 94, 30, 91, 89, 53, 35, 76, 88, 83, 76, 33, 72, 51, 43, 62, 03, 44, 59, 64, 57, 40, 46 }
};

/* decimal of the minimal int64 is -9.22 33 72 03 68 54 77 58 08 * 10^18 */
const dec2_t DEC2_MIN_INT64 = {
    .len = 11,
    .head = CONVERT_EXPN(18, GS_TRUE),
    .cells = { 9, 22, 33, 72, 03, 68, 54, 77, 58, 8 }
};

/* decimal of the minimal int32 is -21.47483648 * 10^8 */
static const dec2_t DEC2_MIN_INT32 = {
    .len = 6,
    .head = CONVERT_EXPN(8, GS_TRUE),
    .cells = { 21, 47, 48, 36, 48 }
};

static const dec2_t g_inv_fact[] = {
    /* 1/3! = 0.166666666666666666666666666666666666666666666666666666666666666666666666666
            = 16.6666666666666666666666666666666666666667 * 10^-2 */
    [_I(3)] = {
        .len = DEC2_MAX_LEN,
        .head = CONVERT_EXPN(-2, GS_FALSE),
        .cells = { 16, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 67 }
    },
    /* 1/4! =
     * 0.04166666666666666666666666666666666666666666666666666666666666666666666666666666666666666
     * 6666666666666666666666
     * 4.166666666666666666666666666666666666666667 * 10^-2 */
    [_I(4)] = {
        .len = DEC2_MAX_LEN,
        .head = CONVERT_EXPN(-2, GS_FALSE),
        .cells = { 4, 16, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 67 }
    },
    /* 1/5! = 0.0083333333333333333333333333333333333333333333333333333333333333333333333333333
     * 83.33333333333333333333333333333333333333333 * 10 ^-4 */
    [_I(5)] = {
        .len = DEC2_MAX_LEN,
        .head = CONVERT_EXPN(-4, GS_FALSE),
        .cells = { 83, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33 }
    },
    /* 1/6! =
     * 0.001388888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888
     * 8888888888888888888888888888888888888888888888888888888
     */
    [_I(6)] = {
        .len = DEC2_MAX_LEN,
        .head = CONVERT_EXPN(-4, GS_FALSE),
        .cells = { 13, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 89, 88, 89 }
    },
    /* 1/7! = 0.0001984126984126984126984126984126984126984126984126984126984126984126984126984126984 */
    [_I(7)] = {
        .len = DEC2_MAX_LEN,
        .head = CONVERT_EXPN(-4, GS_FALSE),
        .cells = { 1, 98, 41, 26, 98, 41, 26, 98, 41, 26, 98, 41, 26, 98, 41, 26, 98, 41, 26, 98, 41, 26, 98, 41, 26 }
    },
    /* 1/8! =
     * 0.0000248015873015873015873015873015873015873015873015873015873015873015873015873015873015873
     * 015873015873015873015873015873015873015873015873015873015873015873
     */
    [_I(8)] = {
        .len = DEC2_MAX_LEN,
        .head = CONVERT_EXPN(-6, GS_FALSE),
        .cells = { 24, 80, 15, 87, 30, 15, 87, 30, 15, 87, 30, 15, 87, 30, 15, 87, 30, 15, 87, 30, 15, 87, 30, 15, 87 }
    },
    /* 1/9! = 0.00000275573192239858906525573192239858906525573192239858906525573192239858906525573192
     *                7557319223985890652557319223986 */
    [_I(9)] = {
        .len = DEC2_MAX_LEN,
        .head = CONVERT_EXPN(-6, GS_FALSE),
        .cells = { 2, 75, 57, 31, 92, 23, 98, 58, 90, 65, 25, 57, 31, 92, 23, 98, 58, 90, 65, 25, 57, 31, 92, 23, 99 }
    },
    /* 1/10! = 0.000000275573192239858906525573192239858906525573192239858906525573192239858906525573192
     *                  7557319223985890652557319223986 */
    [_I(10)] = {
        .len = DEC2_MAX_LEN,
        .head = CONVERT_EXPN(-8, GS_FALSE),
        .cells = { 27, 55, 73, 19, 22, 39, 85, 89, 06, 52, 55, 73, 19, 22, 39, 85, 89, 06, 52, 55, 73, 19, 22, 39, 86 }
    },
    /* 1/11! =
     * 0.000000025052108385441718775052108385441718775052108385441718775052108385441718775
     * 0521083854417187750521083854417187750521
     */
    [_I(11)] = {
        .len = DEC2_MAX_LEN,
        .head = CONVERT_EXPN(-8, GS_FALSE),
        .cells = { 2, 50, 52, 10, 83, 85, 44, 17, 18, 77, 50, 52, 10, 83, 85, 44, 17, 18, 77, 50, 52, 10, 83, 85, 44 }
    },
    /* 1/12! =
     * 0.0000000020876756987868098979210090321201432312543423654534765645876756987868098979210090
     * 3212014323125434236545347656458767569878680989792
     */
    [_I(12)] = {
        .len = DEC2_MAX_LEN,
        .head = CONVERT_EXPN(-10, GS_FALSE),
        .cells = { 20, 87, 67, 56, 98, 78, 68, 9, 89, 79, 21, 00, 90, 32, 12, 01, 43, 23, 12, 54, 34, 23, 65, 45, 34 }
    },
    /* 1/13! =
     * 0.00000000016059043836821614599392377170154947932725710503488281266059043836821614599392377
     * 170154947932725710503488281266
     */
    [_I(13)] = {
        .len = DEC2_MAX_LEN,
        .head = CONVERT_EXPN(-10, GS_FALSE),
        .cells = { 1, 60, 59, 04, 38, 36, 82, 16, 14, 59, 93, 92, 37, 71, 70, 15, 49, 47, 93, 27, 25, 71, 05, 03, 49 }
    },
    /* 1/14! =
     * 0.0000000000114707455977297247138516979786821056662326503596344866186136027405868675709945551215
     * 3924852337550750249162947575645988344401042813741226439639138
     */
    [_I(14)] = {
        .len = DEC2_MAX_LEN,
        .head = CONVERT_EXPN(-12, GS_FALSE),
        .cells = { 11, 47, 07, 45, 59, 77, 29, 72, 47, 13, 85, 16, 97, 97, 86, 82, 10, 56, 66, 23, 26, 50, 35, 96, 34 }
    },
    /* 1/15! =
     * 0.0000000000007647163731819816475901131985788070444155100239756324412409068493724578380663036
     * 74769283234891700500166108631717
     */
    [_I(15)] = {
        .len = DEC2_MAX_LEN,
        .head = CONVERT_EXPN(-14, GS_FALSE),
        .cells = { 76, 47, 16, 37, 31, 81, 98, 16, 47, 59, 01, 13, 19, 85, 78, 80, 70, 44, 41, 55, 10, 02, 39, 75, 63 }
    },
    /* 1/16! =
     * 0.0000000000000477947733238738529743820749111754402759693764984770275775566780857786148791439
     * 79673080202180731281260381789482318582847683
     */
    [_I(16)] = {
        .len = DEC2_MAX_LEN,
        .head = CONVERT_EXPN(-14, GS_FALSE),
        .cells = { 4, 77, 94, 77, 33, 23, 87, 38, 52, 97, 43, 82, 07, 49, 11, 17, 54, 40, 27, 59, 69, 37, 64, 98, 48 }
    },
    /* 1/17! =
     * 0.00000000000000281145725434552076319894558301032001623349273520453103397392224033991852230
     * 258703959295306945478125061069
     */
    [_I(17)] = {
        .len = DEC2_MAX_LEN,
        .head = CONVERT_EXPN(-16, GS_FALSE),
        .cells = { 28, 11, 45, 72, 54, 34, 55, 20, 76, 31, 98, 94, 55, 83, 01, 03, 20, 01, 62, 33, 49, 27, 35, 20, 45 }
    },
    /* 1/18! =
     * 0.00000000000000015619206968586226462216364350057333423519404084469616855410679112999547346
     * 125483553294183719193229170059408327555092
     */
    [_I(18)] = {
        .len = DEC2_MAX_LEN,
        .head = CONVERT_EXPN(-16, GS_FALSE),
        .cells = { 1, 56, 19, 20, 69, 68, 58, 62, 26, 46, 22, 16, 36, 43, 50, 05, 73, 33, 42, 35, 19, 40, 40, 84, 47 }
    },
    /* 1/19! =
     * 0.00000000000000000822063524662432971695598123687228074922073899182611413442667321736818281375
     * 025450173378090483854166845232
     */
    [_I(19)] = {
        .len = DEC2_MAX_LEN,
        .head = CONVERT_EXPN(-18, GS_FALSE),
        .cells = { 8, 22, 06, 35, 24, 66, 24, 32, 97, 16, 95, 59, 81, 23, 68, 72, 28, 07, 49, 22, 07, 38, 99, 18, 26 }
    },
    /* 1/20! =
     * 0.0000000000000000004110317623312164858477990618436140374610369495913057067213336608684091406875
     * 1272508668904524192708342261600861987085352324885435075580
     */
    [_I(20)] = {
        .len = DEC2_MAX_LEN,
        .head = CONVERT_EXPN(-20, GS_FALSE),
        .cells = { 41, 10, 31, 76, 23, 31, 21, 64, 85, 84, 77, 99, 06, 18, 43, 61, 40, 37, 46, 10, 36, 94, 95, 91, 31 }
    },
    /* 1/21! =
     * 0.000000000000000000019572941063391261230847574373505430355287473790062176510539698136590911461
     * 31012976603281167818700397250552421999385016777375496908360952830809216
     */
    [_I(21)] = {
        .len = DEC2_MAX_LEN,
        .head = CONVERT_EXPN(-20, GS_FALSE),
        .cells = { 1, 95, 72, 94, 10, 63, 39, 12, 61, 23, 8, 47, 57, 43, 73, 50, 54, 30, 35, 52, 87, 47, 37, 90, 06 }
        },
    /* 1/22! =
     * 0.00000000000000000000088967913924505732867488974425024683433124880863918984138816809711776870278
     * 68240802742187126448638169320692827269931894
     */
    [_I(22)] = {
        .len = DEC2_MAX_LEN,
        .head = CONVERT_EXPN(-22, GS_FALSE),
        .cells = { 8, 89, 67, 91, 39, 24, 50, 57, 32, 86, 74, 88, 97, 44, 25, 02, 46, 83, 43, 31, 24, 88, 8, 63, 92 }
        },
    /* 1/23! =
     * 0.0000000000000000000000386817017063068403771691193152281232317934264625734713647029607442508131646
     * 445252293138570715158181274812731620431821497505038914695840480397078275699598837
     */
    [_I(23)] = {
        .len = DEC2_MAX_LEN,
        .head = CONVERT_EXPN(-24, GS_FALSE),
        .cells = { 38, 68, 17, 01, 70, 63, 06, 84, 03, 77, 16, 91, 19, 31, 52, 28, 12, 32, 31, 79, 34, 26, 46, 25, 73 }
    },
    /* 1/24! =
     * 0.0000000000000000000000016117375710961183490487133048011718013247261026072279735292900310104505485
     * 268552178880773779798257553117197150851
     */
    [_I(24)] = {
        .len = DEC2_MAX_LEN,
        .head = CONVERT_EXPN(-24, GS_FALSE),
        .cells = { 1, 61, 17, 37, 57, 10, 96, 11, 83, 49, 04, 87, 13, 30, 48, 01, 17, 18, 01, 32, 47, 26, 10, 26, 07 }
    },
    /* 1/25! =
     * 0.0000000000000000000000000644695028438447339619485321920468720529890441042891189411716012404180219
     * 410742087155230951191930302124687886034053035829175064857826400800661797126165998
     */
    [_I(25)] = {
        .len = DEC2_MAX_LEN,
        .head = CONVERT_EXPN(-26, GS_FALSE),
        .cells = { 6, 44, 69, 50, 28, 43, 84, 47, 33, 96, 19, 48, 53, 21, 92, 04, 68, 72, 05, 29, 89, 4, 41, 4, 29 }
    },
    /* 1/26! =
     * 0.00000000000000000000000000247959626322479746007494354584795661742265554247265842081429235540069315
     * 15797772582893498122766550081718764847463578301
     */
    [_I(26)] = {
        .len = DEC2_MAX_LEN,
        .head = CONVERT_EXPN(-28, GS_FALSE),
        .cells = { 24, 79, 59, 62, 63, 22, 47, 97, 46, 00, 74, 94, 35, 45, 84, 79, 56, 61, 74, 22, 65, 55, 42, 47, 26 }
    },
    /* 1/27! =
     * 0.00000000000000000000000000009183689863795546148425716836473913397861687194343179336349230945928493
     * 153999175030701295601024648178414357350912436407823006621906358985764413064475299
     */
    [_I(27)] = {
        .len = DEC2_MAX_LEN,
        .head = CONVERT_EXPN(-30, GS_FALSE),
        .cells = { 91, 83, 68, 98, 63, 79, 55, 46, 14, 84, 25, 71, 68, 36, 47, 39, 13, 39, 78, 61, 68, 71, 94, 34, 31 }
    },
    /* 1/28! =
     * 0.00000000000000000000000000000327988923706983791015204172731211192780774542655113547726758248068874
     * 7554999705368107605571794517206576556196754441574222502364966556780630
     */
    [_I(28)] = {
        .len = DEC2_MAX_LEN,
        .head = CONVERT_EXPN(-30, GS_FALSE),
        .cells = { 3, 27, 98, 89, 23, 70, 69, 83, 79, 10, 15, 20, 41, 72, 73, 12, 11, 19, 27, 80, 77, 45, 42, 42, 66 }
    },
    /* 1/29! =
     * 0.0000000000000000000000000000001130996288644771693155876457693831699244050147086598440437097407134
     * 0508810343811614164157144119024850263986885360143359387939189539850967690163872506526007013143054544564
     */
    [_I(29)] = {
        .len = DEC2_MAX_LEN,
        .head = CONVERT_EXPN(-32, GS_FALSE),
        .cells = { 11, 30, 99, 62, 88, 64, 47, 71, 69, 31, 55, 87, 64, 57, 69, 38, 31, 69, 92, 44, 05, 01, 47, 86, 50 }
    },
    /* 1/30! =
     * 0.000000000000000000000000000000003769987628815905643852921525646105664146833823621994801456991357113
     * 502936781270538054719048039674950087995628453381119795979729846616989230
     */
    [_I(30)] = {
        .len = DEC2_MAX_LEN,
        .head = CONVERT_EXPN(-34, GS_FALSE),
        .cells = { 37, 69, 98, 76, 28, 81, 59, 05, 64, 38, 52, 92, 15, 25, 64, 61, 05, 66, 41, 46, 83, 38, 23, 62, 20 }
    },
    /* 1/31! =
     * 0.000000000000000000000000000000000121612504155351794962997468569229214972478510439419187143773914745
     * 59686892842808187273287251740886935767727833720584257406386225311667707193724594093
     */
    [_I(31)] = {
        .len = DEC2_MAX_LEN,
        .head = CONVERT_EXPN(-34, GS_FALSE),
        .cells = { 1, 21, 61, 25, 04, 15, 53, 51, 79, 49, 62, 99, 74, 68, 56, 92, 29, 21, 49, 72, 47, 85, 10, 43, 94 }
    },
    /* 1/32! =
     * 0.00000000000000000000000000000000000380039075485474359259367089278841296788995345123184959824293483
     * 57999021540133775585229022661690271674274149480376825804394956954
     */
    [_I(32)] = {
        .len = DEC2_MAX_LEN,
        .head = CONVERT_EXPN(-36, GS_FALSE),
        .cells = { 3, 80, 03, 90, 75, 48, 54, 74, 35, 92, 59, 36, 70, 89, 27, 88, 41, 29, 67, 88, 99, 53, 45, 12, 32 }
    },
    /* 1/33! =
     * 0.000000000000000000000000000000000000115163356207719502805868814932982211148180407613086351461907
     * 11623636067133373871389463340200512203537658833175871765395271199076999685328781936168648710906456849803
     */
    [_I(33)] = {
        .len = DEC2_MAX_LEN,
        .head = CONVERT_EXPN(-38, GS_FALSE),
        .cells = { 11, 51, 63, 35, 62, 07, 71, 95, 02, 80, 58, 68, 81, 49, 32, 98, 22, 11, 14, 81, 80, 40, 76, 13, 9 }
    },
    /* 1/34! =
     * 0.00000000000000000000000000000000000000338715753552116184723143573332300621024060022391430445476
     * 19740069517844509923151145480412354447657463702450517269898221385879638234368614064518143084443842520
     */
    [_I(34)] = {
        .len = DEC2_MAX_LEN,
        .head = CONVERT_EXPN(-40, GS_FALSE),
        .cells = { 33, 87, 15, 75, 35, 52, 11, 61, 84, 72, 31, 43, 57, 33, 32, 30, 06, 21, 02, 40, 60, 02, 23, 91, 43 }
    },
    /* 1/35! =
     * 0.000000000000000000000000000000000000000096775929586318909920898163809228748864017149254694412993
     * 19925734147955574263757470137260672699330703914985862077113777538822753781248175447
     */
    [_I(35)] = {
        .len = DEC2_MAX_LEN,
        .head = CONVERT_EXPN(-42, GS_FALSE),
        .cells = { 96, 77, 59, 29, 58, 63, 18, 90, 99, 20, 89, 81, 63, 80, 92, 28, 74, 88, 64, 01, 71, 49, 25, 46, 94 }
    },
    /* 1/36! =
     * 0.0000000000000000000000000000000000000000026882202662866363866916156613674652462226985904081781
     * 38699979370596654326184377075038127964638702973309718295021420493760784098272568937624168106594
     */
    [_I(36)] = {
        .len = DEC2_MAX_LEN,
        .head = CONVERT_EXPN(-42, GS_FALSE),
        .cells = { 2, 68, 82, 20, 26, 62, 86, 63, 63, 86, 69, 16, 15, 66, 13, 67, 46, 52, 46, 22, 26, 98, 59, 04, 82 }
    },
    /* 1/37! =
     * 0.0000000000000000000000000000000000000000000726546017915307131538274503072287904384513132542750
     * 848297291721782879547617399209469764314767217019813437377032816349665
     */
    [_I(37)] = {
        .len = DEC2_MAX_LEN,
        .head = CONVERT_EXPN(-44, GS_FALSE),
        .cells = { 7, 26, 54, 60, 17, 91, 53, 07, 13, 15, 38, 27, 45, 03, 07, 22, 87, 90, 43, 84, 51, 31, 32, 54, 26 }
    }
};

static inline bool32 cm_dec2_taylor_break(const dec2_t *total, const dec2_t *delta, int32 prec)
{
    if (DECIMAL2_IS_ZERO(delta)) {
        return GS_TRUE;
    }
    int32 total_expn = GET_100_EXPN(total);
    int32 delta_expn = GET_100_EXPN(delta);
    if (total_expn + (((total)->cells[0] >= 10) ? 1 : 0) >= (int32)SEXP_2_D2EXP(prec) + delta_expn) {
        return GS_TRUE;
    }
    return GS_FALSE;
}

static inline void cm_dec2_left_shift(const dec2_t *dec, uint32 offset, dec2_t *rs)
{
    uint32 ri, di;

    for (ri = 0, di = offset; di < GET_CELLS_SIZE(dec); ++ri, ++di) {
        rs->cells[ri] = dec->cells[di];
    }
    rs->len = (uint8)((uint32)dec->len - offset);
    if (SECUREC_UNLIKELY((int32)GET_100_EXPN(dec) - (int32)offset < DEC2_EXPN_LOW_HALF)) { // offset > 0
        cm_zero_dec2(rs);
        return;
    }
    rs->head = CONVERT_EXPN2(GET_100_EXPN(dec) - offset, IS_DEC_NEG(dec));
}

/**
 * Right shift decimal cells. The leading cells are filled with zero.
 * @note The following conditions should be guaranteed by caller
 * + offset > 0 and offset < DEC2_CELL_SIZE
 * + dec->len > 0
 */
static status_t cm_dec2_right_shift(const dec2_t *dec, int32 offset, dec2_t *rs)
{
    /* di is cell index, should equal len - 2 */
    int32 di = dec->len - 2;
    int32 ri = di + offset;
    /*
    ex 1.02 * 100^10 left shift to 1.02 * 100^30
    len expn   cells
    3   0xcb   01 02
    22  0xdf   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01
    to make sure ri < DEC2_CELL_SIZE - 1, must ignore the ri - (DEC2_CELL_SIZE - 1) digits
    */
    if (ri >= (DEC2_CELL_SIZE - 1)) {
        di -= (ri - (DEC2_CELL_SIZE - 1));
        ri = (DEC2_CELL_SIZE - 1);
    }

    rs->len = (uint8)(ri + 2); // ncells + 1
    if (SECUREC_UNLIKELY((int32)GET_100_EXPN(dec) + (int32)offset) > DEC2_EXPN_UPPER_HALF) { // offset > 0
        GS_THROW_ERROR(ERR_NUM_OVERFLOW);
        return GS_ERROR;
    }
    rs->head = CONVERT_EXPN2(GET_100_EXPN(dec) + offset, IS_DEC_NEG(dec));

    while (di >= 0) {
        rs->cells[ri] = dec->cells[di];
        ri--;
        di--;
    }

    while (ri >= 0) {
        rs->cells[ri] = 0;
        ri--;
    }
    return GS_SUCCESS;
}

static inline void cm_dec2_rebuild_cells(dec2_t *rs, uint8 cell0)
{
    if (GET_CELLS_SIZE(rs) == DEC2_CELL_SIZE) {
        rs->len--;
    }
    errno_t err = memmove_s(rs->cells + sizeof(uint8), (DEC2_CELL_SIZE - 1) * sizeof(uint8), rs->cells,
                            GET_CELLS_SIZE(rs) * sizeof(uint8));
    MEMS_RETVOID_IFERR(err);
    rs->cells[0] = cell0;
    rs->len++;
    return;
}

static status_t cm_dec2_rebuild(dec2_t *rs, uint8 cell0)
{
    int32 rs_expn = GET_100_EXPN(rs);
    rs_expn += 1;
    if (rs_expn > DEC2_EXPN_UPPER_HALF) {
        GS_THROW_ERROR(ERR_NUM_OVERFLOW);
        return GS_ERROR;
    } else if (rs_expn < DEC2_EXPN_LOW_HALF) {
        cm_zero_dec2(rs);
        return GS_SUCCESS;
    }
    rs->head = CONVERT_EXPN2(rs_expn, IS_DEC_NEG(rs));
    cm_dec2_rebuild_cells(rs, cell0);
    return GS_SUCCESS;
}

/**
 * Quickly find the precision of a cells
 * @note  (1) The cell u0 should be specially treated;
 *        (2) The tailing zeros will not be counted. If all cell except u0 are
 *        zeros, then the precision of u0 is re-counted by ignoring tailing zeros
 *        e.g. | u0 = 1000 | u1 = 0 | u2 = 0 |..., the precision 1 will be
 *        returned.
 */
int32 cm_dec2_calc_prec(const dec2_t *dec)
{
    int32 i;
    int32 prec = 0;

    if (GET_CELLS_SIZE(dec) == 0) {
        return 0;
    }

    /* Step 1: Find the precision of remaining cells starting from backend */
    for (i = GET_CELLS_SIZE(dec) - 1; i > 0; --i) {
        if (dec->cells[i] > 0) {  // found the last non-zero cell (dec->cells[i]>0)
            // count digits in this cell by ignoring right tailing zeros
            prec = (i * DEC2_CELL_DIGIT - GET_ZEROS_TAIL_CELL(dec->cells[i]));
            break;
        }
    }

    /* Step 1: Count the precision of u0 */
    if (i == 0) {  // if u1, u2, ... are zeros, then the precision of u0 should remove tailing zeros
        if (dec->cells[0] < 10) {
            prec = 1;
        } else {
            prec = DEC2_CELL_DIGIT - GET_ZEROS_TAIL_CELL(dec->cells[0]);
        }
    } else {
        prec += (int32)GET_DIGITS_HEAD_CELL(dec->cells[0]);
    }

    return prec;
}

/*
 * Truncate the tail of a decimal so that its precision is no more than prec
 * It must be that prec > 0
 */
status_t cm_dec2_finalise(dec2_t *dec, uint32 prec)
{
    uint32 dpos;  // position of truncating in decimal
    uint32 cpos;  // the position of truncating in decimal->cells
    uint32 npos;  // the position of truncating in decimal->cells[x]
    uint32 carry;
    int32 i;
    int32 sci_exp = DEC2_GET_SEXP(dec);
    // underflow check
    if (DECIMAL2_IS_ZERO(dec) || sci_exp < DEC2_EXPN_LOW) {
        cm_zero_dec2(dec);
        return GS_SUCCESS;
    }
    DEC2_OVERFLOW_CHECK_BY_SCIEXP(sci_exp);

    GS_RETSUC_IFTRUE(GET_CELLS_SIZE(dec) <= (prec / DEC2_CELL_DIGIT));

    GS_RETVALUE_IFTRUE(((uint32)cm_dec2_calc_prec(dec) <= prec), GS_SUCCESS);

    dpos = (uint32)DEC2_POS_N_BY_PREC0(prec, GET_DIGITS_HEAD_CELL(dec->cells[0]));
    cpos = dpos / (uint32)DEC2_CELL_DIGIT;
    npos = dpos % (uint32)DEC2_CELL_DIGIT;
    carry = g_5ten_powers[DEC2_CELL_DIGIT - npos];

    dec->len = cpos + 2; // ncells = cpos + 1
    for (i = (int32)cpos; i >= 0; --i) {
        dec->cells[i] += carry;
        carry = (dec->cells[i] >= DEC2_CELL_MASK);
        if (carry == 0) {
            break;
        }
        dec->cells[i] -= DEC2_CELL_MASK;
    }

    // truncate tailing digits to zeros
    dec->cells[cpos] /= g_1ten_powers[DEC2_CELL_DIGIT - npos];
    dec->cells[cpos] *= g_1ten_powers[DEC2_CELL_DIGIT - npos];

    if (carry > 0) {
        GS_RETURN_IFERR(cm_dec2_rebuild(dec, 1));
    }

    cm_dec2_trim_zeros(dec);
    return GS_SUCCESS;
}

/**
 * Product a cell array with the digit at pos (starting from left) is k
 */
static status_t cm_dec2_make_round(const dec2_t *dec, uint32 pos, dec2_t *dx, bool8 *is_carry)
{
    int32 i;
    uint32 carry, j;
    *is_carry = GS_FALSE;

    cm_dec2_copy(dx, dec);
    if (pos >= DEC2_MAX_ALLOWED_PREC) {
        return GS_SUCCESS;
    }

    i = (int32)(pos / DEC2_CELL_DIGIT);
    j = pos % DEC2_CELL_DIGIT;

    carry = (uint32)g_5ten_powers[DEC2_CELL_DIGIT - j];
    for (; i >= 0; i--) {
        dx->cells[i] += carry;
        carry = (dx->cells[i] >= DEC2_CELL_MASK);
        if (!carry) {
            return GS_SUCCESS;
        }
        dx->cells[i] -= DEC2_CELL_MASK;
    }

    if (carry > 0) {
        GS_RETURN_IFERR(cm_dec2_rebuild(dx, 1));
        *is_carry = GS_TRUE;
    }

    return GS_SUCCESS;
}

static inline void cm_dec2_abs(dec2_t *decl)
{
    if (!IS_DEC_NEG(decl)) {
        return;
    }

    int expn = GET_10_EXPN(decl);
    decl->head = CONVERT_EXPN(expn, GS_FALSE);
}

// whether abs(dec) is equal to 1
static inline bool32 cm_dec2_is_absolute_one(const dec2_t *dec)
{
    return (bool32)(dec->len == 2 && dec->cells[0] == 1 &&
                    (dec->head == CONVERT_EXPN(0, GS_FALSE) || dec->head == CONVERT_EXPN(0, GS_TRUE)));
}

//  whether dec is equal to 1
static inline bool32 cm_dec2_is_one(const dec2_t *dec)
{
    return (bool32)(dec->len == 2 && dec->cells[0] == 1 && (dec->head == CONVERT_EXPN(0, GS_FALSE)));
}

static status_t cm_add_aligned_dec2(const dec2_t *d1, const dec2_t *d2, dec2_t *rs)
{
    uint32 i;
    c2typ_t carry = 0;

    if (d1->len > d2->len) {
        SWAP(const dec2_t *, d1, d2);
    }

    i = GET_CELLS_SIZE(d2);
    while (i > GET_CELLS_SIZE(d1)) {
        i--;
        rs->cells[i] = d2->cells[i];
    }
    rs->head = d2->head;
    rs->len = d2->len;
    while (i-- > 0) {
        rs->cells[i] = d1->cells[i] + d2->cells[i] + carry;
        carry = (rs->cells[i] >= DEC2_CELL_MASK);  // carry can be either 1 or 0 in addition
        if (carry) {
            rs->cells[i] -= DEC2_CELL_MASK;
        }
    }

    if (carry) {
        GS_RETURN_IFERR(cm_dec2_rebuild(rs, 1));
    }

    cm_dec2_trim_zeros(rs);
    return GS_SUCCESS;
}

/** Subtraction of two cell array. large must greater than small.
    hit no borrow scenario
    large          small
    1.04050607     1.03
    01 04 05 06 07
    01 03 99
    hit borrow scenario
    1.04           1.03050607
    01 04
    01 03 05 06 07
    
    01 03 99 99 100
    01 03 05 06 07
*/
static void cm_sub_aligned_dec2(const dec2_t *large, const dec2_t *small, bool32 flip_sign, dec2_t *rs)
{
    /* if small has more cells than large, a borrow must be happened */
    int32 borrow = (small->len > large->len) ? 1 : 0;
    uint32 i;

    if ((bool32)borrow) {
        i = GET_CELLS_SIZE(small) - 1;
        rs->cells[i] = DEC2_CELL_MASK - small->cells[i];
        while (i > (uint32)GET_CELLS_SIZE(large)) {
            i--;
            rs->cells[i] = (DEC2_CELL_MASK - 1) - small->cells[i];
        }
        rs->len = small->len;
    } else {
        i = GET_CELLS_SIZE(large);
        while (i > GET_CELLS_SIZE(small)) {
            i--;
            rs->cells[i] = large->cells[i];
        }
        rs->len = large->len;
    }

    while (i-- > 0) {
        int32 tmp = (int32)(large->cells[i] - (small->cells[i] + borrow));
        borrow = (tmp < 0);  // borrow can be either 1 or 0
        if (borrow) {
            tmp += (int32)DEC2_CELL_MASK;
        }
        rs->cells[i] = (c2typ_t)tmp;
    }
    // result sign bit and expn is equal to large decl.
    // in scenario x1+x2, x1 sign is not same with x2, add convert to sub
    // abs(x1) > abs(x2) if x1 > 0, x2 must < 0; x1+x2 = x1 - abs(x2), result is > 0.
    //                   if x1 < 0, x2 must > 0; x1+x2 = x2 - abs(x1), result is < 0.
    // in scenario x1-x2, x1 sign is same with x2
    // abs(x1) > abs(x2) if x1 > 0, x2 must > 0; x1-x2 = x1 - x2, result is > 0.
    //                   if x1 < 0, x2 must < 0; x1-x2 = abs(x2) - abs(x1), result is < 0.
    // if flip_sign = GS_TRUE. RET = !(x1-x2)
    rs->head = flip_sign ? CONVERT_EXPN2(GET_100_EXPN(large), !IS_DEC_NEG(large)) : large->head;
    if (SECUREC_UNLIKELY(rs->cells[0] == 0)) {
        for (i = 1; i < GET_CELLS_SIZE(rs); i++) {
            if (rs->cells[i] > 0) {
                break;
            }
        }
        cm_dec2_left_shift(rs, i, rs);
    }

    cm_dec2_trim_zeros(rs);
}

#define DEC2_CELL_FMT "%02u"

static inline void cm_trim_cell_text(text_t *text)
{
    for (int i = (uint32)text->len - 1; i > 0; --i) {
        if (!CM_IS_ZERO(text->str[i])) {
            break;
        }
        --text->len;
    }
}

/**
 * Convert the significant digits of cells into text with a maximal len
 * @note  The tailing zeros are removed when outputting
 */
static void cm_cell2s_to_text(const cell2_t cells, uint32 ncell, text_buf_t *text, int32 max_len)
{
    uint32 i;
    int iret_snprintf;

    iret_snprintf = snprintf_s(text->str, text->max_size, DEC2_CELL_DIGIT, "%u", cells[0]);
    PRTS_RETVOID_IFERR(iret_snprintf);
    text->len = (uint32)iret_snprintf;
    for (i = 1; (text->len < (uint32)max_len) && (i < ncell); ++i) {
        iret_snprintf = snprintf_s(CM_GET_TAIL(text), text->max_size - text->len, DEC2_CELL_DIGIT, DEC2_CELL_FMT,
                                   (uint32)cells[i]);
        PRTS_RETVOID_IFERR(iret_snprintf);
        text->len += (uint32)iret_snprintf;
    }

    // truncate redundant digits
    if (text->len > (uint32)max_len) {
        text->len = (uint32)max_len;
    }

    // truncate tailing zeros
    cm_trim_cell_text(&text->value);
}

/**
 * Round a decimal to a text with the maximal length max_len
 * If the precision is greater than max_len, a rounding mode is used.
 * The rounding mode may cause a change on precision, e.g., the 8-precision
 * decimal 99999.999 rounds to 7-precision decimal is 100000.00, and then
 * its actual precision is 8. The function will return the change. If
 * no change occurs, zero is returned.
 * @note
 * Performance sensitivity.CM_ASSERT should be guaranteed by caller, i.g. 1.max_len > 0    2.dec->cells[0] > 0
 */
static status_t cm_dec2_round_to_text(const dec2_t *dec, int32 max_len, text_buf_t *text_out, int32 *round)
{
    dec2_t txtdec;
    uint8 prec_u0;
    int32 prec;
    bool8 is_carry;
    *round = 0;

    prec = cm_dec2_calc_prec(dec);
    if (prec <= max_len) {  // total prec under the max_len
        cm_cell2s_to_text(dec->cells, GET_CELLS_SIZE(dec), text_out, prec);
        return GS_SUCCESS;
    }

    /** if prec > max_len, the rounding mode is applied */
    prec_u0 = cm_count_u8digits(dec->cells[0]);
    // Rounding model begins by adding with {5[(prec - max_len) zeros]}
    // Obtain the pos of 5 for rounding, then prec is used to represent position
    prec = DEC2_POS_N_BY_PREC0(max_len, prec_u0);
    // add for rounding and check whether the carry happens, and capture the changes of the precision
    GS_RETURN_IFERR(cm_dec2_make_round(dec, (uint32)prec, &txtdec, &is_carry));
    if (is_carry) {
        // if carry happens, the change must exist
        cm_cell2s_to_text(txtdec.cells, GET_CELLS_SIZE(&txtdec), text_out, max_len);
        *round = 1;
    } else {
        cm_cell2s_to_text(txtdec.cells, GET_CELLS_SIZE(&txtdec), text_out, max_len);
        *round = (cm_count_u8digits(txtdec.cells[0]) > prec_u0) ? 1 : 0;
    }
    return GS_SUCCESS;
}

/*
 * Convert a cell text into a cell of big integer by specifying the
 * length digits in u0 (i.e., len_u0), and return the number of non-zero cells
 * Performance sensitivity.CM_ASSERT should be guaranteed by caller, i.g. cells[0] > 0
 */
static int32 cm_digitext_to_cell2s(dec2_t *dec, num_part_t *np)
{
    uint32 i, k;
    text_t cell_text;
    digitext_t *dtext = &np->digit_text;
    // make u0
    cell_text.str = dtext->str;
    cell_text.len = np->dot_offset;
    dec->cells[0] = (c2typ_t)cm_celltext2uint32(&cell_text);

    // make u1, u2, ..., uk
    k = 1;
    for (i = (uint32)np->dot_offset; k < DEC2_CELL_SIZE && i < dtext->len; k++) {
        cell_text.str = dtext->str + i;
        cell_text.len = (uint32)DEC2_EXPN_UNIT;
        dec->cells[k] = (c2typ_t)cm_celltext2uint32(&cell_text);
        i += DEC2_CELL_DIGIT;
    }

    // the tailing cells of significant cells may be zeros, for returning
    // accurate ncells, they should be ignored.
    while (dec->cells[k - 1] == 0) {
        --k;
    }

    return (int32)k;
}

/*
 -----------------------
| \     |       |       |
|  \expn| even  | odd   |
|dot \  |       |       |
|     \ |       |       |
 -----------------------
|even   | even  |  odd  |
 -----------------------
|odd    | odd   |  even |
-----------------------
left shift dot, the abs(value) is smaller, so expn should add
shift right dot, the abs(value) is bigger, so expn should subtract

*/
static inline void cm_adjust_expn(num_part_t *np)
{
    int32 sci_expn = np->sci_expn;
    bool32 is_odd = cm_is_odd(sci_expn);

    np->dot_offset = 1;
    if (is_odd) {
        np->dot_offset = 2;
        np->sci_expn -= 1;
        if (np->digit_text.len == 1) {
            CM_TEXT_APPEND(&np->digit_text, '0');
        }
    }
}

/**
 * Convert a digit text with a scientific exponent into a decimal
 * The digit text may be changed when adjust the scale of decimal to be
 * an integral multiple of DEC2_CELL_DIGIT, by appending zeros.
 * @return the precision of u0
 * @note
 * Performance sensitivity.CM_ASSERT should be guaranteed by caller,
 * i.g. dtext->len > 0 && dtext->len <= (uint32)DEC2_MAX_ALLOWED_PREC
 */
static void cm_digitext_to_dec2(dec2_t *dec, num_part_t *np)
{
    int32 delta;
    dec->len = 1;
    cm_adjust_expn(np);

    CM_ASSERT(np->digit_text.len >= (uint32)np->dot_offset);

    delta = np->digit_text.len - np->dot_offset;
    delta %= DEC2_EXPN_UNIT;
    if (delta == 1) {
        CM_TEXT_APPEND(&np->digit_text, '0');
    }

    CM_NULL_TERM(&np->digit_text);
    dec->head = CONVERT_EXPN(np->sci_expn, np->is_neg);
    dec->len += cm_digitext_to_cell2s(dec, np);
    return;
}

/**
 * Output a decimal type in scientific format, e.g., 2.34566E-20
 */
static status_t cm_dec2_to_sci_text(text_t *text, const dec2_t *dec, int32 max_len)
{
    int32 i;
    char obuff[GS_NUMBER_BUFFER_SIZE]; /** output buff */
    text_buf_t cell_text;
    CM_INIT_TEXTBUF(&cell_text, GS_NUMBER_BUFFER_SIZE, obuff);

    char sci_buff[DEC_EXPN_BUFF_SZ];
    int32 sci_exp; /** The scientific scale of the dec */
    int32 placer;
    int iret_snprintf;
    int32 round;

    sci_exp = DEC2_GET_SEXP(dec);
    // digits of sci_exp + sign(dec) + dot + E + sign(expn)
    placer = (int32)IS_DEC_NEG(dec) + 3;
    placer += (int32)cm_count_u8digits((uint8)abs(sci_exp));
    if (max_len <= placer) {
        return GS_ERROR;
    }

    /* The round of a decimal may increase the precision by 1 */
    GS_RETURN_IFERR(cm_dec2_round_to_text(dec, max_len - placer, &cell_text, &round));
    if (round > 0) {
        ++sci_exp;
    }
    // compute the exponent placer
    iret_snprintf = snprintf_s(sci_buff, DEC_EXPN_BUFF_SZ, DEC_EXPN_BUFF_SZ - 1, "E%+d", sci_exp);
    PRTS_RETURN_IFERR(iret_snprintf);
    placer = iret_snprintf;

    // Step 1. output sign
    text->len = 0;
    if (IS_DEC_NEG(dec)) {
        CM_TEXT_APPEND(text, '-');
    }

    CM_TEXT_APPEND(text, cell_text.str[0]);
    CM_TEXT_APPEND(text, '.');
    for (i = 1; (int32)text->len < max_len - placer; ++i) {
        if (i < (int32)cell_text.len) {
            CM_TEXT_APPEND(text, cell_text.str[i]);
        } else {
            CM_TEXT_APPEND(text, '0');
        }
    }

    errno_t ret = memcpy_sp(CM_GET_TAIL(text), max_len - text->len, sci_buff, placer);
    MEMS_RETURN_IFERR(ret);
    text->len += placer;
    return GS_SUCCESS;
}

static status_t cm_dec2_text_dot_inside(text_t *text, const dec2_t *dec, text_buf_t *cell_text, int32 max_len,
    int32 *dot)
{
    int32 round;
    // round mode may product carry, and thus may affect the dot_pos
    GS_RETURN_IFERR(cm_dec2_round_to_text(dec, max_len - text->len - 1, cell_text, &round));  // subtract sign & dot
    *dot += round;
    int32 dot_pos = *dot;
    if ((int32)cell_text->len <= dot_pos) {
        cm_concat_text(text, max_len, &cell_text->value);
        cm_text_appendc(text, dot_pos - (int32)cell_text->len, '0');
    } else {
        GS_RETURN_IFERR(cm_concat_ntext(text, &cell_text->value, dot_pos));
        CM_TEXT_APPEND(text, '.');
        // copy remaining digits
        cell_text->str += (uint32)dot_pos;
        cell_text->len -= (uint32)dot_pos;
        cm_concat_text(text, max_len, &cell_text->value);
    }
    return GS_SUCCESS;
}

/**
 * @note
 * Performance sensitivity.CM_ASSERT should be guaranteed by caller, i.g. dot_pos <= max_len - dec->sign
 */
static status_t cm_dec2_to_plain_text(text_t *text, const dec2_t *dec, int32 max_len, int32 sci_exp, int32 prec)
{
    int32 dot_pos;
    char obuff[GS_NUMBER_BUFFER_SIZE]; /** output buff */
    text_buf_t cell_text;
    CM_INIT_TEXTBUF(&cell_text, GS_NUMBER_BUFFER_SIZE, obuff);
    int32 round;

    // clear text & output sign
    text->len = 0;
    if (IS_DEC_NEG(dec)) {
        CM_TEXT_APPEND(text, '-');
    }
    // move the dot to least significant digit
    dot_pos = sci_exp + 1;

    if (prec <= dot_pos) {
        // only integers
        GS_RETURN_IFERR(cm_dec2_round_to_text(dec, max_len - text->len, &cell_text, &round));  // subtract sign
        cm_concat_text(text, max_len, &cell_text.value);
        if (max_len - (int32)text->len < dot_pos - prec) {
            return GS_ERROR;
        }
        cm_text_appendc(text, dot_pos - prec, '0');
        return GS_SUCCESS;
    }

    /* get the position of dot w.r.t. the first significant digit */
    if (dot_pos == max_len - text->len) {
        /* handle the border case with dot at the max_len position,
         * then the dot is not outputted. Suppose max_len = 10,
         *  (1). 1234567890.222 --> 1234567890 is outputted
         * If round mode products carry, e.g. the rounded value of
         * 9999999999.9 is 10000000000, whose length is 11 and greater than
         * max_len, then the scientific format is used to print the decimal
         */
        GS_RETURN_IFERR(cm_dec2_round_to_text(dec, dot_pos, &cell_text, &round));
        if (round > 0) {
            CM_TEXT_CLEAR(text);
            return cm_dec2_to_sci_text(text, dec, max_len);
        }
        cm_concat_text(text, max_len, &cell_text.value);
        cm_text_appendc(text, max_len - (int32)text->len, '0');
    } else if (dot_pos == max_len - text->len - 1) {
        /* handle the border case with dot at the max_len - 1 position,
         * then only max_len-1 is print but the dot is emitted. Assume
         * max_len = 10, the following cases output:
         *  (1). 123456789.2345 ==> 123456789  (.2345 is abandoned)
         *  (2). 987654321.56   ==> 987654322  (.56 is rounded to 1)
         * If a carry happens, e.g., 999999999.6 ==> 1000000000, max_len
         * number of digits will be printed.
         * */
        GS_RETURN_IFERR(cm_dec2_round_to_text(dec, dot_pos, &cell_text, &round));
        cm_concat_text(text, max_len, &cell_text.value);
        cm_text_appendc(text, max_len + round - ((int32)text->len + 1), '0');
    } else if (dot_pos >= 0) { /* dot is inside of cell_text and may be output */
        GS_RETURN_IFERR(cm_dec2_text_dot_inside(text, dec, &cell_text, max_len, &dot_pos));
    } else {  // dot_pos < 0
        /* dot is in the most left & add |dot_pos| zeros between dot and cell_text
         * Thus, the maxi_len should consider sign, dot, and the adding zeros */
        GS_RETURN_IFERR(cm_dec2_round_to_text(dec, max_len - text->len - 1 + dot_pos, &cell_text, &round));
        dot_pos += round;
        CM_TEXT_APPEND(text, '.');
        cm_text_appendc(text, -dot_pos, '0');
        GS_RETURN_IFERR(cm_concat_ntext(text, &cell_text.value, max_len - (int32)text->len));
    }

    return GS_SUCCESS;
}

/**
 * Convert a decimal into a text with a given maximal precision
 * cm_dec2_to_text is not guaranteed end of \0, if need string, should use cm_dec2_to_str
 */
status_t cm_dec2_to_text(const dec2_t *dec, int32 max_len, text_t *text)
{
    int32 sci_exp; /** The scientific scale of the dec */
    int32 prec;
    int32 maxlen = max_len;

    CM_POINTER2(dec, text);
    maxlen = MIN(maxlen, (int32)(GS_NUMBER_BUFFER_SIZE - 1));

    if (DECIMAL2_IS_ZERO(dec)) {
        text->str[0] = '0';
        text->len = 1;
        return GS_SUCCESS;
    }

    // Compute the final scientific scale of the dec, i.e., format of d.xxxx , d > 0.
    // Each decimal has an unique scientific representation.
    sci_exp = DEC2_GET_SEXP(dec);
    // get the total precision of the decimal
    prec = cm_dec2_calc_prec(dec);
    // Scientific representation when the scale exceeds the maximal precision
    // or have many leading zeros and have many significant digits
    // When sci_exp < 0, the length for '.' should be considered
    if ((sci_exp < -6 && (-sci_exp + prec + (int32)IS_DEC_NEG(dec) > maxlen)) ||
        (sci_exp > 0 && (sci_exp + 1 + (int32)IS_DEC_NEG(dec) > maxlen))) {
        return cm_dec2_to_sci_text(text, dec, maxlen);
    }

    // output plain text
    return cm_dec2_to_plain_text(text, dec, maxlen, sci_exp, prec);
}

/**
 * Convert a decimal into C-string, and return the ac
 * max_len should be consided \0, max len should buffer size
 */
status_t cm_dec2_to_str(const dec2_t *dec, int max_len, char *str)
{
    text_t text;
    text.str = str;
    text.len = 0;

    GS_RETURN_IFERR(cm_dec2_to_text(dec, max_len - 1, &text));
    str[text.len] = '\0';
    return GS_SUCCESS;
}

status_t cm_str_to_dec2(const char *str, dec2_t *dec)
{
    text_t text;
    cm_str2text((char *)str, &text);
    return cm_text_to_dec2(&text, dec);
}

static status_t cm_do_numpart_round2(const num_part_t *np, dec2_t *dec)
{
    c2typ_t carry = g_1ten_powers[GET_DIGITS_HEAD_CELL(dec->cells[0]) % DEC2_CELL_DIGIT];
    int32 i = GET_CELLS_SIZE(dec);
    while (--i >= 0) {
        dec->cells[i] += carry;
        carry = dec->cells[i] >= DEC2_CELL_MASK;
        if (!carry) {
            return GS_SUCCESS;
        }
        dec->cells[i] = dec->cells[i] - DEC2_CELL_MASK;
    }

    if (carry > 0) {
        GS_RETURN_IFERR(cm_dec2_rebuild(dec, 1));
    }
    return GS_SUCCESS;
}

static num_errno_t cm_numpart_to_dec2(num_part_t *np, dec2_t *dec)
{
    if (NUMPART_IS_ZERO(np)) {
        cm_zero_dec2(dec);
        return NERR_SUCCESS;
    }

    // Step 3.2. check overflow by comparing scientific scale and DEC2_EXPN_UPPER
    if (np->sci_expn > DEC2_EXPN_UPPER) {  // overflow return Error
        return NERR_OVERFLOW;
    } else if (np->sci_expn < DEC2_EXPN_LOW) {  // underflow return 0
        cm_zero_dec2(dec);
        return NERR_SUCCESS;
    }

    // Step 4: make the final decimal value
    dec->len = 0;
    dec->sign = !np->is_neg;
    cm_digitext_to_dec2(dec, np);

    if (np->do_round) {  // when round happens, the dec->cells should increase 1
        if (cm_do_numpart_round2(np, dec) != GS_SUCCESS) {
            return NERR_OVERFLOW;
        }
        cm_dec2_trim_zeros(dec);
    }

    return NERR_SUCCESS;
}

/**
 * Translates a text_t representation of a decimal into a decimal
 * @param
 * -- precision: records the precision of the decimal text. The initial value
 *               is -1, indicating no significant digit found. When a leading zero
 *               is found, the precision is set to 0, it means the merely
 *               significant digit is zero. precision > 0 represents the
 *               number of significant digits in the decimal text.
 */
status_t cm_text_to_dec2(const text_t *dec_text, dec2_t *dec)
{
    num_errno_t err_no;
    num_part_t np;
    np.excl_flag = NF_NONE;

    err_no = cm_split_num_text(dec_text, &np);
    if (err_no != NERR_SUCCESS) {
        GS_THROW_ERROR(ERR_INVALID_NUMBER, cm_get_num_errinfo(err_no));
        return GS_ERROR;
    }

    err_no = cm_numpart_to_dec2(&np, dec);
    if (err_no != NERR_SUCCESS) {
        GS_THROW_ERROR(ERR_INVALID_NUMBER, cm_get_num_errinfo(err_no));
        return GS_ERROR;
    }

    return GS_SUCCESS;
}


static int8 cm_uint_to_dec2_expn(uint64 u64)
{
    if (u64 >= DEC2_POW5_MASK) {
        if (u64 >= DEC2_POW8_MASK) {
            return (u64 >= DEC2_POW9_MASK) ? 9 : 8;
        }
        if (u64 >= DEC2_POW6_MASK) {
            return (u64 >= DEC2_POW7_MASK) ? 7 : 6;
        }
        return 5;
    }

    if (u64 >= DEC2_POW3_MASK) {
        return (u64 >= DEC2_POW4_MASK) ? 4 : 3;
    }
    if (u64 >= DEC2_CELL_MASK) {
        return (u64 >= DEC2_POW2_MASK) ? 2 : 1;
    }
    return 0;
}

/**
 * Fill a non-zero uint32 into decimal
 * @note u64 > 0
 */
#define FILL_CELL(v, dec, pow, idx)                   \
    do {                                              \
        (dec)->len++;                                 \
        (dec)->cells[(idx)++] = (uint8)((v) / (pow)); \
        (v) = (v) % (pow);                            \
    } while (0)

/*
 * Fill a non-zero uint64(u64 > 0) into decimal
 */
static void cm_fill_uint64_to_dec2(uint64 u64, dec2_t *dec)
{
    dec->len = 1;
    uint8 idx = 0;
    int8 expn = cm_uint_to_dec2_expn(u64);
    dec->head = CONVERT_EXPN2(expn, GS_FALSE);
    switch (expn) {
        case 9:
            FILL_CELL(u64, dec, DEC2_POW9_MASK, idx);
            /* fall-through */
        case 8:
            FILL_CELL(u64, dec, DEC2_POW8_MASK, idx);
            /* fall-through */
        case 7:
            FILL_CELL(u64, dec, DEC2_POW7_MASK, idx);
            /* fall-through */
        case 6:
            FILL_CELL(u64, dec, DEC2_POW6_MASK, idx);
            /* fall-through */
        case 5:
            FILL_CELL(u64, dec, DEC2_POW5_MASK, idx);
            /* fall-through */
        case 4:
            FILL_CELL(u64, dec, DEC2_POW4_MASK, idx);
            /* fall-through */
        case 3:
            FILL_CELL(u64, dec, DEC2_POW3_MASK, idx);
            /* fall-through */
        case 2:
            FILL_CELL(u64, dec, DEC2_POW2_MASK, idx);
            /* fall-through */
        case 1:
            FILL_CELL(u64, dec, DEC2_CELL_MASK, idx);
            /* fall-through */
        case 0:
            dec->len++;
            dec->cells[idx] = (c2typ_t)u64;
            break;
        default:
            CM_NEVER;
            break;
    }
    cm_dec2_trim_zeros(dec);
}

static inline void cm_dec2_negate(dec2_t *dec)
{
    if (DECIMAL2_IS_ZERO(dec)) {
        return;
    } else {
        int32 sci_exp = GET_100_EXPN(dec);
        dec->head = CONVERT_EXPN2(sci_exp, !IS_DEC_NEG(dec));
    }
}

/**
 * Convert an integer32 into a decimal
 */
void cm_int32_to_dec2(int32 i_32, dec2_t *dec)
{
    int32 i32 = i_32;
    bool32 is_neg = GS_FALSE;

    if (i32 < 0) {
        is_neg = GS_TRUE;
        if (i32 == GS_MIN_INT32) {
            cm_dec2_copy(dec, &DEC2_MIN_INT32);
            return;
        }
        i32 = -i32;
    } else if (i32 == 0) {
        cm_zero_dec2(dec);
        return;
    }

    cm_fill_uint64_to_dec2((uint64)i32, dec);
    if (is_neg) {
        cm_dec2_negate(dec);
    }
}

void cm_uint32_to_dec2(uint32 i32, dec2_t *dec)
{
    if (i32 == 0) {
        cm_zero_dec2(dec);
        return;
    }

    cm_fill_uint64_to_dec2((uint64)i32, dec);
}

/** The buffer size to covert an int64 to dec->cells. It must be greater
** max_digits(int64) + DEC2_CELL_DIGIT + 1  than */
#define INT64_BUFF 32

/**
 * Convert an integer64 into a decimal
 */
void cm_int64_to_dec2(int64 i_64, dec2_t *dec)
{
    int64 i64 = i_64;
    bool32 is_neg = GS_FALSE;

    if (i64 < 0) {
        if (i64 == GS_MIN_INT64) {
            cm_dec2_copy(dec, &DEC2_MIN_INT64);
            return;
        }
        i64 = -i64;
        is_neg = GS_TRUE;
    } else if (i64 == 0) {
        cm_zero_dec2(dec);
        return;
    }

    cm_fill_uint64_to_dec2((uint64)i64, dec);
    if (is_neg) {
        cm_dec2_negate(dec);
    }
}

static const double g_pos_pow2[] = {
    1.0,     1.0e2,   1.0e4,   1.0e6,   1.0e8,   1.0e10,  1.0e12,  1.0e14,  1.0e16,  1.0e18,
    1.0e20,  1.0e22,  1.0e24,  1.0e26,  1.0e28,  1.0e30,  1.0e32,  1.0e34,  1.0e36,  1.0e38,
    1.0e40,  1.0e42,  1.0e44,  1.0e46,  1.0e48,  1.0e50,  1.0e52,  1.0e54,  1.0e56,  1.0e58,
    1.0e60,  1.0e62,  1.0e64,  1.0e66,  1.0e68,  1.0e70,  1.0e72,  1.0e74,  1.0e76,  1.0e78,
    1.0e80,  1.0e82,  1.0e84,  1.0e86,  1.0e88,  1.0e90,  1.0e92,  1.0e94,  1.0e96,  1.0e98,
    1.0e100, 1.0e102, 1.0e104, 1.0e106, 1.0e108, 1.0e110, 1.0e112, 1.0e114, 1.0e116, 1.0e118,
    1.0e120, 1.0e122, 1.0e124, 1.0e126, 1.0e128, 1.0e130,
};

/**
 * compute 10000^x, x should be between -40 and 40
 */
static inline double cm_pow2(int32 x)
{
    int32 y = abs(x);
    double r = (y < ARRAY_NUM(g_pos_pow2)) ? g_pos_pow2[y] : pow(10e2, y);
    if (x < 0) {
        r = 1.0 / r;
    }
    return r;
}

/**
 * Convert real value into a decimal. It is similar with the function cm_real_to_dec2.
 * This function may be more efficient than cm_real_to_dec2, but may lose precision.
 * It is suitable for an algorithm which needs an inexact initial value.
 */
static status_t cm_real_to_dec2_inexac(double real, dec2_t *dec)
{
    double r = real;
    if (SECUREC_UNLIKELY(!CM_DBL_IS_FINITE(r))) {
        GS_THROW_ERROR(ERR_INVALID_NUMBER, "");
        return GS_ERROR;
    }
    if (r == 0.0) {
        cm_zero_dec2(dec);
        return GS_SUCCESS;
    }
    uint8 index = 0;
    double int_r;
    int32 dexp;
    bool32 is_neg = (r < 0);
    if (is_neg) {
        r = -r;
    }

    // compute an approximate scientific exponent
    (void)frexp(r, &dexp);
    dexp = (int32)((double)dexp * (double)GS_LOG10_2);
    dexp &= 0xFFFFFFFE;
    if (dexp < DEC2_EXPN_LOW) {
        cm_zero_dec2(dec);
        return GS_SUCCESS;
    }
    DEC2_OVERFLOW_CHECK_BY_SCIEXP(dexp);
    // Set a decimal
    dec->head = CONVERT_EXPN(dexp, is_neg);

    r *= cm_pow2(-dexp / 2);
    // now, int_r is used as the integer part of r
    if (r >= 1.0) {
        r = modf(r, &int_r);
        dec->cells[index] = (c2typ_t)int_r;
        index++;
    } else {
        // only decimal part, dot should move right 2
        dec->head = CONVERT_EXPN(dexp - 2, is_neg);
    }
 
    while (index < DEC2_TO_REAL_MAX_CELLS) {
        if (r == 0) {
            break;
        }
        r = modf(r * (double)DEC2_CELL_MASK, &int_r);
        dec->cells[index++] = (c2typ_t)int_r;
    }
    dec->len = index + 1;
    cm_dec2_trim_zeros(dec);
    return GS_SUCCESS;
}

/**
 * Convert real value into a decimal type
 */
status_t cm_real_to_dec2(double real, dec2_t *dec)
{
    GS_RETURN_IFERR(cm_real_to_dec2_inexac(real, dec));
    // reserving at most GS_MAX_REAL_PREC precisions
    return cm_dec2_finalise(dec, GS_MAX_REAL_PREC);
}


/**
 * NOTE THAT: convert a signed integer into DOUBLE is faster than unsigned integer,
 * therefore, These codes use signed integer for conversation to DOUBLE as much as
 * possible. The following SWITCH..CASE is faster than the loop implementation.
 */
double cm_dec2_to_real(const dec2_t *dec)
{
    if (DECIMAL2_IS_ZERO(dec)) {
        return 0.0;
    }

    double dval;
    int32 pos = MIN(GET_CELLS_SIZE(dec), DEC2_TO_REAL_MAX_CELLS);
    uint64 u64 = 0;

    for (int i = pos; i > 0; i--) {
        u64 += dec->cells[i - 1] * (uint64)g_pos_pow2[pos - i];
    }

    int32 dexpn = GET_100_EXPN(dec);
    dexpn -= (pos - 1);

    /* the maximal expn of a decimal can not exceed 40 */
    dval = (double)u64;
    if (dexpn >= 0) {
        dval *= g_pos_pow2[dexpn];
    } else {
        dval /= g_pos_pow2[-dexpn];
    }
    return IS_DEC_NEG(dec) ? -dval : dval;
}

/**
 * The core algorithm for adding of two decimals, without truncating
 * the result.
 * @see cm_decimal_add for adding of two decimals with truncation
 */
status_t cm_dec2_add_op(const dec2_t *d1, const dec2_t *d2, dec2_t *rs)
{
    int32 offset;
    dec2_t calc_dec;
    bool32 is_same_sign;

    // Ensure the scales of two adding decimal to be even multiple of DEC2_CELL_DIGIT
    if (DECIMAL2_IS_ZERO(d2)) {
        goto DEC_ADD_ZERO;
    }

    if (DECIMAL2_IS_ZERO(d1)) {
        d1 = d2;
        goto DEC_ADD_ZERO;
    }

    // Obtain the exponent offset of two decimals
    offset = (int32)GET_100_EXPN(d1) - (int32)GET_100_EXPN(d2);  // exponent offset
    is_same_sign = (d1->sign == d2->sign);

    if (offset != 0) {
        if (offset < 0) {
            /* offset < 0 means d1 < d2, then swap d1 and d2 to grant d1 > d2 */
            offset = -offset;
            SWAP(const dec2_t *, d1, d2);
        }
        if (offset >= DEC2_MAX_EXP_OFFSET) {
            goto DEC_ADD_ZERO;
        }

        // left shift dot, confirm the d2 expn equal d1 expn
        GS_RETURN_IFERR(cm_dec2_right_shift(d2, offset, &calc_dec));
        d2 = &calc_dec;
    } else if (!is_same_sign) {  // if offset == 0, and d1, d2 have different signs
        int32 cmp = cm_dec2_cmp_cells(GET_PAYLOAD(d1), d1->len, GET_PAYLOAD(d2), d2->len);
        if (cmp == 0) {
            cm_zero_dec2(rs);
            return GS_SUCCESS;
        }
        if (cmp < 0) {
            SWAP(const dec2_t *, d1, d2);
        }
    }

    if (is_same_sign) {
        GS_RETURN_IFERR(cm_add_aligned_dec2(d1, d2, rs));
    } else {
        cm_sub_aligned_dec2(d1, d2, GS_FALSE, rs);
    }
    return GS_SUCCESS;

DEC_ADD_ZERO:
    cm_dec2_copy(rs, d1);
    return GS_SUCCESS;
}

/**
 * The core algorithm for subtracting of two decimals, without truncating
 * the result.
 * @see cm_decimal_sub for subtraction of two decimals with truncation
 */
status_t cm_dec2_sub_op(const dec2_t *d1, const dec2_t *d2, dec2_t *rs)
{
    dec2_t calc_dec;
    int32 offset;
    bool32 do_swap = GS_FALSE;
    bool32 is_same_sign;

    if (DECIMAL2_IS_ZERO(d2)) {
        goto DEC_SUB_ZERO;
    }

    if (DECIMAL2_IS_ZERO(d1)) {
        do_swap = GS_TRUE;
        d1 = d2;
        goto DEC_SUB_ZERO;
    }

    // Obtain the exponent offset of two decimals
    offset = (int32)GET_100_EXPN(d1) - (int32)GET_100_EXPN(d2);  // exponent offset
    is_same_sign = (d1->sign == d2->sign);

    if (offset != 0) {
        if (offset < 0) {
            offset = -offset;
            SWAP(const dec2_t *, d1, d2);
            do_swap = GS_TRUE;
        }

        if (offset >= DEC2_MAX_EXP_OFFSET) {
            goto DEC_SUB_ZERO;
        }

        GS_RETURN_IFERR(cm_dec2_right_shift(d2, offset, &calc_dec));
        d2 = &calc_dec;
    } else if (is_same_sign) {
        int32 cmp = cm_dec2_cmp_cells(GET_PAYLOAD(d1), d1->len, GET_PAYLOAD(d2), d2->len);
        if (cmp == 0) {
            cm_zero_dec2(rs);
            return GS_SUCCESS;
        }
        if (cmp < 0) {
            SWAP(const dec2_t *, d1, d2);
            do_swap = GS_TRUE;
        }
    }

    if (is_same_sign) {
        cm_sub_aligned_dec2(d1, d2, do_swap, rs);
    } else {
        /* if d1 and d2 have different signs, the result sign is the same with
         * the first operand. */
        uint8 sign = do_swap ? d2->sign : d1->sign;
        cm_add_aligned_dec2(d1, d2, rs);
        rs->head = CONVERT_EXPN2(GET_100_EXPN(rs), !sign);
    }
    return GS_SUCCESS;

DEC_SUB_ZERO:
    cm_dec2_copy(rs, d1);
    if (do_swap && !DECIMAL2_IS_ZERO(rs)) {
        cm_dec2_negate(rs);
    }
    return GS_SUCCESS;
}

/**
* The core algorithm for multiplying of two decimals, without truncating
* the result.
* @see cm_dec2_mul_op for multiplying of two decimals with truncation

 assume d1 has n1 cells, d2 has n2 cells, ingore carry, finally the result is (n1 + n2 - 1) cells.
    for example d1 is 4 cells, d2 is 3 cells, precision is max 6 cells
    a0 a1 a2 a3
    b0 b1 b2
    d1 * d2 = M^(e1+e2)* (a0 * M^0 + a1 * M^-1 + a2 * M^-2 + a3 * M^-3 ) * (b0 * M^0 + b1 * M^-1 + b2 * M^-2)
          0 = (a0 * b0) * M +
          1   (a0 * b1 + a1 * b0) * M^-1 +
          2   (a0 * b2 + a1 * b1 + a2 * b0) * M^-2 +
          3   (a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0) * M^-3 +
          4   (a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0) * M^-4 +
          5   (a0 * b5 + a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1 + a5 * b0) * M^-5
   --------------------------------------------------------------------------------------------
              (a0 * b6 + a1 * b5 + a2 * b4 + a3 * b3 + a4 * b2 + a5 * b1 + a6 * b0) * M^-6 = 0
*/
status_t cm_dec2_mul_op(const dec2_t *d1, const dec2_t *d2, dec2_t *rs)
{
    if (DECIMAL2_IS_ZERO(d1) || DECIMAL2_IS_ZERO(d2)) {
        cm_zero_dec2(rs);
        return GS_SUCCESS;
    }

    // carry should define int32 type, DEC2_CELL_SIZE * 9999 = 209979 < 0x7FFFFFFF
    int32 i, j, n;
    int32 carry = 0;
    int32 ncells = GET_CELLS_SIZE(d1) + GET_CELLS_SIZE(d2) - 1;

    i = GET_CELLS_SIZE(d2) - 1;
    j = DEC2_CELL_SIZE - i;

    for (; j < (int32)GET_CELLS_SIZE(d1); j++, i--) {
        carry += (int32)d1->cells[j] * (int32)d2->cells[i];
    }
    carry /= DEC2_CELL_MASK;

    /* Step 2: the main body of the multiplication */
    i = MIN(ncells, DEC2_CELL_SIZE);
    n = i;
    while (i > 0) {
        j = MIN(i, (int32)GET_CELLS_SIZE(d2)) - 1;  // j < i && j < d2.ncells
        i--;
        while (j >= 0 && (i - j) >= 0 && (i - j) < (int32)GET_CELLS_SIZE(d1)) {
            carry += (c2typ_t)d1->cells[i - j] * (c2typ_t)d2->cells[j];
            j--;
        }
        rs->cells[i] = carry % (c2typ_t)DEC2_CELL_MASK;
        carry /= (c2typ_t)DEC2_CELL_MASK;
    }

    rs->len = (uint8)n + 1;

    int32 rs_expn, carry_expn;
    rs_expn = (int32)GET_100_EXPN(d1) + (int32)GET_100_EXPN(d2);
    carry_expn = (carry > 0) ? 1 : 0;
    rs_expn += carry_expn;
    if (SECUREC_UNLIKELY(rs_expn > DEC2_EXPN_UPPER_HALF)) {
        GS_THROW_ERROR(ERR_NUM_OVERFLOW);
        return GS_ERROR;
    } else if (SECUREC_UNLIKELY(rs_expn < DEC2_EXPN_LOW_HALF)) {
        cm_zero_dec2(rs);
        return GS_SUCCESS;
    }
    rs->head = CONVERT_EXPN2(rs_expn, d1->sign ^ d2->sign);

    /* Step 3: handle carry */
    if (carry > 0) {
        cm_dec2_rebuild_cells(rs, (uint8)carry);
    }

    cm_dec2_trim_zeros(rs);
    return GS_SUCCESS;
}

/**
 * @note
 * Performance sensitivity.CM_ASSERT should be guaranteed by caller, i.g. !DECIMAL2_IS_ZERO(d)
 */
static inline status_t cm_dec2_init_inverse(const dec2_t *d, dec2_t *d_inv)
{
    return cm_real_to_dec2_inexac(1.0 / cm_dec2_to_real(d), d_inv);
}

/**
 * Computed the inverse of a decimal, inv_d = 1 / d
 * The Newton Inversion algorithm is used:
 *  $x_{i+1} = 2x_{i} - dx^2_{i} = x_i(2-d * x_i)$
 */
static status_t cm_dec2_inv(const dec2_t *d, dec2_t *inv_d, uint32 prec)
{
    uint32 i;
    dec2_t delta;

    // Step 1. compute an initial and approximate inverse by 1/double(dec)
    GS_RETURN_IFERR(cm_dec2_init_inverse(d, inv_d));
    DEC2_DEBUG_PRINT(inv_d, "inv_init_value");

    // Step 2. Newton iteration begins, At least 2 iterations are required
    for (i = 0; i <= 10; i++) {
        // set delta to x(1-d*x)
        GS_RETURN_IFERR(cm_dec2_mul_op(d, inv_d, &delta));           // set delta to d * inv_d
        GS_RETURN_IFERR(cm_dec2_sub_op(&DEC2_ONE, &delta, &delta));  // set delta to 1 - delta
        GS_RETURN_IFERR(cm_dec2_mul_op(&delta, inv_d, &delta));      // set delta to delta * inv_d
        DEC2_DEBUG_PRINT(&delta, "inv delta: %u", i);

        GS_RETURN_IFERR(cm_dec2_add_op(inv_d, &delta, inv_d));  // set inv_d(i) to inv_d(i) + delta
        DEC2_DEBUG_PRINT(inv_d, "inv(x): %u", i);
        // inv_d = delta + x_i
        if (cm_dec2_taylor_break(inv_d, &delta, prec)) {
            break;
        }
    }
    return GS_SUCCESS;
}

/**
 * The division of two decimals: dec1 / dec2
 */
status_t cm_dec2_divide(const dec2_t *dec1, const dec2_t *dec2, dec2_t *result)
{
    dec2_t inv_y, x, y;
    int32 n, m, sub;
    uint8 res_sign;

    if (SECUREC_UNLIKELY(DECIMAL2_IS_ZERO(dec1))) {
        cm_zero_dec2(result);
        return GS_SUCCESS;
    }

    if (SECUREC_UNLIKELY(DECIMAL2_IS_ZERO(dec2))) {
        GS_THROW_ERROR(ERR_ZERO_DIVIDE);
        return GS_ERROR;
    }

    if (cm_dec2_is_absolute_one(dec2)) {
        cm_dec2_copy(result, dec1);
        res_sign = dec1->sign ^ dec2->sign;
        result->head = CONVERT_EXPN2(GET_100_EXPN(dec1), res_sign);
        return GS_SUCCESS;
    }

    // x*100^n/(y*100^m) = x/y * 100^(n-m), so adjust the numbers by subtracting the exponents and then dividing them
    n = (int32)GET_100_EXPN(dec1);
    m = (int32)GET_100_EXPN(dec2);
    sub = n - m;
    // if result = x/y, then result->expn is in [-1, 0].
    if (SECUREC_UNLIKELY((sub - 1) > DEC2_EXPN_UPPER_HALF) || SECUREC_UNLIKELY((sub) < DEC2_EXPN_LOW_HALF)) {
            GS_THROW_ERROR(ERR_NUM_OVERFLOW);
            return GS_ERROR;
    }

    cm_dec2_copy(&x, dec1);
    cm_dec2_copy(&y, dec2);
    x.head = CONVERT_EXPN2(0, IS_DEC_NEG(dec1));
    y.head = CONVERT_EXPN2(0, IS_DEC_NEG(dec2));

    GS_RETURN_IFERR(cm_dec2_inv(&y, &inv_y, MAX_NUM_CMP_PREC));  // inv_y = 1 / y
    GS_RETURN_IFERR(cm_dec2_multiply(&x, &inv_y, result));

    sub += (int32)GET_100_EXPN(result);
    DEC2_OVERFLOW_CHECK_BY_EXPN(sub);
    result->head = CONVERT_EXPN2(sub, IS_DEC_NEG(result));
    return GS_SUCCESS;
}

/**
 * Get the carry of a decimal with negative expn when convert decimal into integer
 * @note Required: expn < 0
 */
static int32 dec2_make_negexpn_round_value(dec2_t *dec, round_mode_t rnd_mode, int16 expn)
{
    switch (rnd_mode) {
        case ROUND_FLOOR:
            return IS_DEC_NEG(dec) ? -1 : 0;

        case ROUND_HALF_UP: {
            // e.g., 0.5 ==> 1, 0.499 ==> 0
            int32 val = ((expn == -1) && (dec->cells[0] >= DEC2_HALF_MASK)) ? 1 : 0;
            return IS_DEC_NEG(dec) ? -val : val;
        }

        case ROUND_CEILING:
            return IS_DEC_NEG(dec) ? 0 : 1;

        case ROUND_TRUNC:
        default:
            return 0;
    }
}

/* Round a positive and non-zero decimal into uint64 */
static uint64 dec2_make_negexpn_round_value2(const dec2_t *dec, round_mode_t rnd_mode)
{
    int8 expn;
    switch (rnd_mode) {
        case ROUND_HALF_UP:
            // e.g., 0.5 ==> 1, 0.499 ==> 0
            expn = GET_100_EXPN(dec);
            return ((expn == -1) && (dec->cells[0] >= DEC2_HALF_MASK)) ? 1 : 0;

        case ROUND_CEILING:
            return 1;

        case ROUND_TRUNC:
        case ROUND_FLOOR:
        default:
            return 0;
    }
}

static status_t cm_make_dec2_to_int(dec2_t *dec, uint64 *u64, int8 expn, round_mode_t rnd_mode)
{
    uint32 i = 1;
    uint64 u64_val = dec->cells[0];
    int32 inc;

    for (; i <= (uint32)expn; i++) {
        inc = (i >= GET_CELLS_SIZE(dec)) ? 0 : dec->cells[i];  // such as 11 * 100^4 dec->len = 2, expn= 4
        u64_val = u64_val * DEC2_CELL_MASK + inc;
    }

    if (i < GET_CELLS_SIZE(dec)) {  // here i is equal to expn + 1
        switch (rnd_mode) {
            case ROUND_CEILING:
                u64_val += IS_DEC_NEG(dec) ? 0 : 1;
                break;

            case ROUND_FLOOR:
                u64_val += IS_DEC_NEG(dec) ? 1 : 0;
                break;

            case ROUND_HALF_UP:
                u64_val += (dec->cells[i] >= DEC2_HALF_MASK) ? 1 : 0;
                break;

            case ROUND_TRUNC:
            default:
                break;
        }
    }
    *u64 = u64_val;
    return GS_SUCCESS;
}

status_t cm_dec2_to_int64(dec2_t *dec, int64 *val, round_mode_t rnd_mode)
{
    CM_POINTER(dec);

    if (DECIMAL2_IS_ZERO(dec)) {
        *val = 0;
        return GS_SUCCESS;
    }
    int8 expn = GET_100_EXPN(dec);
    if (expn < 0) {
        *val = dec2_make_negexpn_round_value(dec, rnd_mode, expn);
        return GS_SUCCESS;
    }
    // the maximal BIGINT is 9.223372036854775807 * 100^9
    if (expn > DEC2_MAX_INT64_POWER || (expn == DEC2_MAX_INT64_POWER && dec->cells[0] > 9)) {
        GS_THROW_ERROR(ERR_TYPE_OVERFLOW, "BIGINT");
        return GS_ERROR;
    }

    uint64 u64;
    GS_RETURN_IFERR(cm_make_dec2_to_int(dec, &u64, expn, rnd_mode));
    return cm_dec2int64_check_overflow(u64, IS_DEC_NEG(dec), val);
}

static status_t cm_make_dec2_to_uint(const dec2_t *dec, uint64 *u64, int8 expn, round_mode_t rnd_mode)
{
    uint32 i = 1;
    uint64 u64_val = dec->cells[0];
    uint32 inc;
    for (; i <= (uint32)expn; i++) {
        inc = (i >= GET_CELLS_SIZE(dec)) ? 0 : dec->cells[i];  // such as 11 * 100^4,dec->len = 2, expn= 4
        u64_val = u64_val * DEC2_CELL_MASK + inc;
    }

    if (i < GET_CELLS_SIZE(dec)) {  // here i is equal to expn + 1
        switch (rnd_mode) {
            case ROUND_CEILING:
                u64_val += 1;
                break;

            case ROUND_HALF_UP:
                u64_val += (dec->cells[i] >= DEC2_HALF_MASK) ? 1 : 0;
                break;

            case ROUND_FLOOR:
            case ROUND_TRUNC:
            default:
                break;
        }
    }

    *u64 = u64_val;
    return GS_SUCCESS;
}

/**
 * Convert a decimal into uint32. if overflow happened, return ERROR
 */
status_t cm_dec2_to_uint32(dec2_t *dec, uint32 *i32, round_mode_t rnd_mode)
{
    if (DECIMAL2_IS_ZERO(dec)) {
        *i32 = 0;
        return GS_SUCCESS;
    }

    // the maximal UINT32 42 9496 7295
    int8 expn = GET_100_EXPN(dec);
    if (expn > DEC2_MAX_INT32_POWER || IS_DEC_NEG(dec)) {
        GS_THROW_ERROR(ERR_TYPE_OVERFLOW, "UNSIGNED INTEGER");
        return GS_ERROR;
    }

    if (expn < 0) {
        *i32 = (uint32)dec2_make_negexpn_round_value(dec, rnd_mode, expn);
        return GS_SUCCESS;
    }

    uint64 u64;
    GS_RETURN_IFERR(cm_make_dec2_to_uint(dec, &u64, expn, rnd_mode));
    TO_UINT32_OVERFLOW_CHECK(u64, uint64);
    *i32 = (uint32)u64;
    return GS_SUCCESS;
}

status_t cm_dec2_to_uint16(dec2_t *dec, uint16 *i16, round_mode_t rnd_mode)
{
    if (DECIMAL2_IS_ZERO(dec)) {
        *i16 = 0;
        return GS_SUCCESS;
    }

    // the maximal UINT16 is 65535 = 6.5535 * 100^2
    int8 expn = GET_100_EXPN(dec);
    if (expn > DEC2_MAX_INT16_POWER || IS_DEC_NEG(dec)) {
        GS_THROW_ERROR(ERR_TYPE_OVERFLOW, "UNSIGNED INTEGER");
        return GS_ERROR;
    }

    if (expn < 0) {
        *i16 = (uint16)dec2_make_negexpn_round_value(dec, rnd_mode, expn);
        return GS_SUCCESS;
    }

    uint64 u64;
    GS_RETURN_IFERR(cm_make_dec2_to_uint(dec, &u64, expn, rnd_mode));
    if (u64 < (uint64)GS_MIN_UINT16 || u64 > (uint64)GS_MAX_UINT16) {
        GS_THROW_ERROR(ERR_TYPE_OVERFLOW, "UNSIGNED SHORT");
        return GS_ERROR;
    }
    *i16 = (uint16)u64;
    return GS_SUCCESS;
}

status_t cm_dec2_to_uint64(const dec2_t *dec, uint64 *u64, round_mode_t rnd_mode)
{
    if (IS_DEC_NEG(dec)) {
        GS_THROW_ERROR(ERR_VALUE_ERROR, "convert NUMBER into UINT64 failed");
        return GS_ERROR;
    }

    if (DECIMAL2_IS_ZERO(dec)) {
        *u64 = 0;
        return GS_SUCCESS;
    }
    int8 expn = GET_100_EXPN(dec);
    if (expn < 0) {
        *u64 = dec2_make_negexpn_round_value2(dec, rnd_mode);
        return GS_SUCCESS;
    }

    // the maximal UINT64 is 18.446744073709551615 * 100 ^ 9
    if (expn > DEC2_MAX_INT64_POWER || (expn == DEC2_MAX_INT64_POWER && dec->cells[0] > 18)) {
        GS_THROW_ERROR(ERR_TYPE_OVERFLOW, "UINT64");
        return GS_ERROR;
    }

    uint32 i, inc;
    uint64 u64h = dec->cells[0];  // the highest cell
    uint64 u64l = 0;              // the tailing cells

    u64h *= g_pow100_u64[(uint32)expn];
    for (i = 1; i <= (uint32)expn; i++) {
        inc = (i >= GET_CELLS_SIZE(dec)) ? 0 : dec->cells[i];  // such as 11 * 100^4 dec->len = 2, expn= 4
        u64l = u64l * DEC2_CELL_MASK + inc;
    }

    // do round
    if (i < GET_CELLS_SIZE(dec)) {  // here i is dec->expn + 1
        switch (rnd_mode) {
            case ROUND_CEILING:
                u64l += IS_DEC_NEG(dec) ? 0 : 1;
                break;

            case ROUND_FLOOR:
                u64l += IS_DEC_NEG(dec) ? 1 : 0;
                break;

            case ROUND_HALF_UP:
                u64l += (dec->cells[i] >= DEC2_HALF_MASK) ? 1 : 0;
                break;

            case ROUND_TRUNC:
            default:
                break;
        }
    }

    // overflow check
    if (u64h == 18000000000000000000ull && u64l > 446744073709551615ull) {
        GS_THROW_ERROR(ERR_TYPE_OVERFLOW, "UINT64");
        return GS_ERROR;
    }

    *u64 = u64h + u64l;
    return GS_SUCCESS;
}

status_t cm_dec2_to_int32(dec2_t *dec, int32 *i32, round_mode_t rnd_mode)
{
    if (DECIMAL2_IS_ZERO(dec)) {
        *i32 = 0;
        return GS_SUCCESS;
    }
    int8 expn = GET_100_EXPN(dec);
    if (expn < 0) {
        *i32 = dec2_make_negexpn_round_value(dec, rnd_mode, expn);
        return GS_SUCCESS;
    }
    // the maximal INTEGER 2147483647 = 21.47483647 * 100^4
    if (expn > DEC2_MAX_INT32_POWER || (expn == DEC2_MAX_INT32_POWER && dec->cells[0] > 21)) {
        GS_THROW_ERROR(ERR_TYPE_OVERFLOW, "INTEGER");
        return GS_ERROR;
    }

    int64 i64;
    GS_RETURN_IFERR(cm_make_dec2_to_int(dec, (uint64 *)&i64, expn, rnd_mode));
    if (IS_DEC_NEG(dec)) {
        i64 = -i64;
    }

    INT32_OVERFLOW_CHECK(i64);

    *i32 = (int32)i64;
    return GS_SUCCESS;
}

status_t cm_dec2_to_int16(dec2_t *dec, int16 *i16, round_mode_t rnd_mode)
{
    if (DECIMAL2_IS_ZERO(dec)) {
        *i16 = 0;
        return GS_SUCCESS;
    }
    int8 expn = GET_100_EXPN(dec);
    if (expn < 0) {
        *i16 = (int16)dec2_make_negexpn_round_value(dec, rnd_mode, expn);
        return GS_SUCCESS;
    }
    // the maximal SHORT 32767 = 3.2767 * 100^2
    if (expn > DEC2_MAX_INT16_POWER || (expn == DEC2_MAX_INT16_POWER && dec->cells[0] > 3)) {
        GS_THROW_ERROR(ERR_TYPE_OVERFLOW, "SHORT");
        return GS_ERROR;
    }

    int64 i64;
    GS_RETURN_IFERR(cm_make_dec2_to_int(dec, (uint64 *)&i64, expn, rnd_mode));
    if (IS_DEC_NEG(dec)) {
        i64 = -i64;
    }
    if (i64 > GS_MAX_INT16 || i64 < GS_MIN_INT16) {
        GS_THROW_ERROR(ERR_TYPE_OVERFLOW, "SHORT");
        return GS_ERROR;
    }

    *i16 = (int16)i64;
    return GS_SUCCESS;
}

// To decide whether a decimal is an integer
bool32 cm_dec2_is_integer(const dec2_t *dec)
{
    uint32 i;

    if (DECIMAL2_IS_ZERO(dec)) {
        return GS_TRUE;
    }
    int8 expn = GET_100_EXPN(dec);
    if (expn < 0) {
        return GS_FALSE;
    }

    i = expn + 1;
    for (; i < GET_CELLS_SIZE(dec); i++) {
        if (dec->cells[i] > 0) {
            return GS_FALSE;
        }
    }
    return GS_TRUE;
}

/* Round a decimal by persevering at most scale digits after decimal point
 * The round mode can only be ROUND_HALF_UP or ROUND_TRUNC
 * Performance sensitivity.CM_ASSERT should be guaranteed by caller,
 * i.g. rnd_mode == ROUND_HALF_UP || rnd_mode == ROUND_TRUNC
 */
static status_t cm_dec2_scale(dec2_t *dec, int32 scale, round_mode_t rnd_mode)
{
    int32 i, cpos, r_pos;
    uint32 carry, npos;

    GS_RETVALUE_IFTRUE(DECIMAL2_IS_ZERO(dec), GS_SUCCESS);
    int32 expn = GET_10_EXPN(dec);

    r_pos = DEC2_CELL_DIGIT + expn + scale;
    // hit scenario 11.33333*10^-4, left shift dot 0.00113333, if expn + scale + DEC2_CELL_DIGIT < 0. finally ret = 0
    if (r_pos < 0) {
        cm_zero_dec2(dec);
        return GS_SUCCESS;
    }
    // hit scenario 11.33333*10^42, right shift dot, if r_pos > DEC2_MAX_ALLOWED_PREC, no need to scale
    GS_RETVALUE_IFTRUE((r_pos > (int32)DEC2_MAX_ALLOWED_PREC), GS_SUCCESS);

    cpos = r_pos / DEC2_CELL_DIGIT;
    if (cpos >= (int32)GET_CELLS_SIZE(dec)) {
        return GS_SUCCESS;
    }

    npos = DEC2_CELL_DIGIT - ((uint32)r_pos % DEC2_CELL_DIGIT);
    carry = (rnd_mode == ROUND_HALF_UP) ? g_5ten_powers[npos] : 0;

    for (i = cpos; i >= 0; --i) {
        dec->cells[i] += carry;
        carry = (dec->cells[i] >= DEC2_CELL_MASK);
        if (!carry) {
            break;
        }
        dec->cells[i] -= DEC2_CELL_MASK;
    }

    dec->cells[cpos] /= g_1ten_powers[npos];
    dec->cells[cpos] *= g_1ten_powers[npos];

    // trimming zeros and recompute the dec->ncells
    while ((cpos >= 0) && (dec->cells[cpos] == 0)) {
        --cpos;
    }
    dec->len = (uint8)(cpos + 2);

    if (carry) {
        GS_RETURN_IFERR(cm_dec2_rebuild(dec, 1));
    }
    cm_dec2_trim_zeros(dec);

    return GS_SUCCESS;
}

/**
 * Compute the sin(x) using Taylor series, where x in (0, pi/4)
 * @author Added 2018/09/11
 * sin x = x-x^3/3!+x^5/5!- x^7/7! + ...= sum(((-1)^(n)*(x^(2n+1)))/(2n+1)!) n= 0,1,2,3
 */
static status_t cm_dec2_sin_frac(const dec2_t *x, dec2_t *sin_x)
{
    dec2_t x_pow2;
    dec2_t x_i;
    dec2_t item;

    /* initialize the iteration variables */
    GS_RETURN_IFERR(cm_dec2_mul_op(x, x, &x_pow2));  // set x_pow2 to x * x
    cm_dec2_copy(sin_x, x);               // set sin(x) to x
    cm_dec2_copy(&x_i, x);                // set x(i) to x

    for (uint32 i = _I(3); i < ELEMENT_COUNT(g_inv_fact); i += 2) {
        GS_RETURN_IFERR(cm_dec2_mul_op(&x_i, &x_pow2, &x_i));  // set x(i) to x^2 * x(i-1)
        GS_RETURN_IFERR(cm_dec2_mul_op(&x_i, &g_inv_fact[i], &item));
        DEC2_DEBUG_PRINT(&item, "The item at [%u]", i >> 1);

        if (i & 2) {
            GS_RETURN_IFERR(cm_dec2_add_op(sin_x, &item, sin_x));
        } else {
            GS_RETURN_IFERR(cm_dec2_sub_op(sin_x, &item, sin_x));
        }
        DEC2_DEBUG_PRINT(sin_x, "The %u-th iteration", i >> 1);
        if (cm_dec2_taylor_break(sin_x, &item, MAX_NUM_CMP_PREC)) {
            break;
        }
    }

    return GS_SUCCESS;
}

/**
 * Compute the cos(x) using Taylor series, where x in (0, pi/4)
 * @author Added 2018/09/13
 * cos x = 1-x^2/2!+x^4/4!-x^6/6! = sum((-1)^n*(x^2n/(2*n)!)) n = 0,...NAN
 */
static status_t cm_dec2_cos_frac(const dec2_t *x, dec2_t *cos_x)
{
    dec2_t x_pow2;
    dec2_t x_i;
    dec2_t item;

    GS_RETURN_IFERR(cm_dec2_mul_op(x, x, &x_pow2));
    cm_dec2_copy(&x_i, &x_pow2);

    // 1 - (x^2)/2
    GS_RETURN_IFERR(cm_dec2_mul_op(&x_pow2, &DEC2_HALF_ONE, &item));
    GS_RETURN_IFERR(cm_dec2_sub_op(&DEC2_ONE, &item, cos_x));

    for (uint32 i = _I(4); i < ELEMENT_COUNT(g_inv_fact); i += 2) {
        GS_RETURN_IFERR(cm_dec2_mul_op(&x_i, &x_pow2, &x_i));  // set x(i) to x^2 * x(i-1)
        GS_RETURN_IFERR(cm_dec2_mul_op(&x_i, &g_inv_fact[i], &item));
        DEC2_DEBUG_PRINT(&item, "The item at [%u]", i >> 1);

        if (i & 2) {
            GS_RETURN_IFERR(cm_dec2_sub_op(cos_x, &item, cos_x));
        } else {
            GS_RETURN_IFERR(cm_dec2_add_op(cos_x, &item, cos_x));
        }
        DEC2_DEBUG_PRINT(cos_x, "The %u-th iteration", i >> 1);
        if (cm_dec2_taylor_break(cos_x, &item, MAX_NUM_CMP_PREC)) {
            break;
        }
    }

    return GS_SUCCESS;
}

#define MAX2_RANGE_PREC (MAX_NUM_CMP_PREC - DEC2_CELL_DIGIT)

static status_t cm_dec2_range_to_2pi(const dec2_t *x, dec2_t *y, double *dy)
{
    static const double pi = GS_PI * 2.0;

    *y = *x;
    dec2_t rem;
    int32 scale;
    do {
        *dy = cm_dec2_to_real(y);
        if (*dy < pi) {
            break;
        }

        GS_RETURN_IFERR(cm_dec2_mul_op(&DEC2_INV_2PI, y, &rem));  // set rem to y /(2pi)
        int8 expn = GET_100_EXPN(&rem);
        scale = (expn <= SEXP_2_D2EXP(MAX2_RANGE_PREC)) ? 0 : (MAX2_RANGE_PREC) - D2EXP_2_SEXP(expn);

        GS_RETURN_IFERR(cm_dec2_scale(&rem, scale, ROUND_TRUNC));  // truncate rem to integer
        GS_RETURN_IFERR(cm_dec2_mul_op(&rem, &DEC2_2PI, &rem));
        GS_RETURN_IFERR(cm_dec2_sub_op(y, &rem, y));
    } while (1);
    return GS_SUCCESS;
}

static status_t cm_dec2_sin_op(const dec2_t *x, dec2_t *sin_x)
{
    dec2_t tx;
    double dx;
    dec2_t tmp_x;
    bool32 is_neg = IS_DEC_NEG(x);
    cm_dec2_copy(&tmp_x, x);
    cm_dec2_abs(&tmp_x);
    GS_RETURN_IFERR(cm_dec2_range_to_2pi(&tmp_x, &tx, &dx));

    if (dx < GS_PI_2) {  // [0, pi/2)
        // do nothing
    } else if (dx < GS_PI) {                       // [pi/2, pi)
        GS_RETURN_IFERR(cm_dec2_sub_op(&DEC2_PI, &tx, &tx));  // pi - tx
    } else if (dx < GS_PI_2 + GS_PI) {             // [PI, 3/2pi)
        GS_RETURN_IFERR(cm_dec2_sub_op(&tx, &DEC2_PI, &tx));  // tx - pi
        is_neg = !is_neg;
    } else {
        GS_RETURN_IFERR(cm_dec2_sub_op(&DEC2_2PI, &tx, &tx));  // 2pi - tx
        is_neg = !is_neg;
    }

    dx = cm_dec2_to_real(&tx);
    if (dx < GS_PI_4) {
        GS_RETURN_IFERR(cm_dec2_sin_frac(&tx, sin_x));
    } else {
        GS_RETURN_IFERR(cm_dec2_sub_op(&DEC2_HALF_PI, &tx, &tx));
        GS_RETURN_IFERR(cm_dec2_cos_frac(&tx, sin_x));
    }
    if (is_neg) {
        cm_dec2_negate(sin_x);
    }
    return GS_SUCCESS;
}

/**
 * Compute the sin(x) using Taylor series
 * sin x = x-x^3/3!+x^5/5!- x^7/7! + ...= sum(((-1)^(n)*(x^(2n+1)))/(2n+1)!) n= 0,1,2,3
 */
status_t cm_dec2_sin(const dec2_t *dec, dec2_t *result)
{
    if (DECIMAL2_IS_ZERO(dec)) {
        cm_zero_dec2(result);
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(cm_dec2_sin_op(dec, result));
    return cm_dec2_finalise(result, MAX_NUMERIC_BUFF);
}

/*
 * Convert a decimal into a text with all precisions
 */
static inline status_t cm_dec2_to_text_all(const dec2_t *dec, text_buf_t *text)
{
    if (text->max_size <= GS_MAX_DEC_OUTPUT_ALL_PREC) {
        return GS_ERROR;
    }
    return cm_dec2_to_text(dec, GS_MAX_DEC_OUTPUT_ALL_PREC, &text->value);
}

static inline status_t cm_dec2_to_str_all(const dec2_t *dec, char *str, uint32 buffer_len)
{
    text_buf_t text_buf = { .str = str, .len = 0, .max_size = buffer_len };

    GS_RETURN_IFERR(cm_dec2_to_text_all(dec, &text_buf));
    str[text_buf.len] = '\0';
    return GS_SUCCESS;
}

/**
 * Use for debugging. see the macro @DEC2_DEBUG_PRINT
 */
void cm_dec2_print(const dec2_t *dec, const char *file, uint32 line, const char *func_name, const char *fmt, ...)
{
    char buf[100];
    va_list var_list;
    dec2_t fl_dec;

    printf("%s:%u:%s\n", file, line, func_name);
    va_start(var_list, fmt);
    PRTS_RETVOID_IFERR(vsnprintf_s(buf, sizeof(buf), sizeof(buf) - 1, fmt, var_list));

    va_end(var_list);
    printf("%s\n", buf);
    (void)cm_dec2_to_str_all(dec, buf, sizeof(buf));
    printf("dec := %s\n", buf);
    printf("  ncells = %u, expn = %d, sign = %c, bytes = %d\n", GET_CELLS_SIZE(dec), GET_10_EXPN(dec),
           (IS_DEC_NEG(dec)) ? '-' : '+', dec->len + 1);
    printf("  cells = { ");
    for (uint32 i = 0; i < GET_CELLS_SIZE(dec); i++) {
        if (i != 0) {
            printf(", ");
        }
        printf("%02u", dec->cells[i]);
    }
    printf("}\n");

    fl_dec = *dec;
    (void)cm_dec2_finalise(&fl_dec, MAX_NUM_CMP_PREC);
    (void)cm_dec2_to_str_all(&fl_dec, buf, sizeof(buf));
    printf("finalized dec := %s\n\n", buf);
    (void)fflush(stdout);
}

#ifdef __cplusplus
}
#endif

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
 * cm_dec8.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_dec8.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_text.h"
#include "cm_decimal.h"
#include "cm_binary.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DEC8_POW2_MASK ((uint64)(DEC8_CELL_MASK) * (DEC8_CELL_MASK))


static const uint64 g_pow8_u64[] = {
    1,               // 10^0
    DEC8_CELL_MASK,  // 10^8
    DEC8_POW2_MASK,  // 10^16
};

/** The following define some useful constants */
/* decimal 0 */
static const dec8_t DEC8_ZERO = {
    .len = (uint8)1,
    .head = ZERO_D8EXPN,
    .cells = { 0 }
};

/* decimal 0.5 */
static const dec8_t DEC8_HALF_ONE = {
    .len = (uint8)2,
    .head = CONVERT_D8EXPN(-8, CT_FALSE),
    .cells = { 50000000 }
};

/* decimal 1 */
const dec8_t DEC8_ONE = {
    .len = (uint8)2,
    .head = CONVERT_D8EXPN(0, CT_FALSE),
    .cells = { 1 }
};

/* decimal -1 */
static const dec8_t DEC8_NEG_ONE = {
    .len = (uint8)2,
    .head = CONVERT_D8EXPN(0, CT_TRUE),
    .cells = { 1 }
};

/* decimal 2 */
static const dec8_t DEC8_TWO = {
    .len = (uint8)2,
    .head = CONVERT_D8EXPN(0, CT_FALSE),
    .cells = { 2 }
};

/* decimal 4 */
static const dec8_t DEC8_FOUR = {
    .len = (uint8)2,
    .head = CONVERT_D8EXPN(0, CT_FALSE),
    .cells = { 4 }
};

/* decimal pi/2 is 1.570796326794896619231321691639751442098584699687552910487472296153908 */
static const dec8_t DEC8_HALF_PI = {
    .len = DEC8_MAX_LEN,
    .head = CONVERT_D8EXPN(0, CT_FALSE),
    .cells = {1, 57079632, 67948966, 19231321, 69163975, 14420985, 84699688}
};

/* decimal pi is 3.1415926535897932384626433832795028841971693993751058209749445923078164 */
static const dec8_t DEC8_PI = {
    .len = DEC8_MAX_LEN,
    .head = CONVERT_D8EXPN(0, CT_FALSE),
    .cells = {3, 14159265, 35897932, 38462643, 38327950, 28841971, 69399375}
};

/* decimal 2*pi is 6.28318530717958647692528676655900576839433879875021164194988918461563281 */
static const dec8_t DEC8_2PI = {
    .len = DEC8_MAX_LEN,
    .head = CONVERT_D8EXPN(0, CT_FALSE),
    .cells = {6, 28318530, 71795864, 76925286, 76655900, 57683943, 38798750}
};

/* 1/(2pi) is 0.159154943091895335768883763372514362034459645740456448747667344058896797634226535 */
static const dec8_t DEC8_INV_2PI = {
    .len = DEC8_MAX_LEN,
    .head = CONVERT_D8EXPN(-8, CT_FALSE),
    .cells = { 15915494, 30918953, 35768883, 76337251, 43620344, 59645740, 45644875 }
};

/* decimal of the minimal int64 is -9 223 372 036 854 775 808 */
const dec8_t DEC8_MIN_INT64 = {
    // to make the expn be the integer multiple times of DEC_CELL_DIGIT
    .len = (uint8)4,
    .head = CONVERT_D8EXPN(16, CT_TRUE),
    .cells = { 922, 33720368, 54775808 }
};

/* decimal of the maximal bigint is 9,223,372,036,854,775,807 */
const dec8_t DEC8_MAX_INT64 = {
    .len = (uint8)4,
    .head = CONVERT_D8EXPN(16, CT_FALSE),
    .cells = { 922, 33720368, 54775807 }
};

/* decimal of the maximal uint64 is 18,446,744,073,709,551,615 */
const dec8_t DEC8_MAX_UINT64 = {
    .len = (uint8)4,
    .head = CONVERT_D8EXPN(16, CT_FALSE),
    .cells = { 1844, 67440737, 9551615 }
};

/* decimal of the minimal int32 is -2 147 483 648 */
static const dec8_t DEC8_MIN_INT32 = {
    // to make the expn be the integer multiple times of DEC_CELL_DIGIT
    .len = (uint8)3,
    .head = CONVERT_D8EXPN(8, CT_TRUE),
    .cells = { 21, 47483648 }
};

/* 2.71828182845904523536028747135266249775724709369995957496696762772407663 */
static const dec8_t DEC8_EXP = {
    .len = DEC8_MAX_LEN,
    .head = CONVERT_D8EXPN(0, CT_FALSE),
    .cells = { 2, 71828182, 84590452, 35360287, 47135266, 24977572, 47093699 }
};

/* 0.367879441171442321595523770161460867445811131031767834507836801 */
static const dec8_t DEC8_INV_EXP = {
    .len = DEC8_MAX_LEN,
    .head = CONVERT_D8EXPN(-8, CT_FALSE),
    .cells = { 36787944, 11714423, 21595523, 77016146, 8674458, 11131031, 76783451 }
};

/* ln(10) is 2.3025850929940456840179914546843642076011014886287729760333279009675726 */
static const dec8_t DEC8_LN10 = {
    .len = DEC8_MAX_LEN,
    .head = CONVERT_D8EXPN(0, CT_FALSE),
    .cells = {2, 30258509, 29940456, 84017991, 45468436, 42076011, 1488629}
};

#define INV_FACT_START 3
#define _I(i) ((i) - INV_FACT_START)
static const dec8_t g_dec8_inv_fact[] = {
    /* 1/3! = 0.166666666666666666666666666666666666666666666666666666666666666666666666666 */
    [_I(3)] = {
        .len = DEC8_MAX_LEN,
        .head = CONVERT_D8EXPN(-8, CT_FALSE),
        .cells = { 16666666, 66666666, 66666666, 66666666, 66666666, 66666666, 66666667 }
    },
    /* 1/4! =
     * 0.04166666666666666666666666666666666666666666666666666666666666666666666666666666666666666
     * 6666666666666666666666 */
    [_I(4)] = {
        .len = DEC8_MAX_LEN,
        .head = CONVERT_D8EXPN(-8, CT_FALSE),
        .cells = { 4166666, 66666666, 66666666, 66666666, 66666666, 66666666, 66666667 }
    },
    /* 1/5! = 0.0083333333333333333333333333333333333333333333333333333333333333333333333333333 */
    [_I(5)] = {
        .len = DEC8_MAX_LEN,
        .head = CONVERT_D8EXPN(-8, CT_FALSE),
        .cells = { 833333, 33333333, 33333333, 33333333, 33333333, 33333333, 33333333 }
    },
    /* 1/6! =
     * 0.001388888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888
     * 8888888888888888888888888888888888888888888888888888888
     */
    [_I(6)] = {
        .len = DEC8_MAX_LEN,
        .head = CONVERT_D8EXPN(-8, CT_FALSE),
        .cells = { 138888, 88888888, 88888888, 88888888, 88888888, 88888888, 88888889 }
    },
    /* 1/7! = 0.0001984126984126984126984126984126984126984126984126984126984126984126984126984126984 */
    [_I(7)] = {
        .len = DEC8_MAX_LEN,
        .head = CONVERT_D8EXPN(-8, CT_FALSE),
        .cells = { 19841, 26984126, 98412698, 41269841, 26984126, 98412698, 41269841 }
    },
    /* 1/8! =
     * 0.0000248015873015873015873015873015873015873015873015873015873015873015873015873015873015873
     * 015873015873015873015873015873015873015873015873015873015873015873
     */
    [_I(8)] = {
        .len = DEC8_MAX_LEN,
        .head = CONVERT_D8EXPN(-8, CT_FALSE),
        .cells = { 2480, 15873015, 87301587, 30158730, 15873015, 87301587, 30158730 }
    },
    /* 1/9! = 0.00000275573192239858906525573192239858906525573192239858906525573192239858906525573192 */
    [_I(9)] = {
        .len = DEC8_MAX_LEN,
        .head = CONVERT_D8EXPN(-8, CT_FALSE),
        .cells = { 275, 57319223, 98589065, 25573192, 23985890, 65255731, 92239859 }
    },
    /* 1/10! = 0.000000275573192239858906525573192239858906525573192239858906525573192239858906525573192 */
    [_I(10)] = {
        .len = DEC8_MAX_LEN,
        .head = CONVERT_D8EXPN(-8, CT_FALSE),
        .cells = { 27, 55731922, 39858906, 52557319, 22398589, 6525573, 19223986 }
    },
    /* 1/11! =
     * 0.000000025052108385441718775052108385441718775052108385441718775052108385441718775
     * 0521083854417187750521083854417187750521
     */
    [_I(11)] = {
        .len = DEC8_MAX_LEN,
        .head = CONVERT_D8EXPN(-8, CT_FALSE),
        .cells = { 2, 50521083, 85441718, 77505210, 83854417, 18775052, 10838544 }
    },
    /* 1/12! =
     * 0.0000000020876756987868098979210090321201432312543423654534765645876756987868098979210090
     * 3212014323125434236545347656458767569878680989792
     */
    [_I(12)] = {
        .len = DEC8_MAX_LEN,
        .head = CONVERT_D8EXPN(-16, CT_FALSE),
        .cells = { 20876756, 98786809, 89792100, 90321201, 43231254, 34236545, 34765646 }
    },
    /* 1/13! =
     * 0.00000000016059043836821614599392377170154947932725710503488281266059043836821614599392377
     * 170154947932725710503488281266
     */
    [_I(13)] = {
        .len = DEC8_MAX_LEN,
        .head = CONVERT_D8EXPN(-16, CT_FALSE),
        .cells = { 1605904, 38368216, 14599392, 37717015, 49479327, 25710503, 48828127 }
    },
    /* 1/14! =
     * 0.0000000000114707455977297247138516979786821056662326503596344866186136027405868675709945551215
     * 3924852337550750249162947575645988344401042813741226439639138
     */
    [_I(14)] = {
        .len = DEC8_MAX_LEN,
        .head = CONVERT_D8EXPN(-16, CT_FALSE),
        .cells = { 114707, 45597729, 72471385, 16979786, 82105666, 23265035, 96344867 }
    },
    /* 1/15! =
     * 0.0000000000007647163731819816475901131985788070444155100239756324412409068493724578380663036
     * 74769283234891700500166108631717
     */
    [_I(15)] = {
        .len = DEC8_MAX_LEN,
        .head = CONVERT_D8EXPN(-16, CT_FALSE),
        .cells = { 7647, 16373181, 98164759, 1131985, 78807044, 41551002, 39756324 }
    },
    /* 1/16! =
     * 0.0000000000000477947733238738529743820749111754402759693764984770275775566780857786148791439
     * 79673080202180731281260381789482318582847683
     */
    [_I(16)] = {
        .len = DEC8_MAX_LEN,
        .head = CONVERT_D8EXPN(-16, CT_FALSE),
        .cells = { 477, 94773323, 87385297, 43820749, 11175440, 27596937, 64984770 }
    },
    /* 1/17! =
     * 0.00000000000000281145725434552076319894558301032001623349273520453103397392224033991852230
     * 258703959295306945478125061069
     */
    [_I(17)] = {
        .len = DEC8_MAX_LEN,
        .head = CONVERT_D8EXPN(-16, CT_FALSE),
        .cells = { 28, 11457254, 34552076, 31989455, 83010320, 1623349, 27352045 }
    },
    /* 1/18! =
     * 0.00000000000000015619206968586226462216364350057333423519404084469616855410679112999547346
     * 125483553294183719193229170059408327555092
     */
    [_I(18)] = {
        .len = DEC8_MAX_LEN,
        .head = CONVERT_D8EXPN(-16, CT_FALSE),
        .cells = { 1, 56192069, 68586226, 46221636, 43500573, 33423519, 40408447 }
    },
    /* 1/19! =
     * 0.00000000000000000822063524662432971695598123687228074922073899182611413442667321736818281375
     * 025450173378090483854166845232
     */
    [_I(19)] = {
        .len = DEC8_MAX_LEN,
        .head = CONVERT_D8EXPN(-24, CT_FALSE),
        .cells = { 8220635, 24662432, 97169559, 81236872, 28074922, 7389918, 26114134 }
    },
    /* 1/20! =
     * 0.0000000000000000004110317623312164858477990618436140374610369495913057067213336608684091406875
     * 1272508668904524192708342261600861987085352324885435075580
     */
    [_I(20)] = {
        .len = DEC8_MAX_LEN,
        .head = CONVERT_D8EXPN(-24, CT_FALSE),
        .cells = { 411031, 76233121, 64858477, 99061843, 61403746, 10369495, 91305707 }
    },
    /* 1/21! =
     * 0.000000000000000000019572941063391261230847574373505430355287473790062176510539698136590911461
     * 31012976603281167818700397250552421999385016777375496908360952830809216
     */
    [_I(21)] = {
        .len = DEC8_MAX_LEN,
        .head = CONVERT_D8EXPN(-24, CT_FALSE),
        .cells = { 19572, 94106339, 12612308, 47574373, 50543035, 52874737, 90062177 }
    },
    /* 1/22! =
     * 0.00000000000000000000088967913924505732867488974425024683433124880863918984138816809711776870278
     * 68240802742187126448638169320692827269931894
     */
    [_I(22)] = {
        .len = DEC8_MAX_LEN,
        .head = CONVERT_D8EXPN(-24, CT_FALSE),
        .cells = { 889, 67913924, 50573286, 74889744, 25024683, 43312488, 8639190 }
    },
    /* 1/23! =
     * 0.0000000000000000000000386817017063068403771691193152281232317934264625734713647029607442508131646
     * 445252293138570715158181274812731620431821497505038914695840480397078275699598837
     */
    [_I(23)] = {
        .len = DEC8_MAX_LEN,
        .head = CONVERT_D8EXPN(-24, CT_FALSE),
        .cells = { 38, 68170170, 63068403, 77169119, 31522812, 32317934, 26462573 }
    },
    /* 1/24! =
     * 0.0000000000000000000000016117375710961183490487133048011718013247261026072279735292900310104505485
     * 268552178880773779798257553117197150851
     */
    [_I(24)] = {
        .len = DEC8_MAX_LEN,
        .head = CONVERT_D8EXPN(-24, CT_FALSE),
        .cells = { 1, 61173757, 10961183, 49048713, 30480117, 18013247, 26102607 }
    },
    /* 1/25! =
     * 0.0000000000000000000000000644695028438447339619485321920468720529890441042891189411716012404180219
     * 410742087155230951191930302124687886034053035829175064857826400800661797126165998
     */
    [_I(25)] = {
        .len = DEC8_MAX_LEN,
        .head = CONVERT_D8EXPN(-32, CT_FALSE),
        .cells = { 6446950, 28438447, 33961948, 53219204, 68720529, 89044104, 28911894 }
    },
    /* 1/26! =
     * 0.00000000000000000000000000247959626322479746007494354584795661742265554247265842081429235540069315
     * 15797772582893498122766550081718764847463578301
     */
    [_I(26)] = {
        .len = DEC8_MAX_LEN,
        .head = CONVERT_D8EXPN(-32, CT_FALSE),
        .cells = { 247959, 62632247, 97460074, 94354584, 79566174, 22655542, 47265842 }
    },
    /* 1/27! =
     * 0.00000000000000000000000000009183689863795546148425716836473913397861687194343179336349230945928493
     * 153999175030701295601024648178414357350912436407823006621906358985764413064475299
     */
    [_I(27)] = {
        .len = DEC8_MAX_LEN,
        .head = CONVERT_D8EXPN(-32, CT_FALSE),
        .cells = { 9183, 68986379, 55461484, 25716836, 47391339, 78616871, 94343179 }
    },
    /* 1/28! =
     * 0.00000000000000000000000000000327988923706983791015204172731211192780774542655113547726758248068874
     * 7554999705368107605571794517206576556196754441574222502364966556780630
     */
    [_I(28)] = {
        .len = DEC8_MAX_LEN,
        .head = CONVERT_D8EXPN(-32, CT_FALSE),
        .cells = { 327, 98892370, 69837910, 15204172, 73121119, 27807745, 42655114 }
    },
    /* 1/29! =
     * 0.0000000000000000000000000000001130996288644771693155876457693831699244050147086598440437097407134
     * 0508810343811614164157144119024850263986885360143359387939189539850967690163872506526007013143054544564
     */
    [_I(29)] = {
        .len = DEC8_MAX_LEN,
        .head = CONVERT_D8EXPN(-32, CT_FALSE),
        .cells = { 11, 30996288, 64477169, 31558764, 57693831, 69924405, 147865 }
    },
    /* 1/30! =
     * 0.000000000000000000000000000000003769987628815905643852921525646105664146833823621994801456991357113
     * 502936781270538054719048039674950087995628453381119795979729846616989230
     */
    [_I(30)] = {
        .len = DEC8_MAX_LEN,
        .head = CONVERT_D8EXPN(-40, CT_FALSE),
        .cells = { 37699876, 28815905, 64385292, 15256461, 5664146, 83382362, 19948015 }
    },
    /* 1/31! =
     * 0.000000000000000000000000000000000121612504155351794962997468569229214972478510439419187143773914745
     * 59686892842808187273287251740886935767727833720584257406386225311667707193724594093
     */
    [_I(31)] = {
        .len = DEC8_MAX_LEN,
        .head = CONVERT_D8EXPN(-40, CT_FALSE),
        .cells = { 1216125, 4155351, 79496299, 74685692, 29214972, 47851043, 94191871 }
    },
    /* 1/32! =
     * 0.00000000000000000000000000000000000380039075485474359259367089278841296788995345123184959824293483
     * 57999021540133775585229022661690271674274149480376825804394956954
     */
    [_I(32)] = {
        .len = DEC8_MAX_LEN,
        .head = CONVERT_D8EXPN(-40, CT_FALSE),
        .cells = { 38003, 90754854, 74359259, 36708927, 88412967, 88995345, 12318496 }
    },
    /* 1/33! =
     * 0.000000000000000000000000000000000000115163356207719502805868814932982211148180407613086351461907
     * 11623636067133373871389463340200512203537658833175871765395271199076999685328781936168648710906456849803
     */
    [_I(33)] = {
        .len = DEC8_MAX_LEN,
        .head = CONVERT_D8EXPN(-40, CT_FALSE),
        .cells = { 1151, 63356207, 71950280, 58688149, 32982211, 14818040, 76130863 }
    },
    /* 1/34! =
     * 0.00000000000000000000000000000000000000338715753552116184723143573332300621024060022391430445476
     * 19740069517844509923151145480412354447657463702450517269898221385879638234368614064518143084443842520
     */
    [_I(34)] = {
        .len = DEC8_MAX_LEN,
        .head = CONVERT_D8EXPN(-40, CT_FALSE),
        .cells = { 33, 87157535, 52116184, 72314357, 33323006, 21024060, 2239143 }
    },
    /* 1/35! =
     * 0.000000000000000000000000000000000000000096775929586318909920898163809228748864017149254694412993
     * 19925734147955574263757470137260672699330703914985862077113777538822753781248175447
     */
    [_I(35)] = {
        .len = DEC8_MAX_LEN,
        .head = CONVERT_D8EXPN(-48, CT_FALSE),
        .cells = { 96775929, 58631890, 99208981, 63809228, 74886401, 71492546, 94412993 }
    },
    /* 1/36! =
     * 0.0000000000000000000000000000000000000000026882202662866363866916156613674652462226985904081781
     * 38699979370596654326184377075038127964638702973309718295021420493760784098272568937624168106594
     */
    [_I(36)] = {
        .len = DEC8_MAX_LEN,
        .head = CONVERT_D8EXPN(-48, CT_FALSE),
        .cells = { 2688220, 26628663, 63866916, 15661367, 46524622, 26985904, 8178139 }
    },
    /* 1/37! =
     * 0.0000000000000000000000000000000000000000000726546017915307131538274503072287904384513132542750
     * 848297291721782879547617399209469764314767217019813437377032816349665
     */
    [_I(37)] = {
        .len = DEC8_MAX_LEN,
        .head = CONVERT_D8EXPN(-48, CT_FALSE),
        .cells = { 72654, 60179153, 7131538, 27450307, 22879043, 84513132, 54275085 }
    }
};

static int32 cm_dec8_calc_prec(const dec8_t *dec);

static inline bool32 cm_dec8_taylor_break(const dec8_t *total, const dec8_t *delta, int32 prec)
{
    if (DECIMAL8_IS_ZERO(delta)) {
        return CT_TRUE;
    }
    int32 total_expn = GET_DEC8_EXPN(total);
    int32 delta_expn = GET_DEC8_EXPN(delta);
    if ((total_expn + ((total->cells[0] >= 10000000) ? 1 : 0)) > (int32)SEXP_2_D8EXP(prec) + delta_expn) {
        return CT_TRUE;
    }
    return CT_FALSE;
}

static inline void cm_dec8_left_shift(const dec8_t *dec, uint32 offset, dec8_t *rs)
{
    uint32 ri, di;

    for (ri = 0, di = offset; di < GET_CELLS8_SIZE(dec); ++ri, ++di) {
        rs->cells[ri] = dec->cells[di];
    }
    rs->len = (int8)((uint32)dec->len - offset);
    rs->head = CONVERT_D8EXPN2(GET_DEC8_EXPN(dec) - (int32)offset, IS_DEC8_NEG(dec));
}

/**
* Right shift decimal cells. The leading cells are filled with zero.
* @note The following conditions should be guaranteed by caller
* + offset > 0 and offset < DEC_CELL_SIZE
* + dec->ncells > 0
*/
static inline void cm_dec8_right_shift(const dec8_t *dec, int32 offset, dec8_t *rs)
{
    int32 di = GET_CELLS8_SIZE(dec) - 1;
    int32 ri = di + offset;

    if (ri >= (DEC8_CELL_SIZE - 1)) {
        di -= (ri - (DEC8_CELL_SIZE - 1));
        ri = (DEC8_CELL_SIZE - 1);
    }

    rs->len = (uint8)(ri + 2); // ncells is ri + 1
    rs->head = CONVERT_D8EXPN2(GET_DEC8_EXPN(dec) + offset, IS_DEC8_NEG(dec));

    while (di >= 0) {
        rs->cells[ri] = dec->cells[di];
        ri--;
        di--;
    }

    while (ri >= 0) {
        rs->cells[ri] = 0;
        ri--;
    }
}

static inline void cm_dec8_rebuild(dec8_t *rs, uint32 cell0)
{
    /* decide the number of cells */
    if (rs->len < DEC8_MAX_LEN) {
        rs->len++;
    }

    /* right shift cell data by 1 */
    uint32 i = GET_CELLS8_SIZE(rs);
    while (i-- > 1) {
        rs->cells[i] = rs->cells[i - 1];
    }

    /* put the carry into cells[0] */
    rs->cells[0] = (c8typ_t)cell0;
    rs->head = CONVERT_D8EXPN2(GET_DEC8_EXPN(rs) + 1, IS_DEC8_NEG(rs));
}

/*
 * Truncate the tail of a decimal so that its precision is no more than prec
 * It must be that prec > 0
 */
status_t cm_dec8_finalise(dec8_t *dec, uint32 prec, bool32 allow_overflow)
{
    uint32 dpos;  // position of truncating in decimal
    uint32 cpos;  // the position of truncating in decimal->cells
    uint32 npos;  // the position of truncating in decimal->cells[x]
    uint32 carry;
    int32 i;
    int32 sci_exp = DEC8_GET_SEXP(dec);
    // underflow check
    if (sci_exp < DEC8_EXPN_LOW) {
        cm_zero_dec8(dec);
        return CT_SUCCESS;
    }
    if (!allow_overflow) {
        DEC8_OVERFLOW_CHECK_BY_SCIEXP(sci_exp);
    }

    CT_RETSUC_IFTRUE(GET_CELLS8_SIZE(dec) <= (prec / DEC8_CELL_DIGIT));

    CT_RETVALUE_IFTRUE(((uint32)cm_dec8_calc_prec(dec) <= prec), CT_SUCCESS);

    dpos = (uint32)DEC8_POS_N_BY_PREC0(prec, cm_count_u32digits(dec->cells[0]));
    cpos = dpos / (uint32)DEC8_CELL_DIGIT;
    npos = dpos % (uint32)DEC8_CELL_DIGIT;
    carry = g_5ten_powers[DEC8_CELL_DIGIT - npos];

    dec->len = cpos + 2; // ncells is cpos + 1
    for (i = (int32)cpos; i >= 0; --i) {
        dec->cells[i] += carry;
        carry = (dec->cells[i] >= DEC8_CELL_MASK);
        if (carry == 0) {
            break;
        }
        dec->cells[i] -= DEC8_CELL_MASK;
    }

    // truncate tailing digits to zeros
    dec->cells[cpos] /= g_1ten_powers[DEC8_CELL_DIGIT - npos];
    dec->cells[cpos] *= g_1ten_powers[DEC8_CELL_DIGIT - npos];

    if (carry > 0) {
        if (!allow_overflow) {
            DEC8_OVERFLOW_CHECK_BY_SCIEXP(sci_exp + DEC8_CELL_DIGIT);
        } else {
            DEC8_HEAD_OVERFLOW_CHECK(sci_exp + DEC8_CELL_DIGIT);
        }
        cm_dec8_rebuild(dec, 1);
    }

    cm_dec8_trim_zeros(dec);
    return CT_SUCCESS;
}

/**
* Product a cell array with the digit at pos (starting from left) is k
*/
static inline bool32 cm_dec8_make_round(const dec8_t* dec, uint32 pos, dec8_t* dx)
{
    int32 i;
    uint32 carry, j;

    cm_dec8_copy(dx, dec);
    if (pos >= DEC8_MAX_ALLOWED_PREC) {
        return CT_FALSE;
    }

    i = (int32)(pos / DEC8_CELL_DIGIT);
    j = pos % DEC8_CELL_DIGIT;
    
    carry = (uint32)g_5ten_powers[DEC8_CELL_DIGIT - j];
    for (; i >= 0; i--) {
        dx->cells[i] += carry;
        carry = (dx->cells[i] >= DEC8_CELL_MASK);
        if (!carry) {
            return CT_FALSE;
        }
        dx->cells[i] -= DEC8_CELL_MASK;
    }

    if (carry > 0) {
        cm_dec8_rebuild(dx, 1);
    }

    return carry;
}

// whether abs(dec) is equal to 1
static inline bool32 cm_dec8_is_absolute_one(const dec8_t *dec)
{
    return (bool32)(dec->len == 2 && dec->cells[0] == 1 &&
                    (dec->head == CONVERT_D8EXPN(0, CT_FALSE) || dec->head == CONVERT_D8EXPN(0, CT_TRUE)));
}

//  whether dec is equal to 1
static inline bool32 cm_dec8_is_one(const dec8_t *d8)
{
    return (bool32)(d8->len == 2 && d8->cells[0] == 1 && d8->head == CONVERT_D8EXPN(0, CT_FALSE));
}

// check whether abs(x) is greater than 1
static inline bool32 dec8_is_greater_than_one(const dec8_t *x)
{
    if (IS_DEC8_NEG(x)) {
        return cm_dec8_cmp(x, &DEC8_NEG_ONE) < 0;
    } else {
        return cm_dec8_cmp(x, &DEC8_ONE) > 0;
    }

    return CT_FALSE;
}

static inline void cm_add_aligned_dec8(const dec8_t *d1, const dec8_t *d2, dec8_t *rs)
{
    uint32 i;
    c8typ_t carry = 0;

    if (d1->len > d2->len) {
        SWAP(const dec8_t *, d1, d2);
    }

    i = GET_CELLS8_SIZE(d2);
    while (i > GET_CELLS8_SIZE(d1)) {
        i--;
        rs->cells[i] = d2->cells[i];
    }
    rs->head = d2->head;
    rs->len = d2->len;
    while (i-- > 0) {
        rs->cells[i] = d1->cells[i] + d2->cells[i] + carry;
        carry = (rs->cells[i] >= DEC8_CELL_MASK);  // carry can be either 1 or 0 in addition
        if (carry) {
            rs->cells[i] -= DEC8_CELL_MASK;
        }
    }

    if (carry) {
        cm_dec8_rebuild(rs, 1);
    }

    cm_dec8_trim_zeros(rs);
}

/** Subtraction of two cell array. large must greater than small.  */
static inline void cm_sub_aligned_dec8(
    const dec8_t *large, const dec8_t *small, bool32 flip_sign, dec8_t *rs)
{
    /* if small has more cells than large, a borrow must be happened */
    int32 borrow = (small->len > large->len) ? 1 : 0;
    uint32 i;

    if ((bool32)borrow) {
        i = GET_CELLS8_SIZE(small) - 1;
        rs->cells[i] = DEC8_CELL_MASK - small->cells[i];
        while (i > GET_CELLS8_SIZE(large)) {
            i--;
            rs->cells[i] = (DEC8_CELL_MASK - 1) - small->cells[i];
        }
        rs->len = small->len;
    } else {
        i = GET_CELLS8_SIZE(large);
        while (i > GET_CELLS8_SIZE(small)) {
            i--;
            rs->cells[i] = large->cells[i];
        }
        rs->len = large->len;
    }

    while (i-- > 0) {
        int32 tmp = (int32)(large->cells[i] - (small->cells[i] + borrow));
        borrow = (tmp < 0);  // borrow can be either 1 or 0
        if (borrow) {
            tmp += (int32)DEC8_CELL_MASK;
        }
        rs->cells[i] = (c8typ_t)tmp;
    }

    rs->head = flip_sign ? CONVERT_D8EXPN2(GET_DEC8_EXPN(large), !IS_DEC8_NEG(large)) : large->head;
    if (rs->cells[0] == 0) {
        for (i = 1; i < GET_CELLS8_SIZE(rs); i++) {
            if (rs->cells[i] > 0) {
                break;
            }
        }
        cm_dec8_left_shift(rs, i, rs);
    }

    cm_dec8_trim_zeros(rs);
}

/**
* Quickly find the precision of a cells
* @note  (1) The cell u0 should be specially treated;
*        (2) The tailing zeros will not be counted. If all cell except u0 are
*        zeros, then the precision of u0 is re-counted by ignoring tailing zeros
*        e.g. | u0 = 1000 | u1 = 0 | u2 = 0 |..., the precision 1 will be
*        returned.

*/
static int32 cm_dec8_calc_prec(const dec8_t *dec)
{
    int32 i, j;
    uint32 u;
    int32 prec = 0;

    if (dec->len == 1) {
        return 0;
    }

    /* Step 1: Find the precision of remaining cells starting from backend */
    for (i = GET_CELLS8_SIZE(dec) - 1; i > 0; --i) {
        if (dec->cells[i] > 0) {  // found the last non-zero cell (dec->cells[i]>0)
            // count digits in this cell by ignoring tailing zeros
            j = 0;
            u = dec->cells[i];
            while (u % 10 == 0) {
                ++j;
                u /= 10;
            }
            prec += (i * DEC8_CELL_DIGIT - j);
            break;
        }
    }

    /* Step 1: Count the precision of u0 */
    if (i == 0) {  // if u1, u2, ... are zeros, then the precision of u0 should remove tailing zeros
        u = dec->cells[0];
        while (u % 10 == 0) {  // remove tailing zeros
            u /= 10;
        }
        prec = (int32)cm_count_u32digits((c8typ_t)u);
    } else {
        prec += (int32)cm_count_u32digits(dec->cells[0]);
    }

    return prec;
}

/**
* Convert the significant digits of cells into text with a maximal len
* @note  The tailing zeros are removed when outputting

*/
static void cm_cell8s_to_text(const cell8_t cells, uint32 ncell, text_t *text, int32 max_len)
{
    uint32 i;
    int iret_snprintf;

    iret_snprintf = snprintf_s(text->str, DEC8_CELL_DIGIT + 1, DEC8_CELL_DIGIT, "%u", cells[0]);
    PRTS_RETVOID_IFERR(iret_snprintf);
    text->len = (uint32)iret_snprintf;
    for (i = 1; (text->len < (uint32)max_len) && (i < ncell); ++i) {
        iret_snprintf = snprintf_s(CM_GET_TAIL(text), DEC8_CELL_DIGIT + 1,
                                   DEC8_CELL_DIGIT, DEC8_CELL_FMT, (uint32)cells[i]);
        PRTS_RETVOID_IFERR(iret_snprintf);
        text->len += (uint32)iret_snprintf;
    }

    // truncate redundant digits
    if (text->len > (uint32)max_len) {
        text->len = (uint32)max_len;
    }

    // truncate tailing zeros
    for (i = (uint32)text->len - 1; i > 0; --i) {
        if (!CM_IS_ZERO(text->str[i])) {
            break;
        }
        --text->len;
    }
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
static int32 cm_dec8_round_to_text(const dec8_t *dec, int32 max_len, text_t *text_out)
{
    dec8_t txtdec;
    uint32 prec_u0;
    int32 prec;

    prec = cm_dec8_calc_prec(dec);
    if (prec <= max_len) {  // total prec under the max_len
        cm_cell8s_to_text(dec->cells, GET_CELLS8_SIZE(dec), text_out, prec);
        return 0;
    }

    /** if prec > max_len, the rounding mode is applied */
    prec_u0 = cm_count_u32digits(dec->cells[0]);
    // Rounding model begins by adding with {5[(prec - max_len) zeros]}
    // Obtain the pos of 5 for rounding, then prec is used to represent position
    prec = DEC8_POS_N_BY_PREC0(max_len, prec_u0);
    // add for rounding and check whether the carry happens, and capture the changes of the precision
    if (cm_dec8_make_round(dec, (uint32)prec, &txtdec)) {
        // if carry happens, the change must exist
        cm_cell8s_to_text(txtdec.cells, GET_CELLS8_SIZE(dec) + 1, text_out, max_len);
        return 1;
    } else {
        cm_cell8s_to_text(txtdec.cells, GET_CELLS8_SIZE(dec), text_out, max_len);
        return (cm_count_u32digits(txtdec.cells[0]) > prec_u0) ? 1 : 0;
    }
}


/*
* Convert a cell text into a cell of big integer by specifying the
* length digits in u0 (i.e., len_u0), and return the number of non-zero cells
* Performance sensitivity.CM_ASSERT should be guaranteed by caller, i.g. cells[0] > 0
*/
static inline int32 cm_digitext_to_cell8s(digitext_t *dtext, cell8_t cells, int32 len_u0)
{
    uint32 i, k;
    text_t cell_text;

    // make u0
    cell_text.str = dtext->str;
    cell_text.len = (uint32)len_u0;
    cells[0] = (c8typ_t)cm_celltext2uint32(&cell_text);

    // make u1, u2, ..., uk
    k = 1;
    for (i = (uint32)len_u0; k < DEC8_CELL_SIZE && i < dtext->len; k++) {
        cell_text.str = dtext->str + i;
        cell_text.len = (uint32)DEC8_CELL_DIGIT;
        cells[k] = (c8typ_t)cm_celltext2uint32(&cell_text);
        i += DEC8_CELL_DIGIT;
    }

    // the tailing cells of significant cells may be zeros, for returning
    // accurate ncells, they should be ignored.
    while (cells[k - 1] == 0) {
        --k;
    }

    return (int32)k;
}

/**
* Convert a digit text with a scientific exponent into a decimal
* The digit text may be changed when adjust the scale of decimal to be
* an integral multiple of DEC_CELL_DIGIT, by appending zeros.
* @return the precision of u0

* @note
* Performance sensitivity.CM_ASSERT should be guaranteed by caller,
* i.g. dtext->len > 0 && dtext->len <= (uint32)DEC_MAX_ALLOWED_PREC
*/
static inline int32 cm_digitext_to_dec8(dec8_t *dec, digitext_t *dtext, int32 sci, bool32 is_neg)
{
    int32 delta;
    int32 len_u0;  // the length of u0
    int32 sci_exp = sci;

    len_u0 = (int32)dtext->len % DEC8_CELL_DIGIT;

    ++sci_exp;  // increase the sci_exp to obtain the position of dot

    delta = sci_exp - len_u0;
    delta += (int32)DEC8_CELL_DIGIT << 16;  // make delta to be positive
    delta %= DEC8_CELL_DIGIT;               // get the number of appending zeros
    len_u0 = (len_u0 + delta) % DEC8_CELL_DIGIT;

    if (len_u0 == 0) {
        len_u0 = DEC8_CELL_DIGIT;
    }

    while (delta-- > 0) {
        CM_TEXT_APPEND(dtext, '0');
    }

    CM_NULL_TERM(dtext);

    dec->len = (uint8)cm_digitext_to_cell8s(dtext, dec->cells, len_u0) + 1;
    dec->head = CONVERT_D8EXPN(sci_exp - len_u0, is_neg);
    return len_u0;
}

#define DEC_EXPN_BUFF_SZ 16
/**
* Output a decimal type in scientific format, e.g., 2.34566E-20

*/
static inline status_t cm_dec8_to_sci_text(text_t *text, const dec8_t *dec, int32 max_len)
{
    int32 i;
    char obuff[CT_NUMBER_BUFFER_SIZE]; /** output buff */
    text_t cell_text = { .str = obuff, .len = 0 };
    char sci_buff[DEC_EXPN_BUFF_SZ];
    int32 sci_exp; /** The scientific scale of the dec */
    int32 placer;
    int iret_snprintf;

    sci_exp = DEC8_GET_SEXP(dec);
    // digits of sci_exp + sign(dec) + dot + E + sign(expn)
    placer = (int32)IS_DEC8_NEG(dec) + 3;
    placer += (int32)cm_count_u32digits((c8typ_t)abs(sci_exp));
    if (max_len <= placer) {
        CT_THROW_ERROR(ERR_SIZE_ERROR, placer, max_len, "char");
        return CT_ERROR;
    }

    /* The round of a decimal may increase the precision by 1 */
    if (cm_dec8_round_to_text(dec, max_len - placer, &cell_text) > 0) {
        ++sci_exp;
    }
    // compute the exponent placer
    iret_snprintf = snprintf_s(sci_buff, DEC_EXPN_BUFF_SZ, DEC_EXPN_BUFF_SZ - 1, "E%+d", sci_exp);
    PRTS_RETURN_IFERR(iret_snprintf);
    placer = iret_snprintf;

    // Step 1. output sign
    text->len = 0;
    if (IS_DEC8_NEG(dec)) {
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
    return CT_SUCCESS;
}

/**
* @note
* Performance sensitivity.CM_ASSERT should be guaranteed by caller, i.g. dot_pos <= max_len - dec->sign
*/
static inline status_t cm_dec8_to_plain_text(text_t *text, const dec8_t *dec, int32 max_len, int32 sci_exp,
                                             int32 prec)
{
    int32 dot_pos;
    char obuff[CT_NUMBER_BUFFER_SIZE]; /** output buff */
    text_t cell_text;
    cell_text.str = obuff;
    cell_text.len = 0;

    // clear text & output sign
    text->len = 0;
    if (IS_DEC8_NEG(dec)) {
        CM_TEXT_APPEND(text, '-');
    }

    dot_pos = sci_exp + 1;

    if (prec <= dot_pos) {
        (void)cm_dec8_round_to_text(dec, max_len - text->len, &cell_text);  // subtract sign
        cm_concat_text(text, max_len, &cell_text);
        cm_text_appendc(text, dot_pos - prec, '0');
        return CT_SUCCESS;
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
        if (cm_dec8_round_to_text(dec, dot_pos, &cell_text) > 0) {
            CM_TEXT_CLEAR(text);
            return cm_dec8_to_sci_text(text, dec, max_len);
        }
        cm_concat_text(text, max_len, &cell_text);
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
        int32 change = cm_dec8_round_to_text(dec, dot_pos, &cell_text);
        cm_concat_text(text, max_len, &cell_text);
        cm_text_appendc(text, max_len + change - ((int32)text->len + 1), '0');
    } else if (dot_pos >= 0) { /* dot is inside of cell_text and may be output */
        // round mode may product carry, and thus may affect the dot_pos
        dot_pos += cm_dec8_round_to_text(dec, max_len - text->len - 1, &cell_text);  // subtract sign & dot
        if ((int32)cell_text.len <= dot_pos) {
            cm_concat_text(text, max_len, &cell_text);
            cm_text_appendc(text, dot_pos - (int32)cell_text.len, '0');
        } else {
            CT_RETURN_IFERR(cm_concat_ntext(text, &cell_text, dot_pos));
            CM_TEXT_APPEND(text, '.');
            // copy remaining digits
            cell_text.str += (uint32)dot_pos;
            cell_text.len -= (uint32)dot_pos;
            cm_concat_text(text, max_len, &cell_text);
        }
    } else {  // dot_pos is less than 0
        /* dot is in the most left & add |dot_pos| zeros between dot and cell_text
        * Thus, the maxi_len should consider sign, dot, and the adding zeros */
        dot_pos += cm_dec8_round_to_text(dec, max_len - text->len - 1 + dot_pos, &cell_text);
        CM_TEXT_APPEND(text, '.');
        cm_text_appendc(text, -dot_pos, '0');
        CT_RETURN_IFERR(cm_concat_ntext(text, &cell_text, max_len - (int32)text->len));
    }

    return CT_SUCCESS;
}

/**
* Convert a decimal into a text with a given maximal precision

* @note
* Performance sensitivity.CM_ASSERT should be guaranteed by caller,
* cm_dec8_to_text is not guaranteed end of \0, if need string, should use cm_dec8_to_str
*/
status_t cm_dec8_to_text(const dec8_t *dec, int32 max_length, text_t *text)
{
    int32 sci_exp; /** The scientific scale of the dec */
    int32 prec;
    int32 max_len = max_length;

    CM_POINTER2(dec, text);
    max_len = MIN(max_length, (int32)(CT_NUMBER_BUFFER_SIZE - 1));

    if (dec->len == 1) {
        text->str[0] = '0';
        text->len = 1;
        return CT_SUCCESS;
    }

    // Compute the final scientific scale of the dec, i.e., format of d.xxxx , d > 0.
    // Each decimal has an unique scientific representation.
    sci_exp = DEC8_GET_SEXP(dec);
    // get the total precision of the decimal
    prec = cm_dec8_calc_prec(dec);
    // Scientific representation when the scale exceeds the maximal precision
    // or have many leading zeros and have many significant digits
    // When sci_exp < 0, the length for '.' should be considered
    if ((sci_exp < -6 && -sci_exp + prec + (int32)IS_DEC8_NEG(dec) > max_len) ||
        (sci_exp > 0 && sci_exp + 1 + (int32)IS_DEC8_NEG(dec) > max_len)) {
        return cm_dec8_to_sci_text(text, dec, max_len);
    }

    // output plain text
    return cm_dec8_to_plain_text(text, dec, max_len, sci_exp, prec);
}

/**
* Convert a decimal into C-string, and return the ac

* max_len should be consided \0, max len should buffer size
*/
status_t cm_dec8_to_str(const dec8_t *dec, int max_len, char *str)
{
    text_t text;
    text.str = str;
    text.len = 0;

    CT_RETURN_IFERR(cm_dec8_to_text(dec, max_len - 1, &text));
    str[text.len] = '\0';
    return CT_SUCCESS;
}

status_t cm_str_to_dec8(const char *str, dec8_t *dec)
{
    text_t text;
    cm_str2text((char *)str, &text);
    return cm_text_to_dec8(&text, dec);
}

static inline void cm_do_numpart_round8(const num_part_t *np, dec8_t *dec, uint32 prec0)
{
    c8typ_t   carry = g_1ten_powers[prec0 % DEC8_CELL_DIGIT];
    uint32   i = GET_CELLS8_SIZE(dec);
    
    while (i-- > 0) {
        dec->cells[i] += carry;
        carry = (dec->cells[i] >= DEC8_CELL_MASK);
        if (carry == 0) {
            return;
        }
        dec->cells[i] -= DEC8_CELL_MASK;
    }

    if (carry > 0) {
        cm_dec8_rebuild(dec, 1);
    }
}

num_errno_t cm_numpart_to_dec8(num_part_t *np, dec8_t *dec)
{
    if (NUMPART_IS_ZERO(np)) {
        cm_zero_dec8(dec);
        return NERR_SUCCESS;
    }

    // Step 3.2. check overflow by comparing scientific scale and DEC8_EXPN_UPPER
    if (np->sci_expn > DEC8_EXPN_UPPER) {  // overflow return Error
        return NERR_OVERFLOW;
    } else if (np->sci_expn < DEC8_EXPN_LOW) {  // underflow return 0
        cm_zero_dec8(dec);
        return NERR_SUCCESS;
    }

    // Step 4: make the final decimal value
    int32 prec0 = cm_digitext_to_dec8(dec, &np->digit_text, np->sci_expn, np->is_neg);

    if (np->do_round) {  // when round happens, the dec->cells should increase 1
        cm_do_numpart_round8(np, dec, (uint32)prec0);
        if (DEC8_GET_SEXP(dec) > DEC8_EXPN_UPPER) {  // overflow return Error
            return NERR_OVERFLOW;
        }
        cm_dec8_trim_zeros(dec);  // rounding may change the precision
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
status_t cm_text_to_dec8(const text_t *dec_text, dec8_t *dec)
{
    num_errno_t err_no;
    num_part_t np;
    np.excl_flag = NF_NONE;

    err_no = cm_split_num_text(dec_text, &np);
    if (err_no != NERR_SUCCESS) {
        CT_THROW_ERROR(ERR_INVALID_NUMBER, cm_get_num_errinfo(err_no));
        return CT_ERROR;
    }

    err_no = cm_numpart_to_dec8(&np, dec);
    if (err_no != NERR_SUCCESS) {
        CT_THROW_ERROR(ERR_INVALID_NUMBER, cm_get_num_errinfo(err_no));
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cm_hext_to_dec8(const text_t *hex_text, dec8_t *dec)
{
    uint32 i;
    uint8 u8;

    static const dec8_t DEC8_16 = {
        .len = (uint8)2,
        .head = CONVERT_D8EXPN(0, CT_FALSE),
        .cells = { 16 }
    };

    if (CM_IS_EMPTY(hex_text)) {
        CT_THROW_ERROR(ERR_INVALID_NUMBER, cm_get_num_errinfo(NERR_NO_DIGIT));
        return CT_ERROR;
    }

    cm_zero_dec8(dec);

    for (i = 0; i < hex_text->len; i++) {
        u8 = cm_hex2int8((uchar)hex_text->str[i]);
        if (u8 == (uint8)0xFF) {
            CT_THROW_ERROR(ERR_INVALID_NUMBER, cm_get_num_errinfo(NERR_UNEXPECTED_CHAR));
            return CT_ERROR;
        }
        CT_RETURN_IFERR(cm_dec8_multiply(dec, &DEC8_16, dec));
        CT_RETURN_IFERR(cm_dec8_add_int32(dec, u8, dec));
    }

    return CT_SUCCESS;
}

/**
* Fill a non-zero uint32 into decimal
* @note u64 > 0
*/
static inline void cm_fill_uint32_into_dec8(uint32 u32, dec8_t *dec)
{
    if (u32 < DEC8_CELL_MASK) {
        dec->head = CONVERT_D8EXPN(0, IS_DEC8_NEG(dec));
        dec->len = 2;
        dec->cells[0] = (c8typ_t)u32;
        return;
    } else {
        dec->head = CONVERT_D8EXPN(DEC8_CELL_DIGIT, IS_DEC8_NEG(dec));
        dec->cells[0] = (c8typ_t)(u32 / DEC8_CELL_MASK);
        dec->cells[1] = (c8typ_t)(u32 % DEC8_CELL_MASK);
        dec->len = (dec->cells[1] > 0) ? 3 : 2;
    }
}

/**
* Convert an integer32 into a decimal

*/
void cm_int32_to_dec8(int32 i_32, dec8_t *dec)
{
    int32 i32 = i_32;
    if (i32 > 0) {
        dec->sign = DEC8_SIGN_PLUS;
    } else if (i32 < 0) {
        if (i32 == CT_MIN_INT32) {
            cm_dec8_copy(dec, &DEC8_MIN_INT32);
            return;
        }
        dec->sign = DEC8_SIGN_MINUS;
        i32 = -i32;
    } else {
        cm_zero_dec8(dec);
        return;
    }

    cm_fill_uint32_into_dec8((uint32)i32, dec);
}

void cm_uint32_to_dec8(uint32 i32, dec8_t *dec)
{
    if (i32 == 0) {
        cm_zero_dec8(dec);
        return;
    }
    
    dec->sign = DEC8_SIGN_PLUS;
    cm_fill_uint32_into_dec8(i32, dec);
}


/** The buffer size to covert an int64 to dec->cells. It must be greater
** max_digits(int64) + DEC_CELL_DIGIT + 1  than */
#define INT64_BUFF 32

/*
 * Fill a non-zero uint64(u64 > 0) into decimal
 */
static inline void cm_fill_uint64_into_dec8(uint64 u_64, dec8_t *dec)
{
    uint64 u64 = u_64;
    if (u64 < DEC8_POW2_MASK) {
        if (u64 < DEC8_CELL_MASK) {
            dec->head = CONVERT_D8EXPN(0, IS_DEC8_NEG(dec));
            dec->len = 2;
            dec->cells[0] = (c8typ_t)u64;
        } else {
            dec->head = CONVERT_D8EXPN(DEC8_CELL_DIGIT, IS_DEC8_NEG(dec));
            dec->cells[0] = (c8typ_t)(u64 / DEC8_CELL_MASK);
            dec->cells[1] = (c8typ_t)(u64 % DEC8_CELL_MASK);
            dec->len = dec->cells[1] > 0 ? 3 : 2;
        }
        return;
    }

    dec->head = CONVERT_D8EXPN(DEC8_CELL_DIGIT * 2, IS_DEC8_NEG(dec));
    dec->cells[0] = (c8typ_t)(u64 / DEC8_POW2_MASK);
    u64 %= DEC8_POW2_MASK;
    dec->cells[1] = (c8typ_t)(u64 / DEC8_CELL_MASK);
    dec->cells[2] = (c8typ_t)(u64 % DEC8_CELL_MASK);
    dec->len = (dec->cells[2] > 0) ? 4 : ((dec->cells[1] > 0) ? 3 : 2);
}

/**
* Convert an integer64 into a decimal

*/
void cm_int64_to_dec8(int64 i_64, dec8_t *dec)
{
    int64 i64 = i_64;
    if (i64 > 0) {
        dec->sign = DEC8_SIGN_PLUS;
    } else if (i64 < 0) {
        if (i64 == CT_MIN_INT64) {
            cm_dec8_copy(dec, &DEC8_MIN_INT64);
            return;
        }
        dec->sign = DEC8_SIGN_MINUS;
        i64 = -i64;
    } else {
        cm_zero_dec8(dec);
        return;
    }

    cm_fill_uint64_into_dec8((uint64)i64, dec);
}

#define cm_int64_to_dec(i64, dec) cm_int64_to_dec8((i64), (dec))

/**
* Convert an uint64 into a decimal

*/
void cm_uint64_to_dec8(uint64 u64, dec8_t *dec)
{
    if (u64 == 0) {
        cm_zero_dec8(dec);
        return;
    }
    dec->sign = DEC8_SIGN_PLUS;
    cm_fill_uint64_into_dec8(u64, dec);
}

static const double g_pos_pow8[] = {
    1.0,
    1.0e8,
    1.0e16,
    1.0e24,
    1.0e32,
    1.0e40,
    1.0e48,
    1.0e56,
    1.0e64,
    1.0e72,
    1.0e80,
    1.0e88,
    1.0e96,
    1.0e104,
    1.0e112,
    1.0e120,
    1.0e128,
    1.0e136,
    1.0e144,
    1.0e152,
    1.0e160,
};

/**
 * compute 100000000^x, x should be between -21 and 21
 */
static inline double cm_pow8(int32 x, double real)
{
    int32 y = abs(x);
    double r = (y < 21) ? g_pos_pow8[y] : pow(10e8, y);
    if (x < 0) {
        r = real / r;
    } else {
        r = real * r;
    }
    return r;
}

static status_t cm_real_to_dec8_inexac(double real, dec8_t *dec);

/**
* Convert real value into a decimal type
*/
status_t cm_real_to_dec8(double real, dec8_t *dec)
{
    CT_RETURN_IFERR(cm_real_to_dec8_inexac(real, dec));
    // reserving at most CT_MAX_REAL_PREC precisions
    return cm_dec8_finalise(dec, CT_MAX_REAL_PREC, CT_FALSE);
}

/**
 * Convert real value into a decimal type 10 precisions
 */
status_t cm_real_to_dec8_prec16(double real, dec8_t *dec)
{
    CT_RETURN_IFERR(cm_real_to_dec8_inexac(real, dec));
    return cm_dec8_finalise(dec, CT_MAX_INDEX_REAL_PREC, CT_FALSE);
}

status_t cm_real_to_dec8_prec17(double real, dec8_t *dec)
{
    CT_RETURN_IFERR(cm_real_to_dec8_inexac(real, dec));
    return cm_dec8_finalise(dec, CT_MAX_CM_DOUBLE_PREC, CT_FALSE);
}

/**
 * Convert real value into a decimal. It is similar with the function cm_real_to_dec8.
 * This function may be more efficient than cm_real_to_dec8, but may lose precision.
 * It is suitable for an algorithm which needs an inexact initial value.
 */
static status_t cm_real_to_dec8_inexac(double real, dec8_t *dec)
{
    double r = real;
    if (!CM_DBL_IS_FINITE(r)) {
        CT_THROW_ERROR(ERR_INVALID_NUMBER, "");
        return CT_ERROR;
    }

    if (r == 0.0) {
        cm_zero_dec8(dec);
        return CT_SUCCESS;
    }

    double int_r;
    int32 dexp;
    uint8 index = 0;
    bool32 is_neg = (r < 0);
    if (is_neg) {
        r = -r;
    }

    // compute an approximate scientific exponent
    (void)frexp(r, &dexp);
    dexp = (int32)((double)dexp * (double)CT_LOG10_2);
    dexp &= 0xFFFFFFF8;
    // dexp can less than DEC8_EXPN_LOW, because cell[0] may have more than one number, DEC8_GET_SEXP is in the range.
    DEC8_OVERFLOW_CHECK_BY_SCIEXP(dexp);
    // Set a decimal
    dec->head = CONVERT_D8EXPN(dexp, is_neg);

    r = cm_pow8(-SEXP_2_D8EXP(dexp), r);
    // now, int_r is used as the integer part of r
    if (r >= 1.0) {
        r = modf(r, &int_r);
        dec->cells[index] = (c8typ_t)((int32)int_r);
        index++;
    } else {
        dec->head = CONVERT_D8EXPN(dexp - DEC8_EXPN_UNIT, is_neg);
    }

    while (index < DEC8_TO_REAL_MAX_CELLS) {
        if (r == 0) {
            break;
        }
        r = modf(r * (double)DEC8_CELL_MASK, &int_r);
        dec->cells[index++] = (c8typ_t)((int32)int_r);
    }
    dec->len = index + 1;
    cm_dec8_trim_zeros(dec);
    return CT_SUCCESS;
}

/**
 * NOTE THAT: convert a signed integer into DOUBLE is faster than unsigned integer,
 * therefore, These codes use signed integer for conversation to DOUBLE as much as
 * possible. The following SWITCH..CASE is faster than the loop implementation.
 */
double cm_dec8_to_real(const dec8_t *dec)
{
    if (DECIMAL8_IS_ZERO(dec)) {
        return 0.0;
    }

    double dval;
    int32 i = MIN(GET_CELLS8_SIZE(dec), DEC8_TO_REAL_MAX_CELLS);
    uint64 u64;

    if (i == DEC8_TO_REAL_MAX_CELLS) {
        u64 = (uint64)dec->cells[1] * DEC8_CELL_MASK + (uint64)dec->cells[2];
        dval = (double)(int64)dec->cells[0] * (double)DEC8_POW2_MASK;
        dval += (double)(int64)u64;
    } else if (i == DEC8_TO_REAL_MAX_CELLS - 1) {
        u64 = (uint64)dec->cells[0] * DEC8_CELL_MASK + (uint64)dec->cells[1];
        dval = (double)((int64)u64);
    } else {
        dval = (int32)dec->cells[0];
    }

    int32 dexpn = (int32)GET_DEC8_EXPN(dec) - i + 1;
    /* the maximal expn of a decimal can not exceed 21 */
    if (dexpn >= 0) {
        dval *= g_pos_pow8[dexpn];
    } else {
        dval /= g_pos_pow8[-dexpn];
    }

    return IS_DEC8_NEG(dec) ? -dval : dval;
}


/**
* The core algorithm for adding of two decimals, without truncating
* the result.
* @see cm_decimal_add for adding of two decimals with truncation
*/
void cm_dec8_add_op(const dec8_t *d1, const dec8_t *d2, dec8_t *rs)
{
    int32 offset;
    dec8_t calc_dec;
    bool32 is_same_sign;

    // Ensure the scales of two adding decimal to be even multiple of DEC_CELL_DIGIT
    if (DECIMAL8_IS_ZERO(d2)) {
        goto DEC8_ADD_ZERO;
    }

    if (DECIMAL8_IS_ZERO(d1)) {
        d1 = d2;
        goto DEC8_ADD_ZERO;
    }

    // Obtain the exponent offset of two decimals
    offset = (int32)GET_DEC8_EXPN(d1) - (int32)GET_DEC8_EXPN(d2);  // exponent offset
    is_same_sign = (d1->sign == d2->sign);

    if (offset != 0) {
        if (offset < 0) {
            /* offset < 0 means d1 < d2, then swap d1 and d2 to grant d1 > d2 */
            offset = -offset;
            SWAP(const dec8_t*, d1, d2);
        }

        if (offset >= DEC8_MAX_EXP_OFFSET) {
            goto DEC8_ADD_ZERO;
        }

        cm_dec8_right_shift(d2, offset, &calc_dec);
        d2 = &calc_dec;
    } else if (!is_same_sign) { // if offset == 0, and d1, d2 have different signs
        int32 cmp = cm_dec8_cmp_data(d1, d2);
        if (cmp < 0) {
            SWAP(const dec8_t*, d1, d2);
        } else if (cmp == 0) {
            cm_zero_dec8(rs);
            return;
        }
    }

    if (is_same_sign) {
        cm_add_aligned_dec8(d1, d2, rs);
    } else {
        cm_sub_aligned_dec8(d1, d2, CT_FALSE, rs);
    }
    return;

DEC8_ADD_ZERO:
    cm_dec8_copy(rs, d1);
    return;
}


/**
* The core algorithm for subtracting of two decimals, without truncating
* the result.
* @see cm_decimal_sub for subtraction of two decimals with truncation
*/
void cm_dec8_sub_op(const dec8_t *d1, const dec8_t *d2, dec8_t *rs)
{
    dec8_t calc_dec;
    int32 offset;
    bool32 do_swap = CT_FALSE;
    bool32 is_same_sign;

    if (DECIMAL8_IS_ZERO(d2)) {
        goto DEC8_SUB_ZERO;
    }

    if (DECIMAL8_IS_ZERO(d1)) {
        do_swap = CT_TRUE;
        d1 = d2;
        goto DEC8_SUB_ZERO;
    }

    // Obtain the exponent offset of two decimals
    offset = (int32)GET_DEC8_EXPN(d1) - (int32)GET_DEC8_EXPN(d2);  // exponent offset
    is_same_sign = (d1->sign == d2->sign);

    if (offset != 0) {
        if (offset < 0) {
            offset = -offset;
            SWAP(const dec8_t*, d1, d2);
            do_swap = CT_TRUE;
        }

        if (offset >= DEC8_MAX_EXP_OFFSET) {
            goto DEC8_SUB_ZERO;
        }

        cm_dec8_right_shift(d2, offset, &calc_dec);
        d2 = &calc_dec;
    } else if (is_same_sign) {
        int32 cmp = cm_dec8_cmp_data(d1, d2);
        if (cmp < 0) {
            SWAP(const dec8_t*, d1, d2);
            do_swap = CT_TRUE;
        } else if (cmp == 0) {
            cm_zero_dec8(rs);
            return;
        }
    }

    if (is_same_sign) {
        cm_sub_aligned_dec8(d1, d2, do_swap, rs);
    } else {
        /* if d1 and d2 have different signs, the result sign is the same with
         * the first operand. */
        uint8 sign = do_swap ? d2->sign : d1->sign;
        cm_add_aligned_dec8(d1, d2, rs);
        rs->head = CONVERT_D8EXPN2(GET_DEC8_EXPN(rs), !sign);
    }
    return;

DEC8_SUB_ZERO:
    cm_dec8_copy(rs, d1);
    if (do_swap && !DECIMAL8_IS_ZERO(rs)) {
        cm_dec8_negate(rs);
    }
    return;
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
void cm_dec8_mul_op(const dec8_t *d1, const dec8_t *d2, dec8_t *rs)
{
    if (DECIMAL8_IS_ZERO(d1) || DECIMAL8_IS_ZERO(d2)) {
        cm_zero_dec8(rs);
        return;
    }

    int32 i, j, n;
    cc8typ_t carry = 0;
    int32 ncells = GET_CELLS8_SIZE(d1) + GET_CELLS8_SIZE(d2) - 1;
    // n1 + n2 -1 > DEC2_CELL_SIZE, precision needs to be lost
    if (ncells > DEC8_CELL_SIZE) {
        for (i = ncells - 1; i >= DEC8_CELL_SIZE; i--) {
            j = GET_CELLS8_SIZE(d2) - 1;
            while (j >= 0 && (i - j) >= 0 && (i - j) < GET_CELLS8_SIZE(d1)) {
                carry += (cc8typ_t)d1->cells[i - j] * (cc8typ_t)d2->cells[j];
                j--;
            }
            carry /= (cc8typ_t)DEC8_CELL_MASK;
        }
    }

    /* Step 2: the main body of the multiplication */
    i = MIN(ncells, DEC8_CELL_SIZE);
    n = i;
    while (i > 0) {
        j = MIN(i, GET_CELLS8_SIZE(d2)) - 1;  // j < i and j < d2.ncells
        i--;
        while (j >= 0 && (i - j) < GET_CELLS8_SIZE(d1)) {
            carry += (cc8typ_t)d1->cells[i - j] * (cc8typ_t)d2->cells[j];
            j--;
        }
        rs->cells[i] = carry % (cc8typ_t)DEC8_CELL_MASK;
        carry /= DEC8_CELL_MASK;
    }

    rs->len = (uint8)n + 1;
    rs->head = CONVERT_D8EXPN2(GET_DEC8_EXPN(d1) + GET_DEC8_EXPN(d2), d1->sign ^ d2->sign);

    /* Step 3: handle carry */
    if (carry > 0) {
        cm_dec8_rebuild(rs, (uint32)carry);
    }

    cm_dec8_trim_zeros(rs);
    return;
}

/**
* @note
* Performance sensitivity.CM_ASSERT should be guaranteed by caller, i.g. !DECIMAL8_IS_ZERO(d)
*/
static inline status_t cm_dec8_init_inverse(const dec8_t *d, dec8_t *d_inv)
{
    return cm_real_to_dec8_inexac(1.0 / cm_dec8_to_real(d), d_inv);
}

/**
* Computed the inverse of a decimal, inv_d = 1 / d
* The Newton Inversion algorithm is used:
*  $x_{i+1} = 2x_{i} - dx^2_{i} = x_i(2-d * x_i)$

*/
static inline status_t cm_dec8_inv(const dec8_t *d, dec8_t *inv_d)
{
    uint32 i;
    dec8_t delta;

    // Step 1. compute an initial and approximate inverse by 1/double(dec)
    CT_RETURN_IFERR(cm_dec8_init_inverse(d, inv_d));
    DEC8_DEBUG_PRINT(inv_d, "inv_init_value");

    // Step 2. Newton iteration begins, At least 2 iterations are required
    for (i = 0; i <= 10; i++) {
        // set delta to x(1-d*x)
        cm_dec8_mul_op(d, inv_d, &delta);              // set delta to d * inv_d
        cm_dec8_sub_op(&DEC8_ONE, &delta, &delta);  // set delta to 1 - delta
        cm_dec8_mul_op(&delta, inv_d, &delta);         // set delta to delta * inv_d
        DEC8_DEBUG_PRINT(&delta, "inv delta: %u", i);

        cm_dec8_add_op(inv_d, &delta, inv_d);  // set inv_d(i) to inv_d(i) + delta
        DEC8_DEBUG_PRINT(inv_d, "inv(x): %u", i);

        if (cm_dec8_taylor_break(inv_d, &delta, MAX_NUM_CMP_PREC)) {
            break;
        }
    }
    return CT_SUCCESS;
}

/**
* The division of two decimals: dec1 / dec2

*/
status_t cm_dec8_divide(const dec8_t *dec1, const dec8_t *dec2, dec8_t *result)
{
    dec8_t inv_dec2;
    uint8 res_sign;

    if (DECIMAL8_IS_ZERO(dec2)) {
        CT_THROW_ERROR(ERR_ZERO_DIVIDE);
        return CT_ERROR;
    }

    if (DECIMAL8_IS_ZERO(dec1)) {
        cm_zero_dec8(result);
        return CT_SUCCESS;
    }

    if (cm_dec8_is_absolute_one(dec2)) {
        res_sign = dec1->sign ^ dec2->sign;
        cm_dec8_copy(result, dec1);
        result->head = CONVERT_D8EXPN2(GET_DEC8_EXPN(dec1), res_sign);
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(cm_dec8_inv(dec2, &inv_dec2));

    return cm_dec8_multiply(dec1, &inv_dec2, result);
}

/**
* @note
* Performance sensitivity.CM_ASSERT should be guaranteed by caller, i.g. npos<DEC_CELL_DIGIT
*/
static inline bool32 cm_dec8_has_tail(const dec8_t *dec, uint32 c_pos, uint32 npos)
{
    uint32 cpos = c_pos;
    if (npos > 0) {
        if (dec->cells[cpos] % g_1ten_powers[DEC8_CELL_DIGIT - npos] > 0) {
            return CT_TRUE;
        }
        ++cpos;
    }

    for (; cpos < GET_CELLS8_SIZE(dec); cpos++) {
        if (dec->cells[cpos] > 0) {
            return CT_TRUE;
        }
    }

    return CT_FALSE;
}

/**
 * Get a carry for rounding
 * + cpos -- the position of truncating in decimal->cells
 * + npos -- the position of truncating in decimal->cells[x]

 * @note
 * Performance sensitivity.CM_ASSERT should be guaranteed by caller, i.g. npos<DEC_CELL_DIGIT
*/
static inline uint32 cm_dec8_make_round_carry(dec8_t *dec, round_mode_t rnd_mode, uint32 cpos, uint32 npos)
{
    switch (rnd_mode) {
        case ROUND_TRUNC:
            return 0;

        case ROUND_CEILING:
            return (!IS_DEC8_NEG(dec) &&
                    cm_dec8_has_tail(dec, cpos, npos))
                   ? g_1ten_powers[DEC8_CELL_DIGIT - npos]
                   : 0;

        case ROUND_FLOOR:
            return (IS_DEC8_NEG(dec) &&
                    cm_dec8_has_tail(dec, cpos, npos))
                   ? g_1ten_powers[DEC8_CELL_DIGIT - npos]
                   : 0;

        case ROUND_HALF_UP:
            return g_5ten_powers[DEC8_CELL_DIGIT - npos];

        default:
            CM_NEVER;
            return 0;
    }
}

/* d_pos: the round position in decimal */
/**
* @note
* Performance sensitivity.CM_ASSERT should be guaranteed by caller, i.g. d_pos + DEC_CELL_DIGIT >= 0
*/
static inline bool32 cm_dec8_round_cells(dec8_t *dec, int32 precision, int32 deci_pos,
                                         div_t *d, uint32 *carry, round_mode_t rnd_mode)
{
    int32 i;
    int32 r_pos;
    int32 d_pos = deci_pos;

    // d_pos + DEC_CELL_DIGIT is the round position in cells
    r_pos = d_pos + DEC8_CELL_DIGIT;

    if (r_pos > (int32)DEC8_MAX_ALLOWED_PREC) {  // the rounded position exceeds the maximal precision
        return CT_FALSE;
    }
    // Step 1: round begin
    *d = div(r_pos, DEC8_CELL_DIGIT);

    if ((uint32)d->quot >= GET_CELLS8_SIZE(dec)) {
        return CT_TRUE;
    }

    dec->len = (uint8)(d->quot + 2); // ncells is d->quot + 1
    *carry = cm_dec8_make_round_carry(dec, rnd_mode, (uint32)d->quot, (uint32)d->rem);
    for (i = d->quot; i >= 0; --i) {
        *carry += dec->cells[i];
        if (*carry >= DEC8_CELL_MASK) {
            dec->cells[i] = *carry - DEC8_CELL_MASK;
            *carry = 1;
        } else {
            dec->cells[i] = *carry;
            *carry = 0;
            break;
        }
    }

    // Step 2. Check valid again
    if (i <= 0) {  // the rounding mode may change the precision
        d_pos += (*carry == 0) ? (int32)cm_count_u32digits(dec->cells[0]) : (DEC8_CELL_DIGIT + 1);
        if (d_pos > precision) {
            return CT_FALSE;
        }
    }

    // Step 3. handle carry, truncate tailing digits to zeros
    dec->cells[d->quot] /= (c8typ_t)g_1ten_powers[DEC8_CELL_DIGIT - d->rem];
    dec->cells[d->quot] *= (c8typ_t)g_1ten_powers[DEC8_CELL_DIGIT - d->rem];

    return CT_TRUE;
}

/**
* Round the number with fixed precision and scale, and return the number
* of 10-base digits before the scale position

*/
static inline bool32 cm_dec8_round(dec8_t *dec, int32 precision, int32 scale_input, round_mode_t rnd_mode)
{
    div_t d; /* used for round */
    uint32 carry = 0;
    int32 r_pos;
    int32 scale = scale_input;
    CT_RETVALUE_IFTRUE(DECIMAL8_IS_ZERO(dec), CT_TRUE);

    scale += GET_DEC8_SCI_EXP(dec);
    r_pos = scale + (int32)cm_count_u32digits(dec->cells[0]);  // r_pos is then the length of the scaled cells

    // Step 0: early check
    CT_RETVALUE_IFTRUE(r_pos > precision, CT_FALSE);

    if (r_pos < 0) {
        cm_zero_dec8(dec);
        return CT_TRUE;
    }

    // Step 1: scale round
    CT_RETVALUE_IFTRUE(!cm_dec8_round_cells(dec, precision, scale, &d, &carry, rnd_mode), CT_FALSE);

    // The cell[0] may be truncated to zero, e.g. 0.0043 for number(3,2)
    // Then zero is returned
    if ((d.quot == 0) && (carry == 0) && (dec->cells[0] == 0)) {
        cm_zero_dec8(dec);
        return CT_TRUE;
    }

    if (carry > 0) {
        cm_dec8_rebuild(dec, 1);
    }

    cm_dec8_trim_zeros(dec);
    return CT_TRUE;
}


/**
* Adjust a decimal into fixed precision and scale. If failed, an error
* will be returned.
* @see cm_dec8_round

*/
status_t cm_adjust_dec8(dec8_t *dec, int32 precision, int32 scale)
{
    if (precision == CT_UNSPECIFIED_NUM_PREC) {
        return CT_SUCCESS;
    }

    if (!cm_dec8_round(dec, precision, scale, ROUND_HALF_UP)) {
        CT_THROW_ERROR(ERR_VALUE_ERROR, "value larger than specified precision");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

/**
* Get the carry of a decimal with negative expn when convert decimal into integer
* @note Required: expn < 0

*/
static inline int32 dec8_make_negexpn_round_value(const dec8_t *dec, round_mode_t rnd_mode)
{
    switch (rnd_mode) {
        case ROUND_FLOOR:
            return IS_DEC8_NEG(dec) ? -1 : 0;

        case ROUND_HALF_UP: {
            // e.g., 0.5 ==> 1, 0.499 ==> 0
            int32 val = ((GET_DEC8_EXPN(dec) == -1) && (dec->cells[0] >= DEC8_HALF_MASK)) ? 1 : 0;
            return IS_DEC8_NEG(dec) ? -val : val;
        }

        case ROUND_CEILING:
            return IS_DEC8_NEG(dec) ? 0 : 1;

        case ROUND_TRUNC:
        default:
            return 0;
    }
}

/** Round a positive and non-zero decimal into uint64 */
static inline uint64 dec8_make_negexpn_round_value2(const dec8_t *dec, round_mode_t rnd_mode)
{
    switch (rnd_mode) {
        case ROUND_HALF_UP:
            // e.g., 0.5 ==> 1, 0.499 ==> 0
            return ((GET_DEC8_EXPN(dec) == -1) && (dec->cells[0] >= DEC8_HALF_MASK)) ? 1 : 0;

        case ROUND_CEILING:
            return 1;

        case ROUND_TRUNC:
        case ROUND_FLOOR:
        default:
            return 0;
    }
}

status_t cm_dec8_to_uint64(const dec8_t *dec, uint64 *u64, round_mode_t rnd_mode)
{
    if (IS_DEC8_NEG(dec)) {
        CT_THROW_ERROR(ERR_VALUE_ERROR, "convert NUMBER into UINT64 failed");
        return CT_ERROR;
    }

    if (DECIMAL8_IS_ZERO(dec)) {
        *u64 = 0;
        return CT_SUCCESS;
    }
    int8 expn = GET_DEC8_EXPN(dec);
    if (expn < 0) {
        *u64 = dec8_make_negexpn_round_value2(dec, rnd_mode);
        return CT_SUCCESS;
    }

    // the maximal UINT64 is 1844 67440737 09551615
    if (expn > 2 || (expn == 2 && dec->cells[0] > 1844)) {
        CT_THROW_ERROR(ERR_TYPE_OVERFLOW, "UINT64");
        return CT_ERROR;
    }

    uint32 i;
    uint64 u64h = dec->cells[0];  // the highest cell
    u64h *= g_pow8_u64[(uint32)expn];

    uint64 u64l = 0;              // the tailing cells
    for (i = 1; i <= (uint32)expn && i < GET_CELLS8_SIZE(dec); i++) {
        u64l = u64l * DEC8_CELL_MASK + dec->cells[i];
    }
    // here expn must be in [0, 2]
    if (i <= (uint32)expn) {
        u64l *= g_pow8_u64[(uint32)(expn + 1) - i];
        i = expn + 1;
    }

    // do round
    if (i < GET_CELLS8_SIZE(dec)) {  // here i is expn + 1
        switch (rnd_mode) {
            case ROUND_CEILING:
                u64l += IS_DEC8_NEG(dec) ? 0 : 1;
                break;

            case ROUND_FLOOR:
                u64l += IS_DEC8_NEG(dec) ? 1 : 0;
                break;

            case ROUND_HALF_UP:
                u64l += (dec->cells[i] >= DEC8_HALF_MASK) ? 1 : 0;
                break;

            case ROUND_TRUNC:
            default:
                break;
        }
    }

    return cm_dec2uint64_check_overflow(u64h, u64l, u64);
}

static status_t cm_make_dec8_to_int(const dec8_t *dec, uint64 *u64, int8 expn, round_mode_t rnd_mode)
{
    uint32 i = 1;
    uint64 u64_val = dec->cells[0];
    int32 inc;

    for (; i <= (uint32)expn; i++) {
        inc = (i >= GET_CELLS8_SIZE(dec)) ? 0 : dec->cells[i];  // such as 11 * 100000000^4, dec->ncells = 1, expn= 4
        u64_val = u64_val * DEC8_CELL_MASK + inc;
    }

    if (i < GET_CELLS8_SIZE(dec)) {  // here i is equal to expn + 1
        switch (rnd_mode) {
            case ROUND_CEILING:
                u64_val += IS_DEC8_NEG(dec) ? 0 : 1;
                break;

            case ROUND_FLOOR:
                u64_val += IS_DEC8_NEG(dec) ? 1 : 0;
                break;

            case ROUND_HALF_UP:
                u64_val += (dec->cells[i] >= DEC8_HALF_MASK) ? 1 : 0;
                break;

            case ROUND_TRUNC:
            default:
                break;
        }
    }
    *u64 = u64_val;
    return CT_SUCCESS;
}

status_t cm_dec8_to_int64(const dec8_t *dec, int64 *val, round_mode_t rnd_mode)
{
    CM_POINTER(dec);

    if (DECIMAL8_IS_ZERO(dec)) {
        *val = 0;
        return CT_SUCCESS;
    }
    int8 expn = GET_DEC8_EXPN(dec);
    if (expn < 0) {
        *val = dec8_make_negexpn_round_value(dec, rnd_mode);
        return CT_SUCCESS;
    }

    // the maximal BIGINT is 922 33720368 54775807
    if (expn > 2 || (expn == 2 && dec->cells[0] > 922)) {
        CT_THROW_ERROR(ERR_TYPE_OVERFLOW, "BIGINT");
        return CT_ERROR;
    }

    uint64 u64;
    CT_RETURN_IFERR(cm_make_dec8_to_int(dec, &u64, expn, rnd_mode));
    return cm_dec2int64_check_overflow(u64, IS_DEC8_NEG(dec), val);
}

/**
 * Convert a decimal into bigint/int64. if overflow happened, the border
 * value is returned.
 * @return
 * 0: -- no overflow and underflow
 * 1: -- overflow, and return CT_MAX_INT64
 * -1: -- underflow, and return CT_MIN_INT64

 */
int32 cm_dec8_to_int64_range(const dec8_t *dec, int64 *i64, round_mode_t rnd_mode)
{
    if (cm_dec8_to_int64(dec, i64, rnd_mode) != CT_SUCCESS) {
        cm_reset_error();
        *i64 = IS_DEC8_NEG(dec) ? CT_MIN_INT64 : CT_MAX_INT64;
        return IS_DEC8_NEG(dec) ? -1 : 1;
    }

    return 0;
}

static status_t cm_make_dec8_to_uint(const dec8_t *dec, uint64 *u64, int8 expn, round_mode_t rnd_mode)
{
    uint32 i = 1;
    uint64 u64_val = dec->cells[0];
    uint32 inc;
    for (; i <= (uint32)expn; i++) {
        inc = (i >= GET_CELLS8_SIZE(dec)) ? 0 : dec->cells[i];  // such as 11 * 100^4, dec->len = 2, expn= 4
        u64_val = u64_val * DEC8_CELL_MASK + inc;
    }

    if (i < GET_CELLS8_SIZE(dec)) {  // here i is equal to expn + 1
        switch (rnd_mode) {
            case ROUND_CEILING:
                u64_val += 1;
                break;

            case ROUND_HALF_UP:
                u64_val += (dec->cells[i] >= DEC8_HALF_MASK) ? 1 : 0;
                break;

            case ROUND_FLOOR:
            case ROUND_TRUNC:
            default:
                break;
        }
    }

    *u64 = u64_val;
    return CT_SUCCESS;
}

/**
* Convert a decimal into uint32. if overflow happened, return ERROR
*/
status_t cm_dec8_to_uint32(const dec8_t *dec, uint32 *i32, round_mode_t rnd_mode)
{
    if (DECIMAL8_IS_ZERO(dec)) {
        *i32 = 0;
        return CT_SUCCESS;
    }
    int8 expn = GET_DEC8_EXPN(dec);
    // the maximal UINT32 42 9496 7295
    if (expn > 2 || IS_DEC8_NEG(dec)) {
        CT_THROW_ERROR(ERR_TYPE_OVERFLOW, "UNSIGNED INTEGER");
        return CT_ERROR;
    }

    if (expn < 0) {
        *i32 = (uint32)dec8_make_negexpn_round_value(dec, rnd_mode);
        return CT_SUCCESS;
    }

    uint64 u64_val;
    CT_RETURN_IFERR(cm_make_dec8_to_uint(dec, &u64_val, expn, rnd_mode));
    TO_UINT32_OVERFLOW_CHECK(u64_val, uint64);
    *i32 = (uint32)u64_val;
    return CT_SUCCESS;
}


/**
* Convert a decimal into int32. if overflow happened, return ERROR
*/
status_t cm_dec8_to_int32(const dec8_t *dec, int32 *i32, round_mode_t rnd_mode)
{
    if (DECIMAL8_IS_ZERO(dec)) {
        *i32 = 0;
        return CT_SUCCESS;
    }
    int8 expn = GET_DEC8_EXPN(dec);
    if (expn < 0) {
        *i32 = dec8_make_negexpn_round_value(dec, rnd_mode);
        return CT_SUCCESS;
    }

    // the maximal INTEGER 21 47483648
    if (expn > 1) {
        CT_THROW_ERROR(ERR_TYPE_OVERFLOW, "INTEGER");
        return CT_ERROR;
    }

    int64 i64_val;
    CT_RETURN_IFERR(cm_make_dec8_to_int(dec, (uint64 *)&i64_val, expn, rnd_mode));
    if (IS_DEC8_NEG(dec)) {
        i64_val = -i64_val;
    }

    INT32_OVERFLOW_CHECK(i64_val);

    *i32 = (int32)i64_val;
    return CT_SUCCESS;
}

/**
* Convert a decimal into integer(<= MAX_INT32) with max_prec (integer part, <= 10).
* if overflow happened, the border value is returned.
* @return
* 0: -- no overflow and underflow
* 1: -- overflow, and return CT_MAX_INT32
* -1: -- underflow, and return CT_MIN_INT32
*/
static inline int32 cm_dec8_to_int32_range(const dec8_t *dec, int32 *val, uint32 max_prec, round_mode_t rnd_mode)
{
    if (cm_dec8_to_int32(dec, val, rnd_mode) != CT_SUCCESS) {
        cm_reset_error();
        *val = IS_DEC8_NEG(dec) ? CT_MIN_INT32 : CT_MAX_INT32;
        return IS_DEC8_NEG(dec) ? -1 : 1;
    }

    return 0;
}

/**
 * To decide whether a decimal is an integer

 */
bool32 cm_dec8_is_integer(const dec8_t *dec)
{
    uint32 i;

    if (DECIMAL8_IS_ZERO(dec)) {
        return CT_TRUE;
    }
    int8 expn = GET_DEC8_EXPN(dec);
    if (expn < 0) {
        return CT_FALSE;
    }

    i = expn + 1;
    for (; i < GET_CELLS8_SIZE(dec); i++) {
        if (dec->cells[i] > 0) {
            return CT_FALSE;
        }
    }
    return CT_TRUE;
}

/**
* To decide whether a integer decimal is odd;
* note that the decimal must be an integer

*/
static inline bool32 cm_dec8_is_odd(const dec8_t *integer)
{
    if (DECIMAL8_IS_ZERO(integer)) {
        return CT_FALSE;
    }
    return integer->cells[(int32)GET_DEC8_EXPN(integer)] & 1;
}

status_t cm_dec8_floor(dec8_t *dec)
{
    uint32 i;
    bool32 has_tail = CT_FALSE;
    uint32 carry;

    CT_RETVALUE_IFTRUE(DECIMAL8_IS_ZERO(dec), CT_SUCCESS);
    int8 expn = GET_DEC8_EXPN(dec);
    if (expn < 0) {
        if (IS_DEC8_NEG(dec)) {
            cm_dec8_copy(dec, &DEC8_NEG_ONE);
        } else {
            cm_zero_dec8(dec);
        }
        return CT_SUCCESS;
    }

    for (i = expn + 1; i < GET_CELLS8_SIZE(dec); i++) {
        if (dec->cells[i] > 0) {
            has_tail = CT_TRUE;
            break;
        }
    }

    CT_RETVALUE_IFTRUE(!has_tail, CT_SUCCESS);

    dec->len = expn + 2; // ncells is expn + 1
    if (!IS_DEC8_NEG(dec)) {
        cm_dec8_trim_zeros(dec);
        return CT_SUCCESS;
    }

    carry = 1;
    i = GET_CELLS8_SIZE(dec);
    while (i-- > 0) {
        dec->cells[i] += carry;
        carry = (dec->cells[i] >= DEC8_CELL_MASK);
        if (carry == 0) {
            break;
        }

        dec->cells[i] = 0;
    }
    if (carry > 0) {
        cm_dec8_rebuild(dec, 1);
        DEC8_OVERFLOW_CHECK(dec);
    }

    cm_dec8_trim_zeros(dec);
    return CT_SUCCESS;
}

status_t cm_dec8_ceil(dec8_t *dec)
{
    uint32 i;
    bool32 has_tail = CT_FALSE;
    uint32 carry;

    CT_RETVALUE_IFTRUE(DECIMAL8_IS_ZERO(dec), CT_SUCCESS);
    int8 expn = GET_DEC8_EXPN(dec);
    if (expn < 0) {
        if (IS_DEC8_NEG(dec)) {
            cm_zero_dec8(dec);
        } else {
            cm_dec8_copy(dec, &DEC8_ONE);
        }
        return CT_SUCCESS;
    }

    for (i = expn + 1; i < GET_CELLS8_SIZE(dec); i++) {
        if (dec->cells[i] > 0) {
            has_tail = CT_TRUE;
            break;
        }
    }

    CT_RETVALUE_IFTRUE(!has_tail, CT_SUCCESS);

    dec->len = expn + 2; // ncells is expn + 1
    if (IS_DEC8_NEG(dec)) {
        cm_dec8_trim_zeros(dec);
        return CT_SUCCESS;
    }

    carry = 1;
    i = GET_CELLS8_SIZE(dec);
    while (i-- > 0) {
        dec->cells[i] += carry;
        carry = (dec->cells[i] >= DEC8_CELL_MASK);
        if (carry == 0) {
            break;
        }

        dec->cells[i] = 0;
    }
    if (carry > 0) {
        cm_dec8_rebuild(dec, 1);
        DEC8_OVERFLOW_CHECK(dec);
    }

    cm_dec8_trim_zeros(dec);
    return CT_SUCCESS;
}

/* Round a decimal by persevering at most scale digits after decimal point
 * The round mode can only be ROUND_HALF_UP or ROUND_TRUNC
 * Performance sensitivity.CM_ASSERT should be guaranteed by caller,
 * i.g. rnd_mode == ROUND_HALF_UP || rnd_mode == ROUND_TRUNC
*/
status_t cm_dec8_scale(dec8_t *dec, int32 scale, round_mode_t rnd_mode)
{
    int32 i, r_pos, cpos;
    uint32 carry = 0;
    uint32 npos;

    CT_RETVALUE_IFTRUE(DECIMAL8_IS_ZERO(dec), CT_SUCCESS);

    r_pos = GET_DEC8_SCI_EXP(dec) + DEC8_CELL_DIGIT + scale;
    if (r_pos < 0) {
        cm_zero_dec8(dec);
        return CT_SUCCESS;
    }
    // the rounded position exceeds the maximal precision
    CT_RETVALUE_IFTRUE((r_pos > DEC8_MAX_ALLOWED_PREC), CT_SUCCESS);

    cpos = r_pos / DEC8_CELL_DIGIT;
    npos = DEC8_CELL_DIGIT - ((uint32)r_pos % DEC8_CELL_DIGIT);

    if ((uint32)cpos >= GET_CELLS8_SIZE(dec)) {
        return CT_SUCCESS;
    }

    if (rnd_mode == ROUND_HALF_UP) {
        carry = g_5ten_powers[npos];
        for (i = cpos; i >= 0; --i) {
            dec->cells[i] += carry;
            carry = (dec->cells[i] >= DEC8_CELL_MASK);
            if (!carry) {
                break;
            }
            dec->cells[i] -= DEC8_CELL_MASK;
        }
    }

    dec->cells[cpos] /= g_1ten_powers[npos];
    dec->cells[cpos] *= g_1ten_powers[npos];

    // trimming zeros and recompute the dec->ncells
    while ((cpos >= 0) && (dec->cells[cpos] == 0)) {
        --cpos;
    }
    dec->len = (uint8)(cpos + 2);  // ncells is cpos + 1

    if (carry) {
        cm_dec8_rebuild(dec, 1);
        DEC8_OVERFLOW_CHECK(dec);
    } else if (dec->len == 1) {
        dec->head = ZERO_D8EXPN;
    }

    cm_dec8_trim_zeros(dec);
    return CT_SUCCESS;
}

/* decimal 3/8 = 0.375 */
static const dec8_t DEC8_3_in_8 = {
    .len = (uint8)2,
    .head = CONVERT_D8EXPN(-DEC8_CELL_DIGIT, CT_FALSE),
    .cells = { 37500000 }
};

/* decimal 10/8 = 1.25 */
static const dec8_t DEC8_10_in_8 = {
    .len = (uint8)3,
    .head = CONVERT_D8EXPN(0, CT_FALSE),
    .cells = { 1, 25000000 }
};

/* decimal 15/8 = 1.875 */
static const dec8_t DEC8_15_in_8 = {
    .len = (uint8)3,
    .head = CONVERT_D8EXPN(0, CT_FALSE),
    .cells = { 1, 87500000 }
};

status_t cm_dec8_sqrt(const dec8_t *d, dec8_t *r)
{
    dec8_t ti, yi;  // auxiliary variable

    if (DECIMAL8_IS_ZERO(d)) {
        cm_zero_dec8(r);
        return CT_SUCCESS;
    }

    if (IS_DEC8_NEG(d)) {
        CT_THROW_ERROR(ERR_VALUE_ERROR, "argument value of function sqrt must not be a negative number");
        return CT_ERROR;
    }

    /* The Halley's algorithm is applied to compute the square roots.
     *   (0). T(i) = d * X(i)
     *   (1). Y(i) = T(i) * X(i)
     *   (2). X(i+1) = X(i)/8 * {15 - Y(i) * (10 - 3 * Y(i))} = X(i) * K
     *   (3). r = d * X(i + 1) = T(i) * K
     * This algorithm has better performance than Newton's method,
     *   (0). X(i+1) = 0.5 * (X(i) + d/X(i))
     * which involves division, multiplication and addition.
     * However, the Goldschmidt's algorithm merely involves multiply Cadd instruction.
     * Set an initial value */
    CT_RETURN_IFERR(cm_real_to_dec8_inexac(sqrt(1.0 / cm_dec8_to_real(d)), r)); /* set r to 1.0/sqrt(d) */

    cm_dec8_mul_op(d, r, &ti);   /* set ti to d * r */
    cm_dec8_mul_op(&ti, r, &yi); /* set yi to ti * r */

    cm_dec8_mul_op(&yi, &DEC8_3_in_8, r); /* set r to 3/8 * yi */
    cm_dec8_sub_op(&DEC8_10_in_8, r, r);  /* set r to 10/8 - r */
    cm_dec8_mul_op(&yi, r, r);               /* set r to r * yi */

    cm_dec8_sub_op(&DEC8_15_in_8, r, r); /* set r to 15/8 - r */
    cm_dec8_mul_op(&ti, r, r);              /* set r to r * ti */

    return cm_dec8_finalise(r, MAX_NUMERIC_BUFF, CT_FALSE);
}

/**
* Compute the sin(x) using Taylor series, where x in (0, pi/4)

* sin x = x-x^3/3!+x^5/5!-......+(-1)^(n)*(x^(2n+1))/(2n+1)!+......
*/
static void cm_dec8_sin_frac(const dec8_t *x, dec8_t *sin_x)
{
    dec8_t x_pow2;
    dec8_t x_i;
    dec8_t item;

    /* initialize the iteration variables */
    cm_dec8_mul_op(x, x, &x_pow2);  // set x_pow2 to x * x
    cm_dec8_copy(sin_x, x);                  // set sin(x) to x
    cm_dec8_copy(&x_i, x);                   // set x(i) to x

    for (uint32 i = _I(3); i < ELEMENT_COUNT(g_dec8_inv_fact); i += 2) {
        cm_dec8_mul_op(&x_i, &x_pow2, &x_i);  // set x(i) to x^2 * x(i-1)
        cm_dec8_mul_op(&x_i, &g_dec8_inv_fact[i], &item);
        DEC8_DEBUG_PRINT(&item, "The item at [%u]", i >> 1);

        if (i & 2) {
            cm_dec8_add_op(sin_x, &item, sin_x);
        } else {
            cm_dec8_sub_op(sin_x, &item, sin_x);
        }
        DEC8_DEBUG_PRINT(sin_x, "The %u-th iteration", i >> 1);
        if (cm_dec8_taylor_break(sin_x, &item, MAX_NUM_CMP_PREC)) {
            break;
        }
    }

    return;
}

/**
* Compute the cos(x) using Taylor series, where x in (0, pi/4)

* cos x = 1-x^2/2!+x^4/4!-......+(-1)^(n)*(x^(2n))/(2n)!+......
*/
static void cm_dec8_cos_frac(const dec8_t *x, dec8_t *cos_x)
{
    dec8_t x_pow2;
    dec8_t x_i;
    dec8_t item;

    cm_dec8_mul_op(x, x, &x_pow2);
    cm_dec8_copy(&x_i, &x_pow2);

    // 1 - (x^2)/2
    cm_dec8_mul_op(&x_pow2, &DEC8_HALF_ONE, &item);
    cm_dec8_sub_op(&DEC8_ONE, &item, cos_x);

    for (uint32 i = _I(4); i < ELEMENT_COUNT(g_dec8_inv_fact); i += 2) {
        cm_dec8_mul_op(&x_i, &x_pow2, &x_i);  // set x(i) to x^2 * x(i-1)
        cm_dec8_mul_op(&x_i, &g_dec8_inv_fact[i], &item);
        DEC8_DEBUG_PRINT(&item, "The item at [%u]", i >> 1);

        if (i & 2) {
            cm_dec8_sub_op(cos_x, &item, cos_x);
        } else {
            cm_dec8_add_op(cos_x, &item, cos_x);
        }
        DEC8_DEBUG_PRINT(cos_x, "The %u-th iteration", i >> 1);
        if (cm_dec8_taylor_break(cos_x, &item, MAX_NUM_CMP_PREC)) {
            break;
        }
    }

    return;
}

#define MAX8_RANGE_PREC (MAX_NUM_CMP_PREC - DEC8_CELL_DIGIT)

static inline status_t cm_dec8_range_to_2pi(const dec8_t *x, dec8_t *y, double *dy)
{
    static const double pi = CT_PI * 2.0;

    *y = *x;
    dec8_t rem;
    int32 scale;
    do {
        *dy = cm_dec8_to_real(y);
        if (*dy < pi) {
            break;
        }

        cm_dec8_mul_op(&DEC8_INV_2PI, y, &rem);  // set rem to y /(2pi)
        int8 expn = GET_DEC8_EXPN(&rem);
        scale = (expn <= SEXP_2_D8EXP(MAX8_RANGE_PREC)) ? 0 : (MAX8_RANGE_PREC) - D8EXP_2_SEXP(expn);

        CT_RETURN_IFERR(cm_dec8_scale(&rem, scale, ROUND_TRUNC));  // truncate rem to integer
        cm_dec8_mul_op(&rem, &DEC8_2PI, &rem);
        cm_dec8_sub_op(y, &rem, y);
    } while (1);

    return CT_SUCCESS;
}

static status_t cm_dec8_sin_op(const dec8_t *x, dec8_t *sin_x)
{
    dec8_t tx;
    double dx;
    bool8 is_neg = IS_DEC8_NEG(x);
    dec8_t tmp_x;
    cm_dec8_copy(&tmp_x, x);
    cm_dec8_abs(&tmp_x);
    CT_RETURN_IFERR(cm_dec8_range_to_2pi(&tmp_x, &tx, &dx));

    if (dx < CT_PI_2) {  // [0, pi/2)
        // do nothing
    } else if (dx < CT_PI) {                               // [pi/2, pi)
        cm_dec8_sub_op(&DEC8_PI, &tx, &tx);  // pi - tx
    } else if (dx < CT_PI_2 + CT_PI) {                     // [PI, 3/2pi)
        cm_dec8_sub_op(&tx, &DEC8_PI, &tx);  // tx - pi
        is_neg = !is_neg;
    } else {
        cm_dec8_sub_op(&DEC8_2PI, &tx, &tx);  // 2pi - tx
        is_neg = !is_neg;
    }

    dx = cm_dec8_to_real(&tx);
    if (dx < CT_PI_4) {
        cm_dec8_sin_frac(&tx, sin_x);
    } else {
        cm_dec8_sub_op(&DEC8_HALF_PI, &tx, &tx);
        cm_dec8_cos_frac(&tx, sin_x);
    }
    if (is_neg && !IS_DEC8_NEG(sin_x)) {
        cm_dec8_negate(sin_x);
    }
    return CT_SUCCESS;
}

/**
* Compute the sin(x) using Taylor series

* sin x = x-x^3/3!+x^5/5!-......+(-1)^(n)*(x^(2n+1))/(2n+1)!+......
*/
status_t cm_dec8_sin(const dec8_t *dec, dec8_t *result)
{
    if (DECIMAL8_IS_ZERO(dec)) {
        cm_zero_dec8(result);
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(cm_dec8_sin_op(dec, result));
    return cm_dec8_finalise(result, MAX_NUMERIC_BUFF, CT_FALSE);
}

/**
* Compute the cos(x) using cos(x) = sin (x +pi/2)

*/
status_t cm_dec8_cos(const dec8_t *dec, dec8_t *result)
{
    dec8_t tmp_dec;

    if (DECIMAL8_IS_ZERO(dec)) {
        cm_dec8_copy(result, &DEC8_ONE);
        return CT_SUCCESS;
    }

    cm_dec8_add_op(dec, &DEC8_HALF_PI, &tmp_dec);

    return cm_dec8_sin(&tmp_dec, result);
}

/**
* Compute the tan(x) using tan(x) = sin(x) / cos(x)

*/
status_t cm_dec8_tan(const dec8_t *dec, dec8_t *result)
{
    dec8_t sin_dec;
    dec8_t cos_dec;
    dec8_t inv_cos_dec;

    if (DECIMAL8_IS_ZERO(dec)) {
        cm_zero_dec8(result);
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(cm_dec8_sin(dec, &sin_dec));     // sin(x)
    CT_RETURN_IFERR(cm_dec8_cos(dec, &cos_dec));     // cos(x)
    if (DECIMAL8_IS_ZERO(&cos_dec)) {
        CT_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "the value is not exist");
        return CT_ERROR;
    }
    CT_RETURN_IFERR(cm_dec8_inv(&cos_dec, &inv_cos_dec));  // 1 / cos(x)
    cm_dec8_mul_op(&sin_dec, &inv_cos_dec, result);  // sin(x) / cos(x)
    return cm_dec8_finalise(result, MAX_NUMERIC_BUFF, CT_FALSE);
}


/**
* Compute the radians(x) using radians(x) = (x * PI) / 180.0

*/
status_t cm_dec8_radians(const dec8_t *dec, dec8_t *result)
{
    if (DECIMAL8_IS_ZERO(dec)) {
        cm_zero_dec8(result);
        return CT_SUCCESS;
    }
    cm_dec8_mul_op(dec, &DEC8_PI, result);
    cm_dec_div_real(result, 180.0, result);

    return cm_dec8_finalise(result, MAX_NUMERIC_BUFF, CT_FALSE);
}

/**
* Compute the pi() using pi() = PI

*/
status_t cm_dec8_pi(dec8_t *result)
{
    cm_dec8_add_op(&DEC8_ZERO, &DEC8_PI, result);

    return cm_dec8_finalise(result, MAX_NUMERIC_BUFF, CT_FALSE);
}


/**
* Compute the asin(x) using Newton's method

* Xn+1 = Xn - f(Xn)/f'(Xn) = Xn - (sin(Xn) - a)/cos(Xn)
*/
status_t cm_dec8_asin_op(const dec8_t *d, dec8_t *rs)
{
    dec8_t last_dec;
    dec8_t tmp_dec;
    dec8_t cos_dec;
    dec8_t inv_cos_dec;
    dec8_t initial_dec;
    double initial_val;

    if (DECIMAL8_IS_ZERO(d)) {
        cm_zero_dec8(rs);
        return CT_SUCCESS;
    }

    if (dec8_is_greater_than_one(d)) {
        CT_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "argument value of function ASIN must between [-1, 1]");
        return CT_ERROR;
    }

    if (cm_dec8_is_absolute_one(d)) {
        cm_dec8_copy(rs, &DEC8_HALF_PI);
        if (IS_DEC8_NEG(d)) {
            cm_dec8_negate(rs);
        }
        return CT_SUCCESS;
    }

    // result : Xn
    cm_dec8_copy(&initial_dec, d);
    initial_val = asin(cm_dec8_to_real(d));
    if (CT_SUCCESS != cm_real_to_dec8(initial_val, rs)) {
        cm_dec8_copy(rs, d);
    }
    DEC8_DEBUG_PRINT(rs, "asin initial value");

    do {
        cm_dec8_copy(&last_dec, rs);

        CT_RETURN_IFERR(cm_dec8_sin(rs, &tmp_dec));  // sin(Xn)

        cm_dec8_sub_op(&tmp_dec, &initial_dec, &tmp_dec);  // sin(Xn) - a

        CT_RETURN_IFERR(cm_dec8_cos(rs, &cos_dec));          // cos(Xn)
        CT_RETURN_IFERR(cm_dec8_inv(&cos_dec, &inv_cos_dec));  // 1 / cos(Xn)

        cm_dec8_mul_op(&tmp_dec, &inv_cos_dec, &tmp_dec);  // (sin(Xn) - a) / cos(Xn)

        cm_dec8_sub_op(rs, &tmp_dec, rs);  // Xn -  (sin(Xn) - a) / cos(Xn)
        DEC8_DEBUG_PRINT(rs, "asin iteration");
    } while (!cm_dec8_taylor_break(rs, &tmp_dec, MAX_NUM_CMP_PREC));

    return CT_SUCCESS;
}

status_t cm_dec8_acos(const dec8_t *dec, dec8_t *result)
{
    if (dec8_is_greater_than_one(dec)) {
        CT_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "argument value of function ACOS must between [-1, 1]");
        return CT_ERROR;
    }
    CT_RETURN_IFERR(cm_dec8_asin_op(dec, result));
    cm_dec8_sub_op(&DEC8_HALF_PI, result, result);  // set acosx to PI - asinx
    return cm_dec8_finalise(result, MAX_NUMERIC_BUFF, CT_FALSE);
}

/**
* Compute the tan(x) using atan(x)=asin(x/sqrt(x^2+1))
*/
status_t cm_dec8_atan(const dec8_t *dec, dec8_t *result)
{
    dec8_t tmp_x;
    dec8_t tmp_result;
    int sci_exp = DEC8_GET_SEXP(dec);

    if (DECIMAL8_IS_ZERO(dec)) {
        cm_dec8_copy(result, &DEC8_ZERO);
        return CT_SUCCESS;
    }

    if (sci_exp > 63) {   // when sci_exp>63, set atan(x)=+/-PI/2
        cm_dec8_copy(result, &DEC8_HALF_PI);
        if (IS_DEC8_NEG(dec)) {
            cm_dec8_negate(result);
        }
    } else if (sci_exp < -63) {           // when sci_exp<-63,set atan(x) to x
        cm_dec8_copy(result, dec);
    } else {
        cm_dec8_mul_op(dec, dec, &tmp_x);    // x^2
        cm_dec8_add_op(&tmp_x, &DEC8_ONE, &tmp_x);  // x^2 + 1
        CT_RETURN_IFERR(cm_dec8_sqrt(&tmp_x, &tmp_result));      // sqrt(x^2+1)
        CT_RETURN_IFERR(cm_dec8_divide(dec, &tmp_result, &tmp_result)); // x/sqt(x^2+1)
        CT_RETURN_IFERR(cm_dec8_asin(&tmp_result, result));   // set atan(x) to asin(x/sqrt(x^2+1))
    }
    return cm_dec8_finalise(result, MAX_NUMERIC_BUFF, CT_FALSE);
}

/**
*                                     arctan(y/x)    x>0
*                                     arctan(y/x)+PI y>=0,x<0
*                                     arctan(y/x)-PI y<0,x<0
* Compute the tan(x) using atan2(y,x)= PI/2          y>0,x=0
*                                     -PI/2          y<0,x=0
*                                     undefined      y=0,x=0
**/
status_t cm_dec8_atan2(const dec8_t *dec1, const dec8_t *dec2, dec8_t *result)
{
    dec8_t tmp_dec;
    dec8_t tmp_result;

    if (DECIMAL8_IS_ZERO(dec1) && DECIMAL8_IS_ZERO(dec2)) {
        CT_THROW_ERROR(ERR_NUM_OVERFLOW);
        return CT_ERROR;
    }

    if (DECIMAL8_IS_ZERO(dec2)) {
        cm_dec8_copy(result, &DEC8_HALF_PI);
        if (IS_DEC8_NEG(dec1)) {
            cm_dec8_negate(result);
        }
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(cm_dec8_divide(dec1, dec2, &tmp_dec)); // set tmp_dec to dec1/dec2
    CT_RETURN_IFERR(cm_dec8_atan(&tmp_dec, &tmp_result));  // set tmp_result to atan(tmp_dec)

    if (!IS_DEC8_NEG(dec2)) {
        cm_dec8_copy(result, &tmp_result);
    } else if (!IS_DEC8_NEG(dec1)) {
        cm_dec8_add_op(&tmp_result, &DEC8_PI, result);
    } else {
        cm_dec8_sub_op(&tmp_result, &DEC8_PI, result);
    }

    return cm_dec8_finalise(result, MAX_NUMERIC_BUFF, CT_FALSE);
}

status_t cm_dec8_tanh(const dec8_t *dec, dec8_t *result)
{
    dec8_t tmp_dec;
    dec8_t tmp_exp1;
    dec8_t tmp_exp2;
    dec8_t tmp_value1;
    dec8_t tmp_value2;

    cm_dec8_copy(&tmp_dec, dec);

    if (DECIMAL8_IS_ZERO(dec)) {
        cm_dec8_copy(result, &DEC8_ZERO);
        return CT_SUCCESS;
    }

    int32 int_dec;
    (void)cm_dec8_to_int32_range(dec, &int_dec, 3, ROUND_HALF_UP);  // Number 3 is the max accuracy of the integer part

    if (int_dec > 46) {  // tanh(46) is 1
        cm_dec8_copy(result, &DEC8_ONE);
        return CT_SUCCESS;
    }
    if (int_dec < -45) {  // tanh(-45) is -1
        cm_dec8_copy(result, &DEC8_NEG_ONE);
        return CT_SUCCESS;
    }

    (void)cm_dec8_exp(dec, &tmp_exp1);                                  // e^x
    CT_RETURN_IFERR(cm_dec8_divide(&DEC8_ONE, &tmp_exp1, &tmp_exp2));   // e^-x
    cm_dec8_sub_op(&tmp_exp1, &tmp_exp2, &tmp_value1);                  // e^x-e^-x
    cm_dec8_add_op(&tmp_exp1, &tmp_exp2, &tmp_value2);                  // e^x+e^-x
    CT_RETURN_IFERR(cm_dec8_divide(&tmp_value1, &tmp_value2, result));  // (e^x-e^-x)/(e^x+e^-x)

    return cm_dec8_finalise(result, MAX_NUMERIC_BUFF, CT_FALSE);
}

/* x = exp(n), n is an integer */
static status_t cm_dec8_exp_n(int32 i32, dec8_t *x)
{
    dec8_t y;

    if (i32 < 0) {
        CT_RETURN_IFERR(cm_dec8_exp_n(-i32 / 2, x));
        CT_RETURN_IFERR(cm_dec8_inv(x, &y));

        cm_dec8_mul_op(&y, &y, x);
        if ((-i32) & 1) {
            cm_dec8_mul_op(x, &DEC8_INV_EXP, x);
        }
        DEC8_DEBUG_PRINT(x, "exp(-n)");
        return CT_SUCCESS;
    }

    if (i32 == 0) {
        cm_dec8_copy(x, &DEC8_ONE);
        return CT_SUCCESS;
    }
    if (i32 == 1) {
        cm_dec8_copy(x, &DEC8_EXP);
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(cm_dec8_exp_n(i32 / 2, &y));
    cm_dec8_mul_op(&y, &y, x);

    if (i32 & 1) {
        cm_dec8_mul_op(x, &DEC8_EXP, x);
    }
    DEC8_DEBUG_PRINT(x, "exp(%d)", i32);
    return CT_SUCCESS;
}

/* Compute the exp(x) using Taylor series, where abs(x) <= 0.5

* */
static inline void cm_dec8_exp_frac(const dec8_t *x, dec8_t *exp_x, uint32 prec)
{
    uint32 i;
    dec8_t ni, x_i;

    // set exp(x) to 1 + x + x^2/2
    cm_dec8_mul_op(x, x, &x_i);
    cm_dec8_mul_op(&x_i, &DEC8_HALF_ONE, exp_x);  // set exp_x to x^2/2

    cm_dec8_add_op(exp_x, &DEC8_ONE, exp_x);  // set exp_x to exp_x + 1
    cm_dec8_add_op(exp_x, x, exp_x);             // set exp_x to exp_x + x

    for (i = _I(3); i < ELEMENT_COUNT(g_dec8_inv_fact); i++) {
        cm_dec8_mul_op(&x_i, x, &x_i);              // set xi to xi * x
        cm_dec8_mul_op(&x_i, &g_dec8_inv_fact[i], &ni);  // set ni to xi / (i!)

        DEC8_DEBUG_PRINT(&ni, "exp frac item: %u", i);

        cm_dec8_add_op(exp_x, &ni, exp_x);  // set exp_x to exp_x + ni
        DEC8_DEBUG_PRINT(exp_x, "exp frac iteration: %u", i);

        if (cm_dec8_taylor_break(exp_x, &ni, MAX_NUM_CMP_PREC)) {
            break;
        }
    }
}

static inline status_t cm_dec8_exp_op(const dec8_t *x, dec8_t *y, uint32 prec)
{
    if (DECIMAL8_IS_ZERO(x)) {
        cm_dec8_copy(y, &DEC8_ONE);
        return CT_SUCCESS;
    }

    int32 int_x;

    (void)cm_dec8_to_int32_range(x, &int_x, 3, ROUND_HALF_UP);
    if (int_x > 295) {  //  exp(295) is greater than 10^127
        CT_THROW_ERROR(ERR_NUM_OVERFLOW);
        return CT_ERROR;
    } else if (int_x < -300) {  // exp(-300) is less than 10^-130
        cm_zero_dec8(y);
        return CT_SUCCESS;
    }

    if (cm_dec8_is_integer(x)) {
        return cm_dec8_exp_n(int_x, y);
    }

    if (int_x == 0) {  // whether [x] is equal to 0
        DEC8_DEBUG_PRINT(x, "exp(x), integer is zero");
        cm_dec8_exp_frac(x, y, prec);
        return CT_SUCCESS;
    }

    dec8_t frac_x;
    cm_int32_to_dec8(int_x, y);
    cm_dec8_sub_op(x, y, &frac_x);  // when frac_x <= 0.5, set frac_x to x - [x]
    DEC8_DEBUG_PRINT(y, "exp(integer)");
    DEC8_DEBUG_PRINT(&frac_x, "exp(frac)");
    cm_dec8_exp_frac(&frac_x, y, prec);  // set y to exp(x - [x])

    CT_RETURN_IFERR(cm_dec8_exp_n(int_x, &frac_x));   // set frac_x to exp([x])
    cm_dec8_mul_op(y, &frac_x, y);  // set y to y * frac_x

    return CT_SUCCESS;
}

status_t cm_dec8_exp(const dec8_t *dec, dec8_t *result)
{
    DEC8_DEBUG_PRINT(dec, "go into exp(x)");
    if (cm_dec8_exp_op(dec, result, MAX_NUM_CMP_PREC) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return cm_dec8_finalise(result, MAX_NUMERIC_BUFF, CT_FALSE);
}

/* Natural logarithm of small decimal
 * set y to ln(x), x <= 999999999 */
static inline status_t cm_dec8_ln_small(const dec8_t *x, dec8_t *ln_x, uint32 prec)
{
    uint32 i;
    dec8_t x4times;
    dec8_t delta, z2; /* two intermediate variables */

    CT_RETURN_IFERR(cm_real_to_dec8_inexac(log(cm_dec8_to_real(x)), ln_x));
    DEC8_DEBUG_PRINT(ln_x, "ln initial value");
    cm_dec8_mul_op(x, &DEC8_FOUR, &x4times);
    for (i = 0; i <= 5; ++i) {
        // set delta to 4x/(x + exp(ln_x)) - 2
        (void)cm_dec8_exp_op(ln_x, &delta, prec);
        cm_dec8_add_op(x, &delta, &z2);
        CT_RETURN_IFERR(cm_dec8_inv(&z2, &delta));
        cm_dec8_mul_op(&delta, &x4times, &z2);
        cm_dec8_sub_op(&z2, &DEC8_TWO, &delta);
        DEC8_DEBUG_PRINT(&delta, "ln delta: %u", i);

        cm_dec8_add_op(ln_x, &delta, ln_x);
        DEC8_DEBUG_PRINT(ln_x, "ln iteration: %u", i);

        if (cm_dec8_taylor_break(ln_x, &delta, (int32)prec)) {
            break;
        }
    }
    return CT_SUCCESS;
}

static inline status_t cm_dec8_ln_op(const dec8_t *dec, dec8_t *result, uint32 prec)
{
    if (IS_DEC8_NEG(dec) || DECIMAL8_IS_ZERO(dec)) {
        CT_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "argument must be greater than 0");
        return CT_ERROR;
    }
    int8 expn = GET_DEC8_EXPN(dec);
    DEC8_DEBUG_PRINT(dec, "go into ln(x) with expn = %d", expn);
    if (expn == 0) {
        return cm_dec8_ln_small(dec, result, prec);
    } else {
        dec8_t x;
        int32 exponent = D8EXP_2_SEXP(expn);
        cm_dec8_copy(&x, dec);
        x.head = (uint8)NON_NEG_ZERO_D8EXPN;
        // set y to ln(x)
        CT_RETURN_IFERR(cm_dec8_ln_small(&x, result, prec));  // ln(x)

        // set x to exponent  * ln(10)
        cm_int32_to_dec8(exponent, &x);
        cm_dec8_mul_op(&x, &DEC8_LN10, &x);

        // set result to x + y
        cm_dec8_add_op(result, &x, result);
        return CT_SUCCESS;
    }
}

status_t cm_dec8_ln(const dec8_t *dec, dec8_t *result)
{
    DEC8_DEBUG_PRINT(dec, "go into ln(dec)");
    if (cm_dec8_ln_op(dec, result, MAX_NUM_CMP_PREC) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return cm_dec8_finalise(result, MAX_NUMERIC_BUFF, CT_FALSE);
}

// 2. log(n2, n1) = ln(n1) / ln(n2), where n2 > 0 && n2 != 1 && n1 > 0.
status_t cm_dec8_log(const dec8_t *n2, const dec8_t *n1, dec8_t *result)
{
    dec8_t ln_n1;
    dec8_t ln_n2;

    if (cm_dec8_is_one(n2)) {
        CT_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "the first argument can not be 0 or 1");
        return CT_ERROR;
    }

    if (cm_dec8_ln_op(n2, &ln_n2, MAX_NUM_CMP_PREC) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cm_dec8_ln_op(n1, &ln_n1, MAX_NUM_CMP_PREC) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return cm_dec8_divide(&ln_n1, &ln_n2, result);
}

/* Compute the y = x^r
 * + if x < 0 and r is non-integer return error
 * + if x = 0 && r < 0 return error

 **/
status_t cm_dec8_power(const dec8_t *x, const dec8_t *r, dec8_t *y)
{
    if (DECIMAL8_IS_ZERO(x)) {
        if (IS_DEC8_NEG(r)) {
            CT_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "invalid argument for POWER function");
            return CT_ERROR;
        }
        if (DECIMAL8_IS_ZERO(r)) {  // whether 0^0 is equal to 1
            cm_dec8_copy(y, &DEC8_ONE);
            return CT_SUCCESS;
        }
        cm_zero_dec8(y);
        return CT_SUCCESS;
    }

    if (cm_dec8_is_one(r)) {
        cm_dec8_copy(y, x);
        return cm_dec8_finalise(y, MAX_NUMERIC_BUFF, CT_FALSE);
    }

    dec8_t abs_a;
    bool32 is_neg = CT_FALSE;
    const dec8_t *pa = x;

    if (IS_DEC8_NEG(x)) {
        if (!cm_dec8_is_integer(r)) {
            CT_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "invalid argument for POWER function");
            return CT_ERROR;
        }
        if (cm_dec8_is_odd(r)) {
            is_neg = CT_TRUE;
        }
        cm_dec8_negate2((dec8_t *)x, &abs_a);
        pa = &abs_a;
    }

    // extra 5 precisions for achieve a higher computation precision
    CT_RETURN_IFERR(cm_dec8_ln_op(pa, y, MAX_NUM_CMP_PREC + 5));  // set y to ln(abs(x))
    cm_dec8_mul_op(y, r, &abs_a);
    CT_RETURN_IFERR(cm_dec8_exp_op(&abs_a, y, MAX_NUM_CMP_PREC));

    // here y >= 0
    if (is_neg && !DECIMAL8_IS_ZERO(y)) {
        cm_dec8_negate(y);
    }

    return cm_dec8_finalise(y, MAX_NUMERIC_BUFF, CT_FALSE);
}

/** set y to n2 - n1 * FLOOR(n2 / n1)
 ** y must have the same sign of n2 */
status_t cm_dec8_mod(const dec8_t *n2, const dec8_t *n1, dec8_t *y)
{
    if (DECIMAL8_IS_ZERO(n1)) {
        cm_dec8_copy(y, n2);
        return CT_SUCCESS;
    }

    dec8_t z;

    // set y to n2 / n1
    CT_RETURN_IFERR(cm_dec8_inv(n1, &z));
    cm_dec8_mul_op(n2, &z, y);
    CT_RETURN_IFERR(cm_dec8_finalise(y, CT_MAX_DEC_OUTPUT_PREC, CT_TRUE));

    // set z to floor(y) *n1
    CT_RETURN_IFERR(cm_dec8_floor(y));
    cm_dec8_mul_op(y, n1, &z);
    CT_RETURN_IFERR(cm_dec8_finalise(&z, CT_MAX_DEC_OUTPUT_PREC, CT_TRUE));

    // set y to n2 - z
    cm_dec8_sub_op(n2, &z, y);
    CT_RETURN_IFERR(cm_dec8_finalise(y, CT_MAX_DEC_OUTPUT_PREC, CT_TRUE));

    if (DECIMAL8_IS_ZERO(y)) {
        return CT_SUCCESS;
    }

    // for illegal cases return 0
    bool32 cond = (n1->sign == n2->sign && n2->sign != y->sign);
    if (cond) {
        cm_zero_dec8(y);
        return CT_SUCCESS;
    }

    /* to ensure y has the same SIGN of n2 */
    cond = (n2->sign != n1->sign && n2->sign != y->sign);
    if (cond) {
        cm_dec8_sub_op(y, n1, y);
    }

    return cm_dec8_finalise(y, MAX_NUMERIC_BUFF, CT_FALSE);
}

/**
* Compute the sign of a decimal

*/
void cm_dec8_sign(const dec8_t *dec, dec8_t *result)
{
    if (DECIMAL8_IS_ZERO(dec)) {
        cm_dec8_copy(result, &DEC8_ZERO);
        return;
    }

    if (IS_DEC8_NEG(dec)) {
        cm_dec8_copy(result, &DEC8_NEG_ONE);
    } else {
        cm_dec8_copy(result, &DEC8_ONE);
    }
}

/**
 * Use for debugging. see the macro @DEC_DEBUG_PRINT
 */
void cm_dec8_print(const dec8_t *dec, const char *file, uint32 line, const char *func_name, const char *fmt, ...)
{
    char buf[100];
    va_list var_list;
    dec8_t fl_dec;

    printf("%s:%u:%s\n", file, line, func_name);
    va_start(var_list, fmt);
    PRTS_RETVOID_IFERR(vsnprintf_s(buf, sizeof(buf), sizeof(buf) - 1, fmt, var_list));

    va_end(var_list);
    printf("%s\n", buf);
    (void)cm_dec8_to_str_all(dec, buf, sizeof(buf));
    printf("dec := %s\n", buf);
    printf("  ncells = %u, expn = %d, sign = %c, dec4 bytes = %u, dec2 bytes = %u\n",
           GET_CELLS8_SIZE(dec),
           GET_DEC8_EXPN(dec),
           (IS_DEC8_NEG(dec)) ? '-' : '+',
           (uint32)cm_dec8_stor_sz(dec),
           (uint32)cm_dec8_stor_sz2(dec));
    printf("  cells = { ");
    for (uint32 i = 0; i < GET_CELLS8_SIZE(dec); i++) {
        if (i != 0) {
            printf(", ");
        }
        printf("%08u", dec->cells[i]);
    }
    printf("}\n");

    fl_dec = *dec;
    (void)cm_dec8_finalise(&fl_dec, MAX_NUM_CMP_PREC, CT_TRUE);
    (void)cm_dec8_to_str_all(&fl_dec, buf, sizeof(buf));
    printf("finalized dec := %s\n\n", buf);
    (void)fflush(stdout);
}

void cm_dec8_negate(dec8_t *dec)
{
    if (DECIMAL8_IS_ZERO(dec)) {
        return;
    } else {
        dec->head = CONVERT_D8EXPN2(GET_DEC8_EXPN(dec), !IS_DEC8_NEG(dec));
    }
}

void cm_dec8_negate2(dec8_t *dec, dec8_t *ret)
{
    if (DECIMAL8_IS_ZERO(dec)) {
        cm_zero_dec8(ret);
    } else {
        cm_dec8_copy(ret, dec);
        ret->head = CONVERT_D8EXPN2(GET_DEC8_EXPN(dec), !IS_DEC8_NEG(dec));
    }
}

/**
 * the expn range of dec2 is [-130, 125],
 * the expn range of dec4 is [-127, 127],
 * the expn range of dec8 is [-130, 127].
 */
status_t cm_dec8_check_type_overflow(dec8_t *dec, int16 type)
{
    if (DECIMAL8_IS_ZERO(dec)) {
        return CT_SUCCESS;
    }
    int32 sexp = DEC8_GET_SEXP(dec);
    if (type == CT_TYPE_NUMBER2) {
        DEC2_OVERFLOW_CHECK_BY_SCIEXP(sexp);
    } else if (sexp < MIN_NUMERIC_EXPN) { // underflow return 0
        cm_zero_dec8(dec);
    }
    return CT_SUCCESS;
}

#ifdef __cplusplus
}
#endif


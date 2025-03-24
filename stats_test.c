#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "stats.h"
#include "stats_test_data.h"

#define ABSDIFF(a, b) (((a) > (b)) ? ((a) - (b)) : ((b) - (a)))

ULONG64 percent_error(ULONG64 val, ULONG64 est)
{
    // returns percent error of the estimate of a value.
    ULONG64 diff = ABSDIFF(val, est);
    return diff * 100 / val;
}

int __cdecl wmain(int argc, wchar_t** argv)
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);
    int err = NO_ERROR;

    printf("Testing histogram.\n");

    SmStat* s = malloc(sizeof(SmStat));
    if (s == NULL) {
        printf("Failed to create new SmStat\n");
        err = ERROR_NOT_ENOUGH_MEMORY;
        goto exit;
    }
    sm_stat_init(s);

    for (int i = 0; i < RTL_NUMBER_OF(test_data); i++) {
        sm_stat_add(s, test_data[i]);
    }

    for (int i = 0; i < RTL_NUMBER_OF(percentiles); i++) {
        ULONG64 estimate = sm_stat_percentile(s, tested_percentiles[i]);
        printf("p%d=%llu, estimate=%llu, error=%llu%%\n",
            tested_percentiles[i], percentiles[i], estimate,
            percent_error(percentiles[i], estimate));
    }

exit:
    if (s != NULL) {
        free(s);
    }
    return err;
}

/*
The results below for the current Weibull-distributed test data show
very accurate percentile estimates except at low percentiles. This
also seems to be the behavior on uniformly distributed data.

p1=30, estimate=16, error=46%
p2=46, estimate=48, error=4%
p3=60, estimate=48, error=20%
p4=70, estimate=80, error=14%
p5=79, estimate=80, error=1%
p6=90, estimate=80, error=11%
p7=99, estimate=112, error=13%
p8=107, estimate=112, error=4%
p9=118, estimate=112, error=5%
p10=128, estimate=144, error=12%
p11=136, estimate=144, error=5%
p12=146, estimate=144, error=1%
p13=154, estimate=144, error=6%
p14=163, estimate=176, error=7%
p15=171, estimate=176, error=2%
p16=180, estimate=176, error=2%
p17=189, estimate=176, error=6%
p18=197, estimate=208, error=5%
p19=205, estimate=208, error=1%
p20=214, estimate=208, error=2%
p21=222, estimate=208, error=6%
p22=231, estimate=240, error=3%
p23=238, estimate=240, error=0%
p24=246, estimate=240, error=2%
p25=254, estimate=240, error=5%
p26=263, estimate=272, error=3%
p27=270, estimate=272, error=0%
p28=277, estimate=272, error=1%
p29=287, estimate=272, error=5%
p30=295, estimate=304, error=3%
p31=302, estimate=304, error=0%
p32=310, estimate=304, error=1%
p33=319, estimate=304, error=4%
p34=328, estimate=336, error=2%
p35=335, estimate=336, error=0%
p36=345, estimate=336, error=2%
p37=353, estimate=368, error=4%
p38=359, estimate=368, error=2%
p39=365, estimate=368, error=0%
p40=374, estimate=368, error=1%
p41=382, estimate=368, error=3%
p42=390, estimate=400, error=2%
p43=398, estimate=400, error=0%
p44=407, estimate=400, error=1%
p45=413, estimate=400, error=3%
p46=423, estimate=432, error=2%
p47=431, estimate=432, error=0%
p48=440, estimate=432, error=1%
p49=449, estimate=464, error=3%
p50=458, estimate=464, error=1%
p51=468, estimate=464, error=0%
p52=476, estimate=464, error=2%
p53=485, estimate=496, error=2%
p54=493, estimate=496, error=0%
p55=500, estimate=496, error=0%
p56=509, estimate=496, error=2%
p57=518, estimate=528, error=1%
p58=527, estimate=528, error=0%
p59=539, estimate=528, error=2%
p60=549, estimate=560, error=2%
p61=560, estimate=560, error=0%
p62=569, estimate=560, error=1%
p63=576, estimate=592, error=2%
p64=587, estimate=592, error=0%
p65=596, estimate=592, error=0%
p66=607, estimate=592, error=2%
p67=620, estimate=624, error=0%
p68=630, estimate=624, error=0%
p69=642, estimate=656, error=2%
p70=652, estimate=656, error=0%
p71=661, estimate=656, error=0%
p72=672, estimate=688, error=2%
p73=688, estimate=688, error=0%
p74=704, estimate=720, error=2%
p75=719, estimate=720, error=0%
p76=733, estimate=720, error=1%
p77=751, estimate=752, error=0%
p78=769, estimate=784, error=1%
p79=784, estimate=784, error=0%
p80=803, estimate=816, error=1%
p81=818, estimate=816, error=0%
p82=836, estimate=848, error=1%
p83=853, estimate=848, error=0%
p84=871, estimate=880, error=1%
p85=892, estimate=880, error=1%
p86=912, estimate=912, error=0%
p87=931, estimate=944, error=1%
p88=956, estimate=944, error=1%
p89=983, estimate=976, error=0%
p90=1008, estimate=1008, error=0%
p91=1036, estimate=1040, error=0%
p92=1069, estimate=1072, error=0%
p93=1113, estimate=1104, error=0%
p94=1174, estimate=1168, error=0%
p95=1229, estimate=1232, error=0%
p96=1282, estimate=1296, error=1%
p97=1365, estimate=1360, error=0%
p98=1491, estimate=1488, error=0%
p99=1616, estimate=1616, error=0%
*/
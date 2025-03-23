#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "stats.h"

#define ABSDIFF(a, b) (((a) > (b)) ? ((a) - (b)) : ((b) - (a)))

ULONG64 percent_error(ULONG64 val, ULONG64 est)
{
	// returns percent error of the estimate of a value.
	ULONG64 diff = ABSDIFF(val, est);
	return diff * 100 / val;
}

// SmHisto trades accuracy for memory with log buckets.
// Compare its percentile estimates with those of a
// "full record" of values.
//
// The test dataset is a stream of increasing values where
// the (n+1)th value is the (n)th value plus a random number
// between 0 and stride_range, so stride_range gives the
// general resulting scale of values.
// The max value in the stream will likely be somewhere
// around numvals * stride_range / 2.
//
// Return value: the maximum percent error among the percentiles
// we compare.
ULONG64 test_histo(ULONG64 stride_range, ULONG seed)
{
	const ULONG64 numvals = 100000;
	SmHisto* h = sm_new_histo();
	ULONG64* vals = malloc(numvals * sizeof(ULONG64)); // the "full record"

	ULONG64 p30 = 0;
	ULONG64 p30_idx = numvals * 30 / 100;
	ULONG64 p50 = 0;
	ULONG64 p50_idx = numvals * 50 / 100;
	ULONG64 p80 = 0;
	ULONG64 p80_idx = numvals * 80 / 100;
	ULONG64 p90 = 0;
	ULONG64 p90_idx = numvals * 90 / 100;
	ULONG64 p99 = 0;
	ULONG64 p99_idx = numvals * 99 / 100;

	ULONG64 curval = 0;
	srand(seed);
	for(int i = 0; i < numvals; i++) {
		curval += rand() % stride_range; // stride so we don't have to sort.
		vals[i] = curval;
		sm_histo_add(h, curval);

		if (i == p30_idx) {
			p30 = curval;
		} else if (i == p50_idx) {
			p50 = curval;
		} else if (i == p80_idx) {
			p80 = curval;
		} else if (i == p90_idx) {
			p90 = curval;
		} else if (i == p99_idx) {
			p99 = curval;
		}
	}

	printf("\nstride_range=%llu, seed=%d\n", stride_range, seed);

	ULONG64 p30_est = sm_histo_percentile(h, 30);
	ULONG64 p50_est = sm_histo_percentile(h, 50);
	ULONG64 p80_est = sm_histo_percentile(h, 80);
	ULONG64 p90_est = sm_histo_percentile(h, 90);
	ULONG64 p99_est = sm_histo_percentile(h, 99);

	ULONG64 p30_err = percent_error(p30_est, p30);
	ULONG64 p50_err = percent_error(p50_est, p50);
	ULONG64 p80_err = percent_error(p80_est, p80);
	ULONG64 p90_err = percent_error(p90_est, p90);
	ULONG64 p99_err = percent_error(p99_est, p99);

	ULONG64 max_err = 0;
	max_err = max(max_err, p30_err);
	max_err = max(max_err, p50_err);
	max_err = max(max_err, p80_err);
	max_err = max(max_err, p90_err);
	max_err = max(max_err, p99_err);

	printf("p30=%llu, estimate=%llu, err=%llu%%\n", p30, p30_est, p30_err);
	printf("p50=%llu, estimate=%llu, err=%llu%%\n", p50, p50_est, p50_err);
	printf("p80=%llu, estimate=%llu, err=%llu%%\n", p80, p80_est, p80_err);
	printf("p90=%llu, estimate=%llu, err=%llu%%\n", p90, p90_est, p90_err);
	printf("p99=%llu, estimate=%llu, err=%llu%%\n", p99, p99_est, p99_err);

	sm_del_histo(h);

	return max_err;
}

int __cdecl wmain(int argc, wchar_t** argv)
{
	argc;argv;
    int err = NO_ERROR;

    printf("Testing histogram.\n");
    ULONG64 max_histo_error = 0;
    max_histo_error = max(max_histo_error, test_histo(8, 0));
    max_histo_error = max(max_histo_error, test_histo(8, 47));
    max_histo_error = max(max_histo_error, test_histo(8, 12345));
    max_histo_error = max(max_histo_error, test_histo(128, 0));
    max_histo_error = max(max_histo_error, test_histo(128, 47));
    max_histo_error = max(max_histo_error, test_histo(128, 12345));
    max_histo_error = max(max_histo_error, test_histo(10000, 0));
    max_histo_error = max(max_histo_error, test_histo(10000, 47));
    max_histo_error = max(max_histo_error, test_histo(10000, 12345));
    printf("Max histo error: %llu%%\n", max_histo_error);

    return err;
}

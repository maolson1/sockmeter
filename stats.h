#pragma once

// Logarithmic histogram that records the mean
// in each bucket to reduce error.

#define SM_HISTO_NUM_BUCKETS 64

typedef struct {
	ULONG64 count;
	ULONG64 mean;
} SmHistoBucket;

typedef struct {
	SmHistoBucket buckets[SM_HISTO_NUM_BUCKETS];
} SmHisto;


// Merge two means, recording the output into "to" and "to_n".
// "to" is a mean of "to_n" values; "from" is a mean of "from_n" values.
inline void sm_mean(ULONG64* to, ULONG64* to_n, ULONG64 from, ULONG64 from_n)
{
	*to = (*to * *to_n + from * from_n) / (*to_n + from_n);
	*to_n += from_n;
}

inline SmHisto* sm_new_histo(void)
{
	SmHisto* h = malloc(sizeof(SmHisto));
	if (h == NULL) {
		return NULL;
	}
	RtlZeroMemory(h, sizeof(*h));
	return h;
}

inline void sm_del_histo(SmHisto* h)
{
	free(h);
}

inline void sm_histo_add(SmHisto* h, ULONG64 val)
{
	ULONG val_log2;
	_BitScanReverse64(&val_log2, val);
	// printf("val = %llu, val_log2 = %lu\n", val, val_log2);

	SmHistoBucket* bucket = &h->buckets[val_log2];
	sm_mean(&bucket->mean, &bucket->count, val, 1);
}

inline ULONG64 sm_histo_percentile(SmHisto* h, ULONG p)
{
	// p is in units of percent, which means we can return an
	// estimate for the 99th percentile at best.
	// This library is optimized for speed rather than
	// asymptotic accuracy, so don't make any false promises
	// by returning potentially-bogus estimates of the
	// 99.99999999th percentile.

	ULONG64 total = 0;
	for (ULONG i = 0; i < SM_HISTO_NUM_BUCKETS; i++) {
		total += h->buckets[i].count;
	}

	ULONG bucket_i = 0;
	ULONG64 p_count = total * p / 100; // # of vals less than p'th percentile.
	while (p_count > h->buckets[bucket_i].count) {
		p_count -= h->buckets[bucket_i].count;
		bucket_i++;
	}

	return h->buckets[bucket_i].mean;
}

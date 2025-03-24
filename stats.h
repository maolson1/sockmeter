#pragma once

// Merge two means, recording the output into "to" and "to_n".
// "to" is a mean of "to_n" values; "from" is a mean of "from_n" values.
inline void sm_mean(ULONG64* to, ULONG64* to_n, ULONG64 from, ULONG64 from_n)
{
    *to = (*to * *to_n + from * from_n) / (*to_n + from_n);
    *to_n += from_n;
}

// A histogram for estimating percentiles of data without storing
// all of the values. This implementation uses uniformly-sized buckets.
// If a new value is sampled that cannot be encoded by the histogram
// (the max encodable value is num_buckets * bucket_size),
// the bucket size is repeatedly doubled (and existing counts
// reshuffled) until the new value is encodable.

// This gives percentile estimates accurate to within a few percent
// (except at low percentiles- see stats_test) with Weibull-distributed
// data, and hopefully with data of any distribution sockmeter uses it
// for.

#define SM_HISTO_NUM_BUCKETS 100

typedef struct {
    ULONG64 count;
    ULONG64 mean;
    ULONG64 bucket_width;
    ULONG64 buckets[SM_HISTO_NUM_BUCKETS];
} SmStat;

inline SmStat* sm_new_stat(void)
{
    SmStat* s = malloc(sizeof(SmStat));
    if (s == NULL) {
        return NULL;
    }
    RtlZeroMemory(s, sizeof(*s));
    s->bucket_width = 1;
    return s;
}

inline void sm_del_stat(SmStat* s)
{
    free(s);
}

inline void sm_stat_grow(SmStat* s)
{
    s->bucket_width *= 2;

    // Reshuffle the buckets- quite easy when we are doubling the bucket
    // width, since each resulting bucket on the left half of the
    // new histogram layout owns precisely the counts from two buckets
    // of the old layout.

    for (int i = 0; i < SM_HISTO_NUM_BUCKETS / 2; i++) {
        s->buckets[i] = s->buckets[2 * i] + s->buckets[2 * i + 1];
    }
    for (int i = SM_HISTO_NUM_BUCKETS / 2; i < SM_HISTO_NUM_BUCKETS; i++) {
        s->buckets[i] = 0;
    }
}

inline void sm_stat_add(SmStat* s, ULONG64 val)
{
    sm_mean(&s->mean, &s->count, val, 1);
    while (val >= s->bucket_width * SM_HISTO_NUM_BUCKETS) {
        sm_stat_grow(s);
    }
    s->buckets[val / s->bucket_width]++;
}

inline ULONG64 sm_stat_percentile(SmStat* s, ULONG p)
{
    ULONG64 p_count = s->count * p / 100; // # of vals less than p'th percentile.
    ULONG bucket_i = 0;
    while (p_count > s->buckets[bucket_i]) {
        p_count -= s->buckets[bucket_i];
        bucket_i++;
    }
    return s->bucket_width * bucket_i + s->bucket_width / 2;
}

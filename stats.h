#pragma once

// SmStat tracks the statistics of a single metric.
//
// "buckets" is a histogram. The bucket at index i is a count of
// all samples in the range
// [ bucket_width*i,   bucket_width*(i+1) ).
//
// If a new value is sampled that cannot be encoded by the
// histogram (the max encodable value is num_buckets * bucket_size),
// the bucket size is repeatedly doubled and existing counts
// reshuffled until the new value is encodable.
//
// This gives percentile estimates accurate to within a few percent
// (except at low percentiles- see stats_test) with Weibull-distributed
// data, and hopefully with data of any distribution sockmeter uses it
// for.

#define SM_HISTO_NUM_BUCKETS 100

typedef struct {
    ULONG64 count;
    ULONG64 mean;
    ULONG64 min;
    ULONG64 max;
    ULONG64 bucket_width;
    ULONG64 buckets[SM_HISTO_NUM_BUCKETS];
} SmStat;

inline void sm_mean_merge(
    ULONG64* to, ULONG64* to_n, ULONG64 from, ULONG64 from_n)
{
    // Merge two means, recording the output into "to" and "to_n".
    // "to" is a mean of "to_n" values; "from" is a mean of "from_n" values.

    *to = (*to * *to_n + from * from_n) / (*to_n + from_n);
    *to_n += from_n;
}

inline void sm_stat_init(SmStat* s)
{
    RtlZeroMemory(s, sizeof(*s));
    s->min = (ULONG64)-1;
    s->bucket_width = 1;
}

inline void sm_stat_widen(SmStat* s)
{
    s->bucket_width *= 2;

    // Reshuffle the buckets. Since we doubled the bucket width,
    // each resulting bucket in the left half of the
    // new layout owns precisely the counts from two buckets
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
    if (s->max < val) {
        s->max = val;
    }
    if (s->min > val) {
        s->min = val;
    }
    sm_mean_merge(&s->mean, &s->count, val, 1);
    while (val >= s->bucket_width * SM_HISTO_NUM_BUCKETS) {
        sm_stat_widen(s);
    }
    s->buckets[val / s->bucket_width]++;
}

inline void sm_stat_merge(SmStat* to, SmStat* from)
{
    while (to->bucket_width < from->bucket_width) {
        sm_stat_widen(to);
    }
    for (int i = 0; i < SM_HISTO_NUM_BUCKETS; i++) {
        to->buckets[i] += from->buckets[i];
    }
    sm_mean_merge(&to->mean, &to->count, from->mean, from->count);
    to->min = min(to->min, from->min);
    to->max = max(to->max, from->max);
}

inline ULONG64 sm_stat_percentile(SmStat* s, ULONG p)
{
    // Number of values less than or equal to p'th percentile.
    ULONG64 p_count = (s->count * p / 100) + 1;

    ULONG bucket_i = 0;
    while (bucket_i < SM_HISTO_NUM_BUCKETS && p_count > s->buckets[bucket_i]) {
        p_count -= s->buckets[bucket_i];
        bucket_i++;
    }
    return s->bucket_width * bucket_i + s->bucket_width / 2;
}

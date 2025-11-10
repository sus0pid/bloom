#define _POSIX_C_SOURCE 200809L

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../src/bloom.h"

enum {
    kPeerCount = 10,
    kBitmapBytes = 32,
    kHashProbes = 13,
    kMaxKeyLen = 32
};

static const float kTargetFalsePositive = 0.0001f; /* 0.01% */
static const size_t kMemberBatches = 1u << 18;
static const size_t kRandomTrials = 1u << 20;

static inline double elapsed_ns(const struct timespec start,
                                const struct timespec end) {
    const double sec = (double)(end.tv_sec - start.tv_sec) * 1e9;
    const double nsec = (double)(end.tv_nsec - start.tv_nsec);
    return sec + nsec;
}

static uint64_t xorshift64(uint64_t *state) {
    uint64_t x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    return x;
}

static int init_custom_bloom(BloomFilter *bf) {
    if (bloom_filter_init(bf, kPeerCount, kTargetFalsePositive) != BLOOM_SUCCESS) {
        return BLOOM_FAILURE;
    }
    free(bf->bloom);
    bf->bloom_length = kBitmapBytes;
    bf->number_bits = (uint64_t)kBitmapBytes * 8;
    bf->number_hashes = kHashProbes;
    bf->bloom = calloc(kBitmapBytes, sizeof(unsigned char));
    if (bf->bloom == NULL) {
        bloom_filter_destroy(bf);
        return BLOOM_FAILURE;
    }
    bf->elements_added = 0;
    bf->estimated_elements = kPeerCount;
    bf->false_positive_probability = kTargetFalsePositive;
    return BLOOM_SUCCESS;
}

int main(void) {
    BloomFilter bf;
    memset(&bf, 0, sizeof(bf));

    if (init_custom_bloom(&bf) == BLOOM_FAILURE) {
        fprintf(stderr, "Failed to initialize bloom filter\n");
        return EXIT_FAILURE;
    }

    char peers[kPeerCount][kMaxKeyLen];
    struct timespec start, end;

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (uint64_t i = 0; i < kPeerCount; ++i) {
        snprintf(peers[i], kMaxKeyLen, "peer-%02" PRIu64, i);
        if (bloom_filter_add_string(&bf, peers[i]) != BLOOM_SUCCESS) {
            fprintf(stderr, "Insertion failed at %s\n", peers[i]);
            bloom_filter_destroy(&bf);
            return EXIT_FAILURE;
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    const double insert_ns = elapsed_ns(start, end) / kPeerCount;

    for (uint64_t i = 0; i < kPeerCount; ++i) {
        if (bloom_filter_check_string(&bf, peers[i]) != BLOOM_SUCCESS) {
            fprintf(stderr, "Lookup failed for %s\n", peers[i]);
            bloom_filter_destroy(&bf);
            return EXIT_FAILURE;
        }
    }

    const size_t total_member_checks = kMemberBatches * kPeerCount;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (size_t batch = 0; batch < kMemberBatches; ++batch) {
        for (uint64_t i = 0; i < kPeerCount; ++i) {
            (void)bloom_filter_check_string(&bf, peers[i]);
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    const double member_lookup_ns = elapsed_ns(start, end) / total_member_checks;

    size_t false_hits = 0;
    uint64_t rng_state = 0x1234567890abcdefULL;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (size_t trial = 0; trial < kRandomTrials; ++trial) {
        uint64_t candidate = xorshift64(&rng_state);
        char key[kMaxKeyLen];
        snprintf(key, sizeof(key), "noise-%016" PRIx64, candidate);
        if (bloom_filter_check_string(&bf, key) == BLOOM_SUCCESS) {
            ++false_hits;
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    const double random_lookup_ns = elapsed_ns(start, end) / (double)kRandomTrials;
    const double observed_fpr = (double)false_hits / (double)kRandomTrials;

    printf("bloom (barrust) benchmark\n");
    printf(" peers: %d\n bitmap: %d bytes (%u bits)\n hashes: %d\n target FPR: %.5f%%\n",
           kPeerCount,
           kBitmapBytes,
           (unsigned)(kBitmapBytes * 8),
           kHashProbes,
           kTargetFalsePositive * 100.0f);
    printf(" inserts: %.2f ns/op for %d peers\n", insert_ns, kPeerCount);
    printf(" member lookups: %.2f ns/op over %zu checks\n",
           member_lookup_ns, total_member_checks);
    printf(" random lookups: %.2f ns/op over %zu checks\n",
           random_lookup_ns, (size_t)kRandomTrials);
    printf(" observed FPR: %.6f%% (%zu / %zu)\n",
           observed_fpr * 100.0,
           false_hits,
           (size_t)kRandomTrials);

    bloom_filter_destroy(&bf);
    return EXIT_SUCCESS;
}

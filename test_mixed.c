#include <stdint.h>
#include <time.h>
#include <stdlib.h>

#define BSS_ARRAY_SIZE (10 * 1024 * 1024) // 10MB each array
static uint8_t array1[BSS_ARRAY_SIZE];
static uint8_t array2[BSS_ARRAY_SIZE];
static uint8_t array3[BSS_ARRAY_SIZE];
static uint8_t array4[BSS_ARRAY_SIZE]; // Total 40MB BSS

uint32_t xorshift32(uint32_t* state) {
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

int main() {
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    uint32_t rng_state = 0x12345678;
    
    // Sequential access to array1
    for (int i = 0; i < BSS_ARRAY_SIZE; i++) {
        array1[i] = i & 0xFF;
    }
    
    // Random access to array2
    for (int i = 0; i < BSS_ARRAY_SIZE; i++) {
        uint32_t idx = xorshift32(&rng_state) % BSS_ARRAY_SIZE;
        array2[idx] = i & 0xFF;
    }
    
    // Strided access to array3
    for (int stride = 1; stride < 16; stride++) {
        for (int i = 0; i < BSS_ARRAY_SIZE; i += stride) {
            array3[i] = i & 0xFF;
        }
    }
    
    // Mixed sequential/random to array4
    for (int i = 0; i < BSS_ARRAY_SIZE; i++) {
        if (i % 2 == 0) {
            array4[i] = i & 0xFF;
        } else {
            uint32_t idx = xorshift32(&rng_state) % BSS_ARRAY_SIZE;
            array4[idx] = i & 0xFF;
        }
    }
    
    // Verification pass
    uint64_t checksum = 0;
    for (int i = 0; i < BSS_ARRAY_SIZE; i++) {
        checksum += array1[i] + array2[i] + array3[i] + array4[i];
    }
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    uint64_t elapsed = (end.tv_sec - start.tv_sec) * 1000000000UL + 
                      (end.tv_nsec - start.tv_nsec);
    
    volatile uint64_t result = checksum + elapsed;
    return result & 1;
}
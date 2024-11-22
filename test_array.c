#include <stdint.h>
#include <time.h>

#define ARRAY_SIZE (10 * 1024 * 1024) // 10MB

static uint8_t data[ARRAY_SIZE];

int main() {
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    // Sequential initialization
    for (int i = 0; i < ARRAY_SIZE; i++) {
        data[i] = i & 0xFF;
    }
    
    // Sequential access
    uint64_t checksum = 0;
    for (int i = 0; i < ARRAY_SIZE; i++) {
        checksum += data[i];
    }
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    uint64_t elapsed = (end.tv_sec - start.tv_sec) * 1000000000UL + 
                      (end.tv_nsec - start.tv_nsec);
    
    // Prevent compiler from optimizing away the work
    volatile uint64_t result = checksum + elapsed;
    return result & 1;
}

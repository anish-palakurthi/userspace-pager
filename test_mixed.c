
// test_mixed.c - Tests mixed access patterns
#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE (1024 * 1024)  // 1MB chunks
#define NUM_CHUNKS 10

static int data_array[CHUNK_SIZE * NUM_CHUNKS];

int main() {
    long sum = 0;
    
    // Sequential access
    for (int i = 0; i < CHUNK_SIZE; i++) {
        data_array[i] = i;
        sum += data_array[i];
    }
    
    // Strided access
    for (int i = 0; i < CHUNK_SIZE * NUM_CHUNKS; i += 4096) {
        data_array[i] = i;
        sum += data_array[i];
    }
    
    // Localized random access
    for (int chunk = 0; chunk < NUM_CHUNKS; chunk++) {
        int base = chunk * CHUNK_SIZE;
        for (int i = 0; i < 1000; i++) {
            int offset = rand() % CHUNK_SIZE;
            data_array[base + offset] = i;
            sum += data_array[base + offset];
        }
    }
    
    printf("Final sum: %ld\n", sum);
    return 0;
}
// test_random.c - Tests random access patterns
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define ARRAY_SIZE (8 * 1024 * 1024)  // 32MB

int main() {
    static int large_array[ARRAY_SIZE];
    srand(time(NULL));
    
    // Random access pattern
    long sum = 0;
    for (int i = 0; i < 1000000; i++) {
        int index = rand() % ARRAY_SIZE;
        large_array[index] = i;
        sum += large_array[index];
    }
    
    printf("Sum: %ld\n", sum);
    return 0;
}

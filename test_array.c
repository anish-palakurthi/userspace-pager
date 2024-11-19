// test_array.c - Tests sequential memory access pattern
#include <stdio.h>
#include <stdlib.h>

#define ARRAY_SIZE (10 * 1024 * 1024)  // 10MB to span multiple pages

int main() {
    int *array = malloc(ARRAY_SIZE * sizeof(int));
    if (!array) {
        fprintf(stderr, "Allocation failed\n");
        return 1;
    }
    
    // Sequential access - good for testing prediction
    long sum = 0;
    for (int i = 0; i < ARRAY_SIZE; i++) {
        array[i] = i;
        sum += array[i];
    }
    
    printf("Sum: %ld\n", sum);
    free(array);
    return 0;
}
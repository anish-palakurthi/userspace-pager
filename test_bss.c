
// test_bss.c - Tests BSS segment handling
#include <stdio.h>

// Large BSS arrays
static int huge_array1[5 * 1024 * 1024];  // 20MB BSS
static int huge_array2[5 * 1024 * 1024];  // Another 20MB BSS

int main() {
    // Initialize first array sequentially
    for (int i = 0; i < 5 * 1024 * 1024; i++) {
        huge_array1[i] = i;
    }
    
    // Access second array with jumps to test prediction
    long sum = 0;
    for (int i = 0; i < 5 * 1024 * 1024; i += 1024) {
        huge_array2[i] = huge_array1[i];
        sum += huge_array2[i];
    }
    
    printf("Sum: %ld\n", sum);
    return 0;
}
#include <stdint.h>
#include <time.h>

#define MATRIX_SIZE 1024
static uint32_t matrix_a[MATRIX_SIZE][MATRIX_SIZE];
static uint32_t matrix_b[MATRIX_SIZE][MATRIX_SIZE];
static uint32_t matrix_c[MATRIX_SIZE][MATRIX_SIZE];

void initialize_matrices() {
    for (int i = 0; i < MATRIX_SIZE; i++) {
        for (int j = 0; j < MATRIX_SIZE; j++) {
            matrix_a[i][j] = (i + j) & 0xFF;
            matrix_b[i][j] = (i * j) & 0xFF;
            matrix_c[i][j] = 0;
        }
    }
}

void matrix_multiply() {
    for (int i = 0; i < MATRIX_SIZE; i++) {
        for (int j = 0; j < MATRIX_SIZE; j++) {
            uint32_t sum = 0;
            for (int k = 0; k < MATRIX_SIZE; k++) {
                sum += matrix_a[i][k] * matrix_b[k][j];
            }
            matrix_c[i][j] = sum;
        }
    }
}

int main() {
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    initialize_matrices();
    matrix_multiply();
    
    // Verification pass
    uint64_t checksum = 0;
    for (int i = 0; i < MATRIX_SIZE; i++) {
        for (int j = 0; j < MATRIX_SIZE; j++) {
            checksum += matrix_c[i][j];
        }
    }
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    uint64_t elapsed = (end.tv_sec - start.tv_sec) * 1000000000UL + 
                      (end.tv_nsec - start.tv_nsec);
    
    volatile uint64_t result = checksum + elapsed;
    return result & 1;
}
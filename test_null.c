// test_null.c - Tests proper handling of invalid memory access
#include <stdio.h>

int main() {
    int *ptr = NULL;
    return *ptr;  // Should cause segfault
}

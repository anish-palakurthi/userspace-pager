#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
    printf("Starting null pointer test (argc=%d)\n", argc);
    fflush(stdout);
    
    int *ptr = NULL;
    printf("About to dereference null pointer\n");
    fflush(stdout);
    
    return *ptr;  // This should cause a segfault
}
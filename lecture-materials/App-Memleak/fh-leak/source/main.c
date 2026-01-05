#include <stdio.h>
#include <stdlib.h>


#include <stdio.h>
#include <stdlib.h>

int file_handle_leak(const char* filename, int iterations) {
    for (int i = 0; i < iterations; i++) {
        FILE* fp = fopen(filename, "w");
        if (!fp) {
            perror("Failed to open file");
            return -1;
        }
        //...
    }
    return 0;
}

int main() {
    if (file_handle_leak("example.txt", 500000) != 0) {
        return -1;
    }
    //...
    return 0;
}




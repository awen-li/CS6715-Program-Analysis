#include <stdio.h>
#include <stdlib.h>

void process(int idx) {
    int values[4] = {10, 20, 30, 40};
    int result = 0;

    if (idx < 0) {
        printf("invalid index\n");
        return;
    }

    result = values[idx];
    printf("result = %d\n", result);
    values[idx] = idx * 10;
}

int main(int argc, char *argv[]) {
    int idx;

    if (argc < 2) {
        printf("usage: %s <idx>\n", argv[0]);
        return 1;
    }

    idx = atoi(argv[1]);
    process(idx);
    return 0;
}

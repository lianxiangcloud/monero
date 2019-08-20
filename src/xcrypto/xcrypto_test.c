#include <stdio.h>
#include <stdint.h>
#include "xcrypto.h"

int main(int argc, char **argv) {
    uint8_t data[100];
    int i;
    for (i = 0; i < 100; i++) {
        data[i] = i;
    }

    hash_t hash;
    int ret = x_cn_fast_hash(data, sizeof(data), hash);
    printf("x_cn_fast_hash: ret=%d\nhash:\n", ret);
    for (i = 0; i < X_HASH_SIZE; i++) {
        printf("0x%02x ", (unsigned char)(hash[i]));
    }
    printf("\n");

    return 0;
}
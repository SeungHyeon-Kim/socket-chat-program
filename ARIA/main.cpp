#include <iostream>
#include "aria_gcm.h"

using cuint8_t = const uint8_t;
void dump_bytes(const uint8_t *, const int);

int main(int argc, char **argv) {
    cuint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, 
               p[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    uint8_t    c[16] ;


    ARIA aria;
    aria.init(key);
    aria.encrypt(p, c);

    dump_bytes(c, 16);

    return 0;
}

void dump_bytes(const uint8_t *src, const int size) {
    for (int i = 0; i < size; i++) {
        printf("%02x", src[i]);
    }
    printf("\n");
}
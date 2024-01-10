#include "aria_gcm.h"

static 
inline void xor128(uint8_t *x, const uint8_t *y) {
    x[ 0] ^= y[ 0]; x[ 1] ^= y[ 1]; x[ 2] ^= y[ 2]; x[ 3] ^= y[ 3];
    x[ 4] ^= y[ 4]; x[ 5] ^= y[ 5]; x[ 6] ^= y[ 6]; x[ 7] ^= y[ 7];
    x[ 8] ^= y[ 8]; x[ 9] ^= y[ 9]; x[10] ^= y[10]; x[11] ^= y[11];
    x[12] ^= y[12]; x[13] ^= y[13]; x[14] ^= y[14]; x[15] ^= y[15];
}

static 
inline void rshift128(uint8_t *x, const size_t n) {
    x[15] = (x[15] >> n) ^ (x[14] << (8 - n));
    x[14] = (x[14] >> n) ^ (x[13] << (8 - n));
    x[13] = (x[13] >> n) ^ (x[12] << (8 - n));
    x[12] = (x[12] >> n) ^ (x[11] << (8 - n));
    x[11] = (x[11] >> n) ^ (x[10] << (8 - n));
    x[10] = (x[10] >> n) ^ (x[ 9] << (8 - n));
    x[ 9] = (x[ 9] >> n) ^ (x[ 8] << (8 - n));
    x[ 8] = (x[ 8] >> n) ^ (x[ 7] << (8 - n));
    x[ 7] = (x[ 7] >> n) ^ (x[ 6] << (8 - n));
    x[ 6] = (x[ 6] >> n) ^ (x[ 5] << (8 - n));
    x[ 5] = (x[ 5] >> n) ^ (x[ 4] << (8 - n));
    x[ 4] = (x[ 4] >> n) ^ (x[ 3] << (8 - n));
    x[ 3] = (x[ 3] >> n) ^ (x[ 2] << (8 - n));
    x[ 2] = (x[ 2] >> n) ^ (x[ 1] << (8 - n));
    x[ 1] = (x[ 1] >> n) ^ (x[ 0] << (8 - n));
    x[ 0] = (x[ 0] >> n);
}

static
inline void counter_inc(uint8_t *ctr, const int n) {
    int i, j;

    for (i = 0; i < n; i++) {
        j = 16;
        do {
            if (++ctr[--j]) {
                break;
            }
        } while (j);
    }
}

void ARIA_GCM::counter_enc(const uint8_t *in, const int num_block, const int remains, const int offset, uint8_t *out) noexcept {
    int i, j;
    uint8_t ctr[16], temp[16];

    std::memcpy(ctr, this->ctr, 16);

    if (offset) { 
        counter_inc(ctr, offset);
    }

    for (i = 0; i < num_block; i++) {
        counter_inc(ctr, 1);
        encrypt(ctr, temp);
        for (j = 0; j < 16; j++) { 
            out[(16*i) + j] = in[(16*i) + j] ^ temp[j];
        }
    }

    if (remains) {
        counter_inc(ctr, 1);
        encrypt(ctr, temp);
        for (j = 0; j < remains; j++) { 
            out[(16*i) + j] = in[(16*i) + j] ^ temp[j];
        }
    }
}

void ARIA_GCM::mul_h(uint8_t *x) noexcept {
    uint8_t t[16]{0x00, }, z[16]{0x00, };
    int i = 0;

    std::memcpy(t, h, 16);

    do {
        if ((x[i >> 3] >> (7 - (i % 8))) & 0x1) {
            xor128(z, t);
        }

        if (t[15] & 0x1) {
            rshift128(t, 1);
            t[0] ^= 0xe1;
        }
        else {
            rshift128(t, 1);
        }
    } while (++i < 128);

    std::memcpy(x, z, 16);
}

void ARIA_GCM::ghash(const uint8_t *src, const int len_src, const uint8_t *prev, uint8_t *dst) noexcept {
    int i, n = len_src;
    uint8_t temp[16]{0};

    if (prev) {
        std::memcpy(temp, prev, 16);
    }

    while (n > 15) {
        xor128(temp, src);
        mul_h(temp);
        
        src += 16;
        n   -= 16;
    }

    if (n > 0) {
        for (i = 0; i < n; i++) {
            temp[i] ^= src[i];
        }

        mul_h(temp);
    }
    
    std::memcpy(dst, temp, 16);
}

void ARIA_GCM::init(const uint8_t *key, const uint8_t *nonce) {
    uint8_t temp[32]{};

    ARIA::init(key);    // aria
    encrypt(temp, h);   // H
    
    /*
        COUNTER-0
         1. N( 96bits): N|0^31|1
         2. N(!96bits): GHASH(H, N|0^s|len(N))
    */
    #if   (NONCE_BITS == 96)
    std::memcpy(ctr, nonce, (NONCE_BITS / 8));
    ctr[15] = 0x01;
    #elif (NONCE_BITS > 7 && NONCE_BITS < 129 && (NONCE_BITS % 8) == 0)
    std::memcpy(temp, nonce, (NONCE_BITS / 8));
    temp[31] = NONCE_BITS;
    ghash(temp, 32, nullptr, ctr);
    #else
    return;
    #endif

    encrypt(ctr, y);    // Y
}

void ARIA_GCM::auth_enc(const uint8_t *p, const int p_size, const uint8_t *ad, const int ad_size, const int tag_size, uint8_t *c, uint8_t *tag) {
    int p_numblocks =  p_size / 16,  p_remains =  p_size % 16;
    int64_t p_bit64 = (int64_t)p_size * 8, ad_bit64 = (int64_t)ad_size * 8;
    uint8_t len[16], temp1[16], temp2[16];

    // lenBlock[Alen64||Clen64]
    for (int i = 0; i < 8; i++) {
        len[i  ] = (ad_bit64 >> (8 * (7-i))) & 0xff;
        len[i+8] = (p_bit64  >> (8 * (7-i))) & 0xff;
    }

    /*
        CTR Encryption
         if USING_THREAD is greater than 1, two threads will be allocated for encryption.
    */
#if (USING_THREAD)
    int ad_numblocks = ad_size / 16, ad_remains = ad_size % 16;
    std::thread thds[2];

    if (p_numblocks >= 32) {
        thds[0] = std::thread(&ARIA_GCM::counter_enc, this, p, p_numblocks/2, 0, 0, c);
        thds[1] = std::thread(&ARIA_GCM::counter_enc, this, p + (p_numblocks/2)*16, p_numblocks - (p_numblocks/2), p_remains, p_numblocks/2, c + (p_numblocks/2)*16);
    } else {
        counter_enc(p, p_numblocks, p_remains, 0, c);
    }

    ghash(ad, ad_size, nullptr, temp1);
    
    if (thds[0].joinable() && thds[1].joinable()) {
        thds[0].join(); thds[1].join();
    }

    ghash(c, p_size, temp1, temp2);
    ghash(len, 16, temp2, temp1);
#else
    // a single thread
    counter_enc(p, p_numblocks, p_remains, 0, c);

    ghash(ad, ad_size, nullptr, temp1);
    ghash(c, p_size, temp1, temp2);
    ghash(len, 16, temp2, temp1);
#endif

    // Tag
    for (int i = 0; i < tag_size; i++) {
        tag[i] = temp1[i] ^ y[i];
    }
}

bool ARIA_GCM::auth_dec(const uint8_t *c, const int c_size, const uint8_t *ad, const int ad_size, const uint8_t *tag, const int tag_size, uint8_t *p) {
    int c_numblocks =  c_size / 16,  c_remains =  c_size % 16;
    int64_t c_bit64 = (int64_t)c_size * 8, ad_bit64 = (int64_t)ad_size * 8;
    uint8_t len[16], temp1[16], temp2[16];

    // lenBlock[Alen64||Clen64]
    for (int i = 0; i < 8; i++) {
        len[i  ] = (ad_bit64 >> (8 * (7-i))) & 0xff;
        len[i+8] = ( c_bit64 >> (8 * (7-i))) & 0xff;
    }

    // GHASH
    ghash(ad, ad_size, nullptr, temp1);
    ghash(c, c_size, temp1, temp2);
    ghash(len, 16, temp2, temp1);

    // Check tag
    for (int i = 0; i < tag_size; i++) { 
        if ((temp1[i] ^ y[i]) != tag[i]) {
            return false;
        }
    }

#if (USING_THREAD)
    int ad_numblocks = ad_size / 16, ad_remains = ad_size % 16;

    if (c_numblocks >= USING_THREAD) {
        std::thread thd1(&ARIA_GCM::counter_enc, this, c, (c_numblocks / 2), 0, 0, p);
        std::thread thd2(&ARIA_GCM::counter_enc, this, (c + ((c_numblocks / 2) * 16)), (c_numblocks - (c_numblocks / 2)), c_remains, (c_numblocks / 2), (p + (c_numblocks / 2) * 16));
        thd1.join(); thd2.join();
    } else {
        counter_enc(c, c_numblocks, c_remains, 0, p);
    }
#else
    // a single thread
    counter_enc(c, c_numblocks, c_remains, 0, p);
#endif

    return true;
}

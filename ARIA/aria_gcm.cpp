#include "aria_gcm.h"

void ARIA_GCM::counter_inc(uint8_t *ctr, const int oper) noexcept {
    for (int i = 0; i < oper; i++) {
        int j = 16;
        do {
            if (++ctr[--j]) { return; }
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

void ARIA_GCM::mul(uint8_t *x, const uint8_t *y) noexcept {
    bool MSB;
    int i, j, k;
    uint8_t temp[16]{0};

    for (i = 0; i < 16; i++) {
        for (j = 7; j >= 0; j--) {
            if ((y[i] >> j) & 0x01) {
                for (k = 0; k < 16; k++) { 
                    temp[k] ^= x[k];
                }
            }

            MSB = x[15] & 0x01;

            for (k = 15; k > 0; k--) { 
                x[k] = (x[k] >> 1 | x[k-1] << 7);
            }
            if (MSB) {
                x[0] ^= 0xe1;
            }
        }
    }

    std::memcpy(x, temp, 16);
}

void ARIA_GCM::ghash(const uint8_t *src, const int num_block, const uint8_t *prev, uint8_t *dst) noexcept {
    int i, j;
    uint8_t temp[16]{0};

    if (prev) {
        std::memcpy(temp, prev, 16);
    }

    for (i = 0; i < num_block; i++) {
        for (j = 0; j < 16; j++) {
            temp[j] ^= src[(16*i) + j];
        }
        
        mul(temp, H);
    }
    
    std::memcpy(dst, temp, 16);
}

void ARIA_GCM::init(const uint8_t *key, const uint8_t *iv, const int iv_size) {
    uint8_t temp[32]{0};

    ARIA::init(key);    // aria
    encrypt(temp, H);   // H

    std::memcpy(ctr, iv, iv_size);
    
    /*
        COUNTER
         1. IV( 96bits): IV|0^31|1
         2. IV(!96bits): GHASH(IV|0^s|len(IV))
    */
    if (iv_size == 12) {
        ctr[15] = 0x01;
    } 
    else {
        for (int i = 0; i < 8; i++) {
            temp[24+i] = (iv_size >> (8 * (7-i))) & 0xff;
        }
        ghash(temp, 2, nullptr, ctr);
    }

    encrypt(ctr, Y);    // Y
}

void ARIA_GCM::auth_enc(const uint8_t *p, const int p_size, const uint8_t *ad, const int ad_size, const int tag_size, uint8_t *c, uint8_t *tag) {
    int  p_numblocks =  p_size / 16,  p_remains =  p_size % 16,
        ad_numblocks = ad_size / 16, ad_remains = ad_size % 16;
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
#if USING_THREAD > 1
    std::thread thds[2];

    if (p_numblocks >= USING_THREAD) {
        thds[0] = std::thread(&ARIA_GCM::counter_enc, this, p, p_numblocks/2, 0, 0, c);
        thds[1] = std::thread(&ARIA_GCM::counter_enc, this, p + (p_numblocks/2)*16, p_numblocks - (p_numblocks/2), p_remains, p_numblocks/2, c + (p_numblocks/2)*16);
    } else {
        counter_enc(p, p_numblocks, p_remains, 0, c);
    }

    if (ad_remains) { ad_numblocks++; }
    if (p_remains) { p_numblocks++; }

    ghash(ad, ad_numblocks, nullptr, temp1);
    
    if (thds[0].joinable() && thds[1].joinable()) {
        thds[0].join(); thds[1].join();
    }

    ghash(c, p_numblocks, temp1, temp2);
    ghash(len, 1, temp2, temp1);
#else
    // a single thread
    counter_enc(p, p_numblocks, p_remains, 0, c);

    if (ad_remains) { ad_numblocks++; }
    if (p_remains) { p_numblocks++; }

    ghash(ad, ad_numblocks, nullptr, temp1);
    ghash(c, p_numblocks, temp1, temp2);
    ghash(len, 1, temp2, temp1);
#endif

    // Tag
    for (int i = 0; i < tag_size; i++) {
        tag[i] = temp1[i] ^ Y[i];
    }
}

bool ARIA_GCM::auth_dec(const uint8_t *c, const int c_size, const uint8_t *ad, const int ad_size, const uint8_t *tag, const int tag_size, uint8_t *p) {
    int  c_numblocks =  c_size / 16,  c_remains =  c_size % 16,
        ad_numblocks = ad_size / 16, ad_remains = ad_size % 16;
    int64_t c_bit64 = (int64_t)c_size * 8, ad_bit64 = (int64_t)ad_size * 8;
    uint8_t len[16], temp1[16], temp2[16];

    // lenBlock[Alen64||Clen64]
    for (int i = 0; i < 8; i++) {
        len[i  ] = (ad_bit64 >> (8 * (7-i))) & 0xff;
        len[i+8] = ( c_bit64 >> (8 * (7-i))) & 0xff;
    }

    // GHASH
    if (ad_remains) { ad_numblocks++; }
    if (c_remains) { c_numblocks++; }

    ghash(ad, ad_numblocks, nullptr, temp1);
    ghash(c, c_numblocks, temp1, temp2);
    ghash(len, 1, temp2, temp1);

    // Check tag
    for (int i = 0; i < tag_size; i++) { 
        if ((temp1[i] ^ Y[i]) != tag[i]) {
            return false;
        }
    }

    c_numblocks = c_size / 16;
#if USING_THREAD > 1
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

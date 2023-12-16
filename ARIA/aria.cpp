#include "aria.h"

static const size_t
 key_bytes = ARIA_KEY_SIZE / 8;

void ARIA::fo(const uint8_t *in, const uint8_t *r_key, uint8_t* out) noexcept {
    uint8_t temp[16];

    for (size_t i = 0; i < 4; i++) { 
        temp[i*4  ] =  S1[(in[i*4  ] ^ r_key[i*4  ])];
        temp[i*4+1] =  S2[(in[i*4+1] ^ r_key[i*4+1])];
        temp[i*4+2] = iS1[(in[i*4+2] ^ r_key[i*4+2])];
        temp[i*4+3] = iS2[(in[i*4+3] ^ r_key[i*4+3])];
    }

    diff_layer(temp, out);
}

void ARIA::fe(const uint8_t *in, const uint8_t *r_key, uint8_t* out) noexcept {
    uint8_t temp[16];
    
    for (size_t i = 0; i < 4; i++) { 
        temp[i*4  ] = iS1[(in[i*4  ] ^ r_key[i*4  ])];
        temp[i*4+1] = iS2[(in[i*4+1] ^ r_key[i*4+1])];
        temp[i*4+2] =  S1[(in[i*4+2] ^ r_key[i*4+2])];
        temp[i*4+3] =  S2[(in[i*4+3] ^ r_key[i*4+3])];
    }

    diff_layer(temp, out);
}

void ARIA::diff_layer(const uint8_t *in, uint8_t* out) noexcept {
    uint8_t temp;

    temp = in[3] ^ in[4] ^ in[9] ^ in[14];
    out[0] = in[6] ^ in[8] ^ in[13] ^ temp;
    out[5] = in[1] ^ in[10] ^ in[15] ^ temp;
    out[11] = in[2] ^ in[7] ^ in[12] ^ temp;
    out[14] = in[0] ^ in[5] ^ in[11] ^ temp;

    temp = in[2] ^ in[5] ^ in[8] ^ in[15];
    out[1] = in[7] ^ in[9] ^ in[12] ^ temp;
    out[4] = in[0] ^ in[11] ^ in[14] ^ temp;
    out[10] = in[3] ^ in[6] ^ in[13] ^ temp;
    out[15] = in[1] ^ in[4] ^ in[10] ^ temp;
    
    temp = in[1] ^ in[6] ^ in[11] ^ in[12];
    out[2] = in[4] ^ in[10] ^ in[15] ^ temp;
    out[7] = in[3] ^ in[8] ^ in[13] ^ temp;
    out[9] = in[0] ^ in[5] ^ in[14] ^ temp;
    out[12] = in[2] ^ in[7] ^ in[9] ^ temp;
    
    temp = in[0] ^ in[7] ^ in[10] ^ in[13];
    out[3] = in[5] ^ in[11] ^ in[14] ^ temp;
    out[6] = in[2] ^ in[9] ^ in[12] ^ temp;
    out[8] = in[1] ^ in[4] ^ in[15] ^ temp;
    out[13] = in[3] ^ in[6] ^ in[8] ^ temp;
}

void ARIA::shift_xor(const uint8_t *src_x, const uint8_t *src_y, const int shift, const int r) noexcept {
    int i, qu = shift / 8, re = shift % 8;

    for (i = 0; i < 16; i++) {
        rkeys[r][(i + qu    ) % 16] ^= (src_y[i] >> (    re));
        rkeys[r][(i + qu + 1) % 16] ^= (src_y[i] << (8 - re));
    }

    for (i = 0; i < 16; i++) { 
        rkeys[r][i] ^= src_x[i];
    }
}

void ARIA::init(const uint8_t *key) {
    int i;
    uint8_t KL[16], KR[16]{0}, W0[16], W1[16], W2[16], W3[16];
    
    for (i = 0; i < 16; i++) { 
        KL[i] = W0[i] = key[i];
    }
    for (; i < key_bytes; i++) { 
        KR[i-16] = key[i];
    }

    fo(W0, K[0], W1);
    for (i = 0; i < 16; i++) { 
        W1[i] ^= KR[i];
    }
    fe(W1, K[1], W2);
    for (i = 0; i < 16; i++) { 
        W2[i] ^= W0[i];
    }
    fo(W2, K[2], W3);
    for (i = 0; i < 16; i++) { 
        W3[i] ^= W1[i];
    }

    shift_xor(W0, W1, 19,  0); shift_xor(W1, W2, 19,  1); shift_xor(W2, W3, 19,  2);
    shift_xor(W3, W0, 19,  3); shift_xor(W0, W1, 31,  4); shift_xor(W1, W2, 31,  5);
    shift_xor(W2, W3, 31,  6); shift_xor(W3, W0, 31,  7);
    shift_xor(W0, W1, 67,  8); shift_xor(W1, W2, 67,  9); shift_xor(W2, W3, 67, 10);
    shift_xor(W3, W0, 67, 11); shift_xor(W0, W1, 97, 12);

    #if ARIA_ROUNDS > 12        // 192
    shift_xor(W1, W2, 97, 13); shift_xor(W2, W3, 97, 14);
    #endif
    #if ARIA_ROUNDS > 14        // 256
    shift_xor(W3, W0, 97, 15); shift_xor(W0, W1, 109, 16);
    #endif
}

void ARIA::encrypt(const uint8_t *in, uint8_t *out) noexcept {
    int i, j;
    uint8_t state[16], temp[16]{};

    std::memcpy(state, in, 16);

    // Fo -> Fe -> ... -> Fo
    for (i = 0; i < ARIA_ROUNDS-1; i++) { 
        (i % 2 == 0) ? fo(state, rkeys[i], temp) : fe(temp, rkeys[i], state);
    }

    // Ff
    for (j = 0; j < 4; j++)
    {
        temp[j*4  ] = (iS1[temp[j*4  ] ^ rkeys[i][j*4  ]]) ^ rkeys[ARIA_ROUNDS][j*4  ];
        temp[j*4+1] = (iS2[temp[j*4+1] ^ rkeys[i][j*4+1]]) ^ rkeys[ARIA_ROUNDS][j*4+1];
        temp[j*4+2] = ( S1[temp[j*4+2] ^ rkeys[i][j*4+2]]) ^ rkeys[ARIA_ROUNDS][j*4+2];
        temp[j*4+3] = ( S2[temp[j*4+3] ^ rkeys[i][j*4+3]]) ^ rkeys[ARIA_ROUNDS][j*4+3];
    }

    std::memcpy(out, temp, 16);
}

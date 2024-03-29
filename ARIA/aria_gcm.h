#ifndef ARIA_GCM_H
#define ARIA_GCM_H

#include "aria.h"

/*
    The bit size of nonce, when initializing the CTR-0
     - 8 ~ 128
*/
#define NONCE_BITS     128

/*
    Using thread
     - 0: single
     - 1: multi-thread
*/
#define USING_THREAD    0

#if USING_THREAD
#include <thread>
#endif

class ARIA_GCM : public ARIA {
    private:
    uint8_t ctr[ARIA_BLOCK_SIZE]{};
    uint8_t h[ARIA_BLOCK_SIZE]{};
    uint8_t y[ARIA_BLOCK_SIZE]{};

    void counter_enc(const uint8_t *in, const int num_block, const int remains, const int offset, uint8_t *out) noexcept;
    void mul_h(uint8_t *x) noexcept;
    void ghash(const uint8_t *src, const int num_block, const uint8_t *prev, uint8_t *dst) noexcept;
    
    public:
    /**
     * \brief           Generate ARIA round keys and CTR, H and Y for GCM
     * \param key       16, 24 or 32 bytes key (before running, set a key size in "aria.h")
     * \param iv        iv
     * \param iv_size   byte size of iv
    */
    void init(const uint8_t *key, const uint8_t *nonce);
    
    /**
     * \brief           Authenticated encryption with associated data.
     * \param p         plaintext
     * \param p_size    byte size of p
     * \param ad        associated data
     * \param ad_size   byte size of associated data
     * \param tag_size  tag output size
     * \param c         ciphertext
     * \param tag       tag
    */
    void auth_enc(const uint8_t *p, const int p_size, const uint8_t *ad, const int ad_size, const int tag_size, uint8_t *c, uint8_t *tag);
    
    /**
     * \brief           Authenticated decryption with associated data.
     * \param c         ciphertext
     * \param c_size    byte size of c
     * \param ad        associated data
     * \param ad_size   byte size of associated data
     * \param tag       tag
     * \param tag_size  byte size of tag
     * \param p         plaintext
     * \return          tag == tag' ? true : false
    */
    bool auth_dec(const uint8_t *c, const int c_size, const uint8_t *ad, const int ad_size, const uint8_t *tag, const int tag_size, uint8_t *p);
};

#endif /* ARIA_GCM_H */

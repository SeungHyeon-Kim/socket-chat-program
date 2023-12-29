/*
    test.cpp

    ARIA GCM
     implementation accuracy test
*/

#include <iostream>
#include <fstream>
#include <sstream>
#include "aria_gcm.h"

using cuint8_t = const uint8_t;

uint8_t temp_t[1024]{}, temp_c[1024]{};
uint8_t *k, *i, *p, *c, *a, *t;
std::string key = "CEA56A6ED8EE9EEA60A1E144260F995B",
             iv = "5F293AE6B580680890705C25949788F3",
             pt = "6B8C7ED4C4CE0E639BFBAE4CBB432062821B4EEBE536793EB3B192911E8EE80C776304223953D120493E01067C35AB975A3139AC220481CD0E8F3202D73672E77C91C5FF4064314AF1D2A01A70CD85226ED1C2D074D2CADD26730222C8786EAD017E8914DFE974091C1F532FA0F4F52C4664B300E3889A9585C3CC96F83D2385",
             ct = "14f92a75522f268d11a732d47dc789429e39a7fb0c83e6654fad80c81f0d1940551768e96fdd532493b3f04216df63ed6c4553995a31c20d04c9ebdb213a108504ebd58709e3740c64e01fd376648034659104515df532344db8ee8ccb2279a80521aa223751262008345cc9deee13a9fc438c930cdf6808bff9e2edba354cda",
             ad = "8F92180820CBE384518DE4ED129042DD6B53D2E3780E3A1DB2E956096F6BDA98AD3539840BF0C6E4188419FED08AB55C6405E8223A4CF29E354B692136EBDB0DE3CFB630A7416550F96CBC07E2CB96D2B9E1BC64322B09409753CC8654A66E0DB9C855B3FCA607F17DAD93B34E3A2D66F35118526691C92A5F6749E1D183DBC0",
            tag = "0E0F8C3A48231D60FABD9687CD";

uint8_t *string_to_binary(const std::string &);
void dump_bytes(const uint8_t *, const int);

int main(int argc, char **argv) {
    k = string_to_binary(key);
    i = string_to_binary(iv);
    p = string_to_binary(pt);
    c = string_to_binary(ct);
    a = string_to_binary(ad);
    t = string_to_binary(tag);

    ARIA_GCM aria;
    aria.init(k, i);

    dump_bytes(p, 128); printf("\n");
    
    aria.auth_enc(p, 128, a, 128, 13, temp_c, temp_t);
    if (!std::memcmp(temp_c, c, 128)) {
        std::cout << "encryption: true.\n";
    }
    if (!std::memcmp(temp_t, t, 13)) {
        std::cout << "tag: true.\n";
    }

    aria.auth_dec(temp_c, 128, a, 128, temp_t, 13, temp_t);
    if (!std::memcmp(temp_t, p, 128)) {
        std::cout << "decryption: true.\n";
    }

    delete[] k; delete[] i; delete[] p; delete[] c; delete[] a; delete[] t;
    return 0;
}


void dump_bytes(const uint8_t *src, const int size) {
    for (int i = 0; i < size; i++) {
        printf("%02x", src[i]);
    }
    printf("\n");
}

uint8_t *string_to_binary(const std::string &hex) {
    const size_t len = hex.length();
    uint8_t *ret = new uint8_t[len / 2];
    
    for (size_t i = 0; i < len; i += 2) {
        ret[i/2] = static_cast<char>(std::stoi(hex.substr(i, 2), nullptr, 16));
    }

    return ret;
}
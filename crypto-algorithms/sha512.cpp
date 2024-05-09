#include "sha512.hpp"

#define Ch(x, y, z) ((x & (y ^ z)) ^ z)
#define Maj(x, y, z) ((x & (y | z)) | (y & z))
#define SHR(x, n) (x >> n)
#define ROTR32(X, B) rotr32((X), (B))
#define ROTR(x, n) ROTR32(x, n)
#define S0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define S1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define s0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define s1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))

#define RND(a, b, c, d, e, f, g, h, k) \
    h += S1(e) + Ch(e, f, g) + k;      \
    d += h;                            \
    h += S0(a) + Maj(a, b, c);

#define RNDr(S, W, i, ii)                                                   \
    RND(S[(64 - i) % 8], S[(65 - i) % 8], S[(66 - i) % 8], S[(67 - i) % 8], \
        S[(68 - i) % 8], S[(69 - i) % 8], S[(70 - i) % 8], S[(71 - i) % 8], \
        W[i + ii] + Krnd[i + ii])

#define MSCH(W, ii, i) \
    W[i + ii + 16] =   \
        s1(W[i + ii + 14]) + W[i + ii + 9] + s0(W[i + ii + 1]) + W[i + ii]


namespace{

const uint32_t Krnd[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

std::uint64_t load64_be(const uint8_t src[8]){
    std::uint64_t ret = 0;
    for (size_t i = 0; i < sizeof(ret); i++){
        ret <<= 8;
        ret |= src[i];
    }
    return ret;
}

void store64_be(uint8_t dst[8], uint64_t n){
    for (size_t i = sizeof(n); i--;){
        dst[i] = n & 0xFF;
        n >>= 8;
    }
}

uint32_t rotr32(const uint32_t x, const int b){
    return (x >> b) | (x << (32 - b));
}

void be64dec_vect(uint64_t *dst, const unsigned char *src, size_t len){
    for (size_t i = 0; i < len / 8; i++) 
        dst[i] = load64_be(src + i * 8);
}

void SHA512_Transform(uint64_t *state, const uint8_t block[128], uint64_t W[80], uint64_t S[8]){
    int i;

    be64dec_vect(W, block, 128);
    memcpy(S, state, 64);
    for (i = 0; i < 80; i += 16) {
        RNDr(S, W, 0, i);
        RNDr(S, W, 1, i);
        RNDr(S, W, 2, i);
        RNDr(S, W, 3, i);
        RNDr(S, W, 4, i);
        RNDr(S, W, 5, i);
        RNDr(S, W, 6, i);
        RNDr(S, W, 7, i);
        RNDr(S, W, 8, i);
        RNDr(S, W, 9, i);
        RNDr(S, W, 10, i);
        RNDr(S, W, 11, i);
        RNDr(S, W, 12, i);
        RNDr(S, W, 13, i);
        RNDr(S, W, 14, i);
        RNDr(S, W, 15, i);
        if (i == 64) {
            break;
        }
        MSCH(W, 0, i);
        MSCH(W, 1, i);
        MSCH(W, 2, i);
        MSCH(W, 3, i);
        MSCH(W, 4, i);
        MSCH(W, 5, i);
        MSCH(W, 6, i);
        MSCH(W, 7, i);
        MSCH(W, 8, i);
        MSCH(W, 9, i);
        MSCH(W, 10, i);
        MSCH(W, 11, i);
        MSCH(W, 12, i);
        MSCH(W, 13, i);
        MSCH(W, 14, i);
        MSCH(W, 15, i);
    }
    for (i = 0; i < 8; i++) {
        state[i] += S[i];
    }
}

const uint8_t PAD[128] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

void be64enc_vect(unsigned char *dst, const uint64_t *src, size_t len){
    for (size_t i = 0; i < len / 8; i++)
        store64_be(dst + i * 8, src[i]);
}

}

namespace hash {

namespace digest {

SHA512::SHA512(const std::string &digest): SHA512(digest.c_str(), digest.size()){}

SHA512::SHA512(const char *digest, size_t size){
    this->digest = utility::hex_string_to_buffer<this->size>(digest, size);
}

int SHA512::cmp(const SHA512 &other) const{
    return memcmp(this->digest.data(), other.digest.data(), this->digest.size());
}

SHA512::operator std::string() const {
    return detail::to_string(*this);
}

void SHA512::write_to_char_array(char(&array)[string_size]) const {
    detail::write_to_char_array<SHA512>(array, this->digest);
}

void SHA512::write_to_char_vector(std::vector<char> &s) const {
    detail::write_to_char_vector(s, *this);
}

}

namespace algorithm{

void SHA512::reset() noexcept {
    size_t i = 0;
    this->state[i++] = 0x6a09e667f3bcc908ULL;
    this->state[i++] = 0xbb67ae8584caa73bULL;
    this->state[i++] = 0x3c6ef372fe94f82bULL;
    this->state[i++] = 0xa54ff53a5f1d36f1ULL;
    this->state[i++] = 0x510e527fade682d1ULL;
    this->state[i++] = 0x9b05688c2b3e6c1fULL;
    this->state[i++] = 0x1f83d9abfb41bd6bULL;
    this->state[i++] = 0x5be0cd19137e2179ULL;
    this->count[0] = 0;
    this->count[1] = 0;
    memset(this->buf, 0, sizeof(this->buf));
}

void SHA512::update(const void *buffer, size_t length) noexcept{
    if (!length)
        return;

    uint64_t tmp64[80 + 8];
    uint64_t bitlen[2];

    auto r = (unsigned long long) ((this->count[1] >> 3) & 0x7f);

    bitlen[1] = ((uint64_t)length) << 3;
    bitlen[0] = ((uint64_t)length) >> 61;
    /* LCOV_EXCL_START */
    if ((this->count[1] += bitlen[1]) < bitlen[1])
        this->count[0]++;
    /* LCOV_EXCL_STOP */
    this->count[0] += bitlen[0];

    auto in = (const std::uint8_t *)buffer;

    if (length < 128 - r){
        for (size_t i = 0; i < length; i++)
            this->buf[r + i] = in[i];
        return;
    }
    for (size_t i = 0; i < 128 - r; i++)
        this->buf[r + i] = in[i];
    SHA512_Transform(this->state, this->buf, &tmp64[0], &tmp64[80]);
    in += 128 - r;
    length -= 128 - r;

    while (length >= 128) {
        SHA512_Transform(this->state, in, &tmp64[0], &tmp64[80]);
        in += 128;
        length -= 128;
    }
    length &= 127;
    for (size_t i = 0; i < length; i++) {
        this->buf[i] = in[i];
    }
    memset(tmp64, 0, sizeof(tmp64));
}

digest::SHA512 SHA512::get_digest() noexcept{
    uint64_t tmp64[80 + 8];

    digest::SHA512::digest_t ret;

    {
        unsigned int r;
        unsigned int i;

        r = (unsigned int)((this->count[1] >> 3) & 0x7f);
        if (r < 112) {
            for (i = 0; i < 112 - r; i++) {
                this->buf[r + i] = PAD[i];
            }
        }
        else {
            for (i = 0; i < 128 - r; i++) {
                this->buf[r + i] = PAD[i];
            }
            SHA512_Transform(this->state, this->buf, &tmp64[0], &tmp64[80]);
            memset(&this->buf[0], 0, 112);
        }
        be64enc_vect(&this->buf[112], this->count, 16);
        SHA512_Transform(this->state, this->buf, &tmp64[0], &tmp64[80]);
    }
    be64enc_vect(ret.data(), this->state, 64);
    memset(tmp64, 0, sizeof(tmp64));
    memset(this->state, 0, sizeof(this->state));
    memset(this->count, 0, sizeof(this->count));
    memset(this->buf, 0, sizeof(this->buf));

    return ret;
}

}

}

#include "sha512.hpp"

#define Ch(x, y, z) ((x & (y ^ z)) ^ z)
#define Maj(x, y, z) ((x & (y | z)) | (y & z))
#define SHR(x, n) (x >> n)
#define ROTR64(X, B) rotr64((X), (B))
#define ROTR(x, n) ROTR64(x, n)
#define S0(x) (ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39))
#define S1(x) (ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41))
#define s0(x) (ROTR(x, 1) ^ ROTR(x, 8) ^ SHR(x, 7))
#define s1(x) (ROTR(x, 19) ^ ROTR(x, 61) ^ SHR(x, 6))

//#define RND(a, b, c, d, e, f, g, h, k) \
//    h += S1(e) + Ch(e, f, g) + k;      \
//    d += h;                            \
//    h += S0(a) + Maj(a, b, c);

//#define RNDr(S, W, i, ii)                                                   \
//    RND(S[(64 - i) % 8], S[(65 - i) % 8], S[(66 - i) % 8], S[(67 - i) % 8], \
//        S[(68 - i) % 8], S[(69 - i) % 8], S[(70 - i) % 8], S[(71 - i) % 8], \
//        W[i + ii] + Krnd[i + ii])

//#define MSCH(W, ii, i) \
//    W[i + ii + 16] =   \
//        s1(W[i + ii + 14]) + W[i + ii + 9] + s0(W[i + ii + 1]) + W[i + ii]

namespace{

const uint64_t Krnd[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
    0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
    0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
    0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
    0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
    0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
    0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
    0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
    0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
    0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
    0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
    0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
    0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
    0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
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

uint64_t rotr64(const uint64_t x, const int b){
    return (x >> b) | (x << (64 - b));
}

void be64dec_vect(uint64_t *dst, const unsigned char *src, size_t len){
    for (size_t i = 0; i < len / 8; i++) 
        dst[i] = load64_be(src + i * 8);
}

//#define RND(a, b, c, d, e, f, g, h, k) \
//    h += S1(e) + Ch(e, f, g) + k;      \
//    d += h;                            \
//    h += S0(a) + Maj(a, b, c);

void RND(std::uint64_t a, std::uint64_t b, std::uint64_t c, std::uint64_t &d, std::uint64_t e, std::uint64_t f, std::uint64_t g, std::uint64_t &h, std::uint64_t k){
    h += S1(e) + Ch(e, f, g) + k;
	d += h;
	h += S0(a) + Maj(a, b, c);
}

void RNDr(std::uint64_t *S, std::uint64_t *W, size_t i, size_t ii) {
    RND(S[(80 - i) % 8], S[(81 - i) % 8], S[(82 - i) % 8], S[(83 - i) % 8], S[(84 - i) % 8], S[(85 - i) % 8], S[(86 - i) % 8], S[(87 - i) % 8], W[i + ii] + Krnd[i + ii]);
}

void MSCH(std::uint64_t *W, size_t ii, size_t i) {
    W[i + ii + 16] = s1(W[i + ii + 14]) + W[i + ii + 9] + s0(W[i + ii + 1]) + W[i + ii];
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
        }else{
            for (i = 0; i < 128 - r; i++) {
                this->buf[r + i] = PAD[i];
            }
            SHA512_Transform(this->state, this->buf, tmp64, tmp64 + 80);
            memset(this->buf, 0, 112);
        }
        be64enc_vect(this->buf + 112, this->count, 16);
        SHA512_Transform(this->state, this->buf, tmp64, tmp64 + 80);
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

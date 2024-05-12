#include "sha512.hpp"

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

uint64_t rotate_right(const uint64_t x, const int b){
    return (x >> b) | (x << (64 - b));
}

void be64dec_vect(uint64_t *dst, const unsigned char *src, size_t len){
    for (size_t i = 0; i < len / 8; i++) 
        dst[i] = load64_be(src + i * 8);
}

std::uint64_t xor_rotate_shift(std::uint64_t x, int a, int b, int c){
    return rotate_right(x, a) ^ rotate_right(x, b) ^ (x >> c);
}

std::uint64_t xor_rotate(std::uint64_t x, int a, int b, int c){
    return rotate_right(x, a) ^ rotate_right(x, b) ^ rotate_right(x, c);
}

std::uint64_t s0(std::uint64_t x){
    return xor_rotate_shift(x, 1, 8, 7);
}

std::uint64_t s1(std::uint64_t x){
    return xor_rotate_shift(x, 19, 61, 6);
}

std::uint64_t S0(std::uint64_t x){
    return xor_rotate(x, 28, 34, 39);
}

std::uint64_t S1(std::uint64_t x){
    return xor_rotate(x, 14, 18, 41);
}

std::uint64_t ch(std::uint64_t x, std::uint64_t y, std::uint64_t z){
	return (x & y) ^ (~x & z);
}

std::uint64_t maj(std::uint64_t x, std::uint64_t y, std::uint64_t z){
	return (x & (y | z)) | (y & z);
}

void RND(
		std::uint64_t  a,
		std::uint64_t  b,
		std::uint64_t  c,
		std::uint64_t &d,
		std::uint64_t  e,
		std::uint64_t  f,
		std::uint64_t  g,
		std::uint64_t &h,
		std::uint64_t  k
){
    h += S1(e) + ch(e, f, g) + k;
	d += h;
	h += S0(a) + maj(a, b, c);
}

void RNDr(std::uint64_t (&S)[8], const std::uint64_t (&W)[80], size_t i, size_t j) {
    RND(
        S[(80 - i) % 8],
        S[(81 - i) % 8],
        S[(82 - i) % 8],
        S[(83 - i) % 8],
        S[(84 - i) % 8],
        S[(85 - i) % 8],
        S[(86 - i) % 8],
        S[(87 - i) % 8],
        W[i + j] + Krnd[i + j]
    );
}

void MSCH(std::uint64_t (&W)[80], size_t i, size_t j) {
    W[j + i + 16] = s1(W[j + i + 14]) + W[j + i + 9] + s0(W[j + i + 1]) + W[j + i];
}

const uint8_t PAD[128] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

void be64enc_vect(unsigned char *dst, const std::uint64_t *src, size_t len){
    for (size_t i = 0; i < len / 8; i++)
        store64_be(dst + i * 8, src[i]);
}

void transform_part_a(size_t i, std::uint64_t (&W)[80], std::uint64_t (&S)[8]){
	for (size_t j = 0; j < 16; j++)
		RNDr(S, W, j, i);
}

void transform_part_b(size_t i, std::uint64_t (&W)[80]){
	for (size_t j = 0; j < 16; j++)
		MSCH(W, j, i);
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
    this->count = 0;
    memset(this->buf, 0, sizeof(this->buf));
}

void SHA512::transform(const uint8_t block[128], std::uint64_t (&W)[80], std::uint64_t (&S)[8]) noexcept{
    be64dec_vect(W, block, 128);
    memcpy(S, this->state, 8 * sizeof(std::uint64_t));
    for (size_t i = 0; i < 64; i += 16){
        transform_part_a(i, W, S);
        transform_part_b(i, W);
    }
    transform_part_a(64, W, S);
    for (size_t i = 0; i < 8; i++)
        this->state[i] += S[i];
}

void SHA512::update(const void *void_buffer, size_t length) noexcept{
    if (!length)
        return;

    std::uint64_t temp_a[80];
    std::uint64_t temp_b[8];
    auto r = this->count % 128;

    this->count += length;

    auto buffer = (const std::uint8_t *)void_buffer;

    auto delta = 128 - r;
    if (length < delta){
        memcpy(this->buf + r, buffer, length);
        return;
    }
    memcpy(this->buf + r, buffer, delta);
    this->transform(this->buf, temp_a, temp_b);
    buffer += delta;
    length -= delta;

    while (length >= 128){
        this->transform(buffer, temp_a, temp_b);
        buffer += 128;
        length -= 128;
    }
    memcpy(this->buf, buffer, length % 128);
    memset(temp_a, 0, sizeof(temp_a));
    memset(temp_b, 0, sizeof(temp_b));
}

digest::SHA512 SHA512::get_digest() noexcept{
    std::uint64_t temp_a[80];
    std::uint64_t temp_b[8];

    digest::SHA512::digest_t ret;

    {
        auto r = this->count % 128;
        if (r < 112){
            memcpy(this->buf + r, PAD, 112 - r);
        }else{
            memcpy(this->buf + r, PAD, 128 - r);
            this->transform(this->buf, temp_a, temp_b);
            memset(this->buf, 0, 112);
        }
        std::uint64_t data[2];
        data[0] = this->count >> (64 - 3);
        data[1] = this->count << 3;
        be64enc_vect(this->buf + 112, data, 16);
        this->transform(this->buf, temp_a, temp_b);
    }
    be64enc_vect(ret.data(), this->state, 64);
    memset(temp_a, 0, sizeof(temp_a));
    memset(temp_b, 0, sizeof(temp_b));
    memset(this->state, 0, sizeof(this->state));
    this->count = 0;
    memset(this->buf, 0, sizeof(this->buf));

    return ret;
}

}

}

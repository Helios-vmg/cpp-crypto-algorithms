#include "md5.hpp"

static std::uint32_t f1(std::uint32_t x, std::uint32_t y, std::uint32_t z){
	return (x & y) | (~x & z);
}

static std::uint32_t f2(std::uint32_t x, std::uint32_t y, std::uint32_t z){
	return (x & z) | (y & ~z);
}

static std::uint32_t f3(std::uint32_t x, std::uint32_t y, std::uint32_t z){
	return x ^ y ^ z;
}

static std::uint32_t f4(std::uint32_t x, std::uint32_t y, std::uint32_t z){
	return (y ^ (x | ~z));
}

static std::uint32_t rotl(std::uint32_t a, std::uint32_t b){
	return (a << b) | (a >> (32 - b));
}

template <std::uint32_t F(std::uint32_t, std::uint32_t, std::uint32_t)>
void transform(std::uint32_t &a, std::uint32_t b, std::uint32_t c, std::uint32_t d, std::uint32_t m, std::uint32_t s, std::uint32_t t){
	a += F(b, c, d) + m + t;
	a = b + rotl(a, s);
}

struct Parameters{
	char m_index;
	char s;
	std::uint32_t t;
};

struct MetaParameters{
	void(*f)(std::uint32_t &a, std::uint32_t b, std::uint32_t c, std::uint32_t d, std::uint32_t m, std::uint32_t s, std::uint32_t t);
	const Parameters *parameters;
};

static const Parameters parameters[] = {
	{  0,  7, 0xd76aa478 },
	{  1, 12, 0xe8c7b756 },
	{  2, 17, 0x242070db },
	{  3, 22, 0xc1bdceee },
	{  4,  7, 0xf57c0faf },
	{  5, 12, 0x4787c62a },
	{  6, 17, 0xa8304613 },
	{  7, 22, 0xfd469501 },
	{  8,  7, 0x698098d8 },
	{  9, 12, 0x8b44f7af },
	{ 10, 17, 0xffff5bb1 },
	{ 11, 22, 0x895cd7be },
	{ 12,  7, 0x6b901122 },
	{ 13, 12, 0xfd987193 },
	{ 14, 17, 0xa679438e },
	{ 15, 22, 0x49b40821 },

	{  1,  5, 0xf61e2562 },
	{  6,  9, 0xc040b340 },
	{ 11, 14, 0x265e5a51 },
	{  0, 20, 0xe9b6c7aa },
	{  5,  5, 0xd62f105d },
	{ 10,  9, 0x02441453 },
	{ 15, 14, 0xd8a1e681 },
	{  4, 20, 0xe7d3fbc8 },
	{  9,  5, 0x21e1cde6 },
	{ 14,  9, 0xc33707d6 },
	{  3, 14, 0xf4d50d87 },
	{  8, 20, 0x455a14ed },
	{ 13,  5, 0xa9e3e905 },
	{  2,  9, 0xfcefa3f8 },
	{  7, 14, 0x676f02d9 },
	{ 12, 20, 0x8d2a4c8a },

	{  5,  4, 0xfffa3942 },
	{  8, 11, 0x8771f681 },
	{ 11, 16, 0x6d9d6122 },
	{ 14, 23, 0xfde5380c },
	{  1,  4, 0xa4beea44 },
	{  4, 11, 0x4bdecfa9 },
	{  7, 16, 0xf6bb4b60 },
	{ 10, 23, 0xbebfbc70 },
	{ 13,  4, 0x289b7ec6 },
	{  0, 11, 0xeaa127fa },
	{  3, 16, 0xd4ef3085 },
	{  6, 23, 0x04881d05 },
	{  9,  4, 0xd9d4d039 },
	{ 12, 11, 0xe6db99e5 },
	{ 15, 16, 0x1fa27cf8 },
	{  2, 23, 0xc4ac5665 },

	{  0,  6, 0xf4292244 },
	{  7, 10, 0x432aff97 },
	{ 14, 15, 0xab9423a7 },
	{  5, 21, 0xfc93a039 },
	{ 12,  6, 0x655b59c3 },
	{  3, 10, 0x8f0ccc92 },
	{ 10, 15, 0xffeff47d },
	{  1, 21, 0x85845dd1 },
	{  8,  6, 0x6fa87e4f },
	{ 15, 10, 0xfe2ce6e0 },
	{  6, 15, 0xa3014314 },
	{ 13, 21, 0x4e0811a1 },
	{  4,  6, 0xf7537e82 },
	{ 11, 10, 0xbd3af235 },
	{  2, 15, 0x2ad7d2bb },
	{  9, 21, 0xeb86d391 },
};

static const MetaParameters metaparameters[4] = {
	{ transform<f1>, parameters + 16 * 0 },
	{ transform<f2>, parameters + 16 * 1 },
	{ transform<f3>, parameters + 16 * 2 },
	{ transform<f4>, parameters + 16 * 3 },
};

namespace Hashes{
namespace Digests{

int MD5::cmp(const MD5 &other) const{
	return memcmp(this->digest.data(), other.digest.data(), this->digest.size());
}

MD5::operator std::string() const{
	return detail::to_string(*this);
}

void MD5::write_to_char_array(char (&array)[string_size]) const{
	detail::write_to_char_array<MD5>(array, this->digest);
}

void MD5::write_to_char_vector(std::vector<char> &s) const{
	detail::write_to_char_vector(s, *this);
}

} //Digests

namespace Algorithms{


void MD5::transform() noexcept{
	std::uint32_t m[16];

	// MD5 specifies big endian byte order, but this implementation assumes a little
	// endian byte order CPU. Reverse all the bytes upon input, and re-reverse them
	// on output (in md5_final()).
	for (int i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = (this->data[j]) + (this->data[j + 1] << 8) + (this->data[j + 2] << 16) + (this->data[j + 3] << 24);

	std::uint32_t temp[4];
	for (int i = 4; i--;)
		temp[i] = this->state[i];

	for (auto &mp : metaparameters){
		int i = 0;
		for (size_t j = 0; j < 16; j++){
			auto &p = mp.parameters[j];
			auto &a = temp[i++];
			i %= 4;
			auto &b = temp[i++];
			i %= 4;
			auto &c = temp[i++];
			i %= 4;
			auto &d = temp[i];
			mp.f(a, b, c, d, m[p.m_index], p.s, p.t);
		}
	}

	for (int i = 4; i--;)
		this->state[i] += temp[i];
}

void MD5::reset() noexcept{
	this->datalen = 0;
	this->bitlen = 0;
	this->state[0] = 0x67452301;
	this->state[1] = 0xEFCDAB89;
	this->state[2] = 0x98BADCFE;
	this->state[3] = 0x10325476;
}

void MD5::update(const void *void_buffer, size_t length) noexcept{
	auto buffer = (const std::uint8_t *)void_buffer;
	for (size_t i = 0; i < length; i++) {
		this->data[this->datalen++] = buffer[i];
		if (this->datalen == 64) {
			this->transform();
			this->bitlen += 512;
			this->datalen = 0;
		}
	}
}

Digests::MD5 MD5::get_digest() noexcept{
	size_t i = this->datalen;

	// Pad whatever data is left in the buffer.
	if (this->datalen < 56){
		this->data[i++] = 0x80;
		while (i < 56)
			this->data[i++] = 0x00;
	}else if (this->datalen >= 56){
		this->data[i++] = 0x80;
		while (i < 64)
			this->data[i++] = 0x00;
		this->transform();
		memset(this->data, 0, 56);
	}

	// Append to the padding the total message's length in bits and transform.
	this->bitlen += this->datalen * 8;
	for (int j = 0; j < 8; j++)
		this->data[56 + j] = (std::uint8_t)(this->bitlen >> (8 * j));
	this->transform();

	Digests::MD5::digest_t ret;

	// Since this implementation uses little endian byte ordering and MD uses big endian,
	// reverse all the bytes when copying the final state to the output hash.
	for (i = 0; i < 4; ++i){
		ret[i] = (this->state[0] >> (i * 8)) & 0xFF;
		ret[i + 4] = (this->state[1] >> (i * 8)) & 0xFF;
		ret[i + 8] = (this->state[2] >> (i * 8)) & 0xFF;
		ret[i + 12] = (this->state[3] >> (i * 8)) & 0xFF;
	}

	return ret;
}

} //Algorithms

} //Hashes

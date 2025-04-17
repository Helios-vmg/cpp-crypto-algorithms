#include "sha1.hpp"
#include "hex.hpp"
#include "bit.hpp"
#include <cstring>

static const std::uint32_t k[] = {
	0x5a827999,
	0x6ed9eba1,
	0x8f1bbcdc,
	0xca62c1d6,
};

namespace hash{

namespace digest{

SHA1::SHA1(const std::string &digest): SHA1(digest.c_str(), digest.size()){}

SHA1::SHA1(const char *digest, size_t size){
	this->digest = utility::hex_string_to_buffer<this->size>(digest, size);
}

int SHA1::cmp(const SHA1 &other) const{
	return memcmp(this->digest.data(), other.digest.data(), this->digest.size());
}

SHA1::operator std::string() const{
	return detail::to_string(*this);
}

void SHA1::write_to_char_array(char (&array)[string_size]) const{
	detail::write_to_char_array<SHA1>(array, this->digest);
}

void SHA1::write_to_char_vector(std::vector<char> &s) const{
	detail::write_to_char_vector(s, *this);
}

}

namespace algorithm{

void SHA1::reset() noexcept{
	this->datalen = 0;
	this->bitlen = 0;
	this->state[0] = 0x67452301;
	this->state[1] = 0xefcdab89;
	this->state[2] = 0x98badcfe;
	this->state[3] = 0x10325476;
	this->state[4] = 0xc3d2e1f0;
}

void SHA1::update(const void *void_buffer, size_t length) noexcept{
	auto buffer = (const std::uint8_t *)void_buffer;
	for (size_t i = 0; i < length; ++i){
		this->data[this->datalen++] = buffer[i];
		if (this->datalen == 64) {
			this->transform();
			this->bitlen += 512;
			this->datalen = 0;
		}
	}
}

digest::SHA1 SHA1::get_digest() noexcept{
	auto i = this->datalen;

	// Pad whatever data is left in the buffer.
	if (this->datalen < 56) {
		this->data[i++] = 0x80;
		while (i < 56)
			this->data[i++] = 0x00;
	}else{
		this->data[i++] = 0x80;
		while (i < 64)
			this->data[i++] = 0x00;
		this->transform();
		memset(this->data, 0, 56);
	}

	// Append to the padding the total message's length in bits and transform.
	this->bitlen += this->datalen * 8;
	this->data[63] = (std::uint8_t)this->bitlen;
	this->data[62] = (std::uint8_t)(this->bitlen >> 8);
	this->data[61] = (std::uint8_t)(this->bitlen >> 16);
	this->data[60] = (std::uint8_t)(this->bitlen >> 24);
	this->data[59] = (std::uint8_t)(this->bitlen >> 32);
	this->data[58] = (std::uint8_t)(this->bitlen >> 40);
	this->data[57] = (std::uint8_t)(this->bitlen >> 48);
	this->data[56] = (std::uint8_t)(this->bitlen >> 56);
	this->transform();

	digest::SHA1::digest_t ret;

	// Since this implementation uses little endian byte ordering and MD uses big endian,
	// reverse all the bytes when copying the final state to the output hash.
	for (i = 0; i < 4; ++i) {
		ret[i +  0] = (this->state[0] >> (24 - i * 8)) & 0xFF;
		ret[i +  4] = (this->state[1] >> (24 - i * 8)) & 0xFF;
		ret[i +  8] = (this->state[2] >> (24 - i * 8)) & 0xFF;
		ret[i + 12] = (this->state[3] >> (24 - i * 8)) & 0xFF;
		ret[i + 16] = (this->state[4] >> (24 - i * 8)) & 0xFF;
	}

	return ret;
}

void SHA1::transform() noexcept{
	std::uint32_t m[80];

	{
		std::uint32_t i = 0;
		for (std::uint32_t j = 0; i < 16; i++, j += 4)
			m[i] = (data[j] << 24) + (data[j + 1] << 16) + (data[j + 2] << 8) + (data[j + 3]);
		for (; i < 80; ++i){
			m[i] = (m[i - 3] ^ m[i - 8] ^ m[i - 14] ^ m[i - 16]);
			m[i] = (m[i] << 1) | (m[i] >> 31);
		}
	}

	auto a = this->state[0];
	auto b = this->state[1];
	auto c = this->state[2];
	auto d = this->state[3];
	auto e = this->state[4];

	std::uint32_t i = 0;
	for (i = 0; i < 20; i++) {
		auto t = rotate_left_static<5>(a) + ((b & c) ^ (~b & d)) + e + k[0] + m[i];
		e = d;
		d = c;
		c = rotate_left_static<30>(b);
		b = a;
		a = t;
	}
	for ( ; i < 40; i++) {
		auto t = rotate_left_static<5>(a) + (b ^ c ^ d) + e + k[1] + m[i];
		e = d;
		d = c;
		c = rotate_left_static<30>(b);
		b = a;
		a = t;
	}
	for ( ; i < 60; i++) {
		auto t = rotate_left_static<5>(a) + ((b & c) ^ (b & d) ^ (c & d))  + e + k[2] + m[i];
		e = d;
		d = c;
		c = rotate_left_static<30>(b);
		b = a;
		a = t;
	}
	for ( ; i < 80; i++) {
		auto t = rotate_left_static<5>(a) + (b ^ c ^ d) + e + k[3] + m[i];
		e = d;
		d = c;
		c = rotate_left_static<30>(b);
		b = a;
		a = t;
	}

	this->state[0] += a;
	this->state[1] += b;
	this->state[2] += c;
	this->state[3] += d;
	this->state[4] += e;
}

}

}

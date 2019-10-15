#pragma once

#include <cstdint>
#include <cstring>

struct Md5Digest{
	static const size_t length = 16;
	std::uint8_t data[length];
};

class Md5{
	std::uint8_t data[64];
	std::uint32_t datalen;
	std::uint64_t bitlen;
	std::uint32_t state[4];
	
	void transform() noexcept;
public:
	Md5(){
		this->reset();
	}
	Md5(const Md5 &) = default;
	Md5 &operator=(const Md5 &) = default;
	Md5(Md5 &&) = default;
	Md5 &operator=(Md5 &&) = default;
	void reset();
	void update(const void *buffer, size_t length) noexcept;
	Md5Digest get_digest() noexcept;
	static Md5Digest compute(const void *buffer, size_t length) noexcept{
		Md5 hash;
		hash.update(buffer, length);
		return hash.get_digest();
	}
};

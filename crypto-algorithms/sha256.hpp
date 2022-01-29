#pragma once

#include "hash.hpp"
#include <cstdint>
#include <array>
#include <string>
#include <vector>
#include <ostream>

namespace Hashes{

namespace Digests{

class SHA256{
public:
	static const size_t size = 32;
	typedef std::array<std::uint8_t, size> digest_t;
	static const size_t string_size = size * 2 + 1;
private:
	digest_t digest;
public:
	SHA256(){
		memset(this->digest.data(), 0, size);
	}
	SHA256(const std::string &digest);
	SHA256(const char *digest, size_t size);
	SHA256(const digest_t &digest): digest(digest){}
	SHA256(const SHA256 &other) = default;
	int cmp(const SHA256 &other) const;
	bool operator==(const SHA256 &other) const{
		return !this->cmp(other);
	}
	bool operator!=(const SHA256 &other) const{
		return !!this->cmp(other);
	}
	bool operator<(const SHA256 &other) const{
		return this->cmp(other) < 0;
	}
	bool operator>(const SHA256 &other) const{
		return this->cmp(other) > 0;
	}
	bool operator<=(const SHA256 &other) const{
		return this->cmp(other) <= 0;
	}
	bool operator>=(const SHA256 &other) const{
		return this->cmp(other) >= 0;
	}
	bool operator!() const{
		for (auto b : this->digest)
			if (b)
				return false;
		return true;
	}
	operator std::string() const;
	void write_to_char_array(char (&array)[string_size]) const;
	void write_to_char_vector(std::vector<char> &) const;
	const digest_t &to_array() const{
		return this->digest;
	}
	digest_t &to_array(){
		return this->digest;
	}
	size_t std_hash() const{
		size_t ret;
		memcpy(&ret, this->digest.data(), std::min(sizeof(size_t), size));
		return ret;
	}
};

} //Digests

namespace Algorithms{

class SHA256 : public HashAlgorithm{
	std::uint8_t data[64];
	std::uint32_t datalen;
	std::uint64_t bitlen;
	std::uint32_t state[8];

	void transform() noexcept;
public:
	SHA256(){
		this->SHA256::reset();
	}
	SHA256(const SHA256 &) = default;
	SHA256 &operator=(const SHA256 &) = default;
	void reset() noexcept override;
	void update(const void *buffer, size_t length) noexcept override;
	Digests::SHA256 get_digest() noexcept;
	static Digests::SHA256 compute(const void *buffer, size_t length) noexcept{
		SHA256 hash;
		hash.update(buffer, length);
		return hash.get_digest();
	}
	static Digests::SHA256 compute(const char *input) noexcept{
		SHA256 hash;
		hash.update(input, strlen(input));
		return hash.get_digest();
	}
	static Digests::SHA256 compute(const std::string &input) noexcept{
		SHA256 hash;
		hash.update(input.c_str(), input.size());
		return hash.get_digest();
	}
};

} //Algorithms

} //Hashes

inline std::ostream &operator<<(std::ostream &stream, const Hashes::Digests::SHA256 &digest){
	return stream << (std::string)digest;
}

namespace std{

template <>
struct hash<Hashes::Digests::SHA256>{
	size_t operator()(const Hashes::Digests::SHA256 &key) const noexcept{
		return key.std_hash();
	}
};

} //std

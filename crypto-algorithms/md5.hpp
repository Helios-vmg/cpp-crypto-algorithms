#pragma once

#include "hash.hpp"
#include <cstdint>
#include <cstring>
#include <array>
#include <string>
#include <vector>
#include <sstream>

namespace Hashes{

namespace Digests{

class MD5{
public:
	static const size_t size = 16;
	static const size_t string_size = size * 2 + 1;
	typedef std::array<std::uint8_t, size> digest_t;
private:
	digest_t digest;
public:
	MD5(){
		memset(this->digest.data(), 0, size);
	}
	MD5(const digest_t &digest): digest(digest){}
	MD5(const MD5 &other) = default;
	int cmp(const MD5 &other) const;
	bool operator==(const MD5 &other) const{
		return !this->cmp(other);
	}
	bool operator!=(const MD5 &other) const{
		return !!this->cmp(other);
	}
	bool operator<(const MD5 &other) const{
		return this->cmp(other) < 0;
	}
	bool operator>(const MD5 &other) const{
		return this->cmp(other) > 0;
	}
	bool operator<=(const MD5 &other) const{
		return this->cmp(other) <= 0;
	}
	bool operator>=(const MD5 &other) const{
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

class MD5 : public HashAlgorithm{
	std::uint8_t data[64];
	std::uint32_t datalen;
	std::uint64_t bitlen;
	std::uint32_t state[4];
	
	void transform() noexcept;
public:
	MD5(){
		this->MD5::reset();
	}
	MD5(const MD5 &) = default;
	MD5 &operator=(const MD5 &) = default;
	void reset() noexcept override;
	void update(const void *buffer, size_t length) noexcept override;
	Digests::MD5 get_digest() noexcept;
	static Digests::MD5 compute(const void *buffer, size_t length) noexcept{
		MD5 hash;
		hash.update(buffer, length);
		return hash.get_digest();
	}
	static Digests::MD5 compute(const char *input) noexcept{
		MD5 hash;
		hash.update(input, strlen(input));
		return hash.get_digest();
	}
	static Digests::MD5 compute(const std::string &input) noexcept{
		MD5 hash;
		hash.update(input.c_str(), input.size());
		return hash.get_digest();
	}
};

} //Algorithms

} //Hashes

inline std::ostream &operator<<(std::ostream &stream, const Hashes::Digests::MD5 &digest){
	return stream << (std::string)digest;
}

namespace std{

template <>
struct hash<Hashes::Digests::MD5>{
	size_t operator()(const Hashes::Digests::MD5 &key) const noexcept{
		return key.std_hash();
	}
};

} //std

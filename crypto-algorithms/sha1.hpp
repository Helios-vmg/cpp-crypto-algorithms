#pragma once

#include "hash.hpp"
#include <cstdint>
#include <array>
#include <string>
#include <vector>
#include <ostream>

namespace hash{

namespace digest{

class SHA1{
public:
	static const size_t size = 20;
	typedef std::array<std::uint8_t, size> digest_t;
	static const size_t string_size = size * 2 + 1;
private:
	digest_t digest;
public:
	SHA1(){
		memset(this->digest.data(), 0, size);
	}
	SHA1(const std::string &digest);
	SHA1(const char *digest, size_t size = 0);
	SHA1(const digest_t &digest): digest(digest){}
	SHA1(const SHA1 &other) = default;
	int cmp(const SHA1 &other) const;
	bool operator==(const SHA1 &other) const{
		return !this->cmp(other);
	}
	bool operator!=(const SHA1 &other) const{
		return !!this->cmp(other);
	}
	bool operator<(const SHA1 &other) const{
		return this->cmp(other) < 0;
	}
	bool operator>(const SHA1 &other) const{
		return this->cmp(other) > 0;
	}
	bool operator<=(const SHA1 &other) const{
		return this->cmp(other) <= 0;
	}
	bool operator>=(const SHA1 &other) const{
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

namespace algorithm{

class SHA1 : public HashAlgorithm{
	std::uint8_t data[64];
	std::uint32_t datalen;
	std::uint64_t bitlen;
	std::uint32_t state[5];

	void transform() noexcept;
public:
	SHA1(){
		this->SHA1::reset();
	}
	SHA1(const SHA1 &) = default;
	SHA1 &operator=(const SHA1 &) = default;
	void reset() noexcept override;
	void update(const void *buffer, size_t length) noexcept override;
	digest::SHA1 get_digest() noexcept;
	static digest::SHA1 compute(const void *buffer, size_t length) noexcept{
		SHA1 hash;
		hash.update(buffer, length);
		return hash.get_digest();
	}
	static digest::SHA1 compute(const char *input) noexcept{
		SHA1 hash;
		hash.update(input, strlen(input));
		return hash.get_digest();
	}
	static digest::SHA1 compute(const std::string &input) noexcept{
		SHA1 hash;
		hash.update(input.c_str(), input.size());
		return hash.get_digest();
	}
};

}

}

inline std::ostream &operator<<(std::ostream &stream, const hash::digest::SHA1 &digest){
	return stream << (std::string)digest;
}

namespace std{

template <>
struct hash<::hash::digest::SHA1>{
	size_t operator()(const ::hash::digest::SHA1 &key) const noexcept{
		return key.std_hash();
	}
};

}

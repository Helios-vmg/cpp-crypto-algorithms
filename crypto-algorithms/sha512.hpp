#pragma once

#include "hash.hpp"
#include <cstdint>
#include <array>
#include <string>
#include <vector>
#include <ostream>

namespace hash {

namespace digest {

class SHA512 {
public:
	static const size_t size = 64;
	typedef std::array<std::uint8_t, size> digest_t;
	static const size_t string_size = size * 2 + 1;
private:
	digest_t digest;
public:
	SHA512() {
		memset(this->digest.data(), 0, size);
	}
	SHA512(const std::string &digest);
	SHA512(const char *digest, size_t size = 0);
	SHA512(const digest_t &digest) : digest(digest) {}
	SHA512(const SHA512 &other) = default;
	int cmp(const SHA512 &other) const;
	bool operator==(const SHA512 &other) const {
		return !this->cmp(other);
	}
	bool operator!=(const SHA512 &other) const {
		return !!this->cmp(other);
	}
	bool operator<(const SHA512 &other) const {
		return this->cmp(other) < 0;
	}
	bool operator>(const SHA512 &other) const {
		return this->cmp(other) > 0;
	}
	bool operator<=(const SHA512 &other) const {
		return this->cmp(other) <= 0;
	}
	bool operator>=(const SHA512 &other) const {
		return this->cmp(other) >= 0;
	}
	bool operator!() const {
		for (auto b : this->digest)
			if (b)
				return false;
		return true;
	}
	operator std::string() const;
	void write_to_char_array(char(&array)[string_size]) const;
	void write_to_char_vector(std::vector<char> &) const;
	const digest_t &to_array() const {
		return this->digest;
	}
	digest_t &to_array() {
		return this->digest;
	}
	size_t std_hash() const {
		size_t ret;
		memcpy(&ret, this->digest.data(), std::min(sizeof(size_t), size));
		return ret;
	}
};

} //Digests

namespace algorithm {

class SHA512 : public HashAlgorithm {
	std::uint64_t state[8];
	std::uint64_t count;
	std::uint8_t buf[128];

	void transform(const std::uint8_t block[128], std::uint64_t (&W)[80], std::uint64_t (&S)[8]) noexcept;
public:
	SHA512() {
		this->SHA512::reset();
	}
	SHA512(const SHA512 &) = default;
	SHA512 &operator=(const SHA512 &) = default;
	void reset() noexcept override;
	void update(const void *void_buffer, size_t length) noexcept override;
	digest::SHA512 get_digest() noexcept;
	static digest::SHA512 compute(const void *buffer, size_t length) noexcept {
		SHA512 hash;
		hash.update(buffer, length);
		return hash.get_digest();
	}
	static digest::SHA512 compute(const char *input) noexcept {
		SHA512 hash;
		hash.update(input, strlen(input));
		return hash.get_digest();
	}
	static digest::SHA512 compute(const std::string &input) noexcept {
		SHA512 hash;
		hash.update(input.c_str(), input.size());
		return hash.get_digest();
	}
};

}

}

inline std::ostream &operator<<(std::ostream &stream, const hash::digest::SHA512 &digest) {
	return stream << (std::string)digest;
}

namespace std {

template <>
struct hash<::hash::digest::SHA512> {
	size_t operator()(const ::hash::digest::SHA512 &key) const noexcept {
		return key.std_hash();
	}
};

}

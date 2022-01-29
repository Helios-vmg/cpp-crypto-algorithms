#pragma once

#include <exception>
#include <cstdint>
#include <array>
#include <string>
#include <vector>

namespace Hashes{

namespace Digests{

class InvalidHexException : public std::exception{
public:
	const char *what() const noexcept override{
		return "invalid hex";
	}
};

} //Digests

namespace Algorithms{

class HashAlgorithm{
public:
	virtual ~HashAlgorithm(){}
	virtual void reset() = 0;
	virtual void update(const void *buffer, size_t length) = 0;
};

} //Algorithms

namespace detail{

extern const char hex_digits[];

inline std::uint8_t hex2val(char c){
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	throw Digests::InvalidHexException();
}

template <typename T>
void write_to_char_array(char (&dst)[T::string_size], const std::array<std::uint8_t, T::size> &digest){
	dst[T::string_size - 1] = 0;
	for (size_t i = 0; i < T::size; i++){
		dst[i * 2 + 0] = hex_digits[digest[i] >> 4];
		dst[i * 2 + 1] = hex_digits[digest[i] & 0x0F];
	}
}

template <typename T>
std::string to_string(const T &digest){
	char temp[T::string_size];
	digest.write_to_char_array(temp);
	return std::string(temp, T::size * 2);
}

template <typename T>
void write_to_char_vector(std::vector<char> &dst, const T &digest){
	char array[T::string_size];
	digest.write_to_char_array(array);
	for (int i = 0; i < sizeof(array) - 1; i++)
		dst.push_back(array[i]);
}

} //detail

} //Hashes

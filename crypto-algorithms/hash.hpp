#pragma once

#include "hex.hpp"
#include <exception>
#include <cstdint>
#include <array>
#include <string>
#include <vector>

namespace hash{

namespace algorithm{

class HashAlgorithm{
public:
	virtual ~HashAlgorithm(){}
	virtual void reset() = 0;
	virtual void update(const void *buffer, size_t length) = 0;
};

}

namespace detail{

template <typename T>
void write_to_char_array(char (&dst)[T::string_size], const std::array<std::uint8_t, T::size> &digest){
	dst[T::string_size - 1] = 0;
	for (size_t i = 0; i < T::size; i++){
		dst[i * 2 + 0] = utility::hex_digits[digest[i] >> 4];
		dst[i * 2 + 1] = utility::hex_digits[digest[i] & 0x0F];
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

}

}

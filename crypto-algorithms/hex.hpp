#pragma once

#include <cstdint>
#include <exception>
#include <stdexcept>
#include <array>

namespace utility{

extern const char hex_digits[];

class InvalidHexException : public std::exception{
public:
	const char *what() const noexcept override{
		return "invalid hex";
	}
};

inline std::uint8_t hex2val(char c){
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	throw InvalidHexException();
}

template <size_t N>
std::array<std::uint8_t, N> hex_string_to_buffer(const char *s, size_t size = 0){
	if (!size)
		size = strlen(s);
	if (size != N * 2)
		throw std::runtime_error("invalid hex string");
	std::array<std::uint8_t, N> ret;
	for (auto &b : ret){
		b = utility::hex2val(*(s++)) << 4;
		b |= utility::hex2val(*(s++));
	}
	return ret;
}

}

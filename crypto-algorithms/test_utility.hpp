#pragma once

#include "hash.hpp"
#include <array>
#include <cstdint>

template <size_t N>
std::array<std::uint8_t, N> hex_string_to_buffer(const char *s){
	auto l = strlen(s);
	if (l != N * 2)
		throw std::exception();
	std::array<std::uint8_t, N> ret;
	for (auto &b : ret){
		b = Hashes::detail::hex2val(*(s++)) << 4;
		b |= Hashes::detail::hex2val(*(s++));
	}
	return ret;
}

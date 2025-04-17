#pragma once

#include <cstdint>

template <int b>
std::uint32_t rotate_left_static(std::uint32_t a){
	return (a << b) | (a >> (32 - b));
}

inline std::uint32_t rotate_left(std::uint32_t a, std::uint32_t b){
	return (a << b) | (a >> (32 - b));
}

inline std::uint32_t rotate_right(std::uint32_t a, std::uint32_t b){
	return (a >> b) | (a << (32 - b));
}

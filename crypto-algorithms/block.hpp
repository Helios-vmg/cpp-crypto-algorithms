#pragma once

#include "hex.hpp"
#include <cstdint>
#include <array>
#include <stdexcept>
#include <cstring>

namespace symmetric{

template <size_t Size>
class Key{
public:
	static const size_t bits = Size;
	static const size_t size = bits / 8;
private:
	std::array<std::uint8_t, size> key;
public:
	Key(){
		memset(this->key.data(), 0, size);
	}
	Key(const std::array<std::uint8_t, size> &src): key(src){}
	Key(const void *src){
		memcpy(this->key.data(), src, size);
	}
	Key(const char *s){
		this->key = utility::hex_string_to_buffer<size>(s);
	}
	Key(const Key &) = default;
	Key(Key &&) = default;
	Key &operator=(const Key &) = default;
	Key &operator=(Key &&) = default;
	const auto &data() const{
		return this->key;
	}
};

template <size_t BlockSize>
class BlockCipher{
public:
	static inline const size_t block_size = BlockSize;
	typedef std::array<std::uint8_t, block_size> block_t;

	virtual ~BlockCipher(){}
	virtual void encrypt_block(void *void_dst, const void *void_src) const noexcept = 0;
	virtual void decrypt_block(void *void_dst, const void *void_src) const noexcept = 0;
	void encrypt_block(block_t &dst, const block_t &src) const noexcept{
		this->encrypt_block(dst.data(), src.data());
	}
	void decrypt_block(block_t &dst, const block_t &src) const noexcept{
		this->decrypt_block(dst.data(), src.data());
	}
	block_t encrypt_block(const block_t &src) const noexcept{
		block_t dst;
		this->encrypt_block(dst, src);
		return dst;
	}
	block_t decrypt_block(const block_t &src) const noexcept{
		block_t dst;
		this->decrypt_block(dst, src);
		return dst;
	}

	static block_t block_from_string(const char *s){
		auto l = strlen(s);
		if (l != block_size * 2)
			throw std::runtime_error("invalid hex string");
		block_t ret;
		for (auto &b : ret){
			b = utility::hex2val(*(s++)) << 4;
			b |= utility::hex2val(*(s++));
		}
		return ret;
	}
	static void array_xor(void *void_dst, const void *void_left, const void *void_right, size_t size){
		auto dst = (std::uint8_t *)void_dst;
		auto left = (std::uint8_t *)void_left;
		auto right = (std::uint8_t *)void_right;
		for (size_t i = 0; i < size; i++)
			dst[i] = left[i] ^ right[i];
	}
	static block_t block_xor(const void *left, const block_t &right){
		block_t ret;
		array_xor(ret.data(), left, right.data(), BlockSize);
		return ret;
	}
	static block_t block_xor(const block_t &left, const block_t &right){
		block_t ret;
		array_xor(ret.data(), left.data(), right.data(), BlockSize);
		return ret;
	}
};

}

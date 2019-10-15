#pragma once

#include <array>
#include <cstdint>

namespace AES{

template <int Size>
class AesKey{
public:
	static_assert(Size == 128 || Size == 192 || Size == 256, "Key size must be 128, 192, or 256!");

	static const size_t bits = Size;
	static const size_t size = bits / 8;
private:
	std::uint8_t key[size];
public:
	AesKey(){
		memset(this->key, 0, size);
	}
	AesKey(const void *src){
		memcpy(this->key, src, size);
	}
	AesKey(const AesKey &) = default;
	AesKey(AesKey &&) = default;
	AesKey &operator=(const AesKey &) = default;
	AesKey &operator=(AesKey &&) = default;
	const auto data() const{
		return this->key;
	}
};

namespace detail{

template <size_t Size>
struct AesParameters{
	static const int rounds = (Size - 128) / 32 + 11;
};

std::uint32_t rotate32(std::uint32_t x);
std::uint32_t subword(uint32_t word);

template <size_t Size>
class AesKeySchedule{
public:
	static const size_t size = 4 * AesParameters<Size>::rounds;
private:
	std::uint8_t schedule[size * 4];
public:
	AesKeySchedule(const AesKey<Size> &key){
		static const std::uint32_t rcon[] = {
			0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
			0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000,
			0x6c000000, 0xd8000000, 0xab000000, 0x4d000000, 0x9a000000,
		};
		constexpr int n = AesKey<Size>::size;
		memcpy(this->schedule, key.data(), n);

		for (int i = n / 4; i < size; i++){
			std::uint32_t temp;
			temp = (std::uint32_t)this->schedule[(i - 1) * 4 + 0] << 24;
			temp |= (std::uint32_t)this->schedule[(i - 1) * 4 + 1] << 16;
			temp |= (std::uint32_t)this->schedule[(i - 1) * 4 + 2] << 8;
			temp |= (std::uint32_t)this->schedule[(i - 1) * 4 + 3];
			if (i % (n / 4) == 0)
				temp = subword(rotate32(temp)) ^ rcon[(i - 1) / (n / 4)];
			else if (n > 24 && i % (n / 4) == 4)
				temp = subword(temp);
			this->schedule[i * 4 + 0] = this->schedule[i * 4 + 0 - n] ^ ((temp >> 24) & 0xFF);
			this->schedule[i * 4 + 1] = this->schedule[i * 4 + 1 - n] ^ ((temp >> 16) & 0xFF);
			this->schedule[i * 4 + 2] = this->schedule[i * 4 + 2 - n] ^ ((temp >> 8) & 0xFF);
			this->schedule[i * 4 + 3] = this->schedule[i * 4 + 3 - n] ^ (temp & 0xFF);
		}
	}
	AesKeySchedule(const AesKeySchedule &) = default;
	AesKeySchedule(AesKeySchedule &&) = default;
	AesKeySchedule &operator=(const AesKeySchedule &) = default;
	AesKeySchedule &operator=(AesKeySchedule &&) = default;
	const auto data() const{
		return this->schedule;
	}
};

void add_round_key(std::uint8_t *state, const uint8_t *w) noexcept;
void sub_bytes(std::uint8_t *state) noexcept;
void shift_rows(std::uint8_t *state) noexcept;
void mix_columns(std::uint8_t *state) noexcept;
void invert_sub_bytes(std::uint8_t *state) noexcept;
void invert_shift_rows(std::uint8_t *state) noexcept;
void invert_mix_columns(std::uint8_t *state) noexcept;

}

static const size_t block_size = 16;

typedef std::array<std::uint8_t, block_size> block_t;

template <size_t Size>
class Aes{
	detail::AesKeySchedule<Size> key;
public:
	Aes(const AesKey<Size> &key): key(key){}
	Aes(const Aes &) = default;
	Aes(Aes &&) = default;
	Aes &operator=(const Aes &) = default;
	Aes &operator=(Aes &&) = default;
	void encrypt_block(void *void_dst, const void *void_src) noexcept{
		auto src = (const std::uint8_t *)void_src;
		auto dst = (std::uint8_t *)void_dst;
		if (dst != src){
			dst[0x0] = src[0x0];
			dst[0x1] = src[0x1];
			dst[0x2] = src[0x2];
			dst[0x3] = src[0x3];
			dst[0x4] = src[0x4];
			dst[0x5] = src[0x5];
			dst[0x6] = src[0x6];
			dst[0x7] = src[0x7];
			dst[0x8] = src[0x8];
			dst[0x9] = src[0x9];
			dst[0xA] = src[0xA];
			dst[0xB] = src[0xB];
			dst[0xC] = src[0xC];
			dst[0xD] = src[0xD];
			dst[0xE] = src[0xE];
			dst[0xF] = src[0xF];
		}

		auto key = this->key.data();

		detail::add_round_key(dst, key);
		for (auto i = detail::AesParameters<Size>::rounds - 2; i--;){
			key += 16;
			detail::sub_bytes(dst);
			detail::shift_rows(dst);
			detail::mix_columns(dst);
			detail::add_round_key(dst, key);
		}
		detail::sub_bytes(dst);
		detail::shift_rows(dst);
		detail::add_round_key(dst, key + 16);
	}
	void decrypt_block(void *void_dst, const void *void_src) noexcept{
		auto src = (const std::uint8_t *)void_src;
		auto dst = (std::uint8_t *)void_dst;
		if (dst != src){
			dst[0x0] = src[0x0];
			dst[0x1] = src[0x1];
			dst[0x2] = src[0x2];
			dst[0x3] = src[0x3];
			dst[0x4] = src[0x4];
			dst[0x5] = src[0x5];
			dst[0x6] = src[0x6];
			dst[0x7] = src[0x7];
			dst[0x8] = src[0x8];
			dst[0x9] = src[0x9];
			dst[0xA] = src[0xA];
			dst[0xB] = src[0xB];
			dst[0xC] = src[0xC];
			dst[0xD] = src[0xD];
			dst[0xE] = src[0xE];
			dst[0xF] = src[0xF];
		}

		const auto rounds = detail::AesParameters<Size>::rounds;
		auto key = this->key.data() + (rounds - 1) * 16;

		detail::add_round_key(dst, key);
		for (auto i = rounds - 2; i--;){
			key -= 16;
			detail::invert_shift_rows(dst);
			detail::invert_sub_bytes(dst);
			detail::add_round_key(dst, key);
			detail::invert_mix_columns(dst);
		}
		detail::invert_shift_rows(dst);
		detail::invert_sub_bytes(dst);
		detail::add_round_key(dst, key - 16);
	}
};

}

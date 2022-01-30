#pragma once

#include "block.hpp"
#include <cstdint>
#include <cstring>
#include <array>

namespace symmetric{

template <size_t Size>
class Twofish : public BlockCipher<16>{
public:
	static inline const int rounds = 16;
	static inline const size_t bits_per_block = 128;
	static inline const size_t output_whiten = bits_per_block / 32;
	static inline const size_t round_subkeys = output_whiten + bits_per_block / 32;
	static inline const size_t subkeys_size = round_subkeys + 2 * rounds;
	static inline const size_t block_size = bits_per_block / 8;
	typedef std::array<std::uint8_t, block_size> block_t;
	static_assert(Size == 128 || Size == 192 || Size == 256, "Key size must be 128, 192, or 256!");
	typedef Key<Size> key_t;

	class KeySchedule{
	public:
		//key bits used for S-boxes
		std::uint32_t sbox_keys[Size / 64];
		//round subkeys, input/output whitening bits
		std::uint32_t sub_keys[subkeys_size];
		
		KeySchedule(const key_t &key);
		KeySchedule(const KeySchedule &) = default;
		KeySchedule(KeySchedule &&) = default;
		KeySchedule &operator=(const KeySchedule &) = default;
		KeySchedule &operator=(KeySchedule &&) = default;
	};
private:
	KeySchedule key;
public:
	Twofish(const key_t &key): key(key){}
	Twofish(const Twofish &) = default;
	Twofish(Twofish &&) = default;
	Twofish &operator=(const Twofish &) = default;
	Twofish &operator=(Twofish &&) = default;
	
	void encrypt_block(void *void_dst, const void *void_src) const noexcept override;
	void decrypt_block(void *void_dst, const void *void_src) const noexcept override;
	using BlockCipher<16>::encrypt_block;
	using BlockCipher<16>::decrypt_block;
};

}

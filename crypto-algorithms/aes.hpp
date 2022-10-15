#pragma once

#include "block.hpp"
#include <array>
#include <cstdint>

namespace symmetric{

template <size_t KeySize, size_t BlockSize>
class Rijndael : public BlockCipher<BlockSize / 8>{
public:
	static const size_t subblocks = BlockSize / 32;
	static const size_t subblock_size = 4;
	static const size_t round_size = subblock_size * subblocks;
	static_assert(KeySize % 64 == 0 && 2 <= KeySize / 64 && KeySize / 64 <= 4, "Key size must be 128, 192, or 256!");
	static_assert(BlockSize % 32 == 0 && 4 <= subblocks && subblocks <= 8, "Block size must be 128, 160, 192, 224, or 256!");
	static const size_t rounds = std::max(KeySize, BlockSize) / 32 + 7;
	typedef Key<KeySize> key_t;
	
	class KeySchedule{
		static const size_t schedule_size = rounds * round_size;
		std::uint8_t schedule[schedule_size];
	public:
		KeySchedule(const key_t &key);
		KeySchedule(const KeySchedule &) = default;
		KeySchedule(KeySchedule &&) = default;
		KeySchedule &operator=(const KeySchedule &) = default;
		KeySchedule &operator=(KeySchedule &&) = default;
		const auto &data() const{
			return this->schedule;
		}
	};

private:
	KeySchedule key;
public:
	Rijndael(const key_t &key): key(key){}
	Rijndael(const Rijndael &) = default;
	Rijndael(Rijndael &&) = default;
	Rijndael &operator=(const Rijndael &) = default;
	Rijndael &operator=(Rijndael &&) = default;
	
	void encrypt_block(void *void_dst, const void *void_src) const noexcept override;
	void decrypt_block(void *void_dst, const void *void_src) const noexcept override;
	using BlockCipher<BlockSize / 8>::encrypt_block;
	using BlockCipher<BlockSize / 8>::decrypt_block;
};

template <size_t KeySize>
using Aes = Rijndael<KeySize, 128>;

}

#pragma once

#include "block.hpp"
#include <array>
#include <cstdint>

namespace symmetric{

template <size_t Size>
class Aes : public BlockCipher<16>{
public:
	static const int rounds = (Size - 128) / 32 + 11;
	static_assert(Size == 128 || Size == 192 || Size == 256, "Key size must be 128, 192, or 256!");
	typedef Key<Size> key_t;
	
	class KeySchedule{
	public:
		static const size_t size = 4 * rounds;
	private:
		std::uint8_t schedule[size * 4];
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
	Aes(const key_t &key): key(key){}
	Aes(const Aes &) = default;
	Aes(Aes &&) = default;
	Aes &operator=(const Aes &) = default;
	Aes &operator=(Aes &&) = default;
	
	void encrypt_block(void *void_dst, const void *void_src) const noexcept override;
	void decrypt_block(void *void_dst, const void *void_src) const noexcept override;
	using BlockCipher<16>::encrypt_block;
	using BlockCipher<16>::decrypt_block;
};

}

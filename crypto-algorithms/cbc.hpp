#pragma once

#include "block.hpp"
#include <vector>

namespace symmetric{

template <typename Cipher>
class CbcEncryptor{
	typedef typename Cipher::block_t block_t;
	static const size_t block_size = Cipher::block_size;
	Cipher cipher;
	block_t iv;
public:
	CbcEncryptor(const Cipher &cipher, const block_t &iv) : cipher(cipher), iv(iv){}
	CbcEncryptor(const CbcEncryptor &) = default;
	CbcEncryptor &operator=(const CbcEncryptor &) = default;
	void encrypt_block(void *ciphertext, const void *plaintext) noexcept{
		auto encrypted = this->cipher.encrypt_block(cipher.block_xor(plaintext, iv));
		memcpy(ciphertext, encrypted.data(), encrypted.size());
		this->iv = encrypted;
	}
	void encrypt_last_block(void *ciphertext, const void *plaintext, size_t size) noexcept{
		if (!size)
			return;
		if (size < block_size){
			auto mask = this->cipher.encrypt_block(this->iv);
			this->cipher.array_xor(ciphertext, mask.data(), plaintext, size);
		}else
			this->encrypt_block(ciphertext, plaintext);
	}
	block_t get_iv() const{
		return this->iv;
	}
	void encrypt(void *void_ciphertext, const void *void_plaintext, size_t size){
		auto ciphertext = (std::uint8_t *)void_ciphertext;
		auto plaintext = (const std::uint8_t *)void_plaintext;
		if (size % block_size == 0){
			for (size_t i = 0; i < size; i += block_size)
				this->encrypt_block(ciphertext + i, plaintext + i);
		}else{
			for (size_t i = 0; i + block_size < size; i += block_size)
				this->encrypt_block(ciphertext + i, plaintext + i);
			auto offset = size / block_size * block_size;
			this->encrypt_last_block(ciphertext + offset, plaintext + offset, size - offset);
		}
	}
	std::vector<std::uint8_t> encrypt(const std::vector<std::uint8_t> &plaintext){
		std::vector<std::uint8_t> ciphertext(plaintext.size());
		this->encrypt(ciphertext.data(), plaintext.data(), plaintext.size());
		return ciphertext;
	}
};

template <typename Cipher>
class CbcDecryptor{
	typedef typename Cipher::block_t block_t;
	static const size_t block_size = Cipher::block_size;
	Cipher cipher;
	block_t iv;
public:
	CbcDecryptor(const Cipher &cipher, const block_t &iv): cipher(cipher), iv(iv){}
	CbcDecryptor(const CbcDecryptor &) = default;
	CbcDecryptor &operator=(const CbcDecryptor &) = default;
	void decrypt_block(void *plaintext, const void *ciphertext) noexcept{
		this->cipher.decrypt_block(plaintext, ciphertext);
		this->cipher.array_xor(plaintext, plaintext, this->iv.data(), block_size);
		memcpy(this->iv.data(), ciphertext, block_size);
	}
	void decrypt_last_block(void *plaintext, const void *ciphertext, size_t size) noexcept{
		if (!size)
			return;
		if (size < block_size){
			auto mask = this->cipher.encrypt_block(this->iv);
			this->cipher.array_xor(plaintext, mask.data(), ciphertext, size);
		}else
			this->decrypt_block(plaintext, ciphertext);
	}
	block_t get_iv() const{
		return this->iv;
	}
	void decrypt(void *void_plaintext, const void *void_ciphertext, size_t size){
		auto plaintext = (std::uint8_t *)void_plaintext;
		auto ciphertext = (const std::uint8_t *)void_ciphertext;
		if (size % block_size == 0){
			for (size_t i = 0; i < size; i += block_size)
				this->decrypt_block(plaintext + i, ciphertext + i);
		}else{
			for (size_t i = 0; i + block_size < size; i += block_size)
				this->decrypt_block(plaintext + i, ciphertext + i);
			auto offset = size / block_size * block_size;
			this->decrypt_last_block(plaintext + offset, ciphertext + offset, size - offset);
		}
	}
	std::vector<std::uint8_t> decrypt(const std::vector<std::uint8_t> &ciphertext){
		std::vector<std::uint8_t> plaintext(ciphertext.size());
		this->decrypt(plaintext.data(), ciphertext.data(), ciphertext.size());
		return plaintext;
	}
};

}

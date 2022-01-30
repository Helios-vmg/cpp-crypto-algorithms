#pragma once

#include "sha256.hpp"
#include <sstream>
#include <stdexcept>

template <typename Cipher>
void test_block_cipher_sanity(const char *cipher_string){
	static_assert(Cipher::block_size == 16, "This cipher cannot be tested with this function");
	static_assert(Cipher::key_t::size <= hash::digest::SHA256::size, "This cipher cannot be tested with this function");
	
	const char * const passphrases[] = {
		"",
		"hello",
		"engouement cardophagus ipseity kalamkari",
	};
	static const char * const base_plaintext = "ABCDEFGHIJKLMNOP";
	typename Cipher::block_t plaintext;
	memcpy(plaintext.data(), base_plaintext, plaintext.size());

	for (auto passphrase : passphrases){
		auto digest = hash::algorithm::SHA256::compute(passphrase, strlen(passphrase)).to_array();
		Cipher aes(digest.data());
		auto ciphertext = aes.encrypt_block(plaintext);
		auto decrypted = aes.decrypt_block(ciphertext);

		if (decrypted != plaintext){
			std::stringstream stream;
			stream << cipher_string << " failed test 1 for passphrase \"" << passphrase << "\"";
			throw std::runtime_error(stream.str());
		}

		auto ciphertext2 = aes.encrypt_block(ciphertext);
		decrypted = aes.decrypt_block(ciphertext2);

		if (decrypted != ciphertext){
			std::stringstream stream;
			stream << cipher_string << " failed test 2 for passphrase \"" << passphrase << "\"";
			throw std::runtime_error(stream.str());
		}
	}
}

template <typename Cipher>
void test_block_cipher_with_vector(const char *key_string, const char *plaintext_string, const char *ciphertext_string, const char *cipher_string){
	typename Cipher::key_t key(key_string);
	auto plaintext = Cipher::block_from_string(plaintext_string);
	auto expected_ciphertext = Cipher::block_from_string(ciphertext_string);
	Cipher cipher(key);
	auto ciphertext = cipher.encrypt_block(plaintext);
	if (ciphertext != expected_ciphertext){
		std::stringstream stream;
		stream << cipher_string << " failed to encrypt correctly with key=" << key_string << ", plaintext=" << plaintext_string << ", ciphertext=" << ciphertext_string;
		throw std::runtime_error(stream.str());
	}
	auto decrypted = cipher.decrypt_block(ciphertext);
	if (decrypted != plaintext){
		std::stringstream stream;
		stream << cipher_string << " failed to decrypt correctly with key=" << key_string << ", plaintext=" << plaintext_string << ", ciphertext=" << ciphertext_string;
		throw std::runtime_error(stream.str());
	}
}

template <typename Cipher, size_t N, typename T>
void test_block_cipher_with_vectors(const T (&vectors)[N][3], const char *cipher_string){
	for (auto &vector : vectors)
		test_block_cipher_with_vector<Cipher>(vector[0], vector[1], vector[2], cipher_string);
}

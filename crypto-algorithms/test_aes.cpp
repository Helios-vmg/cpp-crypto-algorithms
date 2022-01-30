#include "aes.hpp"
#include "md5.hpp"
#include "hash.hpp"
#include <iostream>
#include <sstream>

template <size_t N>
void test_aes_sanity(){
	const char * const passphrases[] = {
		"",
		"hello",
		"engouement cardophagus ipseity kalamkari",
	};

	for (auto passphrase : passphrases){
		auto digest = Hashes::Algorithms::MD5::compute(passphrase, strlen(passphrase)).to_array();
		AES::AesKey<N> key(digest.data());
		AES::Aes<N> aes(key);
		const char plaintext[] = "ABCDEFGHIJKLMNOP";
		char ciphertext[AES::block_size];
		aes.encrypt_block(ciphertext, plaintext);
		char decrypted[AES::block_size];
		aes.decrypt_block(decrypted, ciphertext);

		if (memcmp(decrypted, plaintext, AES::block_size)){
			std::stringstream stream;
			stream << "AES-" << N << " failed test 1 for passphrase \"" << passphrase << "\"";
			throw std::runtime_error(stream.str());
		}

		char ciphertext2[AES::block_size];
		aes.encrypt_block(ciphertext2, ciphertext);
		aes.decrypt_block(decrypted, ciphertext2);

		if (memcmp(decrypted, ciphertext, AES::block_size)){
			std::stringstream stream;
			stream << "AES-" << N << " failed test 2 for passphrase \"" << passphrase << "\"";
			throw std::runtime_error(stream.str());
		}
	}
}

static void test_aes_sanity(){
	test_aes_sanity<128>();
	test_aes_sanity<192>();
	test_aes_sanity<256>();
}

template <size_t N>
AES::AesKey<N> set_key(const char *s){
	auto l = strlen(s);
	if (l != N * 2 / 8)
		throw std::exception();
	std::uint8_t buffer[N / 8];
	for (auto &b : buffer){
		b = Hashes::detail::hex2val(*(s++)) << 4;
		b |= Hashes::detail::hex2val(*(s++));
	}
	AES::AesKey<N> ret(buffer);
	return ret;
}

static std::array<std::uint8_t, AES::block_size> block_from_string(const char *s){
	auto l = strlen(s);
	if (l != AES::block_size * 2)
		throw std::exception();
	std::array<std::uint8_t, AES::block_size> ret;
	for (auto &b : ret){
		b = Hashes::detail::hex2val(*(s++)) << 4;
		b |= Hashes::detail::hex2val(*(s++));
	}
	return ret;
}

template <size_t N>
void test_aes_with_vector(const char *key_string, const char *plaintext_string, const char *ciphertext_string){
	auto key = set_key<N>(key_string);
	auto plaintext = block_from_string(plaintext_string);
	auto expected_ciphertext = block_from_string(ciphertext_string);
	char temp[AES::block_size];
	AES::Aes<N> aes(key);
	aes.encrypt_block(temp, plaintext.data());
	if (memcmp(temp, expected_ciphertext.data(), AES::block_size)){
		std::stringstream stream;
		stream << "AES-" << N << " failed to encrypt correctly with key=" << key_string << ", plaintext=" << plaintext_string << ", ciphertext=" << ciphertext_string;
		throw std::runtime_error(stream.str());
	}
	aes.decrypt_block(temp, temp);
	if (memcmp(temp, plaintext.data(), AES::block_size)){
		std::stringstream stream;
		stream << "AES-" << N << " failed to decrypt correctly with key=" << key_string << ", plaintext=" << plaintext_string << ", ciphertext=" << ciphertext_string;
		throw std::runtime_error(stream.str());
	}
}

static void test_aes_with_vectors(){
	static const char * const v[3][4][3] = {
		//128-bit key
		{
			{"2b7e151628aed2a6abf7158809cf4f3c", "6bc1bee22e409f96e93d7e117393172a", "3ad77bb40d7a3660a89ecaf32466ef97"},
			{"2b7e151628aed2a6abf7158809cf4f3c", "ae2d8a571e03ac9c9eb76fac45af8e51", "f5d3d58503b9699de785895a96fdbaaf"},
			{"2b7e151628aed2a6abf7158809cf4f3c", "30c81c46a35ce411e5fbc1191a0a52ef", "43b1cd7f598ece23881b00e3ed030688"},
			{"2b7e151628aed2a6abf7158809cf4f3c", "f69f2445df4f9b17ad2b417be66c3710", "7b0c785e27e8ad3f8223207104725dd4"},
		},
		//192-bit key
		{
			{"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "6bc1bee22e409f96e93d7e117393172a", "bd334f1d6e45f25ff712a214571fa5cc"},
			{"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "ae2d8a571e03ac9c9eb76fac45af8e51", "974104846d0ad3ad7734ecb3ecee4eef"},
			{"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "30c81c46a35ce411e5fbc1191a0a52ef", "ef7afd2270e2e60adce0ba2face6444e"},
			{"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "f69f2445df4f9b17ad2b417be66c3710", "9a4b41ba738d6c72fb16691603c18e0e"},
		},
		//256-bit key
		{
			{"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "6bc1bee22e409f96e93d7e117393172a", "f3eed1bdb5d2a03c064b5a7e3db181f8"},
			{"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "ae2d8a571e03ac9c9eb76fac45af8e51", "591ccb10d410ed26dc5ba74a31362870"},
			{"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "30c81c46a35ce411e5fbc1191a0a52ef", "b6ed21b99ca6f4f9f153e7b1beafed1d"},
			{"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "f69f2445df4f9b17ad2b417be66c3710", "23304b7a39f9f3ff067d8d8f9e24ecc7"},
		},
	};
	int i = 0;
	for (int j = 0; j < 4; j++)
		test_aes_with_vector<128>(v[i][j][0], v[i][j][1], v[i][j][2]);
	i++;
	for (int j = 0; j < 4; j++)
		test_aes_with_vector<192>(v[i][j][0], v[i][j][1], v[i][j][2]);
	i++;
	for (int j = 0; j < 4; j++)
		test_aes_with_vector<256>(v[i][j][0], v[i][j][1], v[i][j][2]);
}

void test_aes(){
	test_aes_sanity();
	test_aes_with_vectors();
	std::cout << "AES implementation passed the test!\n";
}

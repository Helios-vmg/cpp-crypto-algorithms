#include "aes.hpp"
#include "sha256.hpp"
#include "test_block.hpp"
#include "hash.hpp"
#include <iostream>
#include <sstream>

namespace {

void test_aes_sanity(){
	test_block_cipher_sanity<symmetric::Aes<128>>("AES-128");
	test_block_cipher_sanity<symmetric::Aes<192>>("AES-192");
	test_block_cipher_sanity<symmetric::Aes<256>>("AES-256");
}

void test_aes_with_vectors(){
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
	test_block_cipher_with_vectors<symmetric::Aes<128>>(v[i++], "AES-128");
	test_block_cipher_with_vectors<symmetric::Aes<192>>(v[i++], "AES-192");
	test_block_cipher_with_vectors<symmetric::Aes<256>>(v[i++], "AES-256");
}

}

void test_aes(){
	test_aes_sanity();
	test_aes_with_vectors();
	std::cout << "AES implementation passed the test!\n";
}

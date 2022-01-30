#include "twofish.hpp"
#include "hash.hpp"
#include "test_block.hpp"
#include <exception>
#include <algorithm>
#include <array>
#include <iostream>
#include <sstream>

namespace{

void test_twofish_with_vectors(){
	static const char * const v[3][4][3] = {
		//128-bit key
		{
			{"2b7e151628aed2a6abf7158809cf4f3c", "6bc1bee22e409f96e93d7e117393172a", "291ed11a7b141a067e773959f13974df"},
			{"2b7e151628aed2a6abf7158809cf4f3c", "ae2d8a571e03ac9c9eb76fac45af8e51", "9b05aa1ecbb6650fe3080aa10c2333d3"},
			{"2b7e151628aed2a6abf7158809cf4f3c", "30c81c46a35ce411e5fbc1191a0a52ef", "69e255a54af4617452a65ff06375ab73"},
			{"2b7e151628aed2a6abf7158809cf4f3c", "f69f2445df4f9b17ad2b417be66c3710", "ec939150df26b24d377943e213332f47"},
		},
		//192-bit key
		{
			{"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "6bc1bee22e409f96e93d7e117393172a", "dd250b486e904968b4495f5a110a6936"},
			{"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "ae2d8a571e03ac9c9eb76fac45af8e51", "bab94ee6dbb02af4502c90087ea78b4d"},
			{"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "30c81c46a35ce411e5fbc1191a0a52ef", "dba3ec4cf1ac94b1270f6ed948691807"},
			{"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "f69f2445df4f9b17ad2b417be66c3710", "c05fa84d69f3dd5d16f2798faf14f833"},
		},
		//256-bit key
		{
			{"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "6bc1bee22e409f96e93d7e117393172a", "e1b45f5f5bd0c9ea0de77424054222a4"},
			{"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "ae2d8a571e03ac9c9eb76fac45af8e51", "341a841d6fff65c96f7924f8bf481072"},
			{"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "30c81c46a35ce411e5fbc1191a0a52ef", "8c03971edb3fc796f861998549b7055d"},
			{"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "f69f2445df4f9b17ad2b417be66c3710", "f8c5a1e78eba66292b59d0baaa235d07"},
		},
	};
	
	int i = 0;
	test_block_cipher_with_vectors<symmetric::Twofish<128>>(v[i++], "Twofish-128");
	test_block_cipher_with_vectors<symmetric::Twofish<192>>(v[i++], "Twofish-192");
	test_block_cipher_with_vectors<symmetric::Twofish<256>>(v[i++], "Twofish-256");
}

}

void test_twofish(){
	test_twofish_with_vectors();
	std::cout << "Twofish implementation passed the test!\n";
}

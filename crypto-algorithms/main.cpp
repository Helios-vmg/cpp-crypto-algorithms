#include "test_md5.hpp"
#include "test_sha256.hpp"
#include "test_aes.hpp"
#include "test_secp256k1.hpp"
#include "test_bignum.hpp"
#include <iostream>
#include <exception>

int main(){
	try{
		test_md5();
		test_sha256();
		test_aes_sanity();
		test_aes_with_vectors();
		test_secp256k1();
		test_bignum();
	}catch (std::exception &e){
		std::cerr << e.what() << std::endl;
		return -1;
	}
	return 0;
}

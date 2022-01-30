#include "test_md5.hpp"
#include "test_sha256.hpp"
#include "test_aes.hpp"
#include "test_twofish.hpp"
#include "test_secp256k1.hpp"
#include "test_bignum.hpp"
#include <iostream>
#include <exception>

int main(){
	try{
		test_bignum();
		test_md5();
		test_sha256();
		test_aes();
		test_twofish();
		//test_secp256k1();
	}catch (std::exception &e){
		std::cerr << e.what() << std::endl;
		return -1;
	}
	return 0;
}

#include "test_md5.hpp"
#include "test_sha1.hpp"
#include "test_sha256.hpp"
#include "test_sha512.hpp"
#include "test_aes.hpp"
#include "test_twofish.hpp"
#include "test_secp256k1.hpp"
#include "test_bignum.hpp"
#include "test_stream.hpp"
#include "test_cbc.hpp"
#include "test_rng.hpp"
#include "test_base64.hpp"
#include "test_shamir.hpp"
#include "test_ed25519.hpp"
#include <iostream>
#include <exception>

int main(){
	try{
		test_fixed_bignum();
		test_arbitrary_bignum();
		test_md5();
		test_sha1();
		test_sha256();
		test_sha512();
		test_aes();
		test_twofish();
		test_stream();
		test_cbc();
		test_rng();
		test_secp256k1();
		test_ed25519();
		test_base64();
		test_shamir();
	}catch (std::exception &e){
		std::cerr << e.what() << std::endl;
		return -1;
	}
	return 0;
}

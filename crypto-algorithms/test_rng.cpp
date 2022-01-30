#include "rng.hpp"
#include "aes.hpp"
#include "twofish.hpp"
#include "hex.hpp"
#include "sha256.hpp"
#include <iostream>

template <typename C>
static bool basic_test_rng(const char *seed, const char *iv, const char *expected_digest){
	csprng::BlockCipherRng<C> rng(seed, C::block_from_string(iv));
	std::uint8_t buffer[257];
	rng.get_bytes(buffer);
	auto digest = hash::algorithm::SHA256::compute(buffer, sizeof(buffer));
	auto expected = hash::digest::SHA256(expected_digest);
	return digest == expected;
}

void test_rng(){
	const char * const seed = "4981a79c10b27bc32fcd024ccab3fa25cee961e9498ea559ea35d2207db238c6";
	const char * const iv = "1d03d849cd296e6062c3211c14f657de";
	if (!basic_test_rng<symmetric::Aes<256>>(seed, iv, "eec87370d061a403f96bd3a09dd030b1e7b4ce9541bf106259df9d6a2795b3df"))
		throw std::runtime_error("BlockCipherRng failed to generate the expected result with AES-256");
	if (!basic_test_rng<symmetric::Twofish<256>>(seed, iv, "45a1711f7d53214b64b7e42cb3a0669b5bbcffaf7ee343ebbf3fdef57f6cf175"))
		throw std::runtime_error("BlockCipherRng failed to generate the expected result with Twofish-256");
	std::cout << "BlockCipherRng passed the test!\n";
}

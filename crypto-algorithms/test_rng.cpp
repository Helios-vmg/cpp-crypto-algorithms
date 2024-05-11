#include "rng.hpp"
#include "aes.hpp"
#include "twofish.hpp"
#include "hex.hpp"
#include "sha256.hpp"
#include <iostream>
#include <sstream>

template <typename C>
static void basic_test_rng(const char *seed, const char *iv, const char *expected_digest, const char *cipher){
	csprng::BlockCipherRng<C> rng(seed, C::block_from_string(iv));
	std::uint8_t buffer[257];
	rng.get_bytes(buffer);
	auto actual = hash::algorithm::SHA256::compute(buffer, sizeof(buffer));
	auto expected = hash::digest::SHA256(expected_digest);
	if (actual != expected){
		std::stringstream stream;
		stream <<
			"BlockCipherRng failed to generate the expected result with " << cipher << ".\n"
			"Expected: " << expected << "\n"
			"Actual: " << actual;
		throw std::runtime_error(stream.str());
	}
}

void test_rng(){
	const char * const seed = "4981a79c10b27bc32fcd024ccab3fa25cee961e9498ea559ea35d2207db238c6";
	const char * const iv = "1d03d849cd296e6062c3211c14f657de";
	basic_test_rng<symmetric::Aes<256>>(seed, iv, "92fffe422f2ad00369eadcd09943d47aea7b69b12edb4c81bde6b6ac7c62fad2", "AES-256");
	basic_test_rng<symmetric::Twofish<256>>(seed, iv, "839fc32045e548b266009e5f5e6aa7b844ba2070797d32d22822de63a6b748d3", "Twofish-256");
	std::cout << "BlockCipherRng passed the test!\n";
}

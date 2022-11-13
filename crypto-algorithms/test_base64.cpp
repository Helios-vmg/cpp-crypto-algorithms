#include "test_base64.hpp"
#include "base64.hpp"
#include "rng.hpp"
#include "aes.hpp"

static void test_base64_sanity(){
	const char * const seed = "4981a79c10b27bc32fcd024ccab3fa25cee961e9498ea559ea35d2207db238c6";
	const char * const iv = "1d03d849cd296e6062c3211c14f657de";
	typedef symmetric::Aes<256> C;
	csprng::BlockCipherRng<C> rng(seed, C::block_from_string(iv));

	auto input_data = rng.get_bytes(256);

	auto encoded = utility::Base64Encoder::encode(input_data.data(), input_data.size());
	auto decoded = utility::Base64Decoder::decode(encoded);

	if (decoded.size() != input_data.size())
		throw std::runtime_error("base64 failed sanity check; incorrect decoded length");
	if (memcmp(input_data.data(), decoded.data(), input_data.size()))
		throw std::runtime_error("base64 failed sanity check; incorrect decoded content");
}

void test_base64(){
	test_base64_sanity();
	std::cout << "Base64 passed the test!\n";
}

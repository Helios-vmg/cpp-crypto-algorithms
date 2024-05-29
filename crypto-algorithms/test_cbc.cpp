#include "cbc.hpp"
#include "aes.hpp"
#include "twofish.hpp"
#include "testutils.hpp"
#include <iostream>
#include <string>
#include <stdexcept>

using namespace std::string_literals;

bool equal(const std::vector<std::uint8_t> &l, const std::vector<std::uint8_t> &r){
	if (l.size() != r.size())
		return false;
	return !memcmp(l.data(), r.data(), l.size());
}

template <typename C>
void basic_test_cbc_with_size(const C &cipher, size_t size_to_test, testutils::Rng &rng, const char *cipher_name){
	auto plaintext1 = rng.get_bytes(size_to_test);
	auto iv = rng.get_bytes_fixed<C::block_size>();

	symmetric::CbcEncryptor<C> cbc1(cipher, iv);
	auto ciphertext1 = cbc1.encrypt(plaintext1);

	symmetric::CbcDecryptor<C> cbc2(cipher, iv);
	auto plaintext2 = cbc2.decrypt(ciphertext1);

	if (!equal(plaintext1, plaintext2))
		throw std::runtime_error("CBC<"s + cipher_name + "> failed round-trip encryption at size " + std::to_string(size_to_test));

	symmetric::CbcEncryptor<C> cbc3(cipher, iv);

	auto ciphertext2 = cbc3.encrypt(plaintext2);
	if (!equal(ciphertext1, ciphertext2))
		throw std::runtime_error("CBC<"s + cipher_name + "> failed round-trip decryption at size " + std::to_string(size_to_test));
}

template <typename C>
void basic_test_cbc(const char *cipher_name){
	typedef typename C::key_t K;

	auto rng = testutils::init_rng();
	C cipher(rng.get_bytes_fixed<K::size>());

	static const auto b = C::block_size;
	static const size_t sizes[] = {
		0,
		1,
		b / 2,
		b - 1,
		b * 3 - 1,
		b * 3,
		b * 64,
	};
	for (auto size : sizes)
		basic_test_cbc_with_size<C>(cipher, size, rng, cipher_name);
}

void test_cbc(){
	basic_test_cbc<symmetric::Aes<256>>("AES-256");
	basic_test_cbc<symmetric::Twofish<256>>("Twofish-256");
	std::cout << "CBC implementation passed the test!\n";
}

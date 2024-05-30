#include "sha512.hpp"
#include <array>
#include <sstream>
#include <cstring>
#include <iostream>
#include <random>

template <typename DigestT>
std::array<char, DigestT::length * 2 + 1> to_string(const DigestT &digest){
	static const char alphabet[] = "0123456789abcdef";
	std::array<char, DigestT::length * 2 + 1> ret;
	for (size_t i = 0; i < DigestT::length; i++){
		ret[i * 2 + 0] = alphabet[digest.data[i] >> 4];
		ret[i * 2 + 1] = alphabet[digest.data[i] & 0x0F];
	}
	ret[DigestT::length * 2] = 0;
	return ret;
}

void test_sha512(const char *data, const char *sum){
	std::string digest = hash::algorithm::SHA512::compute(data, strlen(data));
	if (digest != sum){
		std::stringstream stream;
		stream << "Failed test: sha512(" << data << ") != " << sum << "\nActual: " << digest;
		throw std::runtime_error(stream.str());
	}
}

std::string generate_data(){
	std::string ret;
	ret.reserve(199933);
	std::mt19937 rng(42);
	while (ret.size() < ret.capacity()){
		auto n = rng();
		for (int i = 0; i < 4 && ret.size() < ret.capacity(); i++){
			ret.push_back(n & 0xFF);
			n >>= 8;
		}
	}
	return ret;
}

void test_sha512(){
	struct vector{
		const char *input;
		const char *result;
	};
	static const vector test_vectors[] = {
		{"", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"},
		{"a", "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75"},
		{"abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"},
		{"message digest", "107dbf389d9e9f71a3a95f6c055b9251bc5268c2be16d6c13492ea45b0199f3309e16455ab1e96118e8a905d5597b72038ddb372a89826046de66687bb420e7c"},
		{"abcdefghijklmnopqrstuvwxyz", "4dbff86cc2ca1bae1e16468a05cb9881c97f1753bce3619034898faa1aabe429955a1bf8ec483d7421fe3c1646613a59ed5441fb0f321389f77f48a879c7b1f1"},
		{"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "1e07be23c26a86ea37ea810c8ec7809352515a970e9253c26f536cfc7a9996c45c8370583e0a78fa4a90041d71a4ceab7423f19c71b9d5a3e01249f0bebd5894"},
		{"12345678901234567890123456789012345678901234567890123456789012345678901234567890", "72ec1ef1124a45b047e8b7c75a932195135bb61de24ec0d1914042246e0aec3a2354e093d76f3048b456764346900cb130d2a4fd5dd16abb5e30bcb850dee843"},
		{"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz3456", "e32b3fc4f2c1866c960e3732219458c495fad63083d11bd6393b13bd0ba186b06c75342f07645b2026d6841b1354cd5284df267a407f3c508963977b04b36932"},
		{"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz345", "babba8b7cb91f405c0d9f244618cfd474f14ed8ff3628529546bc2fa3d45130725959ddcebd462da4b42ce93db66486701da1ad25077fa916b0cf6b0107612c4"},
		{"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz34567", "9f1ead7179f97a1992d7427118cf7d112fb812b10bfba04b6d31b811bb5d8fe818c436ce8eb594a77ac3cc54a9250c60a59215d291e17d2812e503fa52e55545"},
		{"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz345678901234", "6341b11418e42b62bf302854b6bbc295f1da66ab8fc2c0bd56cd69aa29ecce145bd977fa704c1931b7fc4015351a926eb9d071942a6ffcb5a0c78f912df6b9b1"},
		{"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz34567890123", "0c14fbebb46de31617c46dea35f16dc280e4283d49b7e658bebcf39a919e5fbced06ee7c28d59e5bc1f7eb71654c62dff5a4fe5c914a8e1d949c4085271f41eb"},
	};

	for (auto &vector : test_vectors)
		test_sha512(vector.input, vector.result);

	{
		static const char * const expected = "a47843565d28924baf296db45606820282cf05fde6e0a2b16d9c57d5018af0d2eec8afd71c0b2ab44154256c522dc1f64594a9fd8dbc8ebb9f3b3044e44b06eb";
		std::string digest = hash::algorithm::SHA512::compute(generate_data());
		if (digest != expected){
			std::stringstream stream;
			stream << "Failed test: sha512(<generated>) != " << expected << "\nActual: " << digest;
			throw std::runtime_error(stream.str());
		}
	}

	std::cout << "SHA-512 implementation passed the test!\n";
}

#include "md5.hpp"
#include "aes.hpp"
#include "bignum.hpp"
#include "sha256.hpp"
#include "ECDSA.hpp"
#include <array>
#include <iostream>
#include <string>
#include <sstream>
#include <stdexcept>
#include <chrono>

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

void test_md5(const char *data, const char *sum){
	auto digest = Md5::compute(data, strlen(data));
	auto string = to_string(digest);
	if (strcmp(sum, string.data())){
		std::stringstream stream;
		stream << "Failed test: md5(" << data << ") != " << sum;
		throw std::runtime_error(stream.str());
	}
}

void test_256(const char *data, const char *sum){
	auto digest = Sha256::compute(data, strlen(data));
	auto string = to_string(digest);
	if (strcmp(sum, string.data())){
		std::stringstream stream;
		stream << "Failed test: sha256(" << data << ") != " << sum;
		throw std::runtime_error(stream.str());
	}
}

void test_md5(){
	test_md5("", "d41d8cd98f00b204e9800998ecf8427e");
	test_md5("a", "0cc175b9c0f1b6a831c399e269772661");
	test_md5("abc", "900150983cd24fb0d6963f7d28e17f72");
	test_md5("message digest", "f96b697d7cb7938d525a2f31aaf161d0");
	test_md5("abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b");
	test_md5("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "d174ab98d277d9f5a5611c2c9f419d9f");
	test_md5("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "57edf4a22be3c955ac49da2e2107b67a");
	test_md5("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz3456", "6831fa90115bb9a54fbcd4f9fee0b5c4");
	test_md5("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz345", "bc40505cc94a43b7ff3e2ac027325233");
	test_md5("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz34567", "fa94b73a6f072a0239b52acacfbcf9fa");
	test_md5("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz345678901234", "bd201eae17f29568927414fa326f1267");
	test_md5("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz34567890123", "80063db1e6b70a2e91eac903f0e46b85");
	std::cout << "MD5 implementation passed the test!\n";
}

void test_sha256(){
	test_256("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
	test_256("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
	test_256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
	test_256("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");
	std::cout << "SHA-256 implementation passed the test!\n";
}

template <size_t N>
void test_aes_sized(){
	const char * const passphrases[] = {
		"",
		"hello",
		"engouement cardophagus ipseity kalamkari",
	};

	for (auto passphrase : passphrases){
		auto digest = Md5::compute(passphrase, strlen(passphrase));
		AES::AesKey<N> key(digest.data);
		AES::Aes<N> aes(key);
		const char plaintext[] = "ABCDEFGHIJKLMNOP";
		char ciphertext[AES::block_size];
		aes.encrypt_block(ciphertext, plaintext);
		char decrypted[AES::block_size];
		aes.decrypt_block(decrypted, ciphertext);

		if (memcmp(decrypted, plaintext, AES::block_size)){
			std::stringstream stream;
			stream << "AES-" << N << " failed test 1 for passphrase \"" << passphrase << "\"";
			throw std::runtime_error(stream.str());
		}

		char ciphertext2[AES::block_size];
		aes.encrypt_block(ciphertext2, ciphertext);
		aes.decrypt_block(decrypted, ciphertext2);

		if (memcmp(decrypted, ciphertext, AES::block_size)){
			std::stringstream stream;
			stream << "AES-" << N << " failed test 2 for passphrase \"" << passphrase << "\"";
			throw std::runtime_error(stream.str());
		}
	}
	std::cout << "AES-" << N << " implementation passed the test!\n";
}

void test_aes_sanity(){
	test_aes_sized<128>();
	test_aes_sized<192>();
	test_aes_sized<256>();
}

std::uint8_t hex2val(char c){
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	throw std::exception();
}

template <size_t N>
AES::AesKey<N> set_key(const char *s){
	auto l = strlen(s);
	if (l != N * 2 / 8)
		throw std::exception();
	std::uint8_t buffer[N / 8];
	for (auto &b : buffer){
		b = hex2val(*(s++)) << 4;
		b |= hex2val(*(s++));
	}
	AES::AesKey<N> ret(buffer);
	return ret;
}

template <size_t N>
std::array<std::uint8_t, N> hex_string_to_buffer(const char *s){
	auto l = strlen(s);
	if (l != N * 2)
		throw std::exception();
	std::array<std::uint8_t, N> ret;
	for (auto &b : ret){
		b = hex2val(*(s++)) << 4;
		b |= hex2val(*(s++));
	}
	return ret;
}

std::array<std::uint8_t, AES::block_size> block_from_string(const char *s){
	auto l = strlen(s);
	if (l != AES::block_size * 2)
		throw std::exception();
	std::array<std::uint8_t, AES::block_size> ret;
	for (auto &b : ret){
		b = hex2val(*(s++)) << 4;
		b |= hex2val(*(s++));
	}
	return ret;
}

template <size_t N>
void test_aes_with_vector(const char *key_string, const char *plaintext_string, const char *ciphertext_string){
	auto key = set_key<N>(key_string);
	auto plaintext = block_from_string(plaintext_string);
	auto expected_ciphertext = block_from_string(ciphertext_string);
	char temp[AES::block_size];
	AES::Aes<N> aes(key);
	aes.encrypt_block(temp, plaintext.data());
	if (memcmp(temp, expected_ciphertext.data(), AES::block_size)){
		std::stringstream stream;
		stream << "AES-" << N << " failed to encrypt correctly with key=" << key_string << ", plaintext=" << plaintext_string << ", ciphertext=" << ciphertext_string;
		throw std::runtime_error(stream.str());
	}
	aes.decrypt_block(temp, temp);
	if (memcmp(temp, plaintext.data(), AES::block_size)){
		std::stringstream stream;
		stream << "AES-" << N << " failed to decrypt correctly with key=" << key_string << ", plaintext=" << plaintext_string << ", ciphertext=" << ciphertext_string;
		throw std::runtime_error(stream.str());
	}
}

void test_aes_with_vectors(){
	test_aes_with_vector<128>("2b7e151628aed2a6abf7158809cf4f3c", "6bc1bee22e409f96e93d7e117393172a", "3ad77bb40d7a3660a89ecaf32466ef97");
	test_aes_with_vector<128>("2b7e151628aed2a6abf7158809cf4f3c", "ae2d8a571e03ac9c9eb76fac45af8e51", "f5d3d58503b9699de785895a96fdbaaf");
	test_aes_with_vector<128>("2b7e151628aed2a6abf7158809cf4f3c", "30c81c46a35ce411e5fbc1191a0a52ef", "43b1cd7f598ece23881b00e3ed030688");
	test_aes_with_vector<128>("2b7e151628aed2a6abf7158809cf4f3c", "f69f2445df4f9b17ad2b417be66c3710", "7b0c785e27e8ad3f8223207104725dd4");

	test_aes_with_vector<192>("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "6bc1bee22e409f96e93d7e117393172a", "bd334f1d6e45f25ff712a214571fa5cc");
	test_aes_with_vector<192>("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "ae2d8a571e03ac9c9eb76fac45af8e51", "974104846d0ad3ad7734ecb3ecee4eef");
	test_aes_with_vector<192>("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "30c81c46a35ce411e5fbc1191a0a52ef", "ef7afd2270e2e60adce0ba2face6444e");
	test_aes_with_vector<192>("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "f69f2445df4f9b17ad2b417be66c3710", "9a4b41ba738d6c72fb16691603c18e0e");

	test_aes_with_vector<256>("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "6bc1bee22e409f96e93d7e117393172a", "f3eed1bdb5d2a03c064b5a7e3db181f8");
	test_aes_with_vector<256>("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "ae2d8a571e03ac9c9eb76fac45af8e51", "591ccb10d410ed26dc5ba74a31362870");
	test_aes_with_vector<256>("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "30c81c46a35ce411e5fbc1191a0a52ef", "b6ed21b99ca6f4f9f153e7b1beafed1d");
	test_aes_with_vector<256>("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "f69f2445df4f9b17ad2b417be66c3710", "23304b7a39f9f3ff067d8d8f9e24ecc7");
}

template <size_t N>
void test_addition(const BigNum<N> &a, const BigNum<N> &b, const BigNum<N> &c){
	if (a + b != c)
		throw std::exception();
}

template <size_t N>
void test_multiplication(const BigNum<N> &a, const BigNum<N> &b, const BigNum<N> &c){
	if (a * b != c)
		throw std::exception();
}

template <size_t N>
void test_division(const BigNum<N> &a, const BigNum<N> &b, const BigNum<N> &c){
	if (a / b != c)
		throw std::exception();
}

template <size_t N>
void test_modulo(const BigNum<N> &a, const BigNum<N> &b, const BigNum<N> &c){
	if (a % b != c)
		throw std::exception();
}

void test_addition2(const char *a, const char *b, const char *c){
	test_addition<64>(a, b, c);
	test_addition<256>(a, b, c);
	test_addition<1024>(a, b, c);
}

void test_addition3(const char *a, const char *b, const char *c){
	test_addition<256>(BigNum<256>::from_hex_string(a), BigNum<256>::from_hex_string(b), BigNum<256>::from_hex_string(c));
	test_addition<1024>(BigNum<1024>::from_hex_string(a), BigNum<1024>::from_hex_string(b), BigNum<1024>::from_hex_string(c));
}

void test_multiplication2(const char *a, const char *b, const char *c){
	test_multiplication<64>(a, b, c);
	test_multiplication<256>(a, b, c);
	test_multiplication<1024>(a, b, c);
}

void test_multiplication3(const char *a, const char *b, const char *c){
	test_multiplication<256>(BigNum<256>::from_hex_string(a), BigNum<256>::from_hex_string(b), BigNum<256>::from_hex_string(c));
	test_multiplication<1024>(BigNum<1024>::from_hex_string(a), BigNum<1024>::from_hex_string(b), BigNum<1024>::from_hex_string(c));
}

void test_division2(const char *a, const char *b, const char *c){
	test_division<64>(a, b, c);
	test_division<256>(a, b, c);
	test_division<1024>(a, b, c);
}

void test_division3(const char *a, const char *b, const char *c){
	test_division<256>(BigNum<256>::from_hex_string(a), BigNum<256>::from_hex_string(b), BigNum<256>::from_hex_string(c));
	test_division<1024>(BigNum<1024>::from_hex_string(a), BigNum<1024>::from_hex_string(b), BigNum<1024>::from_hex_string(c));
}

void test_bignum(){
	test_addition2("0", "0", "0");
	test_addition2("0", "1", "1");
	test_addition2("1", "0", "1");
	test_addition2("1", "1", "2");

	test_addition3("0", "0", "0");
	test_addition3("0", "1", "1");
	test_addition3("1", "0", "1");
	test_addition3("1", "1", "2");

	test_addition3("ffffffffffffffff", "0", "ffffffffffffffff");
	test_addition3("ffffffffffffffff", "1", "10000000000000000");
	test_addition3("ffffffffffffffff", "ffffffffffffffff", "1fffffffffffffffe");
	test_addition3("deadbeef8badf00d", "8badf00ddeadbeef", "16a5baefd6a5baefc");
	test_addition<64>(BigNum<64>::from_hex_string("ffffffffffffffff"), BigNum<64>::from_hex_string("1"), BigNum<64>());
	test_addition<128>(BigNum<128>::from_hex_string("ffffffffffffffff0000000000000000"), BigNum<128>::from_hex_string("10000000000000000"), BigNum<128>());
	test_addition<128>(BigNum<128>::from_hex_string("ffffffffffffffff0000000000000000"), BigNum<128>::from_hex_string("1deadbeef8badf00d"), BigNum<128>::from_hex_string("deadbeef8badf00d"));

	test_multiplication2("0", "0", "0");
	test_multiplication2("0", "1", "0");
	test_multiplication2("0", "2", "0");
	test_multiplication2("0", "3", "0");
	test_multiplication2("1", "0", "0");
	test_multiplication2("1", "1", "1");
	test_multiplication2("1", "2", "2");
	test_multiplication2("1", "3", "3");
	test_multiplication2("2", "0", "0");
	test_multiplication2("2", "1", "2");
	test_multiplication2("2", "2", "4");
	test_multiplication2("2", "3", "6");
	test_multiplication2("3", "0", "0");
	test_multiplication2("3", "1", "3");
	test_multiplication2("3", "2", "6");
	test_multiplication2("3", "3", "9");

	test_multiplication3("8badf00d", "8badf00d", "4c3658dc70aa60a9");
	test_multiplication3("deadbeef8badf00d", "8badf00ddeadbeef", "797fa2e50c3de8120b97a6adfe55c223");
	test_multiplication<64>(BigNum<64>::from_hex_string("8badf00d"), BigNum<64>::from_hex_string("8badf00d") * 10, BigNum<64>::from_hex_string("fa1f789c66a7c69a"));
	test_multiplication<64>(BigNum<64>::from_hex_string("8badf00d"), BigNum<64>::from_hex_string("8badf00d") * 1000, BigNum<64>::from_hex_string("b44b1d1819899428"));

	for (int i = 0; i <= (1 << 8); i++){
		test_division<64>(BigNum<64>(i), BigNum<64>(), BigNum<64>());
		test_division<256>(BigNum<256>(i), BigNum<256>(), BigNum<256>());
		test_division<1024>(BigNum<1024>(i), BigNum<1024>(), BigNum<1024>());
		for (int j = 1; j <= (1 << 8); j++){
			test_division<64>(BigNum<64>(i), BigNum<64>(j), BigNum<64>(i / j));
			test_division<256>(BigNum<256>(i), BigNum<256>(j), BigNum<256>(i / j));
			test_division<1024>(BigNum<1024>(i), BigNum<1024>(j), BigNum<1024>(i / j));
		}
	}
	test_division<256>(BigNum<256>::from_hex_string("6aa343c2f12bd9d379a2c9dfc2ecb8b04cba1e4b17cea53c10857850d2cc"), BigNum<256>::from_hex_string("55b6358dc9b6ec040173da7718866b"), BigNum<256>::from_hex_string("13e803628a11d92d7bf112dbade44a8"));
	test_division<1024>(BigNum<1024>::from_hex_string("6aa343c2f12bd9d379a2c9dfc2ecb8b04cba1e4b17cea53c10857850d2cc"), BigNum<1024>::from_hex_string("55b6358dc9b6ec040173da7718866b"), BigNum<1024>::from_hex_string("13e803628a11d92d7bf112dbade44a8"));
	test_division<256>(BigNum<256>::from_hex_string("d1c66eb7442349f9a8781e496471f40"), BigNum<256>::from_hex_string("e1f9389c6eaf092a7ab88558fffe65"), BigNum<256>::from_hex_string("e"));
	test_division<1024>(BigNum<1024>::from_hex_string("d1c66eb7442349f9a8781e496471f40"), BigNum<1024>::from_hex_string("e1f9389c6eaf092a7ab88558fffe65"), BigNum<1024>::from_hex_string("e"));

	test_modulo<256>(BigNum<256>::from_hex_string("6aa343c2f12bd9d379a2c9dfc2ecb8b04cba1e4b17cea53c10857850d2cc"), BigNum<256>::from_hex_string("55b6358dc9b6ec040173da7718866b"), BigNum<256>::from_hex_string("458adfb646b8e6b8752cc77dba3094"));
	test_modulo<1024>(BigNum<1024>::from_hex_string("6aa343c2f12bd9d379a2c9dfc2ecb8b04cba1e4b17cea53c10857850d2cc"), BigNum<1024>::from_hex_string("55b6358dc9b6ec040173da7718866b"), BigNum<1024>::from_hex_string("458adfb646b8e6b8752cc77dba3094"));
	test_modulo<256>(BigNum<256>::from_hex_string("d1c66eb7442349f9a8781e496471f40"), BigNum<256>::from_hex_string("e1f9389c6eaf092a7ab88558fffe65"), BigNum<256>::from_hex_string("c0c5d2e634a21f47d16a99b84735ba"));
	test_modulo<1024>(BigNum<1024>::from_hex_string("d1c66eb7442349f9a8781e496471f40"), BigNum<1024>::from_hex_string("e1f9389c6eaf092a7ab88558fffe65"), BigNum<1024>::from_hex_string("c0c5d2e634a21f47d16a99b84735ba"));

	std::cout << "Bignum implementation passed the test!\n";
}

template <typename DstT, typename SrcT>
std::unique_ptr<DstT> static_pointer_cast(std::unique_ptr<SrcT> &&p){
	return std::unique_ptr<DstT>(static_cast<DstT *>(p.release()));
}

void test_secp256k1(const char *digest_string, const char *private_key_string, const char *public_key_string, const char *nonce_string, const char *r_string, const char *s_string){
	using namespace ECDSA::Secp256k1;
	
	auto digest = hex_string_to_buffer<32>(digest_string);
	std::reverse(digest.begin(), digest.end());
	PrivateKey private_key(BigNum<1024>::from_hex_string(private_key_string));
	Nonce nonce(BigNum<1024>::from_hex_string(nonce_string));
	Signature expected_sig(BigNum<256>::from_hex_string(r_string), BigNum<256>::from_hex_string(s_string));

	auto t0 = std::chrono::high_resolution_clock::now();
	auto signature = static_pointer_cast<Signature>(private_key.sign_digest(digest.data(), digest.size(), nonce));
	auto t1 = std::chrono::high_resolution_clock::now();
	auto public_key = private_key.get_public_key();
	if (!signature || *signature != expected_sig)
		throw std::runtime_error("Secp256k1 failed signature test");
	std::cout << "Signature time: " << (t1 - t0).count() * 1e-6 << " ms\n";
	auto t2 = std::chrono::high_resolution_clock::now();
	if (signature->verify_digest(digest.data(), digest.size(), *public_key) != ECDSA::MessageVerificationResult::MessageVerified)
		throw std::runtime_error("Secp256k1 failed signature verification test");
	auto t3 = std::chrono::high_resolution_clock::now();
	std::cout << "Verification time: " << (t3 - t2).count() * 1e-6 << " ms\n";
}

void test_secp256k1(const char *original_message, const char *digest_string, const char *private_key_string, const char *public_key_string, const char *nonce_string, const char *r_string, const char *s_string){
	if (strcmp(to_string(Sha256::compute(original_message, strlen(original_message))).data(), digest_string))
		throw std::runtime_error("Secp256k1 failed hashing test");
	test_secp256k1(digest_string, private_key_string, public_key_string, nonce_string, r_string, s_string);
}

void test_secp256k1(){
	test_secp256k1("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "90c4ed5178ee4886f3f0d9bb8ea879b381d41352f43f579e8a88a0fcfa42bb59", "03d44c71f4116983b4fd0f41b030c4fdb8ae6deb7a923f37f4cb90b03ade7ca35c", "1", "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "3d6801fa9f9d05b34b79d687f9f94faccfb3f9ad6b7d50557b8e633054936bf7");
	test_secp256k1("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "3de510dd2cec8e861389b2de8e8215116ca417742bc3fc6542b0b1c6aee2cef7", "02efbbf25882a5cb6d355371cc4c97fc940c119fbf96ccdc43e243326b9ff8a68a", "2", "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5", "ebf23d1cbd83da356b2a837e7007fefd8800c5249e28f101c0f30a94588aaf76");
	test_secp256k1("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "64774742326b5d90f3862cd4943d394c3767c02c97abde5158c5cdaa61374b28", "035dc695ccb8f00036d1d328f40de03ed92b83610f06d8026702fa97fff10f3f61", "3", "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9", "e1cec2aca5305b34076fd3ee08444f68b19597049b8b2fd908e87eb375087f75");
	test_secp256k1("test", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "32bfbf1b2c56dfcd3b3ea1aaba7e612cf03b847a33900a7cf1d0246320d2d625", "03705b8b93ad034c6e440fcdffaa4ab341efd3c31d46cc7083eb6e4b04b5571306", "2a", "fe8d1eb1bcb3432b1db5833ff5f2226d9cb5e65cee430558c18ed3a3c86ce1af", "ecf2babaf1c42ea91ec9554c55cd40d5155d61a9983f8b41b59ffe22dd6b9c61");
	test_secp256k1("7d950b680dba26c22f10a4404c9ab47a21d4ef63e2fd26043602c91bedfc373a", "61c322b3efbf1008f2f72ee787d4bbc86d66c91ac75eaf96f74253c7b551305f", "03606d8a0092236d78964afdd88294b5ef6e1ac6deb23a67a72f96c4f53d707638", "799b3a176d288365b612984fd5e0d761f1c826ad2de9fbc1159e8e1898644506", "a43e084ef130db0106fe34493f1837325b29c48d083daf2dc6c1b817e1ffd4c6", "6183f775ef0b3e1b6eb4fff587cb6ff818517b2f7717bd801b14505d959e08f4");
	test_secp256k1("20f894017befa2a2aa6d8b60933540a67f5ed1a75a8957c255025698af79ba12", "c6bbb200062b9e57f92d20e0ad156da02e1e1801a15965ceaf2f4c90dfebb9b", "028610edeef6ac776e178cf1d6b864efb9c8a4ec8228b6c88aeab5437c1f8bd08d", "daac42bb81354b573df678a7104d3821790554d2dff8ed0de6bff07afd0050b7", "df7d4eb0c105c87d8515fb60df0fb334684e77a2ba9cbf978fdb43310011c777", "6ea5645b27149ea1a0e857a93f630ab6f8ca16c5b7060e75e38f476261cc0778");
	test_secp256k1("13ee15ba27dfa9527df1d09dfb05dd156c87eed127fa9f92368481b5aa3c3124", "a636ce5f7bc51d722e15189607d4bb27a424298807a38b2f3e86c5679ca2a483", "0380ad0adb682f18ff2aff82415a1781a1afc5693d0da3051b9310fc5246a1b673", "f2007bc6baea419e953fa185c53ba956d0e9ca899326acddf40aac7a40d36452", "ec52c47e6de160c43028d08a38a2ec40c844ceeb370f2795d0acc5d0efa7654d", "33bd64904ee7b2f1a83d2740d76b5d3f8c6b31ea1d2d990951a370bcd0132ced");
	test_secp256k1("b1b78c212c7f87e4215ee2ece82c2544d0b7a5bc63d56ec3b07089de2ba30d18", "e0dca7845b1321338b7bbfd54e130aff482336b6111331bc112c216f3c0dc5ed", "03ac42ce3f1b90118a312f16b1be7f0fa2e5e853b75aa3e35a59f5d9f98406e96c", "32932debf1e8c0d21947bce534baa70d744aa86bb9d1dc383c8ee5b8bd65f22d", "1e2a088ef1638ef6aa8e6a239f220e80b543c6d6fea77ffb864c51e76d9d5ad4", "e98a15364daca8518beb7054abae088d964d38a401e51a96448110b7e077824d");
	test_secp256k1("4fd53b6b31ae067dcb74a65ffa340ddd2491249354afb66bae917dd49cb177b6", "22379d7d94461d0c7bc8afd81592cbe3d7f26bcbc5471e57e0c1377a60bea8b2", "02b3fdc4ed6c2ada9c0c28cea5ca133773aa2069c89b435ec23009d6f76be5e8ee", "73293744db1cfd12f258ed9b690eb93342318b5f71c0b85df82b8d28c74c9084", "28f49387fc828e9cee4db584feebd8cade978ac7f8251eae6b978e8165646d14", "2205053d22b26d0ec893d6a72547b431d640a03c895181ae57eb2d33a1a62520");
	test_secp256k1("7f95201ab52ec3b71513f9337587a8245e3a89f5f3a53d59a4cb59a7479656b9", "cc87a54d38b16e57fb04e823a607d101ea8953417a7b09b9449074e30562a051", "028be8331bc5c61f2304fae6ebf97d0aa680fd68b2e1ba121347233905689c34a1", "ac6625efb9aed09e7ec7eab96cf4fd1354112f4325892a00d673559a2fd324f4", "8f1c4d659b3f6d74d22556e82ec0decaa6f1a396361ea36872485510a4d58ab3", "7bde5d99ff00c7a7c83d5665a0f56788a1e3f775909ba9e7d225f4e43960c675");
	std::cout << "Secp256k1 implementation passed the test!\n";
}

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

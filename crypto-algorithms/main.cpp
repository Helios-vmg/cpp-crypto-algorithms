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

void test_secp256k1(const char *digest_string, const char *private_key_string, const char *nonce_string, const char *r_string, const char *s_string){
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

void test_secp256k1(){
	test_secp256k1("4b688df40bcedbe641ddb16ff0a1842d9c67ea1c3bf63f3e0471baa664531d1a", "ebb2c082fd7727890a28ac82f6bdf97bad8de9f5d7c9028692de1a255cad3e0f", "49a0d7b786ec9cde0d0721d72804befd06571c974b191efb42ecf322ba9ddd9a", "241097efbf8b63bf145c8961dbdf10c310efbb3b2676bbc0f8b08505c9e2f795", "21006b7838609339e8b415a7f9acb1b661828131aef1ecbc7955dfb01f3ca0e");
	std::cout << "Secp256k1 implementation passed the test!\n";
}

void test_secp256k1_2(){
	using namespace ECDSA::Secp256k1;

	auto digest = block_from_string("4b688df40bcedbe641ddb16ff0a1842d9c67ea1c3bf63f3e0471baa664531d1a");
	std::reverse(digest.begin(), digest.end());
	PrivateKey private_key(BigNum<1024>::from_hex_string("ebb2c082fd7727890a28ac82f6bdf97bad8de9f5d7c9028692de1a255cad3e0f"));
	Nonce nonce(BigNum<1024>::from_hex_string("49a0d7b786ec9cde0d0721d72804befd06571c974b191efb42ecf322ba9ddd9a"));
	Signature expected_sig(BigNum<256>::from_hex_string("241097efbf8b63bf145c8961dbdf10c310efbb3b2676bbc0f8b08505c9e2f795"), BigNum<256>::from_hex_string("21006b7838609339e8b415a7f9acb1b661828131aef1ecbc7955dfb01f3ca0e"));

	for (int i = 0; i < 100; i++){
		auto signature = static_pointer_cast<Signature>(private_key.sign_digest(digest.data(), digest.size(), nonce));
		if (!signature || *signature != expected_sig)
			throw std::runtime_error("Secp256k1 failed test");
	}
}

int main(){
	try{
		//test_secp256k1_2();
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

#include "test_secp256k1.hpp"
#include "test_utility.hpp"
#include "sha256.hpp"
#include "ECDSA.hpp"
#include <iostream>
#include <chrono>

template <typename DstT, typename SrcT>
std::unique_ptr<DstT> static_pointer_cast(std::unique_ptr<SrcT> &&p){
	return std::unique_ptr<DstT>(static_cast<DstT *>(p.release()));
}

static void test_secp256k1(const char *digest_string, const char *private_key_string, const char *public_key_string, const char *nonce_string, const char *r_string, const char *s_string){
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


static void test_secp256k1(const char *original_message, const char *digest_string, const char *private_key_string, const char *public_key_string, const char *nonce_string, const char *r_string, const char *s_string){
	std::string string = Hashes::Algorithms::SHA256::compute(original_message, strlen(original_message));
	if (string != digest_string)
		throw std::runtime_error("Secp256k1 failed hashing test");
	test_secp256k1(digest_string, private_key_string, public_key_string, nonce_string, r_string, s_string);
}


void test_secp256k1(){
	struct test_case{
		const char *a;
		const char *b;
		const char *c;
		const char *d;
		const char *e;
		const char *f;
		const char *g;
	};

	static const test_case test_cases[] = {
		{
			"",
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			"90c4ed5178ee4886f3f0d9bb8ea879b381d41352f43f579e8a88a0fcfa42bb59",
			"03d44c71f4116983b4fd0f41b030c4fdb8ae6deb7a923f37f4cb90b03ade7ca35c",
			"1",
			"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
			"3d6801fa9f9d05b34b79d687f9f94faccfb3f9ad6b7d50557b8e633054936bf7",
		},
		{
			"",
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			"3de510dd2cec8e861389b2de8e8215116ca417742bc3fc6542b0b1c6aee2cef7",
			"02efbbf25882a5cb6d355371cc4c97fc940c119fbf96ccdc43e243326b9ff8a68a",
			"2",
			"c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
			"ebf23d1cbd83da356b2a837e7007fefd8800c5249e28f101c0f30a94588aaf76",
		},
		{
			"",
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			"64774742326b5d90f3862cd4943d394c3767c02c97abde5158c5cdaa61374b28",
			"035dc695ccb8f00036d1d328f40de03ed92b83610f06d8026702fa97fff10f3f61",
			"3",
			"f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
			"e1cec2aca5305b34076fd3ee08444f68b19597049b8b2fd908e87eb375087f75",
		},
		{
			"test",
			"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
			"32bfbf1b2c56dfcd3b3ea1aaba7e612cf03b847a33900a7cf1d0246320d2d625",
			"03705b8b93ad034c6e440fcdffaa4ab341efd3c31d46cc7083eb6e4b04b5571306",
			"2a",
			"fe8d1eb1bcb3432b1db5833ff5f2226d9cb5e65cee430558c18ed3a3c86ce1af",
			"ecf2babaf1c42ea91ec9554c55cd40d5155d61a9983f8b41b59ffe22dd6b9c61",
		},
		{
			nullptr,
			"7d950b680dba26c22f10a4404c9ab47a21d4ef63e2fd26043602c91bedfc373a",
			"61c322b3efbf1008f2f72ee787d4bbc86d66c91ac75eaf96f74253c7b551305f",
			"03606d8a0092236d78964afdd88294b5ef6e1ac6deb23a67a72f96c4f53d707638",
			"799b3a176d288365b612984fd5e0d761f1c826ad2de9fbc1159e8e1898644506",
			"a43e084ef130db0106fe34493f1837325b29c48d083daf2dc6c1b817e1ffd4c6",
			"6183f775ef0b3e1b6eb4fff587cb6ff818517b2f7717bd801b14505d959e08f4",
		},
		{
			nullptr,
			"20f894017befa2a2aa6d8b60933540a67f5ed1a75a8957c255025698af79ba12",
			"c6bbb200062b9e57f92d20e0ad156da02e1e1801a15965ceaf2f4c90dfebb9b",
			"028610edeef6ac776e178cf1d6b864efb9c8a4ec8228b6c88aeab5437c1f8bd08d",
			"daac42bb81354b573df678a7104d3821790554d2dff8ed0de6bff07afd0050b7",
			"df7d4eb0c105c87d8515fb60df0fb334684e77a2ba9cbf978fdb43310011c777",
			"6ea5645b27149ea1a0e857a93f630ab6f8ca16c5b7060e75e38f476261cc0778",
		},
		{
			nullptr,
			"13ee15ba27dfa9527df1d09dfb05dd156c87eed127fa9f92368481b5aa3c3124",
			"a636ce5f7bc51d722e15189607d4bb27a424298807a38b2f3e86c5679ca2a483",
			"0380ad0adb682f18ff2aff82415a1781a1afc5693d0da3051b9310fc5246a1b673",
			"f2007bc6baea419e953fa185c53ba956d0e9ca899326acddf40aac7a40d36452",
			"ec52c47e6de160c43028d08a38a2ec40c844ceeb370f2795d0acc5d0efa7654d",
			"33bd64904ee7b2f1a83d2740d76b5d3f8c6b31ea1d2d990951a370bcd0132ced",
		},
		{
			nullptr,
			"b1b78c212c7f87e4215ee2ece82c2544d0b7a5bc63d56ec3b07089de2ba30d18",
			"e0dca7845b1321338b7bbfd54e130aff482336b6111331bc112c216f3c0dc5ed",
			"03ac42ce3f1b90118a312f16b1be7f0fa2e5e853b75aa3e35a59f5d9f98406e96c",
			"32932debf1e8c0d21947bce534baa70d744aa86bb9d1dc383c8ee5b8bd65f22d",
			"1e2a088ef1638ef6aa8e6a239f220e80b543c6d6fea77ffb864c51e76d9d5ad4",
			"e98a15364daca8518beb7054abae088d964d38a401e51a96448110b7e077824d",
		},
		{
			nullptr,
			"4fd53b6b31ae067dcb74a65ffa340ddd2491249354afb66bae917dd49cb177b6",
			"22379d7d94461d0c7bc8afd81592cbe3d7f26bcbc5471e57e0c1377a60bea8b2",
			"02b3fdc4ed6c2ada9c0c28cea5ca133773aa2069c89b435ec23009d6f76be5e8ee",
			"73293744db1cfd12f258ed9b690eb93342318b5f71c0b85df82b8d28c74c9084",
			"28f49387fc828e9cee4db584feebd8cade978ac7f8251eae6b978e8165646d14",
			"2205053d22b26d0ec893d6a72547b431d640a03c895181ae57eb2d33a1a62520",
		},
		{
			nullptr,
			"7f95201ab52ec3b71513f9337587a8245e3a89f5f3a53d59a4cb59a7479656b9",
			"cc87a54d38b16e57fb04e823a607d101ea8953417a7b09b9449074e30562a051",
			"028be8331bc5c61f2304fae6ebf97d0aa680fd68b2e1ba121347233905689c34a1",
			"ac6625efb9aed09e7ec7eab96cf4fd1354112f4325892a00d673559a2fd324f4",
			"8f1c4d659b3f6d74d22556e82ec0decaa6f1a396361ea36872485510a4d58ab3",
			"7bde5d99ff00c7a7c83d5665a0f56788a1e3f775909ba9e7d225f4e43960c675",
		},
	};

	for (auto &t : test_cases){
		if (t.a)
			test_secp256k1(t.a, t.b, t.c, t.d, t.e, t.f, t.g);
		else
			test_secp256k1(t.b, t.c, t.d, t.e, t.f, t.g);
	}

	std::cout << "Secp256k1 implementation passed the test!\n";
}

#include "md5.hpp"
#include <array>
#include <sstream>
#include <cstring>
#include <iostream>

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
	std::string digest = Hashes::Algorithms::MD5::compute(data, strlen(data));
	if (digest != sum){
		std::stringstream stream;
		stream << "Failed test: md5(" << data << ") != " << sum;
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

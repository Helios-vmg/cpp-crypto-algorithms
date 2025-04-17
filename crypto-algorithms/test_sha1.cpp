#include "sha1.hpp"
#include <sstream>
#include <stdexcept>
#include <iostream>

void test_1(const char *data, const char *sum){
	auto digest = hash::algorithm::SHA1::compute(data, strlen(data));
	auto string = (std::string)digest;
	if (string != sum){
		std::stringstream stream;
		stream << "Failed test: sha1(" << data << ") == " << string << " != " << sum;
		throw std::runtime_error(stream.str());
	}
}

void test_sha1(){
	test_1("", "da39a3ee5e6b4b0d3255bfef95601890afd80709");
	test_1("abc", "a9993e364706816aba3e25717850c26c9cd0d89d");
	test_1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
	test_1("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "a49b2446a02c645bf419f995b67091253a04a259");
	std::cout << "SHA-1 implementation passed the test!\n";
}

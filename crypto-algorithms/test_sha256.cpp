#include "sha256.hpp"
#include <sstream>
#include <stdexcept>
#include <iostream>

void test_256(const char *data, const char *sum){
	auto digest = hash::algorithm::SHA256::compute(data, strlen(data));
	auto string = (std::string)digest;
	if (string != sum){
		std::stringstream stream;
		stream << "Failed test: sha256(" << data << ") != " << sum;
		throw std::runtime_error(stream.str());
	}
}

void test_sha256(){
	test_256("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
	test_256("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
	test_256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
	test_256("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");
	std::cout << "SHA-256 implementation passed the test!\n";
}

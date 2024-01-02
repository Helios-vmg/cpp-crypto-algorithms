#include "bignum.hpp"
#include <iostream>
#include <exception>

using arithmetic::fixed::BigNum;

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

static void test_addition2(const char *a, const char *b, const char *c){
	test_addition<64>(a, b, c);
	test_addition<256>(a, b, c);
	test_addition<1024>(a, b, c);
}

static void test_addition3(const char *a, const char *b, const char *c){
	test_addition<256>(BigNum<256>::from_hex_string(a), BigNum<256>::from_hex_string(b), BigNum<256>::from_hex_string(c));
	test_addition<1024>(BigNum<1024>::from_hex_string(a), BigNum<1024>::from_hex_string(b), BigNum<1024>::from_hex_string(c));
}

static void test_multiplication2(const char *a, const char *b, const char *c){
	test_multiplication<64>(a, b, c);
	test_multiplication<256>(a, b, c);
	test_multiplication<1024>(a, b, c);
}

static void test_multiplication3(const char *a, const char *b, const char *c){
	test_multiplication<256>(BigNum<256>::from_hex_string(a), BigNum<256>::from_hex_string(b), BigNum<256>::from_hex_string(c));
	test_multiplication<1024>(BigNum<1024>::from_hex_string(a), BigNum<1024>::from_hex_string(b), BigNum<1024>::from_hex_string(c));
}

static void test_division2(const char *a, const char *b, const char *c){
	test_division<64>(a, b, c);
	test_division<256>(a, b, c);
	test_division<1024>(a, b, c);
}

static void test_division3(const char *a, const char *b, const char *c){
	test_division<256>(BigNum<256>::from_hex_string(a), BigNum<256>::from_hex_string(b), BigNum<256>::from_hex_string(c));
	test_division<1024>(BigNum<1024>::from_hex_string(a), BigNum<1024>::from_hex_string(b), BigNum<1024>::from_hex_string(c));
}

static void test_addition1(){
	test_addition2("0", "0", "0");
	test_addition2("0", "1", "1");
	test_addition2("1", "0", "1");
	test_addition2("1", "1", "2");
}

static void test_addition2(){
	test_addition3("0", "0", "0");
	test_addition3("0", "1", "1");
	test_addition3("1", "0", "1");
	test_addition3("1", "1", "2");
}

static void test_addition3(){
	test_addition3(
		"ffffffffffffffff",
		"0",
		"ffffffffffffffff"
	);
	test_addition3(
		"ffffffffffffffff",
		"1",
		"10000000000000000"
	);
	test_addition3(
		"ffffffffffffffff",
		"ffffffffffffffff",
		"1fffffffffffffffe"
	);
	test_addition3(
		"deadbeef8badf00d",
		"8badf00ddeadbeef",
		"16a5baefd6a5baefc"
	);
	test_addition<64>(
		BigNum<64>::from_hex_string("ffffffffffffffff"),
		BigNum<64>::from_hex_string("1"),
		BigNum<64>()
	);
	test_addition<128>(
		BigNum<128>::from_hex_string("ffffffffffffffff0000000000000000"),
		BigNum<128>::from_hex_string("10000000000000000"),
		BigNum<128>()
	);
	test_addition<128>(
		BigNum<128>::from_hex_string("ffffffffffffffff0000000000000000"),
		BigNum<128>::from_hex_string("1deadbeef8badf00d"),
		BigNum<128>::from_hex_string("deadbeef8badf00d")
	);
}

static void test_multiplication1(){
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
}

static void test_multiplication2(){
	test_multiplication3(
		"8badf00d",
		"8badf00d",
		"4c3658dc70aa60a9"
	);
	test_multiplication3(
		"deadbeef8badf00d",
		"8badf00ddeadbeef",
		"797fa2e50c3de8120b97a6adfe55c223"
	);
	test_multiplication<64>(
		BigNum<64>::from_hex_string("8badf00d"),
		BigNum<64>::from_hex_string("8badf00d") * 10,
		BigNum<64>::from_hex_string("fa1f789c66a7c69a")
	);
	test_multiplication<64>(
		BigNum<64>::from_hex_string("8badf00d"),
		BigNum<64>::from_hex_string("8badf00d") * 1000,
		BigNum<64>::from_hex_string("b44b1d1819899428")
	);
}

static void test_division(){
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

	struct test_case{
		const char *a;
		const char *b;
		const char *c;
	};

	static const test_case test_cases[] = {
		{
			"6aa343c2f12bd9d379a2c9dfc2ecb8b04cba1e4b17cea53c10857850d2cc",
			"55b6358dc9b6ec040173da7718866b",
			"13e803628a11d92d7bf112dbade44a8",
		},
		{
			"d1c66eb7442349f9a8781e496471f40",
			"e1f9389c6eaf092a7ab88558fffe65",
			"e",
		},
	};
	for (auto &t : test_cases){
		test_division<256>(
			BigNum<256>::from_hex_string(t.a),
			BigNum<256>::from_hex_string(t.b),
			BigNum<256>::from_hex_string(t.c)
		);
		test_division<1024>(
			BigNum<1024>::from_hex_string(t.a),
			BigNum<1024>::from_hex_string(t.b),
			BigNum<1024>::from_hex_string(t.c)
		);
	}
}

static void test_modulo(){
	static const char *test_cases[] = {
		"6aa343c2f12bd9d379a2c9dfc2ecb8b04cba1e4b17cea53c10857850d2cc",
		"55b6358dc9b6ec040173da7718866b",
		"458adfb646b8e6b8752cc77dba3094",
		"d1c66eb7442349f9a8781e496471f40",
		"e1f9389c6eaf092a7ab88558fffe65",
		"c0c5d2e634a21f47d16a99b84735ba",
	};
	for (int i = 0; i < 2; i++){
		auto a = test_cases[i * 3 + 0];
		auto b = test_cases[i * 3 + 1];
		auto c = test_cases[i * 3 + 2];
		test_modulo<256>(
			BigNum<256>::from_hex_string(a),
			BigNum<256>::from_hex_string(b),
			BigNum<256>::from_hex_string(c)
		);
		test_modulo<1024>(
			BigNum<1024>::from_hex_string(a),
			BigNum<1024>::from_hex_string(b),
			BigNum<1024>::from_hex_string(c)
		);
	}
}

void test_bignum(){
	test_addition1();
	test_addition2();
	test_addition3();
	test_multiplication1();
	test_multiplication2();
	test_division();
	test_modulo();
	

	std::cout << "Bignum implementation passed the test!\n";
}

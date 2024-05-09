#pragma once

#include <cstdint>
#include <random>
#include <iostream>
#include <string>
#include <vector>
#include <limits>
#include <type_traits>

namespace arithmetic::arbitrary{

class BigNum{
	typedef uintptr_t T;
	std::vector<T> data;
	T div_aux;
	unsigned div_shift_amount;
	static const T max = std::numeric_limits<T>::max();
	static const T bits = sizeof(T) * 8;
	bool overflow;
	void reduce();
	static T multiplication_carry(T dst, const T src);
	std::vector<char> prepare_exponent() const;
	void div_shift(T bit);
	bool div_geq(const BigNum &other) const;
	void div_shift_normalize();
	bool is_prime_trial_division(const std::vector<bool> &sieve) const;
	template <typename Random>
	bool is_prime_fermat(const unsigned k, Random &source) const{
		auto &n = *this;
		auto n_minus_1 = n - 1;
		auto n_minus_2 = n_minus_1 - 1;
		for (auto i = k; i--;){
			BigNum pick(source, n_minus_2, 2);
			if (pick.mod_pow(n_minus_1, n) != 1)
				return false;
		}
		return true;
	}
	template <typename Random>
	bool is_prime_miller_rabin(const unsigned k, Random &source) const{
		auto &n = *this;
		auto d = n - 1;
		unsigned r = 0;
		while (d.even()){
			d >>= 1;
			r++;
		}
		const auto n_minus_1 = n - 1;
		const auto n_minus_2 = n_minus_1 - 1;
		for (auto i = k; i--;){
			BigNum pick(source, n_minus_2, 2);
			pick = pick.mod_pow(d, n);
			if (pick == 1 || pick == n_minus_1)
				continue;
			bool done = true;
			for (auto j = r - 1; j--;){
				pick = pick.mod_pow(2, n);
				if (pick == 1)
					return false;
				if (pick == n_minus_1){
					done = false;
					break;
				}
			}
			if (done)
				return false;
		}
		return true;
	}

public:
	BigNum() : data(1, 0), overflow(false){}
	template <typename T2>
	BigNum(T2 value, typename std::enable_if<std::is_integral<T2>::value, T2>::type * = nullptr): data(1, (T)value), overflow(false){}
	BigNum(const BigNum &other) : data(other.data), overflow(other.overflow){}
	BigNum(const BigNum &&other) : overflow(other.overflow){
		this->data = std::move(other.data);
	}
	BigNum(const char *value);
	template <typename Randomness>
	BigNum(Randomness &source, BigNum max, const BigNum &min = 0){
		this->overflow = false;
		std::uniform_int_distribution<T> dist;
		max -= min;
		auto rand_max = max;
		auto more_max = max + 1;
		rand_max.all_bits_on();
		rand_max = rand_max - (rand_max + 1) % more_max;

		do{
			this->data.resize(max.data.size());
			for (auto &i : this->data)
				i = dist(source);
			this->reduce();
		}while (*this > rand_max);
		*this %= more_max;
		*this += min;
	}
	// ((const unsigned char *)buffer)[0] -> least significant byte
	// ((const unsigned char *)buffer)[size - 1] -> most significant byte
	BigNum(const void *buffer, size_t size);
	// ((const unsigned char *)buffer)[0] -> least significant byte
	// ((const unsigned char *)buffer)[size - 1] -> most significant byte
	template <typename T2>
	BigNum(const std::vector<T2> &buffer, typename std::enable_if<std::is_integral<T2>::value && sizeof(T2) == 1>::type * = nullptr)
		: BigNum(buffer.size() ? &buffer[0] : nullptr, buffer.size()){}

	static BigNum from_hex_string(const char *string, size_t n = 0){
		if (!n)
			n = strlen(string);
		BigNum ret;
		for (size_t i = 0; i < n; i++){
			T digit = 0;
			auto c = string[i];
			if (c >= '0' && c <= '9')
				digit = c - '0';
			else if (c >= 'A' && c <= 'F')
				digit = c - 'A' + 10;
			else if (c >= 'a' && c <= 'f')
				digit = c - 'a' + 10;
			else
				continue;

			ret <<= 4;
			ret.data.front() |= digit;
		}
		return ret;
	}
	void all_bits_on();
	const BigNum &operator=(const BigNum &other);
	const BigNum &operator=(const BigNum &&other);
	const BigNum &operator+=(const BigNum &other);
	const BigNum &operator-=(const BigNum &other);
	const BigNum &operator<<=(T shift);
	const BigNum &operator>>=(T shift);
	BigNum operator*(const BigNum &other) const;
	bool even() const{
		return this->data.front() % 2 == 0;
	}
	bool odd() const{
		return !this->even();
	}
	BigNum pow(const BigNum &exponent) const;
	BigNum mod_pow(const BigNum &exponent, const BigNum &modulo) const;
	// first = quotient, second = remainder
	std::pair<BigNum, BigNum> div(const BigNum &other) const;
	BigNum operator/(const BigNum &other) const;
	BigNum operator%(const BigNum &other) const;
	BigNum operator+(const BigNum &other) const{
		auto ret = *this;
		ret += other;
		return ret;
	}
	BigNum operator-(const BigNum &other) const{
		auto ret = *this;
		ret -= other;
		return ret;
	}
	BigNum operator<<(T other) const{
		auto ret = *this;
		ret <<= other;
		return ret;
	}
	BigNum operator>>(T other) const{
		auto ret = *this;
		ret >>= other;
		return ret;
	}
	const BigNum &operator*=(const BigNum &other){
		*this = *this * other;
		return *this;
	}
	const BigNum &operator/=(const BigNum &other){
		*this = *this / other;
		return *this;
	}
	const BigNum &operator%=(const BigNum &other){
		*this = *this % other;
		return *this;
	}
	BigNum operator++(int){
		auto ret = *this;
		++*this;
		return ret;
	}
	BigNum &operator++(){
		bool overflow = false;
		for (auto &i : this->data){
			overflow = false;
			if (++i)
				break;
			overflow = true;
		}
		if (overflow)
			this->data.push_back(1);
		return *this;
	}
	BigNum operator--(int){
		auto ret = *this;
		--*this;
		return ret;
	}
	BigNum &operator--(){
		bool overflow = false;
		for (auto &i : this->data){
			overflow = false;
			if (i--)
				break;
			overflow = true;
		}
		this->reduce();
		this->overflow = overflow;
		return *this;
	}
	bool operator!() const{
		for (auto i : this->data)
			if (i)
				return false;
		return true;
	}
	bool operator==(const BigNum &other) const;
	bool operator!=(const BigNum &other) const{
		return !(*this == other);
	}
	bool operator<(const BigNum &other) const;
	bool operator>(const BigNum &other) const{
		return other < *this;
	}
	bool operator<=(const BigNum &other) const{
		return !(*this > other);
	}
	bool operator>=(const BigNum &other) const{
		return !(*this < other);
	}
	std::string to_string() const;
	std::string to_string_hex() const;

	struct primality_config{
		unsigned sieve_size = 1 << 10;
		unsigned fermat_tests = 10;
		unsigned miller_rabin_tests = 100;
	};

	static std::vector<bool> create_sieve(unsigned max);
	
	template <typename Random>
	bool is_probably_prime(const std::vector<bool> &sieve, Random &source, const primality_config &config = primality_config()) const{
		auto &n = *this;
		if (!n.is_prime_trial_division(sieve))
			return false;
		if (!n.is_prime_fermat(config.fermat_tests, source))
			return false;
		if (!n.is_prime_miller_rabin(config.miller_rabin_tests, source))
			return false;
		return true;
	}

	template <typename Random>
	static BigNum generate_prime(Random &source, const BigNum &bits, primality_config config = primality_config()){
		auto sieve = create_sieve(config.sieve_size);
		auto ret = BigNum(source, BigNum(2).pow(bits) - 1);
		if (ret.even())
			ret += 1;
		while (!ret.is_probably_prime(sieve, source, config))
			ret -= 2;
		return ret;
	}

	BigNum gcd(BigNum b) const;
	std::vector<std::uint8_t> to_buffer() const;
	size_t all_bits() const{
		return this->data.size() * this->bits;
	}
	size_t active_bits() const{
		auto ret = (this->data.size() - 1) * this->bits;
		for (auto word = this->data.back(); word; word >>= 1)
			ret++;
		return ret;
	}
	template <typename T>
	typename std::enable_if<std::is_integral<T>::value, T>::type
	convert_to() const{
		if (*this > std::numeric_limits<T>::max())
			throw std::bad_cast();
		T ret = 0;
		for (auto it = this->data.rbegin(), e = this->data.rend(); it != e; ++it){
			ret <<= bits;
			ret |= (T)*it;
		}
		return ret;
	}
	template <typename T>
	typename std::enable_if<std::is_integral<T>::value, T>::type
	convert_to_wrapping() const{
		BigNum mod = std::numeric_limits<T>::max();
		mod = mod + 1;
		return (*this % mod).convert_to<T>();
	}
};

std::ostream &operator<<(std::ostream &stream, const BigNum &n);

class SignedBigNum{
	BigNum bignum;
	bool sign;
	SignedBigNum sum(const SignedBigNum &other, bool flip_right_sign) const;
public:
	SignedBigNum() : bignum(), sign(false) {}
	SignedBigNum(int value) : bignum(value), sign(value < 0){}
	SignedBigNum(const BigNum &b): bignum(b), sign(false){}
	SignedBigNum(BigNum &&b): bignum(std::move(b)), sign(false){}
	bool positive() const{
		return !this->sign;
	}
	bool negative() const{
		return this->sign;
	}
	bool even() const{
		return this->bignum.even();
	}
	bool odd() const{
		return this->bignum.odd();
	}
	void invert_sign(){
		this->sign = !this->sign;
	}
	SignedBigNum operator-() const{
		auto ret = *this;
		ret.invert_sign();
		return ret;
	}
	const BigNum &abs() const{
		return this->bignum;
	}
	SignedBigNum operator++(int){
		auto ret = *this;
		++*this;
		return ret;
	}
	SignedBigNum &operator++(){
		if (this->sign){
			--this->bignum;
			if (!this->bignum)
				this->sign = false;
		}else
			++this->bignum;
		return *this;
	}
	SignedBigNum operator--(int){
		auto ret = *this;
		--*this;
		return ret;
	}
	SignedBigNum &operator--(){
		if (this->sign){
			++this->bignum;
			if (!this->bignum)
				this->sign = false;
		}else
			--this->bignum;
		return *this;
	}
	bool operator==(const SignedBigNum &other) const {
		return this->bignum == other.bignum && this->sign == other.sign;
	}
	bool operator!=(const SignedBigNum &other) const {
		return !(*this == other);
	}
	bool operator<(const SignedBigNum &other) const;
	bool operator>(const SignedBigNum &other) const {
		return other < *this;
	}
	bool operator<=(const SignedBigNum &other) const {
		return !(*this > other);
	}
	bool operator>=(const SignedBigNum &other) const {
		return !(*this < other);
	}
	SignedBigNum operator+(const SignedBigNum &other) const;
	SignedBigNum operator-(const SignedBigNum &other) const;
	const SignedBigNum &operator*=(const SignedBigNum &other){
		this->bignum *= other.bignum;
		this->sign ^= other.sign;
		return *this;
	}
	const SignedBigNum &operator/=(const SignedBigNum &other){
		this->bignum /= other.bignum;
		this->sign ^= other.sign;
		return *this;
	}
	const SignedBigNum &operator%=(const SignedBigNum &other){
		this->bignum %= other.bignum;
		this->sign = this->sign;
		return *this;
	}
	std::pair<SignedBigNum, SignedBigNum> div(const SignedBigNum &other) const{
		auto temp = this->bignum.div(other.bignum);
		std::pair<SignedBigNum, SignedBigNum> ret;
		ret.first.bignum = std::move(temp.first);
		ret.second.bignum = std::move(temp.second);
		ret.first.sign = this->sign ^ other.sign;
		ret.second.sign = this->sign;
		return ret;
	}
	const SignedBigNum &operator+=(const SignedBigNum &other){
		return *this = *this + other;
	}
	const SignedBigNum &operator-=(const SignedBigNum &other){
		return *this = *this - other;
	}
	SignedBigNum operator*(const SignedBigNum &other) const{
		auto ret = *this;
		ret *= other;
		return ret;
	}
	SignedBigNum operator/(const SignedBigNum &other) const{
		auto ret = *this;
		ret /= other;
		return ret;
	}
	SignedBigNum operator%(const SignedBigNum &other) const{
		auto ret = *this;
		ret %= other;
		return ret;
	}
	SignedBigNum operator>>(const SignedBigNum &other) const{
		auto ret = *this;
		ret >>= other;
		return ret;
	}
	SignedBigNum &operator>>=(const SignedBigNum &other){
		if (other.sign)
			this->bignum <<= other.bignum.convert_to<uintptr_t>();
		else
			this->bignum >>= other.bignum.convert_to<uintptr_t>();
		return *this;
	}
	SignedBigNum operator<<(const SignedBigNum &other) const{
		auto ret = *this;
		ret <<= other;
		return ret;
	}
	SignedBigNum &operator<<=(const SignedBigNum &other){
		if (other.sign)
			this->bignum >>= other.bignum.convert_to<uintptr_t>();
		else
			this->bignum <<= other.bignum.convert_to<uintptr_t>();
		return *this;
	}
	bool operator!() const{
		return !this->bignum;
	}
	std::string to_string() const{
		std::string ret;
		if (this->sign)
			ret += '-';
		ret += this->bignum.to_string();
		return ret;
	}
	SignedBigNum extended_euclidean(const SignedBigNum &) const;
	BigNum euclidean_modulo(const SignedBigNum &other) const;
	SignedBigNum pow(const SignedBigNum &exponent) const;
	BigNum mod_pow(const SignedBigNum &exponent, const SignedBigNum &modulo) const;
};

std::ostream &operator<<(std::ostream &stream, const SignedBigNum &n);

bool tonelli_shanks(SignedBigNum &first_solution, SignedBigNum &second_solution, const SignedBigNum &a, const SignedBigNum &n);

}

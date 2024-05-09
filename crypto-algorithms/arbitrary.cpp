#include "arbitrary.hpp"
#include <cstdint>
#include <random>
#include <vector>
#include <algorithm>
#include <limits>
#include <cassert>
#include <string>
#include <type_traits>
#include <sstream>
#include <iomanip>

namespace arithmetic::arbitrary{

BigNum::BigNum(const char *value){
	this->overflow = false;
	this->data.resize(1, 0);
	if (!strcmp(value, "0"))
		return;
	for (; *value; value++){
		*this *= 10;
		*this += *value - '0';
	}
}

BigNum::BigNum(const void *buffer, size_t size){
	this->overflow = false;
	if (!buffer || !size){
		*this = 0;
		return;
	}
	T accum = 0;
	unsigned shift = 0;
	const auto n = sizeof(T);
	this->data.clear();
	this->data.reserve((size + (n - 1)) / n);
	for (size_t i = 0; i < size; i++){
		if (i && !(i % n)){
			this->data.push_back(accum);
			accum = 0;
		}
		//auto index = i / n * n + (n - 1) - i % n;
		T byte = ((const unsigned char *)buffer)[i];
		accum |= byte << (i % n * 8);
	}
	if (accum)
		this->data.push_back(accum);
	this->reduce();
}

void BigNum::reduce(){
	while (this->data.size() > 1 && !this->data.back())
		this->data.pop_back();
}

BigNum::T BigNum::multiplication_carry(T dst, const T src){
	const auto bits2 = bits / 2;
	const auto mask = ((T)1 << bits2) - 1;
	auto dst_lo = dst & mask;
	auto dst_hi = dst >> bits2;
	auto src_lo = src & mask;
	auto src_hi = src >> bits2;

	auto a = dst_hi * src_lo;
	auto b = dst_lo * src_hi;
	auto c = dst_lo * src_lo;
	auto d = dst_hi * src_hi;
	auto e = c >> bits2;
	auto f = a + e;
	T carry = (T)(f > max - b) << bits2;
	f += b;
	auto g = (f >> bits2) + carry;
	auto h = g + d;
	return h;
}

std::vector<char> BigNum::prepare_exponent() const{
	std::vector<char> ret;
	ret.reserve(this->data.size() * this->bits);
	for (auto i : this->data){
		for (auto j = this->bits; j--;){
			ret.push_back(i & 1);
			i >>= 1;
		}
	}
	while (ret.size() && !ret.back())
		ret.pop_back();
	return ret;
}

void BigNum::div_shift(T bit){
	this->div_aux <<= 1;
	this->div_aux |= bit;
	if (++this->div_shift_amount == this->bits){
		auto aux = this->div_aux;
		this->div_aux = 0;
		this->div_shift_amount = 0;
		*this <<= this->bits;
		this->data.front() = aux;
	}
}

bool BigNum::div_geq(const BigNum &other) const{
	if (!this->div_shift_amount)
		return *this >= other;

	T last_word = this->data.back() >> (this->bits - this->div_shift_amount);
	if (last_word){
		if (this->data.size() + 1 > other.data.size())
			return true;
		if (this->data.size() + 1 < other.data.size())
			return false;
		if (last_word > other.data.back())
			return true;
		if (last_word < other.data.back())
			return false;
	}else{
		if (this->data.size() > other.data.size())
			return true;
		if (this->data.size() < other.data.size())
			return false;
	}

	for (auto i = this->data.size(); i--;){
		T word = this->data[i];
		word <<= this->div_shift_amount;
		if (i)
			word |= this->data[i - 1] >> (this->bits - this->div_shift_amount);
		else
			word |= this->div_aux;
		if (word > other.data[i])
			return true;
		if (word < other.data[i])
			return false;
	}
	return true;
}

void BigNum::div_shift_normalize(){
	*this <<= this->div_shift_amount;
	this->div_shift_amount = 0;
	this->data.front() |= this->div_aux;
	this->div_aux = 0;
}

std::vector<bool> BigNum::create_sieve(unsigned max){
	std::vector<bool> sieve(max, true);
	sieve[0] = false;
	sieve[1] = false;
	for (size_t i = 2; i < sieve.size(); i++){
		if (!sieve[i])
			continue;
		for (size_t j = i * 2; j < sieve.size(); j += i)
			sieve[j] = false;
	}
	return sieve;
}

bool BigNum::is_prime_trial_division(const std::vector<bool> &sieve) const{
	auto &n = *this;
	for (size_t i = 2; i < sieve.size(); i++)
		if (sieve[i] && n % i == 0)
			return false;
	return true;
}

void BigNum::all_bits_on(){
	for (auto &i : this->data)
		i = std::numeric_limits<typename std::remove_reference<decltype(i)>::type>::max();
}

const BigNum &BigNum::operator=(const BigNum &other){
	this->data = other.data;
	this->overflow = other.overflow;
	return *this;
}

const BigNum &BigNum::operator=(const BigNum &&other){
	if (this != &other)
		this->data = std::move(other.data);
	this->overflow = other.overflow;
	return *this;
}

const BigNum &BigNum::operator+=(const BigNum &other){
	this->overflow = false;
	if (this == &other){
		*this <<= 1;
		return *this;
	}
	T carry = 0;
	auto &v = this->data;
	auto &v2 = other.data;
	v.resize(std::max(v.size(), v2.size()));
	for (size_t i = 0; i < v.size(); i++){
		if (carry){
			if (v[i] > max - carry){
				v[i] -= max - carry + 1;
				carry = 1;
			}else{
				v[i] += carry;
				carry = 0;
			}
		}
		if (i >= v2.size())
			continue;
		if (v[i] > max - v2[i]){
			v[i] -= max - v2[i] + 1;
			carry++;
		}
		else
			v[i] += v2[i];
	}
	if (carry)
		this->data.push_back(carry);
	this->reduce();
	return *this;
}

const BigNum &BigNum::operator-=(const BigNum &other){
	this->overflow = false;
	if (this == &other){
		this->data.resize(1);
		this->data[0] = 0;
		return *this;
	}
	auto &v = this->data;
	auto &v2 = other.data;
	v.resize(std::max(v.size(), v2.size()));
	T borrow = 0;
	for (size_t i = 0; i < v.size(); i++){
		if (borrow){
			if (borrow > v[i]){
				v[i] = max - (borrow - v[i]) + 1;
				borrow = 1;
			}else{
				v[i] -= borrow;
				borrow = 0;
			}
		}
		if (i >= v2.size())
			continue;
		if (v2[i] > v[i]){
			v[i] = max - v2[i] + v[i] + 1;
			borrow++;
		}
		else
			v[i] -= v2[i];
	}
	this->overflow = borrow > 0;
	this->reduce();
	return *this;
}

const BigNum &BigNum::operator<<=(T shift){
	if (!*this)
		return *this;
	this->overflow = false;
	auto mod_shift = shift % this->bits;
	shift /= this->bits;
	if (mod_shift){
		T carry = 0;
		for (auto &i : this->data){
			auto new_value = i << mod_shift;
			auto rotation = i >> (this->bits - mod_shift);
			i = new_value | carry;
			carry = rotation;
		}
		if (carry)
			this->data.push_back(carry);
	}
	if (shift)
		this->data.insert(this->data.begin(), shift, 0);
	this->reduce();
	return *this;
}

const BigNum &BigNum::operator>>=(T shift){
	if (!*this)
		return *this;
	this->overflow = false;
	auto mod_shift = shift % this->bits;
	shift /= this->bits;
	if (shift)
		this->data.erase(this->data.begin(), this->data.begin() + shift);
	if (mod_shift){
		T carry = 0;
		for (size_t i = this->data.size(); i--;){
			auto &el = this->data[i];
			auto new_value = el >> mod_shift;
			auto rotation = el << (this->bits - mod_shift);
			el = new_value | carry;
			carry = rotation;
		}
	}
	this->reduce();
	return *this;
}

BigNum BigNum::operator*(const BigNum &other) const{
#if 0
	BigNum ret;
	auto &v = this->data;
	auto &v2 = other.data;
	BigNum temp;
	for (size_t i = 0; i < v2.size(); i++){
		temp.data.clear();
		temp.data.resize(i);
		T carry = 0;
		for (size_t j = 0; j < v.size(); j++){
			auto product = v[j] * v2[i];
			if (carry){
				if (product > max - carry){
					product -= max - carry + 1;
					carry = 1;
				}else{
					product += carry;
					carry = 0;
				}
			}
			temp.data.push_back(product);
			carry += multiplication_carry(v[j], v2[i]);
		}
		if (carry)
			temp.data.push_back(carry);
		ret += temp;
	}
#else
	if (!*this)
		return *this;
	if (!other)
		return other;
	auto multiplicand = *this;
	BigNum ret = 0;
	auto bits = other.prepare_exponent();
	for (size_t i = 0;;){
		auto bit = bits[i];
		if (bit)
			ret += multiplicand;
		if (++i == bits.size())
			break;
		multiplicand <<= 1;
	}
#endif
	return ret;
}

BigNum BigNum::pow(const BigNum &exponent) const{
	auto multiplier = *this;
	BigNum ret = 1;
	auto exp = exponent.prepare_exponent();
	for (size_t i = 0;;){
		auto bit = exp[i];
		if (bit)
			ret *= multiplier;
		if (++i == exp.size())
			break;
		multiplier *= multiplier;
	}
	return ret;
}

BigNum BigNum::mod_pow(const BigNum &exponent, const BigNum &modulo) const{
	auto multiplier = *this;
	BigNum ret = 1;
	auto exp = exponent.prepare_exponent();
	for (size_t i = 0;;){
		auto bit = exp[i];
		if (bit){
			ret *= multiplier;
			ret %= modulo;
		}
		if (++i == exp.size())
			break;
		multiplier *= multiplier;
		multiplier %= modulo;
	}
	return ret;
}

std::pair<BigNum, BigNum> BigNum::div(const BigNum &other) const{
	std::pair<BigNum, BigNum> ret;
	if (!other)
		return ret;
	auto &N = *this;
	auto &D = other;
	auto &Q = ret.first;
	auto &R = ret.second;
	auto n = this->bits * this->data.size();
	R.div_aux = 0;
	R.div_shift_amount = 0;
	for (auto i = n; i--;){
		auto bit = (this->data[i / this->bits] >> (i % this->bits)) & 1;
		R.div_shift(bit);
		if (R.div_geq(D)){
			R.div_shift_normalize();
			R -= D;
			if (Q.data.size() < i / this->bits + 1)
				Q.data.resize(i / this->bits + 1, 0);
			Q.data[i / this->bits] |= (T)1 << (i % this->bits);
		}
	}
	R.div_shift_normalize();
	return ret;
}

BigNum BigNum::operator/(const BigNum &other) const{
#if 0
	return this->div(other).first;
#else
	BigNum ret;
	if (!other)
		return ret;
	auto &N = *this;
	auto &D = other;
	auto &Q = ret;
	BigNum R;
	auto n = this->bits * this->data.size();
	R.div_aux = 0;
	R.div_shift_amount = 0;
	for (auto i = n; i--;){
		auto bit = (this->data[i / this->bits] >> (i % this->bits)) & 1;
		R.div_shift(bit);
		if (R.div_geq(D)){
			R.div_shift_normalize();
			R -= D;
			if (Q.data.size() < i / this->bits + 1)
				Q.data.resize(i / this->bits + 1, 0);
			Q.data[i / this->bits] |= (T)1 << (i % this->bits);
		}
	}
	return ret;
#endif
}

BigNum BigNum::operator%(const BigNum &other) const{
#if 0
	return this->div(other).second;
#else
	BigNum ret;
	if (!other)
		return ret;
	auto &N = *this;
	auto &D = other;
	auto &R = ret;
	auto n = this->bits * this->data.size();
	R.div_aux = 0;
	R.div_shift_amount = 0;
	for (auto i = n; i--;){
		auto bit = (this->data[i / this->bits] >> (i % this->bits)) & 1;
		R.div_shift(bit);
		if (R.div_geq(D)){
			R.div_shift_normalize();
			R -= D;
		}
	}
	R.div_shift_normalize();
	return ret;
#endif
}

bool BigNum::operator==(const BigNum &other) const{
	if (this->data.size() != other.data.size())
		return false;
	for (size_t i = this->data.size(); i--;)
		if (this->data[i] != other.data[i])
			return false;
	return true;
}

bool BigNum::operator<(const BigNum &other) const{
	auto &v = this->data;
	auto &v2 = other.data;
	if (v.size() < v2.size())
		return true;
	if (v.size() > v2.size())
		return false;
	for (size_t i = v.size(); i--;){
		if (v[i] < v2[i])
			return true;
		if (v[i] > v2[i])
			return false;
	}
	return false;
	//return (*this - other).overflow;
}

std::string BigNum::to_string() const{
	if (!*this)
		return "0";
	auto copy = *this;
	std::string ret;
	while (!!copy){
		auto div = copy.div(1000000000);
		copy = div.first;
		auto &v = div.second.data;
		assert(v.size() == 1);
		for (int i = 9; i--;){
			ret += '0' + v.front() % 10;
			v.front() /= 10;
		}
	}
	while (ret.size() && ret.back() == '0')
		ret.resize(ret.size() - 1);
	std::reverse(ret.begin(), ret.end());
	return ret;
}

std::string BigNum::to_string_hex() const{
	std::stringstream stream;
	if (!*this){
		for (auto i = this->bits; i--;)
			stream << '0';
	}else{
		for (auto i = this->data.size(); i--;){
			stream << std::hex << std::setw(sizeof(T) * 2) << std::setfill('0') << (std::uintmax_t)this->data[i];
			if (i)
				stream << ' ';
		}
	}
	return stream.str();
}

BigNum BigNum::gcd(BigNum b) const{
	auto a = *this;
	while (!!b){
		auto temp = b;
		b = a % b;
		a = temp;
	}
	return a;
}

std::vector<std::uint8_t> BigNum::to_buffer() const{
	std::vector<std::uint8_t> ret;
	if (!*this){
		ret.push_back(0);
	}else{
		for (auto digit : this->data){
			for (auto i = sizeof(T); i--;){
				ret.push_back(digit & 0xFF);
				digit >>= 8;
			}
		}
		while (ret.size() > 1 && !ret.back())
			ret.pop_back();
	}
	return ret;
}

bool SignedBigNum::operator<(const SignedBigNum &other) const{
	if (this->negative() && other.positive())
		return true;
	if (this->positive() && other.negative())
		return false;
	bool ret = this->positive();
	return this->bignum < other.bignum ? ret : !ret;
}

SignedBigNum SignedBigNum::operator+(const SignedBigNum &other) const{
	return this->sum(other, false);
}

SignedBigNum SignedBigNum::sum(const SignedBigNum &other, bool flip_right_sign) const{
	SignedBigNum ret;
	if (this->positive()){
		if (other.positive() ^ flip_right_sign)
			ret.bignum = this->bignum + other.bignum;
		else{
			if (this->bignum >= other.bignum)
				ret.bignum = this->bignum - other.bignum;
			else{
				ret.bignum = other.bignum - this->bignum;
				ret.sign = true;
			}
		}
	}else{
		if ((!other.positive()) ^ flip_right_sign){
			ret.bignum = this->bignum + other.bignum;
			ret.sign = true;
		}else{
			if (other.bignum >= this->bignum) {
				ret.bignum = other.bignum - this->bignum;
				ret.sign = true;
			}else{
				ret.bignum = this->bignum - other.bignum;
				ret.sign = false;
			}
		}
	}
	return ret;
}

SignedBigNum SignedBigNum::operator-(const SignedBigNum &other) const{
	return this->sum(other, true);
}

std::ostream &operator<<(std::ostream &stream, const BigNum &n){
	return stream << n.to_string();
}

std::ostream &operator<<(std::ostream &stream, const SignedBigNum &n){
	return stream << n.to_string();
}

SignedBigNum SignedBigNum::extended_euclidean(const SignedBigNum &b) const{
	auto a = *this;
	SignedBigNum x0(1);
	SignedBigNum x1;
	auto b2 = b;
	while (!!b2){
		auto [quotient, remainder] = a.div(b2);
		a = std::move(b2);
		b2 = std::move(remainder);

		auto temp = std::move(x0);
		x0 = std::move(x1);
		x1 = temp - quotient * x0;
	}

	return x0.euclidean_modulo(b);
}

BigNum SignedBigNum::euclidean_modulo(const SignedBigNum &other) const{
	if (this->sign)
		return ((*this % other + other) % other).bignum;
	return (*this % other).bignum;
}

SignedBigNum SignedBigNum::pow(const SignedBigNum &exponent) const{
	if (exponent.sign)
		throw std::runtime_error("cannot raise integer to negative power");
	auto sign = exponent.bignum.odd() && this->sign;
	SignedBigNum ret = this->bignum.pow(exponent.bignum);
	ret.sign = exponent.bignum.odd() && this->sign;
	return ret;
}

BigNum SignedBigNum::mod_pow(const SignedBigNum &exponent, const SignedBigNum &modulo) const{
	if (exponent.sign)
		throw std::runtime_error("cannot raise integer to negative power");
	SignedBigNum m = modulo.abs();
	return this->euclidean_modulo(m).mod_pow(exponent.bignum, m.bignum);
}

SignedBigNum legendre_operation(const SignedBigNum &a, const SignedBigNum &b){
	return a.mod_pow((b - 1) >> 1, b);
}

bool tonelli_shanks(SignedBigNum &first_solution, SignedBigNum &second_solution, const SignedBigNum &a, const SignedBigNum &n){
	if (legendre_operation(a, n) != 1)
		return false;

	typedef SignedBigNum Z;

	auto n1 = n - 1;
	auto q = n1;
	Z s;
	while (q.even()){
		q >>= 1;
		++s;
	}

	if (s == 1){
		Z temp = a.mod_pow((n + 1) >> 2, n);
		first_solution = temp;
		second_solution = (-temp).euclidean_modulo(n);
		return true;
	}

	Z z(2);
	for (auto n2 = n1 >> 1; (Z)z.mod_pow(n2, n) != n1;)
		z++;

	Z c = z.mod_pow(q, n);
	Z r = a.mod_pow((q + 1) >> 1, n);
	Z t = a.mod_pow(q, n);
	Z m = s;
	const Z one(1);
	while (t % n != 1){
		Z i;
		auto m2 = m - 1;

		for (auto z2 = t; z2 != one && i < m2; ++i)
			z2 = z2 * z2 % n;

		SignedBigNum b = c;
		for (auto e = m - i - 1; !!e; --e)
			b = b * b % n;

		r = r * b % n;
		c = b * b % n;
		t = t * c % n;
		m = i;
	}
	first_solution = r;
	second_solution = (n - r) % n;
	return true;
}

}

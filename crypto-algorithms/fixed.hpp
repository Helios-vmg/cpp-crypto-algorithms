#pragma once

#include <cstddef>
#include <climits>
#include <cstring>
#include <algorithm>
#include <array>
#include <type_traits>
#include <cstdint>

namespace arithmetic::fixed{

template <size_t MinimumBits, typename number_t = uintptr_t>
class SignedBigNum;

template <size_t MinimumBits, typename number_t = uintptr_t>
class BigNum{
public:
	static inline const size_t bits_per_byte = CHAR_BIT;
	static inline const size_t bits_per_number = sizeof(number_t) * bits_per_byte;
	static inline const size_t numbers = (MinimumBits + bits_per_number - 1) / bits_per_number;
	static inline const size_t bytes = numbers * sizeof(number_t);
	static inline const size_t bits = bits_per_number * numbers;
	static inline const number_t max = std::numeric_limits<number_t>::max();
private:
	template <size_t N, typename T>
	friend class BigNum;
	template <size_t N, typename T>
	friend class SignedBigNum;
	number_t data[numbers];
#define USE_DIV_OPTIMIZATION

	std::array<char, bits> prepare_exponent(size_t &bit_count) const{
		std::array<char, bits> ret;
		size_t n = 0;
		for (auto i : this->data){
			for (auto j = bits_per_number; j--;){
				ret[n++] = i & 1;
				i >>= 1;
			}
		}
		bit_count = 0;
		for (size_t i = 0; i < bits; i++)
			if (ret[i])
				bit_count = i + 1;
		return ret;
	}
#ifndef USE_DIV_OPTIMIZATION
	void div_shift(uintptr_t bit){
		*this <<= 1;
		this->data[0] |= bit;
	}
	bool div_geq(const BigNum &other) const{
		return *this >= other;
	}
	void div_shift_normalize(){
	}
#else
	number_t div_aux = 0;
	int div_shift_amount = 0;

	void div_shift(number_t bit){
		this->div_aux <<= 1;
		this->div_aux |= bit;
		if (++this->div_shift_amount == bits_per_number){
			auto aux = this->div_aux;
			this->div_aux = 0;
			this->div_shift_amount = 0;
			*this <<= bits_per_number;
			this->data[0] = aux;
		}
	}
	bool div_geq(const BigNum &other) const{
#if 1
		auto s = this->div_shift_amount;
		if (!s)
			return *this >= other;
		if (!this->div_aux && !*this)
			return false;
		auto ns = bits_per_number - this->div_shift_amount;

		for (auto i = numbers; i-- != 1;){
			auto word = this->data[i] << s;
			word |= this->data[i - 1] >> ns;
			if (word > other.data[i])
				return true;
			if (word < other.data[i])
				return false;
		}
		auto word = this->data[0] << this->div_shift_amount;
		word |= this->div_aux;
		return word >= other.data[0];
#else
		auto s = this->div_shift_amount;
		if (!s)
			return *this >= other;

		auto ns = bits_per_number - this->div_shift_amount;

		auto carry = this->data[numbers - 1] << s;
		for (auto i = numbers - 1; i--;){
			auto word = carry | (this->data[i] >> ns);
			carry = this->data[i] << s;
			if (word > other.data[i + 1])
				return true;
			if (word < other.data[i + 1])
				return false;
		}
		return (carry | this->div_aux) >= other.data[0];
#endif
	}
	void div_shift_normalize(){
		*this <<= this->div_shift_amount;
		this->div_shift_amount = 0;
		this->data[0] |= this->div_aux;
		this->div_aux = 0;
	}
#endif
public:
	BigNum(){
		std::fill(this->data, this->data + numbers, 0);
	}

#define DEFINE_BIGNUM_CONSTRUCTOR(x) \
	BigNum(x value){ \
		this->data[0] = (uintptr_t)(typename std::make_unsigned<x>::type)value; \
		std::fill(this->data + 1, this->data + numbers, 0); \
	}
	DEFINE_BIGNUM_CONSTRUCTOR(uintptr_t)
	DEFINE_BIGNUM_CONSTRUCTOR(int)
	DEFINE_BIGNUM_CONSTRUCTOR(long)
	DEFINE_BIGNUM_CONSTRUCTOR(long long)
	DEFINE_BIGNUM_CONSTRUCTOR(short)

	BigNum(const void *void_buffer, size_t n): BigNum(){
		auto buffer = (const std::uint8_t *)void_buffer;
		for (size_t i = 0; i < n && i < bytes; i++)
			this->data[i / sizeof(number_t)] |= ((number_t)buffer[i]) << (i % sizeof(number_t) * bits_per_byte);
	}
	BigNum(const char *string);
	static BigNum from_hex_string(const char *string, size_t length = 0){
		if (!length)
			length = strlen(string);
		BigNum ret;
		for (size_t write_pos = 0, read_pos = length; write_pos < bytes * 2 && read_pos--;){
			number_t digit = 0;
			auto c = string[read_pos];
			if (c >= '0' && c <= '9')
				digit = c - '0';
			else if (c >= 'A' && c <= 'F')
				digit = c - 'A' + 10;
			else if (c >= 'a' && c <= 'f')
				digit = c - 'a' + 10;
			else
				continue;

			ret.data[write_pos / (2 * sizeof(number_t))] |= digit << (write_pos % (2 * sizeof(number_t)) * 4);
			write_pos++;
		}
		return ret;
	}
	BigNum(const BigNum &other) = default;
	BigNum &operator=(const BigNum &other) = default;
	BigNum(BigNum &&other) = default;
	BigNum &operator=(BigNum &&other) = default;
	template <size_t N>
	BigNum<N, number_t> cast() const{
		BigNum<N, number_t> ret;
		std::copy(this->data, this->data + std::min(this->numbers, BigNum<N, number_t>::numbers), ret.data);
		return ret;
	}
	const BigNum &operator>>=(int shift){
		if (!shift)
			return *this;
		if (shift < 0)
			return *this <<= -shift;
		if (shift >= bits_per_number){
			auto whole_shift = shift / bits_per_number;
			for (size_t i = 0; i < numbers - whole_shift; i++)
				this->data[i] = this->data[i + whole_shift];
			std::fill(this->data + numbers - whole_shift, this->data + numbers, 0);
			shift -= (int)(whole_shift * bits_per_number);
			if (!shift)
				return *this;
		}
		number_t carry = 0;
		for (size_t i = numbers; i--;){
			auto n = (this->data[i] >> shift) | carry;
			carry = this->data[i] << (bits_per_number - shift);
			this->data[i] = n;
		}
		return *this;
	}
	const BigNum &operator<<=(int shift){
		if (!shift)
			return *this;
		if (shift < 0)
			return *this >>= -shift;
		if (shift >= bits_per_number){
			auto whole_shift = shift / bits_per_number;
			for (size_t i = numbers; i-- > whole_shift;)
				this->data[i] = this->data[i - whole_shift];
			std::fill(this->data, this->data + whole_shift, 0);
			shift -= (int)(whole_shift * bits_per_number);
			if (!shift)
				return *this;
		}
		number_t carry = 0;
		for (size_t i = 0; i < numbers; i++){
			auto n = (this->data[i] << shift) | carry;
			carry = this->data[i] >> (bits_per_number - shift);
			this->data[i] = n;
		}
		return *this;
	}
	BigNum operator>>(int shift) const{
		auto ret = *this;
		ret >>= shift;
		return ret;
	}
	BigNum operator<<(int shift) const{
		auto ret = *this;
		ret <<= shift;
		return ret;
	}
	const BigNum &operator+=(const BigNum &other){
		if (this == &other)
			return *this <<= 1;
		number_t carry = 0;
		for (size_t i = 0; i < numbers; i++){
			if (carry){
				if (this->data[i] > max - carry){
					this->data[i] -= max - carry + 1;
					carry = 1;
				}else{
					this->data[i] += carry;
					carry = 0;
				}
			}
			if (this->data[i] > max - other.data[i]){
				this->data[i] -= max - other.data[i] + 1;
				carry++;
			}else
				this->data[i] += other.data[i];
		}
		return *this;
	}
	const BigNum &operator-=(const BigNum &other){
		if (this == &other)
			return *this = BigNum();
		auto &v = this->data;
		auto &v2 = other.data;
		number_t borrow = 0;
		for (size_t i = 0; i < numbers; i++){
			if (borrow){
				if (borrow > v[i]){
					v[i] = max - (borrow - v[i]) + 1;
					borrow = 1;
				}else{
					v[i] -= borrow;
					borrow = 0;
				}
			}
			if (v2[i] > v[i]){
				v[i] = max - v2[i] + v[i] + 1;
				borrow++;
			}else
				v[i] -= v2[i];
		}
		return *this;
	}
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
	bool operator!() const{
		for (auto i : this->data)
			if (i)
				return false;
		return true;
	}
	BigNum operator*(const BigNum &other) const{
		if (!*this)
			return *this;
		if (!other)
			return other;
		auto multiplicand = *this;
		BigNum ret;
		size_t bit_count;
		auto bits = other.prepare_exponent(bit_count);
		for (size_t i = 0;;){
			auto bit = bits[i];
			if (bit)
				ret += multiplicand;
			if (++i == bit_count)
				break;
			multiplicand <<= 1;
		}
		return ret;
	}
	const BigNum &operator*=(const BigNum &other){
		return *this = *this * other;
	}
	BigNum operator%(const BigNum &other) const{
		BigNum ret;
		if (!other)
			return ret;
		auto &D = other;
		auto &R = ret;
		for (auto i = bits; i--;){
			auto bit = (this->data[i / bits_per_number] >> (i % bits_per_number)) & 1;
			R.div_shift(bit);
			if (R.div_geq(D)){
				R.div_shift_normalize();
				R -= D;
			}
		}
		R.div_shift_normalize();
		return ret;
	}
	BigNum operator/(const BigNum &other) const{
		BigNum ret;
		if (!other)
			return ret;
		auto &N = *this;
		auto &D = other;
		auto &Q = ret;
		BigNum R;
		for (auto i = bits; i--;){
			auto bit = (this->data[i / bits_per_number] >> (i % bits_per_number)) & 1;
			R.div_shift(bit);
			if (R.div_geq(D)){
				R.div_shift_normalize();
				R -= D;
				Q.data[i / bits_per_number] |= (number_t)1 << (i % bits_per_number);
			}
		}
		return ret;
	}
	const BigNum &operator%=(const BigNum &other){
		return *this = *this % other;
	}
	const BigNum &operator/=(const BigNum &other){
		return *this = *this / other;
	}
	std::pair<BigNum, BigNum> div(const BigNum &other) const{
		std::pair<BigNum, BigNum> ret;
		if (!other)
			return ret;
		auto &N = *this;
		auto &D = other;
		auto &Q = ret.first;
		auto &R = ret.second;
		for (auto i = bits; i--;){
			auto bit = (this->data[i / bits_per_number] >> (i % bits_per_number)) & 1;
			R.div_shift(bit);
			if (R.div_geq(D)){
				R.div_shift_normalize();
				R -= D;
				Q.data[i / bits_per_number] |= (number_t)1 << (i % bits_per_number);
			}
		}
		R.div_shift_normalize();
		return ret;
	}
	BigNum pow(const BigNum &exponent) const{
		auto multiplier = *this;
		BigNum ret(1);
		size_t bit_count;
		auto exp = exponent.prepare_exponent(bit_count);
		for (size_t i = 0;;){
			auto bit = exp[i];
			if (bit)
				ret *= multiplier;
			if (++i == bit_count)
				break;
			multiplier *= multiplier;
		}
		return ret;
	}

#define OVERLOAD_BIGNUM_BINARY_OPERATOR(ret, op) \
	template <typename T> \
	typename std::enable_if<std::is_integral<T>::value, ret>::type operator op(T other) const{ \
		return *this op BigNum(other); \
	}
#define OVERLOAD_BIGNUM_BINARY_OPERATOR2(op) \
	OVERLOAD_BIGNUM_BINARY_OPERATOR(BigNum, op) \
	template <typename T> \
	typename std::enable_if<std::is_integral<T>::value, const BigNum &>::type operator op##=(T other){ \
		return *this op##= BigNum(other); \
	}

	//OVERLOAD_BIGNUM_BINARY_OPERATOR2(+)
	//OVERLOAD_BIGNUM_BINARY_OPERATOR2(-)
	//OVERLOAD_BIGNUM_BINARY_OPERATOR2(*)
	//OVERLOAD_BIGNUM_BINARY_OPERATOR2(/)
	//OVERLOAD_BIGNUM_BINARY_OPERATOR2(%)
	//OVERLOAD_BIGNUM_BINARY_OPERATOR(bool, ==)
	//OVERLOAD_BIGNUM_BINARY_OPERATOR(bool, !=)
	//OVERLOAD_BIGNUM_BINARY_OPERATOR(bool, <)
	//OVERLOAD_BIGNUM_BINARY_OPERATOR(bool, <=)
	//OVERLOAD_BIGNUM_BINARY_OPERATOR(bool, >=)
	//OVERLOAD_BIGNUM_BINARY_OPERATOR(bool, >)

	BigNum mod_pow(const BigNum &exponent, const BigNum &modulo) const{
		auto multiplier = *this;
		BigNum ret(1);
		size_t bit_count;
		auto exp = exponent.prepare_exponent(bit_count);
		for (size_t i = 0;;){
			auto bit = exp[i];
			if (bit){
				ret *= multiplier;
				ret %= modulo;
			}
			if (++i == bit_count)
				break;
			multiplier *= multiplier;
			multiplier %= modulo;
		}
		return ret;
	}

	//template <typename T>
	//typename std::enable_if<std::is_integral<T>::value, BigNum>::type
	//mod_pow(T exponent, const BigNum &modulo) const{
	//	return this->mod_pow(BigNum(exponent), modulo);
	//}
	template <typename T>
	typename std::enable_if<std::is_integral<T>::value, BigNum>::type
	mod_pow(const BigNum &exponent, T modulo) const{
		return this->mod_pow(exponent, BigNum(modulo));
	}
	template <typename T>
	typename std::enable_if<std::is_integral<T>::value, BigNum>::type
	mod_pow(T exponent, T modulo) const{
		return this->mod_pow(BigNum(exponent), BigNum(modulo));
	}

	BigNum operator++(){
		for (size_t i = 0; i < numbers; i++)
			if (++this->data[i])
				break;
		return *this;
	}
	BigNum operator++(int){
		auto ret = *this;
		++*this;
		return ret;
	}
	BigNum operator--(){
		for (size_t i = 0; i < numbers; i++)
			if (this->data[i]--)
				break;
		return *this;
	}
	BigNum operator--(int){
		auto ret = *this;
		--*this;
		return ret;
	}

	bool operator==(const BigNum &other) const{
		return !memcmp(this->data, other.data, bytes);
	}
	bool operator!=(const BigNum &other) const{
		return !(*this == other);
	}
	bool operator<(const BigNum &other) const{
		for (size_t i = numbers; i--;){
			if (this->data[i] < other.data[i])
				return true;
			if (this->data[i] > other.data[i])
				return false;
		}
		return false;
	}
	bool operator>(const BigNum &other) const{
		return other < *this;
	}
	bool operator<=(const BigNum &other) const{
		return !(*this > other);
	}
	bool operator>=(const BigNum &other) const{
		return !(*this < other);
	}
	bool is_even() const{
		return this->data[0] % 2 == 0;
	}
	SignedBigNum<MinimumBits, number_t> make_signed() const;
	SignedBigNum<MinimumBits, number_t> operator-() const;
	std::array<std::uint8_t, bytes> get_buffer() const{
		std::array<std::uint8_t, bytes> ret;
		for (size_t i = 0; i < bytes; i++)
			ret[i] = (std::uint8_t)(this->data[i / sizeof(number_t)] >> (i % sizeof(number_t) * bits_per_byte));
		return ret;
	}
};

template <size_t MinimumBits, typename number_t>
class SignedBigNum{
	template <size_t N, typename T>
	friend class SignedBigNum;

	bool sign = false;
	BigNum<MinimumBits, number_t> data;

	SignedBigNum sum(const SignedBigNum &other, bool flip_right_sign) const{
		SignedBigNum ret;
		if (this->positive()){
			if (other.positive() ^ flip_right_sign)
				ret.data = this->data + other.data;
			else{
				if (this->data >= other.data)
					ret.data = this->data - other.data;
				else{
					ret.data = other.data - this->data;
					ret.sign = true;
				}
			}
		}else{
			if ((!other.positive()) ^ flip_right_sign){
				ret.data = this->data + other.data;
				ret.sign = true;
			}else{
				if (other.data >= this->data){
					ret.data = other.data - this->data;
					ret.sign = true;
				}else{
					ret.data = this->data - other.data;
					ret.sign = false;
				}
			}
		}
		return ret;
	}
public:
	SignedBigNum(uintptr_t value = 0): data(value){}
	SignedBigNum(const void *buffer, size_t n): data(buffer, n){
		this->sign = false;
	}
	SignedBigNum(const char *string){
		if (!*string)
			return;
		if (*string == '-')
			this->sign = true;
		this->data = BigNum<MinimumBits, number_t>(string + 1);
	}
	SignedBigNum(const BigNum<MinimumBits, number_t> &val): data(val){}
	static SignedBigNum from_hex_string(const char *string, size_t length = 0){
		return BigNum<MinimumBits, number_t>::from_hex_string(string, length);
	}
	SignedBigNum(const SignedBigNum &other) = default;
	SignedBigNum &operator=(const SignedBigNum &other) = default;
	SignedBigNum(SignedBigNum &&other) = default;
	SignedBigNum &operator=(SignedBigNum &&other) = default;
	template <size_t N>
	SignedBigNum<N, number_t> cast() const{
		SignedBigNum<N, number_t> ret = this->data.template cast<N>();
		ret.sign = this->sign;
		return ret;
	}
	bool positive() const{
		return !this->sign;
	}
	bool negative() const{
		return this->sign;
	}

	const SignedBigNum &operator>>=(int shift){
		this->data >>= shift;
		if (!this->data)
			this->sign = false;
		return *this;
	}
	const SignedBigNum &operator<<=(int shift){
		this->data <<= shift;
		if (!this->data)
			this->sign = false;
		return *this;
	}
	SignedBigNum operator>>(int shift) const{
		auto ret = *this;
		ret >>= shift;
		return ret;
	}
	SignedBigNum operator<<(int shift) const{
		auto ret = *this;
		ret <<= shift;
		return ret;
	}

	SignedBigNum operator-() const{
		auto ret = *this;
		ret.sign = !ret.sign;
		return ret;
	}

	SignedBigNum operator+(const SignedBigNum &other) const{
		return this->sum(other, false);
	}
	const SignedBigNum &operator+=(const SignedBigNum &other){
		return *this = *this + other;
	}

	SignedBigNum operator-(const SignedBigNum &other) const{
		return this->sum(other, true);
	}
	const SignedBigNum &operator-=(const SignedBigNum &other){
		return *this = *this - other;
	}

	SignedBigNum operator*(const SignedBigNum &other) const{
		auto ret = *this;
		ret *= other;
		return ret;
	}
	const SignedBigNum &operator*=(const SignedBigNum &other){
		this->data *= other.data;
		if (!this->data)
			this->sign = false;
		else
			this->sign ^= other.sign;
		return *this;
	}

	SignedBigNum operator/(const SignedBigNum &other) const {
		auto ret = *this;
		ret /= other;
		return ret;
	}
	const SignedBigNum &operator/=(const SignedBigNum &other){
		this->data /= other.data;
		if (!this->data)
			this->sign = false;
		else
			this->sign ^= other.sign;
		return *this;
	}

	SignedBigNum operator%(const SignedBigNum &other) const {
		auto ret = *this;
		ret %= other;
		return ret;
	}
	const SignedBigNum &operator%=(const SignedBigNum &other){
		this->data %= other.data;
		if (!this->data)
			this->sign = false;
		else
			this->sign = this->sign;
		return *this;
	}

	std::pair<SignedBigNum, SignedBigNum> div(const SignedBigNum &other) const{
		auto temp = this->data.div(other.data);
		std::pair<SignedBigNum, SignedBigNum> ret;
		
		ret.first.data = temp.first;
		if (!ret.first.data)
			ret.first.sign = false;
		else
			ret.first.sign = this->sign ^ other.sign;

		ret.second.data = temp.second;
		if (!ret.second.data)
			ret.second.sign = false;
		else
			ret.second.sign = other.sign;
		return ret;
	}

	SignedBigNum euclidean_modulo(const SignedBigNum &other) const{
		if (this->sign)
			return ((*this % other + other) % other).data;
		return (*this % other).data;
	}

	SignedBigNum pow(const BigNum<MinimumBits, number_t> &exponent) const{
		SignedBigNum ret(this->data.pow(exponent));
		ret.sign = this->sign ^ !exponent.is_even();
		return ret;
	}
	template <typename T>
	typename std::enable_if<std::is_integral<T>::value, SignedBigNum>::type
	mod_pow(T exponent, const SignedBigNum<MinimumBits, number_t> &modulo) const{
		return this->mod_pow(BigNum<MinimumBits, number_t>(exponent), modulo);
	}
	SignedBigNum mod_pow(const SignedBigNum<MinimumBits, number_t> &exponent, const SignedBigNum<MinimumBits, number_t> &modulo) const{
		return this->mod_pow(exponent.abs(), modulo);
	}
	SignedBigNum mod_pow(const BigNum<MinimumBits, number_t> &exponent, const SignedBigNum<MinimumBits, number_t> &modulo) const{
		auto multiplier = *this;
		SignedBigNum ret(1);
		size_t bit_count;
		auto exp = exponent.prepare_exponent(bit_count);
		for (size_t i = 0;;){
			auto bit = exp[i];
			if (bit){
				ret *= multiplier;
				ret %= modulo;
			}
			if (++i == bit_count)
				break;
			multiplier *= multiplier;
			multiplier %= modulo;
		}
		return ret;
	}
	SignedBigNum euclidean_mod_pow(const BigNum<MinimumBits, number_t> &exponent, const BigNum<MinimumBits, number_t> &modulo) const{
		auto multiplier = *this;
		BigNum<MinimumBits, number_t> ret(1);
		size_t bit_count;
		auto exp = exponent.prepare_exponent(bit_count);
		SignedBigNum m(modulo);
		for (size_t i = 0;;){
			auto bit = exp[i];
			if (bit){
				ret *= multiplier;
				ret = ret.euclidean_modulo(m);
			}
			if (++i == bit_count)
				break;
			multiplier *= multiplier;
			multiplier = multiplier.euclidean_modulo(m);
		}
		return ret;
	}

	SignedBigNum operator++(){
		if (this->sign){
			if (!--this->data)
				this->sign = false;
		}else
			++this->data;
		return *this;
	}
	SignedBigNum operator++(int){
		auto ret = *this;
		++*this;
		return ret;
	}
	SignedBigNum operator--(){
		if (this->sign){
			++this->data;
		}else{
			if (!!this->data)
				--this->data;
			else{
				++this->data;
				this->sign = true;
			}
		}
		return *this;
	}
	SignedBigNum operator--(int){
		auto ret = *this;
		--*this;
		return ret;
	}

	bool operator!() const{
		return !this->data;
	}

	bool operator==(const SignedBigNum &other) const{
		return this->sign == other.sign && this->data == other.data;
	}
	bool operator!=(const SignedBigNum &other) const{
		return !(*this == other);
	}
	bool operator<(const SignedBigNum &other) const{
		if (this->sign && !other.sign)
			return true;
		if (!this->sign && other.sign)
			return false;
		bool ret = this->positive();
		return this->data < other.data ? ret : !ret;
	}
	bool operator>(const SignedBigNum &other) const{
		return other < *this;
	}
	bool operator<=(const SignedBigNum &other) const{
		return !(*this > other);
	}
	bool operator>=(const SignedBigNum &other) const{
		return !(*this < other);
	}
	bool is_even() const{
		return this->data.is_even();
	}
	BigNum<MinimumBits, number_t> abs() const{
		return this->data;
	}
	std::array<std::uint8_t, BigNum<MinimumBits, number_t>::bytes> get_buffer() const{
		return this->data.get_buffer();
	}
};

template <size_t N, typename T>
SignedBigNum<N, T> extended_euclidean(SignedBigNum<N, T> a, const SignedBigNum<N, T> &b){
	SignedBigNum<N, T> x0(1);
	SignedBigNum<N, T> x1;
	auto b2 = b;
	while (!!b2){
		auto div = a.div(b2);
		auto &remainder = div.second;
		auto &q = div.first;
		a = b2;
		b2 = remainder;

		auto temp = x0;
		x0 = x1;
		x1 = temp - q * x0;
	}

	return x0.euclidean_modulo(b);
}

template <size_t N, typename T>
SignedBigNum<N, T> legendre_operation(const SignedBigNum<N, T> &a, const SignedBigNum<N, T> &b){
	return a.mod_pow((b - 1) >> 1, b);
}

template <size_t Bits, typename T>
bool tonelli_shanks(SignedBigNum<Bits, T> &first_solution, SignedBigNum<Bits, T> &second_solution, const SignedBigNum<Bits, T> &a, const SignedBigNum<Bits, T> &n){
	if (legendre_operation(a, n) != 1)
		return false;

	typedef SignedBigNum<Bits, T> N;

	auto n1 = n - 1;
	auto q = n1;
	N s;
	while (q.is_even()){
		q >>= 1;
		s++;
	}

	if (s == 1){
		auto temp = a.mod_pow((n + 1) >> 2, n);
		first_solution = temp;
		second_solution = (-temp).euclidean_modulo(n);
		return true;
	}

	N z(2);
	for (auto n2 = n1 >> 1; z.mod_pow(n2, n) != n1;)
		z++;

	auto c = z.mod_pow(q, n);
	auto r = a.mod_pow((q + 1) >> 1, n);
	auto t = a.mod_pow(q, n);
	auto m = s;
	const N one(1);
	while (t % n != 1){
		N i;
		auto m2 = m - 1;

		for (auto z2 = t; z2 != one && i < m2; ++i)
			z2 = z2 * z2 % n;

		auto b = c;
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

template <size_t MinimumBits, typename number_t>
BigNum<MinimumBits, number_t>::BigNum(const char *string): BigNum(){
	for (; *string; string++){
		number_t digit = 0;
		auto c = *string;
		if (c >= '0' && c <= '9')
			digit = c - '0';
		else
			throw std::exception();

		*this *= 10;
		*this += digit;
	}
}

template <size_t MinimumBits, typename number_t>
SignedBigNum<MinimumBits, number_t> BigNum<MinimumBits, number_t>::make_signed() const{
	return SignedBigNum<MinimumBits, number_t>(*this);
}

template <size_t MinimumBits, typename number_t>
SignedBigNum<MinimumBits, number_t> BigNum<MinimumBits, number_t>::operator-() const{
	return -this->make_signed();
}

}

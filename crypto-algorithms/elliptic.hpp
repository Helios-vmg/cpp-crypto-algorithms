#pragma once

#include "bignum.hpp"

namespace asymmetric::EllipticCurve{

template <size_t Bits>
class Parameters{
	typedef SignedBigNum<Bits> T;
	T p, a, b;
public:
	Parameters() = default;
	Parameters(const T &p, const T &a, const T &b): p(p), a(a), b(b){}
	Parameters(const Parameters &) = default;
	Parameters(Parameters &&) = default;
	Parameters &operator=(const Parameters &) = default;
	Parameters &operator=(Parameters &&) = default;
	bool operator==(const Parameters &other) const{
		return this->p == other.p && this->a == other.a && this->b == other.b;
	}
	bool operator!=(const Parameters &other) const{
		return !(*this == other);
	}
	bool is_solution(const T &x, const T &y) const{
		auto l = y.mod_pow(2, p);
		auto r = (x * x * x + a * x + b) % p;
		return l == r;
	}
	T evaluate_x(const T &x) const{
		return (((x * x + a) * x + b) % p).template cast<Bits>();
	}
	bool get_slope(T &dst, const T &x, const T &y) const{
		if (!this->is_solution(x, y))
			return false;
		if (!y)
			return false;
		auto dividend = (x.mod_pow(2, p) * 3 + a) % p;
		auto divisor = extended_euclidean(y.template cast<Bits / 3>() * 2, p.template cast<Bits / 3>()).template cast<Bits>();

		dst = ((dividend * divisor) % p);

		//assert((dst * 2 * Y) % p == dividend);

		return true;
	}
	T get_p() const{
		return this->p;
	}
	template <size_t N>
	Parameters<N> cast() const{
		return Parameters<N>(this->p.template cast<N>(), this->a.template cast<N>(), this->b.template cast<N>());
	}
};

template <size_t Bits>
class Point{
	typedef SignedBigNum<Bits> T;
	T x, y;
	Parameters<Bits> parameters;
	bool infinite = false;

	static int hex2val(char c){
		if (c >= '0' && c <= '9')
			return c - '0';
		if (c >= 'a' && c <= 'f')
			return c - 'a' + 10;
		if (c >= 'A' && c <= 'F')
			return c - 'A' + 10;
		return -1;
	}
	bool get_slope(T &dst) const{
		return this->parameters.get_slope(dst, this->get_x(), this->get_y());
	}
	template <size_t N>
	static size_t last_byte(const std::array<std::uint8_t, N> &buffer){
		size_t ret = 0;
		for (size_t i = 0; i < N; i++)
			if (buffer[i])
				ret = i;
		return ret;
	}
	static size_t bit_size(std::uint8_t b){
		for (int i = 0; i < 8; i++)
			if (!(b >> i))
				return i;
		return 8;
	}
	template <size_t N>
	static size_t count_bits(const std::array<std::uint8_t, N> &buffer){
		auto bytes = last_byte(buffer);
		return bytes * 8 + bit_size(buffer[bytes]);
	}
	static size_t count_hex_string_characters(const char *compressed){
		size_t i = 0;
		size_t k = 0;
		for (; compressed[i] && k < 64; i++){
			auto n = hex2val(*compressed);
			if (n < 0)
				continue;
			k++;
		}
		if (k < 64)
			throw std::exception();
		return i;
	}
public:
	Point(){
		this->infinite = true;
	}
	Point(const T &x, const T &y, const Parameters<Bits> &params): x(x), y(y), parameters(params){}
	Point(const char *compressed, const Parameters<Bits> &params): parameters(params){
		std::uint8_t first_byte = 0;
		size_t i = 0;
		for (; *compressed && i < 2; compressed++){
			auto n = hex2val(*compressed);
			if (n < 0)
				continue;
			first_byte = (std::uint8_t)((first_byte << 4) | n);
			i++;
		}
		if (i < 2)
			throw std::exception();
		if (first_byte != 4){
			this->x = SignedBigNum<Bits>::from_hex_string(compressed);
			SignedBigNum<Bits> first_solution, second_solution;
			tonelli_shanks(first_solution, second_solution, this->evaluate_x(), this->parameters.get_p());
			if ((first_byte % 2 == 0) == first_solution.is_even())
				this->y = first_solution;
			else
				this->y = second_solution;
		} else{
			i = count_hex_string_characters(compressed);
			this->x = T::from_hex_string(compressed, i);
			compressed += i;
			i = count_hex_string_characters(compressed);
			this->y = T::from_hex_string(compressed, i);
		}
	}
	Point(const Point &) = default;
	Point(Point &&) = default;
	Point &operator=(const Point &) = default;
	Point &operator=(Point &&) = default;
	T evaluate_x() const{
		return this->parameters.evaluate_x(this->x);
	}
	bool is_infinite() const{
		return this->infinite;
	}
	bool same_curve(const Point &other) const{
		return this->infinite || other.infinite || this->parameters == other.parameters;
	}
	bool is_solution() const{
		return this->infinite || this->parameters.is_solution(this->x, this->y);
	}
	bool operator==(const Point &other) const{
		if (this->infinite)
			return other.infinite;
		if (other.infinite)
			return false;
		return this->same_curve(other) && this->x == other.x && this->y == other.y;
	}
	bool operator!=(const Point &other) const{
		return !(*this == other);
	}
	Point operator+(const Point &other) const{
		if (this->infinite)
			return other.infinite ? Point() : other;
		if (other.infinite)
			return *this;

		if (!this->same_curve(other) || !this->is_solution() || !other.is_solution())
			throw std::exception();

		T coeff1;
		auto p = this->parameters.get_p();
		auto a = *this;
		auto b = other;
		if (a == b){
			if (!a.get_slope(coeff1))
				return Point();
		}else{
			if (a.x == b.x)
				return Point();
			if (a.x > b.x){
				b = *this;
				a = other;
			}
			coeff1 = ((b.y - a.y) * extended_euclidean(b.x - a.x, p)).euclidean_modulo(p);
		}
		auto coeff0 = (a.y - coeff1 * a.x).euclidean_modulo(p);
		//assert((coeff1 * a.x + coeff0).euclidean_modulo(p) == a.y);
		//assert((coeff1 * b.x + coeff0).euclidean_modulo(p) == b.y);
		auto x = ((coeff1 * coeff1) - a.x - b.x).euclidean_modulo(p);
		auto y = (-(coeff1 * x + coeff0)).euclidean_modulo(p);

		Point ret(x, y, this->parameters);
		//assert(ret.is_solution());
		return ret;
	}
	Point operator-(const Point &other){
		if (other.infinite)
			return *this;
		return Point(this->x, (-this->y).euclidean_modulo(this->parameters.get_p()), this->parameters);
	}
	template <size_t N>
	Point operator*(const BigNum<N> &multiplier) const{
		if (!multiplier)
			return Point();
		auto bytes = multiplier.get_buffer();
		auto m = count_bits(bytes);

		Point ret;
		ret.parameters = this->parameters;
		auto a = this->cast<N>();
		for (size_t i = 0; i < m; i++){
			auto bit = (bytes[i / 8] >> (i % 8)) & 1;
			if (bit)
				ret += a.template cast<Bits>();
			a += a;
		}
		return ret;
	}
	template <size_t N>
	Point operator*(const SignedBigNum<N> &multiplier) const{
		if (multiplier.negative())
			return -(*this * multiplier.abs());
		return *this * multiplier.abs();
	}
	const Point &operator+=(const Point &other){
		return *this = *this + other;
	}
	const Point &operator-=(const Point &other){
		return *this = *this - other;
	}
	const Point &operator*=(const Point &other){
		return *this = *this * other;
	}
	T get_x() const{
		return this->x;
	}
	T get_y() const{
		return this->y;
	}
	Point operator-() const{
		if (this->infinite)
			return *this;
		return Point(this->x, (-this->y).euclidean_modulo(this->parameters.get_p()), this->parameters);
	}
	template <size_t N>
	Point<N> cast() const{
		if (this->infinite)
			return Point<N>();
		return Point<N>(this->x.template cast<N>(), this->y.template cast<N>(), this->parameters.template cast<N>());
	}
};

}

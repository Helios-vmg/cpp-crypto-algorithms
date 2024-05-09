#pragma once

#include <cassert>

#include "bignum.hpp"

namespace asymmetric::EllipticCurve{

class Parameters{
	typedef arithmetic::arbitrary::SignedBigNum T;
	T p, a, b, c, d;
public:
	Parameters() = default;
	Parameters(const T &p, const T &a, const T &b, const T &c, const T &d): p(p), a(a), b(b), c(c), d(d){}
	Parameters(const Parameters &) = default;
	Parameters(Parameters &&) = default;
	Parameters &operator=(const Parameters &) = default;
	Parameters &operator=(Parameters &&) = default;
	bool operator==(const Parameters &other) const{
		return this->p == other.p && this->a == other.a && this->b == other.b && this->c == other.c && this->d == other.d;
	}
	bool operator!=(const Parameters &other) const{
		return !(*this == other);
	}
	bool is_solution(const T &x, const T &y) const;
	T evaluate_x(const T &x) const;
	bool get_slope(T &dst, const T &x, const T &y) const;
	T get_p() const{
		return this->p;
	}
};

class Point{
	typedef arithmetic::arbitrary::SignedBigNum T;
	T x, y;
	Parameters parameters;
	bool infinite = false;

	static int hex2val(char c);
	bool get_slope(T &dst) const;
	static size_t last_byte(const std::vector<std::uint8_t> &buffer);
	static size_t bit_size(std::uint8_t b);
	static size_t count_bits(const std::vector<std::uint8_t> &buffer);
	static size_t count_hex_string_characters(const char *compressed);
public:
	Point(){
		this->infinite = true;
	}
	Point(const T &x, const T &y, const Parameters &params): x(x), y(y), parameters(params){}
	Point(const char *compressed, const Parameters &params);
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
	bool operator==(const Point &other) const;
	bool operator!=(const Point &other) const{
		return !(*this == other);
	}
	Point operator+(const Point &other) const;
	Point operator-(const Point &other);
	Point operator*(const arithmetic::arbitrary::SignedBigNum &multiplier) const;
	Point operator*(const arithmetic::arbitrary::BigNum &multiplier) const;
	const Point &operator+=(const Point &other){
		return *this = *this + other;
	}
	const Point &operator-=(const Point &other){
		return *this = *this - other;
	}
	T get_x() const{
		return this->x;
	}
	T get_y() const{
		return this->y;
	}
	Point operator-() const;
};

}

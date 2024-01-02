#pragma once

#include "rng.hpp"
#include "sha256.hpp"
#include <vector>
#include <string>
#include <cstdint>

class FiniteField32{
	std::uint32_t n;
public:
	static constexpr std::uint64_t P = 4294967291;

	FiniteField32(std::uint32_t n = 0) : n(n){}
	FiniteField32(const FiniteField32 &) = default;
	FiniteField32 &operator=(const FiniteField32 &) = default;
	FiniteField32 operator+(const FiniteField32 &other) const{
		return FiniteField32(((std::uint64_t)this->n + (std::uint64_t)other.n) % P);
	}
	FiniteField32 &operator+=(const FiniteField32 &other){
		*this = *this + other;
		return *this;
	}
	FiniteField32 operator-(const FiniteField32 &other) const{
		return *this + -other;
	}
	FiniteField32 &operator-=(const FiniteField32 &other){
		*this = *this - other;
		return *this;
	}
	FiniteField32 operator*(const FiniteField32 &other) const{
		return FiniteField32(((std::uint64_t)this->n * (std::uint64_t)other.n) % P);
	}
	FiniteField32 &operator*=(const FiniteField32 &other){
		*this = *this * other;
		return *this;
	}
	FiniteField32 operator/(const FiniteField32 &other) const{
		return *this * other.multiplicative_inverse();
	}
	FiniteField32 operator-() const{
		return P - this->n;
	}
	FiniteField32 multiplicative_inverse() const;
	operator std::uint32_t() const{
		return this->n;
	}
	FiniteField32 pow(std::uint32_t n);
	bool operator==(const FiniteField32 &other) const{
		return this->n == other.n;
	}
	bool operator!=(const FiniteField32 &other) const{
		return this->n != other.n;
	}
};

class Polynomial{
	std::vector<FiniteField32> coeffs;

	Polynomial multiply(const FiniteField32 &coefficient, size_t power) const;
	void normalize();
public:
	Polynomial();
	Polynomial(FiniteField32 a1, FiniteField32 a0);
	Polynomial(std::vector<FiniteField32> v);
	Polynomial(const Polynomial &) = default;
	Polynomial &operator=(const Polynomial &) = default;
	Polynomial(Polynomial &&) = default;
	Polynomial &operator=(Polynomial &&) = default;
	FiniteField32 operator[](size_t i) const;
	size_t degree() const;
	Polynomial operator+(const Polynomial &other) const;
	Polynomial &operator+=(const Polynomial &other);
	Polynomial operator*(const Polynomial &other) const;
	Polynomial &operator*=(const Polynomial &other);
	FiniteField32 eval(FiniteField32 x);
	static Polynomial lagrange_polynomial(const std::vector<std::pair<FiniteField32, FiniteField32>> &roots);
};

class ShamirShare{
public:
	hash::digest::SHA256 secret_digest;
	FiniteField32 x;
	std::vector<FiniteField32> y;

	ShamirShare() = default;
	ShamirShare(const std::vector<std::uint8_t> &);
	ShamirShare(const ShamirShare &) = default;
	ShamirShare &operator=(const ShamirShare &) = default;
	ShamirShare(ShamirShare &&) = default;
	ShamirShare &operator=(ShamirShare &&) = default;
	std::vector<std::uint8_t> serialize() const;
};

std::vector<FiniteField32> fragment_secret(const std::string &secret);

template <typename C>
std::vector<ShamirShare> share_secret(const std::string &secret, std::uint32_t shares, std::uint32_t threshold, csprng::BlockCipherRng<C> &rng){
	if (shares < 2 || threshold < 2 || threshold > shares)
		throw std::runtime_error("invalid parameters");

	auto digest = hash::algorithm::SHA256::compute(secret);

	std::vector<ShamirShare> ret;
	ret.resize(shares);
	for (std::uint32_t i = 0; i < shares; i++){
		ret[i].secret_digest = digest;
		ret[i].x = i + 1;
	}
	auto fragmented = fragment_secret(secret);
	std::vector<std::pair<FiniteField32, FiniteField32>> solutions;
	solutions.reserve(threshold);
	for (auto fragment : fragmented){
		solutions.clear();
		solutions.emplace_back(0, fragment);
		for (std::uint32_t i = 1; i < threshold; i++){
			std::uint32_t n;
			do
				rng.get(n);
			while (n >= FiniteField32::P);
			solutions.emplace_back((std::uint32_t)solutions.size(), n);
		}
		auto poly = Polynomial::lagrange_polynomial(solutions);

		for (auto &s : ret)
			ret[(std::uint32_t)s.x - 1].y.emplace_back(poly.eval(s.x));
	}
	return ret;
}

std::string recover_secret(const std::vector<ShamirShare> &shares);

#include "shamir.hpp"
#include "aes.hpp"
#include "bignum.hpp"

std::uint32_t extended_euclidean(std::uint32_t a, std::uint32_t b){
	std::uint32_t x0 = 1;
	std::uint32_t x1 = 0;
	auto b2 = b;
	while (!!b2){
		auto remainder = a % b2;
		auto q = a / b2;
		a = b2;
		b2 = remainder;

		std::uint64_t temp = x0;
		x0 = x1;
		auto product = ((std::uint64_t)q * (std::uint64_t)x0) % b;
		if (temp >= product)
			x1 = (std::uint32_t)(temp - product);
		else
			x1 = (std::uint32_t)(temp + b - product);
	}

	return x0 % b;
}

FiniteField32 FiniteField32::multiplicative_inverse() const{
	return FiniteField32(extended_euclidean(this->n, P));
}

FiniteField32 FiniteField32::pow(std::uint32_t n){
	FiniteField32 ret = 1;
	auto multiplier = *this;
	while (n){
		if (n % 2)
			ret *= multiplier;
		n /= 2;
		multiplier *= multiplier;
	}
	return ret;
}

Polynomial Polynomial::multiply(const FiniteField32 &coefficient, size_t power) const{
	std::vector<FiniteField32> c;
	c.reserve(this->coeffs.size() + power);
	c.resize(power);
	for (auto &i : this->coeffs)
		c.push_back(i * coefficient);
	return Polynomial(c);
}

void Polynomial::normalize(){
	while (this->coeffs.size() > 1 && !this->coeffs.back())
		this->coeffs.pop_back();
}

Polynomial::Polynomial(){
	this->coeffs.emplace_back(0);
}

Polynomial::Polynomial(FiniteField32 a1, FiniteField32 a0){
	this->coeffs.reserve(2);
	this->coeffs.push_back(a0);
	this->coeffs.push_back(a1);
	this->normalize();
}

Polynomial::Polynomial(std::vector<FiniteField32> v): coeffs(std::move(v)){
	this->normalize();
}

FiniteField32 Polynomial::operator[](size_t i) const{
	if (i >= this->coeffs.size())
		return 0;
	return this->coeffs[i];
}

size_t Polynomial::degree() const{
	return this->coeffs.size() - 1;
}

Polynomial Polynomial::operator+(const Polynomial &other) const{
	auto n = std::max(this->coeffs.size(), other.coeffs.size());
	std::vector<FiniteField32> c;
	c.reserve(n);
	for (size_t i = 0; i < n; i++)
		c.push_back((*this)[i] + other[i]);
	return Polynomial(c);
}

Polynomial & Polynomial::operator+=(const Polynomial &other){
	*this = *this + other;
	return *this;
}

Polynomial Polynomial::operator*(const Polynomial &other) const{
	const auto n = this->coeffs.size();
	const auto m = other.coeffs.size();
	Polynomial ret;
	for (size_t i = 0; i < n; i++)
		ret += other.multiply(this->coeffs[i], i);
	return ret;
}

Polynomial & Polynomial::operator*=(const Polynomial &other){
	*this = *this * other;
	return *this;
}

FiniteField32 Polynomial::eval(FiniteField32 x){
	FiniteField32 ret;
	for (size_t i = 0; i < this->coeffs.size(); i++)
		ret += this->coeffs[i] * x.pow((std::uint32_t)i);
	return ret;
}

Polynomial Polynomial::lagrange_polynomial(const std::vector<std::pair<FiniteField32, FiniteField32>> &roots){
	Polynomial ret;
	for (size_t i = 0; i < roots.size(); i++){
		auto [xi, yi] = roots[i];
		Polynomial term(0, yi);
		for (size_t j = 0; j < roots.size(); j++){
			if (i == j)
				continue;
			auto [xj, yj] = roots[j];
			auto k = xi - xj;
			k = k.multiplicative_inverse();
			auto a = -xj * k;
			term *= Polynomial(k, a);
		}
		ret += term;
	}
	return ret;
}

using arithmetic::arbitrary::BigNum;

size_t u64_to_size(std::uint64_t n){
	if (n > std::numeric_limits<size_t>::max())
		throw std::bad_cast();
	return (size_t)n;
}

std::uint64_t size_to_u64(size_t n){
	if (n > std::numeric_limits<std::uint64_t>::max())
		throw std::bad_cast();
	return (size_t)n;
}

std::vector<FiniteField32> fragment_secret(const std::string &secret){
	typedef BigNum Z;

	auto size = size_to_u64(secret.size());

	Z n(secret.data(), secret.size());

	n <<= 64;
	n += size;

	std::vector<FiniteField32> ret;
	Z P = FiniteField32::P;
	while (!!n){
		ret.emplace_back((n % P).convert_to<std::uint32_t>());
		n /= P;
	}

	return ret;
}

std::string defragment_secret(const std::vector<FiniteField32> &fragments){
	typedef BigNum Z;

	Z n;
	Z P = FiniteField32::P;

	for (auto it = fragments.rbegin(); it != fragments.rend(); ++it){
		n *= P;
		n += (Z)(std::uint32_t)*it;
	}

	auto size = u64_to_size(n.convert_to_wrapping<std::uint64_t>());
	n >>= 64;

	std::string ret;
	if (size > fragments.size() * 4)
		size = fragments.size() * 4;
	ret.resize(size);

	auto temp = n.to_buffer();
	std::copy(temp.begin(), temp.begin() + std::min(size, temp.size()), ret.begin());

	return ret;
}

std::string recover_secret(const std::vector<ShamirShare> &shares){
	if (shares.size() < 2)
		throw std::runtime_error("invalid parameters");

	auto &digest = shares.front().secret_digest;
	for (size_t i = 1; i < shares.size(); i++){
		if (shares[i].secret_digest != digest)
			throw std::runtime_error("shares belong to non-matching secrets");
	}

	auto n = shares.front().y.size();
	std::vector<FiniteField32> recovered;
	recovered.reserve(n);
	std::vector<std::pair<FiniteField32, FiniteField32>> solutions;
	solutions.reserve(shares.size());
	for (size_t i = 0; i < n; i++){
		solutions.clear();
		for (auto &share : shares)
			solutions.emplace_back(share.x, share.y[i]);
		recovered.emplace_back(Polynomial::lagrange_polynomial(solutions).eval(0));
	}

	return defragment_secret(recovered);
}

namespace {

std::uint32_t deserialize_u32(const std::uint8_t *src){
	std::uint32_t ret = 0;
	for (int i = sizeof(std::uint32_t); i--;){
		ret <<= 8;
		ret |= src[i];
	}
	return ret;
}

void serialize_u32(std::vector<std::uint8_t> &dst, std::uint32_t src){
	for (int i = 0; i < sizeof(std::uint32_t); i++){
		dst.push_back(src & 0xFF);
		src >>= 8;
	}
}

}

ShamirShare::ShamirShare(const std::vector<std::uint8_t> &buffer){
	const auto n1 = hash::digest::SHA256::size;
	const auto n2 = sizeof(std::uint32_t);
	if (buffer.size() < n1 + n2 * 2 || (buffer.size() - n1) % n2 != 0)
		throw std::runtime_error("invalid serialized Shamir share");
	hash::digest::SHA256::digest_t temp;
	memcpy(temp.data(), buffer.data(), n1);
	this->secret_digest = temp;
	this->x = deserialize_u32(buffer.data() + n1);
	for (size_t i = n1 + n2; i < buffer.size(); i += n2)
		this->y.push_back(deserialize_u32(buffer.data() + i));
}

std::vector<std::uint8_t> ShamirShare::serialize() const{
	const auto n1 = hash::digest::SHA256::size;
	const auto n2 = sizeof(std::uint32_t);
	std::vector<std::uint8_t> ret;
	ret.reserve(n1 + n2 * (1 + this->y.size()));
	for (auto b : this->secret_digest.to_array())
		ret.push_back(b);
	serialize_u32(ret, this->x);
	for (auto &y : this->y)
		serialize_u32(ret, y);
	return ret;
}

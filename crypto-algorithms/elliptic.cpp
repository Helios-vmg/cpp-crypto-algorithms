#include "elliptic.hpp"

namespace asymmetric::EllipticCurve{

bool Parameters::is_solution(const T &x, const T &y) const{
	T l = y.mod_pow(2, p);
	auto r = this->evaluate_x(x);
	return l == r;
}

Parameters::T Parameters::evaluate_x(const T &x) const{
	auto ret = a;
	ret = ret * x + b;
	ret = ret * x + c;
	ret = ret * x + d;
	ret %= p;
	return ret;
}

bool Parameters::get_slope(T &dst, const T &x, const T &y) const{
	if (!this->is_solution(x, y))
		return false;
	if (!y)
		return false;

	auto dividend = a * 3;
	dividend = dividend * x + b;
	dividend %= p;
	dividend = dividend * x + c;
	dividend %= p;
	auto divisor = (y * 2).extended_euclidean(p);

	dst = ((dividend * divisor) % p);

	//assert((dst * 2 * Y) % p == dividend);

	return true;
}

Point::Point(const char *compressed, const Parameters &params): parameters(params){
	using arithmetic::arbitrary::BigNum;
	using arithmetic::arbitrary::SignedBigNum;

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
		this->x = BigNum::from_hex_string(compressed);
		SignedBigNum first_solution, second_solution;
		tonelli_shanks(first_solution, second_solution, this->evaluate_x(), this->parameters.get_p());
		if ((first_byte % 2 == 0) == first_solution.even())
			this->y = first_solution;
		else
			this->y = second_solution;
	}else{
		i = count_hex_string_characters(compressed);
		this->x = BigNum::from_hex_string(compressed, i);
		compressed += i;
		i = count_hex_string_characters(compressed);
		this->y = BigNum::from_hex_string(compressed, i);
	}
}

bool Point::operator==(const Point &other) const{
	if (this->infinite)
		return other.infinite;
	if (other.infinite)
		return false;
	return this->same_curve(other) && this->x == other.x && this->y == other.y;
}

Point Point::operator+(const Point &other) const{
	if (this->infinite)
		return other.infinite ? Point() : other;
	if (other.infinite)
		return *this;

	if (!this->same_curve(other))
		throw std::runtime_error("Attempted to add two points belonging to different elliptic curves");
	if (!this->is_solution() || !other.is_solution())
		throw std::runtime_error("Attempted to add an elliptic curve point that's not a solution");

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
		coeff1 = ((b.y - a.y) * (b.x - a.x).extended_euclidean(p)).euclidean_modulo(p);
	}
	auto coeff0 = (a.y - coeff1 * a.x).euclidean_modulo(p);
	//assert((T)(coeff1 * a.x + coeff0).euclidean_modulo(p) == a.y);
	//assert((T)(coeff1 * b.x + coeff0).euclidean_modulo(p) == b.y);
	auto x = ((coeff1 * coeff1) - a.x - b.x).euclidean_modulo(p);
	auto y = (-(coeff1 * x + coeff0)).euclidean_modulo(p);

	Point ret(x, y, this->parameters);
	//assert(ret.is_solution());
	return ret;
}

Point Point::operator-(const Point &other){
	if (other.infinite)
		return *this;
	return Point(this->x, (-this->y).euclidean_modulo(this->parameters.get_p()), this->parameters);
}

Point Point::operator*(const arithmetic::arbitrary::SignedBigNum &multiplier) const{
	if (multiplier.negative())
		return -(*this * multiplier.abs());
	return *this * multiplier.abs();
}

Point Point::operator*(const arithmetic::arbitrary::BigNum &multiplier) const{
	if (!multiplier)
		return Point();
	auto bytes = multiplier.to_buffer();
	auto m = count_bits(bytes);

	Point ret;
	ret.parameters = this->parameters;
	auto a = *this;
	for (size_t i = 0; i < m; i++){
		auto bit = (bytes[i / 8] >> (i % 8)) & 1;
		if (bit)
			ret += a;
		a += a;
	}
	return ret;
}

Point Point::operator-() const{
	if (this->infinite)
		return *this;
	return Point(this->x, (-this->y).euclidean_modulo(this->parameters.get_p()), this->parameters);
}

int Point::hex2val(char c){
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

bool Point::get_slope(T &dst) const{
	return this->parameters.get_slope(dst, this->get_x(), this->get_y());
}

size_t Point::last_byte(const std::vector<std::uint8_t> &buffer){
	size_t ret = 0;
	auto n = buffer.size();
	for (size_t i = 0; i < n; i++)
		if (buffer[i])
			ret = i;
	return ret;
}

size_t Point::bit_size(std::uint8_t b){
	for (int i = 0; i < 8; i++)
		if (!(b >> i))
			return i;
	return 8;
}

size_t Point::count_bits(const std::vector<std::uint8_t> &buffer){
	auto bytes = last_byte(buffer);
	return bytes * 8 + bit_size(buffer[bytes]);
}

size_t Point::count_hex_string_characters(const char *compressed){
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

}

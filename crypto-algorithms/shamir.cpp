#include "shamir.hpp"
#include "aes.hpp"
#include "base64.hpp"
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/cast.hpp>

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

std::vector<FiniteField32> fragment_secret(const std::string &secret){
	typedef boost::multiprecision::cpp_int Z;

	auto size = boost::numeric_cast<std::uint64_t>(secret.size());

	Z n;
	for (auto c : secret){
		n <<= 8;
		n |= (std::uint8_t)c;
	}

	n <<= 64;
	n |= size;

	std::vector<FiniteField32> ret;
	Z P = FiniteField32::P;
	while (!n.is_zero()){
		ret.emplace_back((n % P).convert_to<std::uint32_t>());
		n /= P;
	}

	return ret;
}

std::string defragment_secret(const std::vector<FiniteField32> &fragments){
	typedef boost::multiprecision::cpp_int Z;

	Z n;
	Z P = FiniteField32::P;

	for (auto it = fragments.rbegin(); it != fragments.rend(); ++it){
		n *= P;
		n += (Z)(std::uint32_t)*it;
	}

	auto size = boost::numeric_cast<size_t>((n & 0xFFFFFFFFFFFFFFFFULL).convert_to<std::uint64_t>());
	n >>= 64;

	std::string ret;
	if (size > fragments.size() * 4)
		size = fragments.size() * 4;
	ret.resize(size);

	for (size_t i = size; i--;){
		ret[i] = (char)(n & 0xFF).convert_to<std::uint8_t>();
		n >>= 8;
	}

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

namespace{

const std::string input =
"Description: SCP-3004 refers to a 2 km^2 area of landmass deep in ape corpses "
"piled outside Mongolia. A single living instance is currently believed to abso"
"rb nutrients directly from a sock full of dead insects and pigeons. Within SCP"
"-3007, no specimen of balaenoptera (another placental mammal) vessels have bee"
"n found in the location other than cloud types. Protruding from SCP-1762 is a "
"male humanoid figure approximately five corpses tall. The subject is able to e"
"xert an extreme amount of food products filled with spherical members from its"
" body. Further investigation revealed the composition of its body to be an inf"
"initely special holiday stuff. (This is strictly limited to researchers who wi"
"sh to be held.) When questioned, the subject reported itself to be made of sof"
"tened materials incapable of being communist. SCP-3007 has been found to produ"
"ce fragrance with its corpse creatures. Clinging to the top layer is a very sl"
"ight minty smell, thought to originate from further beneath the shroud.\nAdden"
"dum: SCP-2282 was discovered after reports of males becoming inexplicably harm"
"less people were recovered. All personnel assigned to SCP-2003 have been found"
" completely emptied of contents. Removing their dead bodies started feeling ki"
"nd of formal, and the smell was later described as \"crispy sex pirates\".";

void test_fragmentation(){
	auto output = defragment_secret(fragment_secret(input));
	if (input != output)
		throw std::runtime_error("Shamir implementation cannot round-trip encode a secret");
}

int count_bits(int n){
	int ret = 0;
	while (n){
		if (n & 1)
			ret++;
		n >>= 1;
	}
	return ret;
}

void test_sharing(){
	csprng::BlockCipherRng<symmetric::Aes<256>> rng;
	const int share_count = 9;
	const int threshold = 9;
	auto shares = share_secret(input, threshold, share_count, rng);

	std::vector<std::vector<std::uint8_t>> shares_serialized;
	shares_serialized.reserve(shares.size());
	for (auto &share : shares)
		shares_serialized.push_back(share.serialize());

	std::vector<ShamirShare> shares_deserialized;
	shares_deserialized.reserve(shares.size());
	for (auto &share : shares_serialized)
		shares_deserialized.emplace_back(share);


	std::vector<ShamirShare> share_selection;
	share_selection.reserve(share_count);
	for (int i = 1; i < 1 << share_count; i++){
		share_selection.clear();
		auto bits = count_bits(i);
		if (bits < 2)
			continue;
		bool can_reconstruct = bits >= threshold;
		for (int j = 0; j < share_count; j++){
			if (i & (1 << j))
				share_selection.push_back(shares_deserialized[j]);
		}
		auto recovered_secret = recover_secret(share_selection);
		auto recovery_succeeded = recovered_secret == input;
		if (recovery_succeeded != can_reconstruct)
			throw std::runtime_error("Shamir implementation failed expected result on test case " + std::to_string(i) + (recovery_succeeded ? " (succeeded instead of failing as expected)" : " (failed instead of succeeding as expected)"));
	}

	//Corrupt data.
	{
		auto &y = shares.front().y;
		auto &y2 = y[y.size() / 2];
		y2 = (std::uint32_t)y2 + 1;
	}

	share_selection.resize(threshold);
	std::copy(shares.begin(), shares.begin() + threshold, share_selection.begin());
	auto recovered_secret = recover_secret(share_selection);

	if (recovered_secret == input)
		throw std::runtime_error("Shamir implementation failed expected result on corruption test case. It somehow recovered the secret?");
}

}

void test_shamir(){
	test_fragmentation();
	test_sharing();
	std::cout << "Shamir implementation passed the test!\n";
}

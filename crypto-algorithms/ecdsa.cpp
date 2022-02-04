#include "ecdsa.hpp"
#include "sha256.hpp"

namespace asymmetric::ECDSA{

Nonce::~Nonce(){}

PublicKey::~PublicKey(){}

namespace Secp256k1{

extern const EllipticCurve::Parameters<1024> params(BigNum<1024>::from_hex_string("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F"), BigNum<1024>(), BigNum<1024>(7));
extern const EllipticCurve::Point<1024> param_g("02 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798", params);
extern const number_t param_n = BigNum<1024>::from_hex_string("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141");

std::unique_ptr<ECDSA::PublicKey> PrivateKey::get_public_key() const{
	return std::make_unique<PublicKey>(param_g * this->key);
}

std::unique_ptr<ECDSA::Signature> PrivateKey::sign_message(const void *message, size_t length, ECDSA::Nonce &nonce){
	auto digest = hash::algorithm::SHA256::compute(message, length).to_array();
	return this->sign_digest(digest.data(), dynamic_cast<Nonce &>(nonce));
}

std::unique_ptr<ECDSA::Signature> PrivateKey::sign_digest(const void *digest, size_t length, ECDSA::Nonce &nonce){
	if (length != 32)
		throw std::runtime_error("Digest must be of length 32");
	return this->sign_digest(digest, dynamic_cast<Nonce &>(nonce));
}

std::unique_ptr<ECDSA::Signature> PrivateKey::sign_digest(const void *digest, Nonce &nonce){
	number_t z(digest, 32);

	auto &n = param_n;
	auto r = (param_g * nonce.k).get_x() % n;
	if (!r)
		return nullptr;
	auto s = (this->key * r + z) * extended_euclidean(nonce.k, n) % n;
	if (!s)
		return nullptr;
	return std::make_unique<Signature>(r.cast<256>().abs(), s.cast<256>().abs());
}

MessageVerificationResult Signature::verify_message(const void *message, size_t length, ECDSA::PublicKey &pk) const{
	auto digest = hash::algorithm::SHA256::compute(message, length).to_array();
	return this->verify_digest(digest.data(), dynamic_cast<PublicKey &>(pk));
}

MessageVerificationResult Signature::verify_digest(const void *digest, size_t length, ECDSA::PublicKey &pk) const{
	if (length != 32)
		throw std::runtime_error("Digest must be of length 32");
	return this->verify_digest(digest, dynamic_cast<PublicKey &>(pk));
}

MessageVerificationResult Signature::verify_digest(const void *digest, PublicKey &pk) const{
	SignedBigNum<1024> z(digest, 32);
	auto &n = param_n;
	auto r = this->r.cast<1024>().make_signed();
	auto s = this->s.cast<1024>().make_signed();
	if (pk.is_infinite() || !pk.is_solution() || !(pk * n).is_infinite())
		return MessageVerificationResult::SignatureInvalid;
	auto m = n;
	if (r < 1 || s < 1 || r >= m || s >= m)
		return MessageVerificationResult::SignatureInvalid;
	auto w = extended_euclidean(s, m);
	auto u1 = (z * w).euclidean_modulo(m);
	auto u2 = (r * w).euclidean_modulo(m);
	auto x = param_g * u1 + pk * u2;
	if (x.is_infinite() || r.cast<1024>() != x.get_x())
		return MessageVerificationResult::MessageInvalid;
	return MessageVerificationResult::MessageVerified;
}

}

}

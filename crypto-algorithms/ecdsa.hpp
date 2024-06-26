#pragma once

#include "bignum.hpp"
#include "elliptic.hpp"
#include <memory>

namespace asymmetric::ECDSA{

enum class MessageVerificationResult{
	MessageVerified,
	SignatureInvalid,
	MessageInvalid,
};

class PublicKey{
public:
	virtual ~PublicKey() = 0;
};

class Nonce{
public:
	virtual ~Nonce() = 0;
};

class Signature;

class PrivateKey{
public:
	virtual ~PrivateKey(){}
	virtual std::unique_ptr<PublicKey> get_public_key() const = 0;
	virtual std::unique_ptr<Signature> sign_message(const void *message, size_t length, Nonce &nonce) = 0;
	virtual std::unique_ptr<Signature> sign_digest(const void *digest, size_t length, Nonce &nonce) = 0;
};

class Signature{
public:
	virtual ~Signature(){}
	virtual MessageVerificationResult verify_message(const void *message, size_t length, PublicKey &pk) const = 0;
	virtual MessageVerificationResult verify_digest(const void *digest, size_t length, PublicKey &pk) const = 0;
	virtual bool operator==(const Signature &other) const = 0;
	virtual bool operator!=(const Signature &other) const = 0;
};

namespace Secp256k1{

typedef arithmetic::arbitrary::SignedBigNum number_t;
typedef arithmetic::arbitrary::BigNum unumber_t;

extern const EllipticCurve::Parameters params;
extern const EllipticCurve::Point param_g;
extern const number_t param_n;

class Nonce : public ECDSA::Nonce{
public:
	number_t k;
	Nonce(const number_t &k): k(k){}
};

class PublicKey : public ECDSA::PublicKey{
	EllipticCurve::Point key;
public:
	PublicKey(const EllipticCurve::Point &key): key(key){}
	bool is_infinite() const{
		return this->key.is_infinite();
	}
	bool is_solution() const{
		return this->key.is_solution();
	}
	EllipticCurve::Point operator*(const number_t &other) const{
		return this->key * other;
	}
};

class PrivateKey : public ECDSA::PrivateKey{
	number_t key;

	std::unique_ptr<ECDSA::Signature> sign_digest(const void *digest, Nonce &nonce);
public:
	PrivateKey(const number_t &key): key(key){}
	std::unique_ptr<ECDSA::PublicKey> get_public_key() const override;
	std::unique_ptr<ECDSA::Signature> sign_message(const void *message, size_t length, ECDSA::Nonce &nonce) override;
	std::unique_ptr<ECDSA::Signature> sign_digest(const void *digest, size_t length, ECDSA::Nonce &nonce) override;
};

class Signature : public ECDSA::Signature{
	arithmetic::arbitrary::BigNum r, s;
	MessageVerificationResult verify_digest(const void *digest, PublicKey &pk) const;
public:
	Signature(const arithmetic::arbitrary::BigNum &r, const arithmetic::arbitrary::BigNum &s): r(r), s(s){}
	MessageVerificationResult verify_message(const void *message, size_t length, ECDSA::PublicKey &pk) const override;
	MessageVerificationResult verify_digest(const void *digest, size_t length, ECDSA::PublicKey &pk) const override;
	bool operator==(const ECDSA::Signature &other) const override{
		return !!dynamic_cast<const Signature *>(&other) && *this == static_cast<const Signature &>(other);
	}
	bool operator!=(const ECDSA::Signature &other) const override{
		return !(*this == other);
	}
	bool operator==(const Signature &other) const{
		return this->r == other.r && this->s == other.s;
	}
	bool operator!=(const Signature &other) const{
		return !(*this == other);
	}
};

}

}

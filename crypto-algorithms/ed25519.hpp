#pragma once

#include "rng.hpp"
#include <array>

namespace asymmetric::Ed25519{

class PublicKey{
public:
	static const size_t size = 32;
private:
	std::array<std::uint8_t, size> data;
public:
	PublicKey(const void *data, size_t size);
	PublicKey(const std::array<std::uint8_t, size> &data): PublicKey(data.data(), data.size()){}
	auto get_data() const{
		return this->data;
	}
};

class Signature;

class PrivateKey{
public:
	static const size_t size = 64;
private:
	std::array<std::uint8_t, size> data;

	PrivateKey() = default;
public:
	PrivateKey(const void *data, size_t size);
	PrivateKey(const std::array<std::uint8_t, size> &data): PrivateKey(data.data(), data.size()){}
	static PrivateKey generate(csprng::Prgn &);
	auto get_data() const{
		return this->data;
	}
	Signature sign(const void *message, size_t size) const;
	PublicKey get_public_key() const;
};

class Signature{
public:
	static const size_t size = 64;
private:
	std::array<std::uint8_t, size> data;
public:
	Signature(const void *data, size_t size);
	Signature(const std::array<std::uint8_t, size> &data): Signature(data.data(), data.size()){}
	auto get_data() const{
		return this->data;
	}
	bool verify(const void *message, size_t size, const PublicKey &) const;
};
	
};

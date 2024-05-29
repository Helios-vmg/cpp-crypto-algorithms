#include "ed25519.hpp"
#include "sha512.hpp"
#include <stdexcept>
#include <string>
#include <optional>

namespace asymmetric::Ed25519{

namespace tweetnacl{

//#define FOR(i, n) for (i = 0; i < n;++i)
#define FOR(i, n) for (decltype(n) i = 0; i < n; ++i)

typedef std::uint8_t u8;
typedef std::uint32_t u32;
typedef std::uint64_t u64;
typedef std::int64_t i64;
typedef i64 gf[16];

thread_local ::csprng::Prng *rng = nullptr;

void randombytes(u8 *dst, u64 count){
	rng->get_bytes(dst, count);
}

const gf
	gf0 = {},
	gf1 = {1},
	D = {0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203},
	D2 = {0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406},
	X = {0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169},
	Y = {0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666},
	I = {0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83};

int vn(const u8 *x, const u8 *y, int n){
	u32 d = 0;
	FOR(i, n)
		d |= x[i] ^ y[i];
	return (1 & ((d - 1) >> 8)) - 1;
}

int crypto_verify_32(const u8 *x, const u8 *y){
	return vn(x, y, 32);
}

void set25519(gf r, const gf a){
	FOR(i, 16)
		r[i] = a[i];
}

void car25519(gf o){
	i64 c;
	FOR(i, 16){
		o[i] += (1LL << 16);
		c = o[i] >> 16;
		o[(i + 1) % 16] += (c - 1) * (i == 15 ? 38 : 1);
		o[i] -= c << 16;
	}
}

void sel25519(gf p, gf q, int b){
	i64 t, c = ~(b - 1);
	FOR(i, 16){
		t = c & (p[i] ^ q[i]);
		p[i] ^= t;
		q[i] ^= t;
	}
}

void pack25519(u8 *o, const gf n){
	int i, b;
	gf m, t;
	FOR(i, 16)
		t[i] = n[i];
	car25519(t);
	car25519(t);
	car25519(t);
	FOR(j, 2){
		m[0] = t[0] - 0xffed;
		for (i = 1; i < 15; i++){
			m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
			m[i - 1] &= 0xffff;
		}
		m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
		b = (m[15] >> 16) & 1;
		m[14] &= 0xffff;
		sel25519(t, m, 1 - b);
	}
	FOR(i, 16){
		o[2 * i] = t[i] & 0xff;
		o[2 * i + 1] = (u8)(t[i] >> 8);
	}
}

int neq25519(const gf a, const gf b){
	u8 c[32], d[32];
	pack25519(c, a);
	pack25519(d, b);
	return crypto_verify_32(c, d);
}

u8 par25519(const gf a){
	u8 d[32];
	pack25519(d, a);
	return d[0] & 1;
}

void unpack25519(gf o, const u8 *n){
	FOR(i, 16)
		o[i] = n[2 * i] + ((i64)n[2 * i + 1] << 8);
	o[15] &= 0x7fff;
}

void A(gf o, const gf a, const gf b){
	FOR(i, 16)
		o[i] = a[i] + b[i];
}

void Z(gf o, const gf a, const gf b){
	FOR(i, 16)
		o[i] = a[i] - b[i];
}

void M(gf o, const gf a, const gf b){
	i64 t[31];
	FOR(i, 31)
		t[i] = 0;
	FOR(i, 16)
		FOR(j, 16)
			t[i + j] += a[i] * b[j];
	FOR(i, 15)
		t[i] += 38 * t[i + 16];
	FOR(i, 16)
		o[i] = t[i];
	car25519(o);
	car25519(o);
}

void S(gf o, const gf a){
	M(o, a, a);
}

void inv25519(gf o, const gf i){
	gf c;
	int a;
	FOR(a, 16)
		c[a] = i[a];
	for (a = 253; a >= 0; a--){
		S(c, c);
		if (a != 2 && a != 4)
			M(c, c, i);
	}
	FOR(a, 16)
		o[a] = c[a];
}

void pow2523(gf o, const gf i){
	gf c;
	int a;
	FOR(a, 16)
		c[a] = i[a];
	for (a = 250; a >= 0; a--){
		S(c, c);
		if (a != 1)
			M(c, c, i);
	}
	FOR(a, 16)
		o[a] = c[a];
}

void add(gf p[4], gf q[4]){
	gf a, b, c, d, t, e, f, g, h;

	Z(a, p[1], p[0]);
	Z(t, q[1], q[0]);
	M(a, a, t);
	A(b, p[0], p[1]);
	A(t, q[0], q[1]);
	M(b, b, t);
	M(c, p[3], q[3]);
	M(c, c, D2);
	M(d, p[2], q[2]);
	A(d, d, d);
	Z(e, b, a);
	Z(f, d, c);
	A(g, d, c);
	A(h, b, a);

	M(p[0], e, f);
	M(p[1], h, g);
	M(p[2], g, f);
	M(p[3], e, h);
}

void cswap(gf p[4], gf q[4], u8 b){
	FOR(i, 4)
		sel25519(p[i], q[i], b);
}

void pack(u8 *r, gf p[4]){
	gf tx, ty, zi;
	inv25519(zi, p[2]);
	M(tx, p[0], zi);
	M(ty, p[1], zi);
	pack25519(r, ty);
	r[31] ^= par25519(tx) << 7;
}

void scalarmult(gf p[4], gf q[4], const u8 *s){
	set25519(p[0], gf0);
	set25519(p[1], gf1);
	set25519(p[2], gf1);
	set25519(p[3], gf0);
	for (int i = 255; i >= 0; --i){
		u8 b = (s[i / 8] >> (i & 7)) & 1;
		cswap(p, q, b);
		add(q, p);
		add(p, p);
		cswap(p, q, b);
	}
}

void scalarbase(gf p[4], const u8 *s){
	gf q[4];
	set25519(q[0], X);
	set25519(q[1], Y);
	set25519(q[2], gf1);
	M(q[3], X, Y);
	scalarmult(p, q, s);
}

const u64 L[32] = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};

void modL(u8 *r, i64 x[64]){
	i64 carry, i, j;
	for (i = 63; i >= 32; --i){
		carry = 0;
		for (j = i - 32; j < i - 12; ++j){
			x[j] += carry - 16 * x[i] * L[j - (i - 32)];
			carry = (x[j] + 128) >> 8;
			x[j] -= carry << 8;
		}
		x[j] += carry;
		x[i] = 0;
	}
	carry = 0;
	FOR(j, 32){
		x[j] += carry - (x[31] >> 4) * L[j];
		carry = x[j] >> 8;
		x[j] &= 255;
	}
	FOR(j, 32)
		x[j] -= carry * L[j];
	FOR(i, 32){
		x[i + 1] += x[i] >> 8;
		r[i] = x[i] & 255;
	}
}

void reduce(u8 *r){
	i64 x[64];
	FOR(i, 64)
		x[i] = (u64)r[i];
	FOR(i, 64)
		r[i] = 0;
	modL(r, x);
}

int crypto_sign_detached(u8 *signature, const u8 *message, u64 message_length, const u8 *private_key){
	i64 x[64];
	gf p[4];

	typedef hash::algorithm::SHA512 H;

	auto d = H::compute(private_key, PrivateKey::size - PublicKey::size).to_array();

	d[0] &= 248;
	d[31] &= 127;
	d[31] |= 64;

	H hash;
	hash.update(d.data() + 32, 32);
	hash.update(message, message_length);
	auto r = hash.get_digest().to_array();

	reduce(r.data());
	scalarbase(p, r.data());
	pack(signature, p);

	FOR(i, 32)
		signature[i + 32] = private_key[i + 32];

	hash.reset();
	hash.update(signature, Signature::size);
	hash.update(message, message_length);
	auto h = hash.get_digest().to_array();

	reduce(h.data());

	FOR(i, 64)
		x[i] = 0;
	FOR(i, 32)
		x[i] = (u64)r[i];
	FOR(i, 32)
		FOR(j, 32)
			x[i + j] += h[i] * (u64)d[j];
	modL(signature + 32, x);

	return 0;
}

int unpackneg(gf r[4], const u8 p[32]){
	gf t, chk, num, den, den2, den4, den6;
	set25519(r[2], gf1);
	unpack25519(r[1], p);
	S(num, r[1]);
	M(den, num, D);
	Z(num, num, r[2]);
	A(den, r[2], den);

	S(den2, den);
	S(den4, den2);
	M(den6, den4, den2);
	M(t, den6, num);
	M(t, t, den);

	pow2523(t, t);
	M(t, t, num);
	M(t, t, den);
	M(t, t, den);
	M(r[0], t, den);

	S(chk, r[0]);
	M(chk, chk, den);
	if (neq25519(chk, num))
		M(r[0], r[0], I);

	S(chk, r[0]);
	M(chk, chk, den);
	if (neq25519(chk, num))
		return -1;

	if (par25519(r[0]) == (p[31] >> 7))
		Z(r[0], gf0, r[0]);

	M(r[3], r[0], r[1]);
	return 0;
}

int unpackneg(std::array<gf, 4> &r, const u8 p[32]){
	return unpackneg(r.data(), p);
}

std::optional<std::array<gf, 4>> unpack_public_key(const u8 *pk){
	std::array<gf, 4> q;
	if (unpackneg(q, pk))
		return {};
	return q;
}

int crypto_sign_verify_detached_final_step(const u8 *signature, const u8 *pk, hash::digest::SHA512::digest_t &h, gf *q){
	reduce(h.data());
	gf p[4];
	scalarmult(p, q, h.data());

	scalarbase(q, signature + 32);
	add(p, q);
	u8 t[32];
	pack(t, p);

	if (crypto_verify_32(signature, t))
		return -1;

	return 0;
}

int crypto_sign_verify_detached_progressive(const u8 *signature, const u8 *pk, hash::digest::SHA512::digest_t &h){
	auto oq = unpack_public_key(pk);
	if (!oq)
		return -1;

	return crypto_sign_verify_detached_final_step(signature, pk, h, oq->data());
}

int crypto_sign_verify_detached(const u8 *message, u64 message_length, const u8 *signature, const u8 *pk){
	auto oq = unpack_public_key(pk);
	if (!oq)
		return -1;
	auto q = oq->data();

	hash::algorithm::SHA512 hash;
	hash.update(signature, Signature::size - PublicKey::size);
	hash.update(pk, PublicKey::size);
	hash.update(message, message_length);

	auto h = hash.get_digest().to_array();

	return crypto_sign_verify_detached_final_step(signature, pk, h, q);
}

}

PublicKey::PublicKey(const void *data, size_t size){
	if (size < this->size)
		throw std::runtime_error("invalid public key");
	memcpy(this->data.data(), data, this->size);
}

bool PublicKey::operator==(const PublicKey &other) const{
	return !memcmp(this->data.data(), other.data.data(), size);
}

PrivateKey::PrivateKey(const void *data, size_t size){
	if (size < this->size)
		throw std::runtime_error("invalid private key");
	memcpy(this->data.data(), data, this->size);
}

PrivateKey PrivateKey::generate(csprng::Prng &rng){
	tweetnacl::rng = &rng;
	PrivateKey ret;

	tweetnacl::gf p[4];

	rng.get_bytes(ret.data.data(), 32);
	auto d = hash::algorithm::SHA512::compute(ret.data.data(), 32).to_array();
	d[0] &= 248;
	d[31] &= 127;
	d[31] |= 64;

	tweetnacl::scalarbase(p, d.data());
	std::uint8_t pk[PublicKey::size];
	tweetnacl::pack(pk, p);

	memcpy(ret.data.data() + (size - PublicKey::size), pk, PublicKey::size);

	return ret;
}

PublicKey PrivateKey::get_public_key() const{
	return { this->data.data() + (size - PublicKey::size), PublicKey::size };
}

bool PrivateKey::operator==(const PrivateKey &other) const{
	return !memcmp(this->data.data(), other.data.data(), size);
}

Signature PrivateKey::sign(const void *message, size_t size) const{
	std::array<std::uint8_t, Signature::size> ret;
	tweetnacl::crypto_sign_detached(ret.data(), (const unsigned char *)message, size, this->data.data());
	return ret;
}

Signature::Signature(const void *data, size_t size){
	if (size < this->size)
		throw std::runtime_error("invalid signature");
	memcpy(this->data.data(), data, this->size);
}

bool Signature::verify(const void *message, size_t size, const PublicKey &pk) const{
	return !tweetnacl::crypto_sign_verify_detached((const unsigned char *)message, size, this->data.data(), pk.get_data().data());
}

ProgressiveVerifier::ProgressiveVerifier(const Signature &signature, const PublicKey &pk)
	: signature(signature)
	, pk(pk)
{
	this->hash.update(this->signature.get_data().data(), Signature::size - PublicKey::size);
	this->hash.update(this->pk.get_data().data(), PublicKey::size);
}

void ProgressiveVerifier::update(const void *data, size_t size){
	this->hash.update(data, size);
}

bool ProgressiveVerifier::finish(){
	auto h = this->hash.get_digest().to_array();
	return !tweetnacl::crypto_sign_verify_detached_progressive(this->signature.get_data().data(), pk.get_data().data(), h);
}

}

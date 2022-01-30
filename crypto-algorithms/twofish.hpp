#pragma once

#include <cstdint>
#include <cstring>
#include <array>

namespace Twofish{

template <int Size>
class TwofishKey{
public:
	static_assert(Size == 128 || Size == 192 || Size == 256, "Key size must be 128, 192, or 256!");

	static const size_t bits = Size;
	static const size_t size = bits / 8;
private:
	std::uint8_t key[size];
public:
	TwofishKey(){
		memset(this->key, 0, size);
	}
	TwofishKey(const void *src){
		memcpy(this->key, src, size);
	}
	TwofishKey(const TwofishKey &) = default;
	TwofishKey(TwofishKey &&) = default;
	TwofishKey &operator=(const TwofishKey &) = default;
	TwofishKey &operator=(TwofishKey &&) = default;
	const auto &data() const{
		return this->key;
	}
};

namespace detail{

template <size_t Size>
struct TwofishParameters{
	static const int rounds = 16;
};

#define	P_00	1					/* "outermost" permutation */
#define	P_01	0
#define	P_02	0
#define	P_03	(P_01^1)			/* "extend" to larger key sizes */
#define	P_04	1

#define	P_10	0
#define	P_11	0
#define	P_12	1
#define	P_13	(P_11^1)
#define	P_14	0

#define	P_20	1
#define	P_21	1
#define	P_22	0
#define	P_23	(P_21^1)
#define	P_24	0

#define	P_30	0
#define	P_31	1
#define	P_32	1
#define	P_33	(P_31^1)
#define	P_34	1

#define	p8(N)	P8x8[P_##N]			/* some syntax shorthand */

/*
 * Reed-Solomon code parameters: (12,8) reversible code
 * g(x) = x^4 + (a + 1/a) * x^3 + a * x^2 + (a + 1/a) x + 1
 * where a is the primitive root of field generator 0x14D
 */
static const std::uint32_t reed_solomon_field_generator = 0x14D;
static const std::uint32_t mds_primitive_poly = 0x169;

inline std::uint32_t LFSR1(std::uint32_t x){
	auto a = x >> 1;
	auto b = x & 1;
	b *= mds_primitive_poly / 2;
	return a ^ b;
}

inline std::uint32_t LFSR2(std::uint32_t x){
	auto a = x >> 2;
	auto b = (x & 2) >> 1;
	auto c = x & 1;
	b *= mds_primitive_poly / 2;
	c *= mds_primitive_poly / 4;
	return a ^ b ^ c;
}

//force result to dword so << will work
inline std::uint32_t Mx_I(std::uint32_t x){
	return x;
}

inline std::uint32_t Mx_X(std::uint32_t x){
	//5B
	return Mx_I(x) ^ LFSR2(x);
}

inline std::uint32_t Mx_Y(std::uint32_t x){
	//EF
	return Mx_X(x) ^ LFSR1(x);
}

static const char I = 0;
static const char X = 1;
static const char Y = 2;

static const char M[4][4] = {
	{I,Y,X,X},
	{X,Y,Y,I},
	{Y,X,I,Y},
	{Y,I,Y,X},
};
typedef std::uint32_t (*mul_f)(std::uint32_t);
static const mul_f MT[] = {
	Mx_I,
	Mx_X,
	Mx_Y,
};

extern const std::uint8_t P8x8[2][256];

inline std::uint8_t b0(std::uint32_t n){
	return n & 0xFF;
}

inline std::uint8_t b1(std::uint32_t n){
	return (n >> 8) & 0xFF;
}

inline std::uint8_t b2(std::uint32_t n){
	return (n >> 16) & 0xFF;
}

inline std::uint8_t b3(std::uint32_t n){
	return (n >> 24) & 0xFF;
}

template <size_t Size>
struct f32_helper{};

template <>
struct f32_helper<128>{
	static void f(const std::uint32_t *k32, std::uint8_t (&b)[4]){
		uint8_t a0 = p8(02)[b[0]];
		uint8_t a1 = b0(k32[1]);
		uint8_t a2 = p8(01)[a0 ^ a1];
		uint8_t a3 = b0(k32[0]);
		b[0] = p8(00)[a2 ^ a3];
		b[1] = p8(10)[p8(11)[p8(12)[b[1]] ^ b1(k32[1])] ^ b1(k32[0])];
		b[2] = p8(20)[p8(21)[p8(22)[b[2]] ^ b2(k32[1])] ^ b2(k32[0])];
		b[3] = p8(30)[p8(31)[p8(32)[b[3]] ^ b3(k32[1])] ^ b3(k32[0])];
	}
};

template <>
struct f32_helper<192>{
	static void f(const std::uint32_t *k32, std::uint8_t (&b)[4]){
		b[0] = p8(03)[b[0]] ^ b0(k32[2]);
		b[1] = p8(13)[b[1]] ^ b1(k32[2]);
		b[2] = p8(23)[b[2]] ^ b2(k32[2]);
		b[3] = p8(33)[b[3]] ^ b3(k32[2]);
		f32_helper<128>::f(k32, b);
	}
};

template <>
struct f32_helper<256>{
	static void f(const std::uint32_t *k32, std::uint8_t (&b)[4]){
		b[0] = p8(04)[b[0]] ^ b0(k32[3]);
		b[1] = p8(14)[b[1]] ^ b1(k32[3]);
		b[2] = p8(24)[b[2]] ^ b2(k32[3]);
		b[3] = p8(34)[b[3]] ^ b3(k32[3]);
		f32_helper<192>::f(k32, b);
	}
};

inline std::uint32_t ROL(std::uint32_t x, std::uint32_t n){
	auto shift = n & 31;
	auto a = x << shift;
	auto b = x >> (32 - shift);
	return a | b;
}

inline std::uint32_t ROR(std::uint32_t x, std::uint32_t n){
	return ROL(x, 32 - (n & 31));
}

template <size_t Size>
class TwofishKeySchedule{
public:
	static const size_t block_size = 128;
	static const size_t output_whiten = block_size / 32;
	static const size_t round_subkeys = output_whiten + block_size / 32;
	static const size_t subkeys_size = round_subkeys + 2 * TwofishParameters<Size>::rounds;
	
private:
	//key bits used for S-boxes
	std::uint32_t sboxKeys[Size / 64];
	//round subkeys, input/output whitening bits
	std::uint32_t subKeys[subkeys_size];

	//rem=???
	static std::uint32_t reed_solomon_rem(std::uint32_t x){
		auto b  = (std::uint8_t) (x >> 24);
		std::uint32_t g2 = ((b << 1) ^ ((b & 0x80) ? reed_solomon_field_generator : 0u )) & 0xFF;
		std::uint32_t g3 = ((b >> 1) & 0x7Fu) ^ ((b & 1) ? reed_solomon_field_generator >> 1 : 0u ) ^ g2 ;
		x <<= 8;
		auto g4 = g3 << 8;
		g2 <<= 16;
		g3 <<= 24;
		return x ^ g3 ^ g2 ^ g4 ^ b;
	}

	//mds=???
	static std::uint32_t reed_solomon_mds_encode(std::uint32_t k0, std::uint32_t k1){
		std::uint32_t r = 0;
		r = k1;
		//shift one byte at a time
		for (int j = 0; j < 4; j++)
			r = reed_solomon_rem(r);
		r ^= k0;
		for (int j = 0; j < 4; j++)
			r = reed_solomon_rem(r);
		return r;
	}
public:
	TwofishKeySchedule(const TwofishKey<Size> &key){
		static const size_t key32_size = Size / 32;
		std::uint32_t key32[key32_size] = {0};
		{
			static const size_t m = sizeof(std::uint32_t);
			size_t i = 0;
			for (auto b : key.data()){
				key32[i / m] |= b << (i % m * 8);
				i++;
			}
		}

		static const size_t n = key32_size / 2;
		std::uint32_t k32_even[n];
		std::uint32_t k32_odd[n];
		for (size_t i = 0; i < n; i++){
			auto e = k32_even[i] = key32[i * 2 + 0];
			auto o = k32_odd[i] = key32[i * 2 + 1];
			this->sboxKeys[n - 1 - i] = reed_solomon_mds_encode(e, o);
		}

		static const int subkeyCnt = round_subkeys +  2 * TwofishParameters<Size>::rounds;

		static const std::uint32_t SK_STEP = 0x02020202;
		static const std::uint32_t SK_BUMP = 0x01010101;
		static const std::uint32_t SK_ROTL = 9;

		//compute round subkeys for PHT
		for (auto i = 0; i < subkeyCnt / 2; i++){
			//A uses even key dwords
			auto A = f32(i * SK_STEP, k32_even);
			//B uses odd  key dwords
			auto B = f32(i * SK_STEP + SK_BUMP, k32_odd);
			B = ROL(B, 8);
			//combine with a PHT
			this->subKeys[2 * i + 0] = A + B;
			this->subKeys[2 * i + 1] = ROL(A + 2 * B, SK_ROTL);
		}
	}
	TwofishKeySchedule(const TwofishKeySchedule &) = default;
	TwofishKeySchedule(TwofishKeySchedule &&) = default;
	TwofishKeySchedule &operator=(const TwofishKeySchedule &) = default;
	TwofishKeySchedule &operator=(TwofishKeySchedule &&) = default;

	const auto &get_sboxKeys() const{
		return this->sboxKeys;
	}
	const auto &get_subKeys() const{
		return this->subKeys;
	}

	static std::uint32_t f32(std::uint32_t x, const std::uint32_t *k32){
		std::uint8_t b[4];
		
		//Run each byte thru 8x8 S-boxes, xoring with key byte at each stage.
		//Note that each byte goes through a different combination of S-boxes.

		for (int i = 0; i < 4; i++)
			b[i] = (x >> (i * 8)) & 0xFF;

		f32_helper<Size>::f(k32, b);

		//Now perform the MDS matrix multiply
		std::uint32_t ret = 0;
		for (int i = 0; i < 4; i++){
			std::uint32_t a = 0;
			auto &m = M[i];
			for (int j = 0; j < 4; j++)
				a ^= MT[m[j]](b[j]);
			ret ^= a << (i * 8);
		}
		return ret;
	}
};

}

static const size_t block_size = 16;

typedef std::array<std::uint8_t, block_size> block_t;

template <size_t Size>
class Twofish{
public:
	static const size_t block_size = 16;
	typedef std::array<std::uint8_t, block_size> block_t;

private:
	detail::TwofishKeySchedule<Size> key;

	static const auto m = sizeof(std::uint32_t);
	static const auto x_size = block_size / m;
	typedef std::array<std::uint32_t, x_size> x_t;
	void do_round(int r, x_t &x){
		using detail::ROL;
		using detail::ROR;
		static const auto rs = detail::TwofishKeySchedule<Size>::round_subkeys;

		auto &sbk = this->key.get_sboxKeys();
		auto sk = this->key.get_subKeys() + rs + 2 * r;
		
		auto t0	 = this->key.f32(    x[0]    , sbk);
		auto t1	 = this->key.f32(ROL(x[1], 8), sbk);

		x[3] = ROL(x[3],1);

		//PHT, round keys
		x[2] ^= t0 +     t1 + sk[0];
		x[3] ^= t0 + 2 * t1 + sk[1];

		x[2] = ROR(x[2], 1);
	}
	void undo_round(int r, x_t &x){
		using detail::ROL;
		using detail::ROR;
		static const auto rs = detail::TwofishKeySchedule<Size>::round_subkeys;

		auto &sbk = this->key.get_sboxKeys();
		auto sk = this->key.get_subKeys() + rs + 2 * r;
		
		auto t0	 = this->key.f32(    x[0]    , sbk);
		auto t1	 = this->key.f32(ROL(x[1], 8), sbk);

		x[2] = ROL(x[2], 1);
		
		//PHT, round keys
		x[2] ^= t0 +     t1 + sk[0];
		x[3] ^= t0 + 2 * t1 + sk[1];
		
		x[3] = ROR(x[3], 1);
	}
	x_t load_block(const std::uint8_t *block, size_t offset){
		x_t ret;
		for (size_t i = 0; i < x_size; i++){
			auto p = block + i * 4;
			ret[i]  = *(p++);
			ret[i] |= *(p++) <<  8;
			ret[i] |= *(p++) << 16;
			ret[i] |= *(p  ) << 24;
			ret[i] ^= this->key.get_subKeys()[offset + i];
		}
		return ret;
	}
	void unload_block(std::uint8_t *block, const x_t &x, size_t offset){
		for (size_t i = 0; i < x_size; i++){
			auto y = x[i] ^ this->key.get_subKeys()[offset + i];
			auto p = block + i * 4;
			*(p++) = (y      ) & 0xFF;
			*(p++) = (y >>  8) & 0xFF;
			*(p++) = (y >> 16) & 0xFF;
			*(p  ) = (y >> 24) & 0xFF;
		}
	}
public:
	Twofish(const TwofishKey<Size> &key): key(key){}
	Twofish(const Twofish &) = default;
	Twofish(Twofish &&) = default;
	Twofish &operator=(const Twofish &) = default;
	Twofish &operator=(Twofish &&) = default;
	void encrypt_block(void *void_dst, const void *void_src) noexcept{
		auto src = (const std::uint8_t *)void_src;
		auto dst = (std::uint8_t *)void_dst;

		auto x = this->load_block(src, 0);

		static const auto rounds = detail::TwofishParameters<Size>::rounds;
		for (int r = 0; r < rounds - 1; r++){
			this->do_round(r, x);
			std::swap(x[0], x[2]);
			std::swap(x[1], x[3]);
		}
		this->do_round(rounds - 1, x);

		this->unload_block(dst, x, this->key.output_whiten);
	}
	void decrypt_block(void *void_dst, const void *void_src) noexcept{
		auto src = (const std::uint8_t *)void_src;
		auto dst = (std::uint8_t *)void_dst;
		
		auto x = this->load_block(src, this->key.output_whiten);

		static const auto rounds = detail::TwofishParameters<Size>::rounds;
		for (auto r = rounds; r-- > 1;){
			this->undo_round(r, x);
			std::swap(x[0], x[2]);
			std::swap(x[1], x[3]);
		}
		this->undo_round(0, x);
		
		this->unload_block(dst, x, 0);
	}
};

}

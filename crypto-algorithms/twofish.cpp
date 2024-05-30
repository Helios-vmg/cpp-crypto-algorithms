#include "twofish.hpp"

namespace{
/*
 * Reed-Solomon code parameters: (12,8) reversible code
 * g(x) = x^4 + (a + 1/a) * x^3 + a * x^2 + (a + 1/a) x + 1
 * where a is the primitive root of field generator 0x14D
 */
const std::uint32_t reed_solomon_field_generator = 0x14D;
const std::uint32_t mds_primitive_poly = 0x169;

const char permutation[4][5] = {
	{1, 0, 0, 1, 1},
	{0, 0, 1, 1, 0},
	{1, 1, 0, 0, 0},
	{0, 1, 1, 0, 1},
};

/* fixed 8x8 permutation S-boxes */

/***********************************************************************
*  07:07:14  05/30/98  [4x4]  TestCnt=256. keySize=128. CRC=4BD14D9E.
* maxKeyed:  dpMax = 18. lpMax =100. fixPt =  8. skXor =  0. skDup =  6. 
* log2(dpMax[ 6..18])=   --- 15.42  1.33  0.89  4.05  7.98 12.05
* log2(lpMax[ 7..12])=  9.32  1.01  1.16  4.23  8.02 12.45
* log2(fixPt[ 0.. 8])=  1.44  1.44  2.44  4.06  6.01  8.21 11.07 14.09 17.00
* log2(skXor[ 0.. 0])
* log2(skDup[ 0.. 6])=   ---  2.37  0.44  3.94  8.36 13.04 17.99
***********************************************************************/
extern const std::uint8_t P8x8[2][256] = {
/*  p0:   */
/*  dpMax      = 10.  lpMax      = 64.  cycleCnt=   1  1  1  0.         */
/* 817D6F320B59ECA4.ECB81235F4A6709D.BA5E6D90C8F32471.D7F4126E9B3085CA. */
/* Karnaugh maps:
*  0111 0001 0011 1010. 0001 1001 1100 1111. 1001 1110 0011 1110. 1101 0101 1111 1001. 
*  0101 1111 1100 0100. 1011 0101 0010 0000. 0101 1000 1100 0101. 1000 0111 0011 0010. 
*  0000 1001 1110 1101. 1011 1000 1010 0011. 0011 1001 0101 0000. 0100 0010 0101 1011. 
*  0111 0100 0001 0110. 1000 1011 1110 1001. 0011 0011 1001 1101. 1101 0101 0000 1100. 
*/
	{
		0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76, 
		0x9A, 0x92, 0x80, 0x78, 0xE4, 0xDD, 0xD1, 0x38, 
		0x0D, 0xC6, 0x35, 0x98, 0x18, 0xF7, 0xEC, 0x6C, 
		0x43, 0x75, 0x37, 0x26, 0xFA, 0x13, 0x94, 0x48, 
		0xF2, 0xD0, 0x8B, 0x30, 0x84, 0x54, 0xDF, 0x23, 
		0x19, 0x5B, 0x3D, 0x59, 0xF3, 0xAE, 0xA2, 0x82, 
		0x63, 0x01, 0x83, 0x2E, 0xD9, 0x51, 0x9B, 0x7C, 
		0xA6, 0xEB, 0xA5, 0xBE, 0x16, 0x0C, 0xE3, 0x61, 
		0xC0, 0x8C, 0x3A, 0xF5, 0x73, 0x2C, 0x25, 0x0B, 
		0xBB, 0x4E, 0x89, 0x6B, 0x53, 0x6A, 0xB4, 0xF1, 
		0xE1, 0xE6, 0xBD, 0x45, 0xE2, 0xF4, 0xB6, 0x66, 
		0xCC, 0x95, 0x03, 0x56, 0xD4, 0x1C, 0x1E, 0xD7, 
		0xFB, 0xC3, 0x8E, 0xB5, 0xE9, 0xCF, 0xBF, 0xBA, 
		0xEA, 0x77, 0x39, 0xAF, 0x33, 0xC9, 0x62, 0x71, 
		0x81, 0x79, 0x09, 0xAD, 0x24, 0xCD, 0xF9, 0xD8, 
		0xE5, 0xC5, 0xB9, 0x4D, 0x44, 0x08, 0x86, 0xE7, 
		0xA1, 0x1D, 0xAA, 0xED, 0x06, 0x70, 0xB2, 0xD2, 
		0x41, 0x7B, 0xA0, 0x11, 0x31, 0xC2, 0x27, 0x90, 
		0x20, 0xF6, 0x60, 0xFF, 0x96, 0x5C, 0xB1, 0xAB, 
		0x9E, 0x9C, 0x52, 0x1B, 0x5F, 0x93, 0x0A, 0xEF, 
		0x91, 0x85, 0x49, 0xEE, 0x2D, 0x4F, 0x8F, 0x3B, 
		0x47, 0x87, 0x6D, 0x46, 0xD6, 0x3E, 0x69, 0x64, 
		0x2A, 0xCE, 0xCB, 0x2F, 0xFC, 0x97, 0x05, 0x7A, 
		0xAC, 0x7F, 0xD5, 0x1A, 0x4B, 0x0E, 0xA7, 0x5A, 
		0x28, 0x14, 0x3F, 0x29, 0x88, 0x3C, 0x4C, 0x02, 
		0xB8, 0xDA, 0xB0, 0x17, 0x55, 0x1F, 0x8A, 0x7D, 
		0x57, 0xC7, 0x8D, 0x74, 0xB7, 0xC4, 0x9F, 0x72, 
		0x7E, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34, 
		0x6E, 0x50, 0xDE, 0x68, 0x65, 0xBC, 0xDB, 0xF8, 
		0xC8, 0xA8, 0x2B, 0x40, 0xDC, 0xFE, 0x32, 0xA4, 
		0xCA, 0x10, 0x21, 0xF0, 0xD3, 0x5D, 0x0F, 0x00, 
		0x6F, 0x9D, 0x36, 0x42, 0x4A, 0x5E, 0xC1, 0xE0
	},
/*  p1:   */
/*  dpMax      = 10.  lpMax      = 64.  cycleCnt=   2  0  0  1.         */
/* 28BDF76E31940AC5.1E2B4C376DA5F908.4C75169A0ED82B3F.B951C3DE647F208A. */
/* Karnaugh maps:
*  0011 1001 0010 0111. 1010 0111 0100 0110. 0011 0001 1111 0100. 1111 1000 0001 1100. 
*  1100 1111 1111 1010. 0011 0011 1110 0100. 1001 0110 0100 0011. 0101 0110 1011 1011. 
*  0010 0100 0011 0101. 1100 1000 1000 1110. 0111 1111 0010 0110. 0000 1010 0000 0011. 
*  1101 1000 0010 0001. 0110 1001 1110 0101. 0001 0100 0101 0111. 0011 1011 1111 0010. 
*/
	{
		0x75, 0xF3, 0xC6, 0xF4, 0xDB, 0x7B, 0xFB, 0xC8, 
		0x4A, 0xD3, 0xE6, 0x6B, 0x45, 0x7D, 0xE8, 0x4B, 
		0xD6, 0x32, 0xD8, 0xFD, 0x37, 0x71, 0xF1, 0xE1, 
		0x30, 0x0F, 0xF8, 0x1B, 0x87, 0xFA, 0x06, 0x3F, 
		0x5E, 0xBA, 0xAE, 0x5B, 0x8A, 0x00, 0xBC, 0x9D, 
		0x6D, 0xC1, 0xB1, 0x0E, 0x80, 0x5D, 0xD2, 0xD5, 
		0xA0, 0x84, 0x07, 0x14, 0xB5, 0x90, 0x2C, 0xA3, 
		0xB2, 0x73, 0x4C, 0x54, 0x92, 0x74, 0x36, 0x51, 
		0x38, 0xB0, 0xBD, 0x5A, 0xFC, 0x60, 0x62, 0x96, 
		0x6C, 0x42, 0xF7, 0x10, 0x7C, 0x28, 0x27, 0x8C, 
		0x13, 0x95, 0x9C, 0xC7, 0x24, 0x46, 0x3B, 0x70, 
		0xCA, 0xE3, 0x85, 0xCB, 0x11, 0xD0, 0x93, 0xB8, 
		0xA6, 0x83, 0x20, 0xFF, 0x9F, 0x77, 0xC3, 0xCC, 
		0x03, 0x6F, 0x08, 0xBF, 0x40, 0xE7, 0x2B, 0xE2, 
		0x79, 0x0C, 0xAA, 0x82, 0x41, 0x3A, 0xEA, 0xB9, 
		0xE4, 0x9A, 0xA4, 0x97, 0x7E, 0xDA, 0x7A, 0x17, 
		0x66, 0x94, 0xA1, 0x1D, 0x3D, 0xF0, 0xDE, 0xB3, 
		0x0B, 0x72, 0xA7, 0x1C, 0xEF, 0xD1, 0x53, 0x3E, 
		0x8F, 0x33, 0x26, 0x5F, 0xEC, 0x76, 0x2A, 0x49, 
		0x81, 0x88, 0xEE, 0x21, 0xC4, 0x1A, 0xEB, 0xD9, 
		0xC5, 0x39, 0x99, 0xCD, 0xAD, 0x31, 0x8B, 0x01, 
		0x18, 0x23, 0xDD, 0x1F, 0x4E, 0x2D, 0xF9, 0x48, 
		0x4F, 0xF2, 0x65, 0x8E, 0x78, 0x5C, 0x58, 0x19, 
		0x8D, 0xE5, 0x98, 0x57, 0x67, 0x7F, 0x05, 0x64, 
		0xAF, 0x63, 0xB6, 0xFE, 0xF5, 0xB7, 0x3C, 0xA5, 
		0xCE, 0xE9, 0x68, 0x44, 0xE0, 0x4D, 0x43, 0x69, 
		0x29, 0x2E, 0xAC, 0x15, 0x59, 0xA8, 0x0A, 0x9E, 
		0x6E, 0x47, 0xDF, 0x34, 0x35, 0x6A, 0xCF, 0xDC, 
		0x22, 0xC9, 0xC0, 0x9B, 0x89, 0xD4, 0xED, 0xAB, 
		0x12, 0xA2, 0x0D, 0x52, 0xBB, 0x02, 0x2F, 0xA9, 
		0xD7, 0x61, 0x1E, 0xB4, 0x50, 0x04, 0xF6, 0xC2, 
		0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xBE, 0x91
	}
};

const auto m = sizeof(std::uint32_t);
template <size_t N>
struct x_size{
	static const auto value = symmetric::Twofish<N>::block_size / m;
};
template <size_t N>
using x_t = std::array<std::uint32_t, x_size<N>::value>;
template <size_t N>
using K = typename symmetric::Twofish<N>::KeySchedule;

template <size_t Size>
x_t<Size> load_block(const std::uint8_t *block, size_t offset, const K<Size> &key){
	x_t<Size> ret;
	for (size_t i = 0; i < x_size<Size>::value; i++){
		auto p = block + i * 4;
		ret[i]  = *(p++);
		ret[i] |= *(p++) <<  8;
		ret[i] |= *(p++) << 16;
		ret[i] |= *(p  ) << 24;
		ret[i] ^= key.sub_keys[offset + i];
	}
	return ret;
}

template <size_t Size>
void unload_block(std::uint8_t *block, const x_t<Size> &x, size_t offset, const K<Size> &key){
	for (size_t i = 0; i < x_size<Size>::value; i++){
		auto y = x[i] ^ key.sub_keys[offset + i];
		auto p = block + i * 4;
		*(p++) = (y      ) & 0xFF;
		*(p++) = (y >>  8) & 0xFF;
		*(p++) = (y >> 16) & 0xFF;
		*(p  ) = (y >> 24) & 0xFF;
	}
}

std::uint8_t get_byte(std::uint32_t n, int i){
	return (std::uint8_t)(n >> (i * 8));
}

auto &p9(int x, int y){
	return P8x8[(int)permutation[x][y]];
};

std::uint32_t LFSR1(std::uint32_t x){
	auto a = x >> 1;
	auto b = x & 1;
	b *= mds_primitive_poly / 2;
	return a ^ b;
}

std::uint32_t LFSR2(std::uint32_t x){
	auto a = x >> 2;
	auto b = (x & 2) >> 1;
	auto c = x & 1;
	b *= mds_primitive_poly / 2;
	c *= mds_primitive_poly / 4;
	return a ^ b ^ c;
}

//force result to dword so << will work
std::uint32_t Mx_I(std::uint32_t x){
	return x;
}

std::uint32_t Mx_X(std::uint32_t x){
	//5B
	return Mx_I(x) ^ LFSR2(x);
}

std::uint32_t Mx_Y(std::uint32_t x){
	//EF
	return Mx_X(x) ^ LFSR1(x);
}

const char I = 0;
const char X = 1;
const char Y = 2;

const char M[4][4] = {
	{I,Y,X,X},
	{X,Y,Y,I},
	{Y,X,I,Y},
	{Y,I,Y,X},
};
typedef std::uint32_t (*mul_f)(std::uint32_t);
const mul_f MT[] = {
	Mx_I,
	Mx_X,
	Mx_Y,
};

//rem=???
std::uint32_t reed_solomon_rem(std::uint32_t x){
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
std::uint32_t reed_solomon_mds_encode(std::uint32_t k0, std::uint32_t k1){
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

template <size_t Size>
struct f32_helper{};

template <>
struct f32_helper<128>{
	static void f(const std::uint32_t *k32, std::uint8_t (&b)[4]){
		for (int i = 0; i < 4; i++){
			auto a0 = p9(i, 2)[b[i]];
			auto a1 = get_byte(k32[1], i);
			auto a2 = p9(i, 1)[a0 ^ a1];
			auto a3 = get_byte(k32[0], i);
			b[i] = p9(i, 0)[a2 ^ a3];
		}
	}
};

template <>
struct f32_helper<192>{
	static void f(const std::uint32_t *k32, std::uint8_t (&b)[4]){
		for (int i = 0; i < 4; i++)
			b[i] = p9(i, 3)[b[i]] ^ get_byte(k32[2], i);
		f32_helper<128>::f(k32, b);
	}
};

template <>
struct f32_helper<256>{
	static void f(const std::uint32_t *k32, std::uint8_t (&b)[4]){
		for (int i = 0; i < 4; i++)
			b[i] = p9(i, 4)[b[i]] ^ get_byte(k32[3], i);
		f32_helper<192>::f(k32, b);
	}
};

template <size_t Size>
std::uint32_t f32(std::uint32_t x, const std::uint32_t *k32){
	std::uint8_t b[4];
	
	//Run each byte through 8x8 S-boxes, xoring with key byte at each stage.
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

std::uint32_t rotate_left(std::uint32_t x, std::uint32_t n){
	auto shift = n & 31;
	auto a = x << shift;
	auto b = x >> (32 - shift);
	return a | b;
}

std::uint32_t rotate_right(std::uint32_t x, std::uint32_t n){
	return rotate_left(x, 32 - (n & 31));
}

template <size_t Size>
void do_round(int r, x_t<Size> &x, const K<Size> &key){
	static const auto rs = symmetric::Twofish<Size>::round_subkeys;

	auto &sbk = key.sbox_keys;
	auto sk = key.sub_keys + rs + 2 * r;
	
	auto t0	 = f32<Size>(    x[0]    , sbk);
	auto t1	 = f32<Size>(rotate_left(x[1], 8), sbk);

	x[3] = rotate_left(x[3],1);

	//PHT, round keys
	x[2] ^= t0 +     t1 + sk[0];
	x[3] ^= t0 + 2 * t1 + sk[1];

	x[2] = rotate_right(x[2], 1);
}

template <size_t Size>
void undo_round(int r, x_t<Size> &x, const K<Size> &key){
	static const auto rs = symmetric::Twofish<Size>::round_subkeys;

	auto &sbk = key.sbox_keys;
	auto sk = key.sub_keys + rs + 2 * r;
	
	auto t0	 = f32<Size>(    x[0]    , sbk);
	auto t1	 = f32<Size>(rotate_left(x[1], 8), sbk);

	x[2] = rotate_left(x[2], 1);
	
	//PHT, round keys
	x[2] ^= t0 +     t1 + sk[0];
	x[3] ^= t0 + 2 * t1 + sk[1];
	
	x[3] = rotate_right(x[3], 1);
}

}

namespace symmetric{

template <size_t Size>
Twofish<Size>::KeySchedule::KeySchedule(const key_t &key){
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
		this->sbox_keys[n - 1 - i] = reed_solomon_mds_encode(e, o);
	}

	static const int subkeyCnt = round_subkeys + 2 * rounds;

	static const std::uint32_t SK_STEP = 0x02020202;
	static const std::uint32_t SK_BUMP = 0x01010101;
	static const std::uint32_t SK_ROTL = 9;

	//compute round subkeys for PHT
	for (auto i = 0; i < subkeyCnt / 2; i++){
		//A uses even key dwords
		auto A = f32<Size>(i * SK_STEP, k32_even);
		//B uses odd  key dwords
		auto B = f32<Size>(i * SK_STEP + SK_BUMP, k32_odd);
		B = rotate_left(B, 8);
		//combine with a PHT
		this->sub_keys[2 * i + 0] = A + B;
		this->sub_keys[2 * i + 1] = rotate_left(A + 2 * B, SK_ROTL);
	}
}

template <size_t Size>
void Twofish<Size>::encrypt_block(void *void_dst, const void *void_src) const noexcept{
	auto src = (const std::uint8_t *)void_src;
	auto dst = (std::uint8_t *)void_dst;

	auto x = load_block<Size>(src, 0, this->key);

	for (int r = 0; r < rounds - 1; r++){
		do_round<Size>(r, x, this->key);
		std::swap(x[0], x[2]);
		std::swap(x[1], x[3]);
	}
	do_round<Size>(rounds - 1, x, this->key);

	unload_block<Size>(dst, x, output_whiten, this->key);
}

template <size_t Size>
void Twofish<Size>::decrypt_block(void *void_dst, const void *void_src) const noexcept{
	auto src = (const std::uint8_t *)void_src;
	auto dst = (std::uint8_t *)void_dst;
	
	auto x = load_block<Size>(src, output_whiten, this->key);

	for (auto r = rounds; r-- > 1;){
		undo_round<Size>(r, x, this->key);
		std::swap(x[0], x[2]);
		std::swap(x[1], x[3]);
	}
	undo_round<Size>(0, x, this->key);
	
	unload_block<Size>(dst, x, 0, this->key);
}

template class Twofish<128>;
template class Twofish<192>;
template class Twofish<256>;

}
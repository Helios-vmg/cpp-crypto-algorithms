#pragma once

#include <cstdint>
#include <algorithm>
#include <vector>
#include <type_traits>
#include <random>
#include <array>
#include <cstring>

namespace csprng{

class Prgn{
protected:
	virtual void internal_get_bytes(void *dst, size_t size) = 0;
public:
	virtual ~Prgn(){}
	void get_bytes(void *dst, size_t size){
		this->internal_get_bytes(dst, size);
	}
	template <typename T, size_t N>
	void get_bytes(T (&dst)[N]){
		this->get_bytes(&dst, sizeof(dst));
	}
	std::vector<std::uint8_t> get_bytes(size_t size){
		std::vector<std::uint8_t> ret(size);
		if (size)
			this->get_bytes(ret.data(), ret.size());
		return ret;
	}
	template <typename T>
	typename std::enable_if<std::is_integral<T>::value, void>::type
	get(T &dst){
		std::uint8_t temp[sizeof(T)];
		this->get_bytes(temp, sizeof(temp));
		dst = 0;
		for (int i = sizeof(T); i--;){
			dst <<= 8;
			dst |= temp[i];
		}
	}
	template <typename T>
	typename std::enable_if<std::is_integral<T>::value, T>::type
	get(){
		T dst;
		this->get(dst);
		return dst;
	}
};

template <typename C>
class BlockCipherRng : public Prgn{
	typedef uintptr_t T;
	static const size_t state_size = (C::block_size + sizeof(T) - 1) / sizeof(T);
	
	C c;
	T state[state_size];
	void increment_state(){
		for (auto &s : this->state)
			if (++s)
				break;
	}
	template <size_t N>
	static std::array<std::uint8_t, N> random_array(){
		std::random_device dev;
		std::array<std::uint8_t, N> ret;
		for (size_t i = 0; i < N;){
			auto x = dev();
			for (size_t j = 0; j < sizeof(x) && i < N; j++, i++){
				ret[i] = x & 0xFF;
				x >>= 8;
			}
		}
		return ret;
	}
	void internal_get_bytes(void *vdst, size_t size) override{
		auto dst = (std::uint8_t *)vdst;
		while (size){
			auto block = (*this)();
			auto n = std::min(size, C::block_size);
			memcpy(dst, block.data(), n);
			dst += n;
			size -= n;
		}
	}
public:
	BlockCipherRng(): c(typename C::key_t(random_array<C::key_t::size>())){
		auto temp = random_array<sizeof(state)>();
		memcpy(state, temp.data(), sizeof(state));
	}
	BlockCipherRng(const typename C::key_t &key, const typename C::block_t &initial_state = {}): c(key){
		std::fill(this->state, this->state + state_size, 0);
		size_t i = 0;
		for (auto s : initial_state){
			this->state[i / sizeof(T)] |= (T)s << (i % sizeof(T) * 8);
			i++;
		}
	}
	BlockCipherRng(const BlockCipherRng &) = default;
	BlockCipherRng &operator=(const BlockCipherRng &) = default;
	BlockCipherRng(BlockCipherRng &&) = default;
	BlockCipherRng &operator=(BlockCipherRng &&) = default;
	typename C::block_t operator()(){
		typename C::block_t ret;
		size_t i = 0;
		for (auto s : this->state)
			for (size_t j = 0; j < sizeof(T); j++)
				ret[i++] = (s >> (j * 8)) & 0xFF;
		this->increment_state();
		ret = this->c.encrypt_block(ret);
		return ret;
	}
};

}

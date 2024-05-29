#pragma once

#include "ringbuffer.hpp"
#include <cstdint>
#include <algorithm>
#include <vector>
#include <type_traits>
#include <random>
#include <array>
#include <cstring>

namespace csprng{

class Prng{
public:
	virtual ~Prng(){}
	virtual void get_bytes(void *void_dst, size_t size) = 0;
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
	template <size_t N>
	void get_bytes(std::uint8_t (&dst)[N]){
		this->get_bytes(dst, N);
	}
	template <size_t N>
	std::array<std::uint8_t, N> get_bytes_fixed(){
		std::array<std::uint8_t, N> ret;
		this->get_bytes(ret.data(), N);
		return ret;
	}
	template <typename T>
	typename std::enable_if<std::is_integral<T>::value, T>::type
	get(){
		T dst;
		this->get(dst);
		return dst;
	}
};

template <size_t N>
class BlockPrgn : public Prng{
	std::uint8_t buffer[N];
	size_t offset = 0;
	size_t size = 0;
	void fill_buffer(){
		this->internal_get_bytes(this->buffer);
		this->offset = 0;
		this->size = N;
	}
protected:
	virtual void internal_get_bytes(void *dst) = 0;
public:
	virtual ~BlockPrgn(){}
	void get_bytes(void *void_dst, size_t size) override{
		auto dst = (std::uint8_t *)void_dst;
		while (size){
			if (!this->size)
				this->fill_buffer();
			auto write_size = std::min(size, this->size);
			memcpy(dst, this->buffer + this->offset, write_size);
			this->offset += write_size;
			this->size -= write_size;
			dst += write_size;
			size -= write_size;
		}
	}
	using csprng::Prng::get_bytes;
};

template <typename C>
class BlockCipherRng : public BlockPrgn<C::block_size - 4>{
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
	void internal_get_bytes(void *dst) override{
		auto block = (*this)();
		//To get the indistinguishability property, discard 32 bits per block.
		memcpy(dst, block.data(), C::block_size - 4);
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

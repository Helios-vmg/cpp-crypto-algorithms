#pragma once

#include "block.hpp"
#include "source_sink.hpp"
#include "ringbuffer.hpp"

namespace symmetric{

namespace stream{

template <typename Cipher>
class CipherStream : public utility::DataSource, public utility::DataSink{
protected:
	using block_t = typename Cipher::block_t;
	Cipher c;
	bool encrypt;
	block_t iv;
	utility::RingBuffer input_buffer;
	utility::RingBuffer output_buffer;

	void process_all(){
		const auto bs = Cipher::block_size;
		block_t block;
		while (true){
			auto ilength = this->input_buffer.get_length();
			if (ilength < bs)
				break;
			auto olength = this->output_buffer.free();
			if (olength < bs)
				break;
			this->input_buffer.read(block.data(), bs);
			block = this->process(block);
			this->output_buffer.write(block.data(), bs);
		}
	}
	virtual block_t process(const block_t &) = 0;
public:
	CipherStream(const Cipher &c, const block_t &iv, bool encrypt)
		: c(c)
		, encrypt(encrypt)
		, iv(iv)
		, input_buffer(128 << 10)
		, output_buffer(128 << 10){}
	virtual ~CipherStream() = 0;
	CipherStream(const CipherStream &) = delete;
	CipherStream &operator=(const CipherStream &) = delete;
	CipherStream(CipherStream &&other) = delete;
	CipherStream &operator=(CipherStream &&other) = delete;
	size_t write(const void *vsrc, size_t size) override{
		auto src = (const std::uint8_t *)vsrc;
		size_t ret = 0;
		while (size){
			this->process_all();
			auto written = this->input_buffer.write(src, size);
			if (!written)
				break;
			src += written;
			size -= written;
			ret += written;
		}
		this->process_all();
		return ret;
	}
	size_t read(void *vdst, size_t size) override{
		auto dst = (std::uint8_t *)vdst;
		size_t ret = 0;
		while (size){
			this->process_all();
			auto read = this->output_buffer.read(dst, size);
			if (!read)
				break;
			dst += read;
			size -= read;
			ret += read;
		}
		this->process_all();
		return ret;
	}
	std::optional<size_t> available() const override{
		return this->output_buffer.get_length();
	}
	virtual void terminate(){}
};

template <typename Cipher>
CipherStream<Cipher>::~CipherStream(){}

template <typename Cipher>
class CtrCipherStream : public CipherStream<Cipher>{
	std::uint64_t state = 0;
	typename Cipher::block_t process(const typename Cipher::block_t &input) override{
		auto ret = this->iv;
		auto s = this->state++;
		for (size_t i = 0; i < Cipher::block_size && s; i++){
			ret[i] ^= s & 0xFF;
			s >>= 8;
		}
		ret = this->c.encrypt_block(ret);
		for (size_t i = 0; i < Cipher::block_size; i++)
			ret[i] ^= input[i];
		return ret;
	}
public:
	CtrCipherStream(const Cipher &c, const typename Cipher::block_t &iv, bool encrypt): CipherStream<Cipher>(c, iv, encrypt){}
	CtrCipherStream(const CtrCipherStream &) = delete;
	CtrCipherStream &operator=(const CtrCipherStream &) = delete;
	CtrCipherStream(CtrCipherStream &&other) = delete;
	CtrCipherStream &operator=(CtrCipherStream &&other) = delete;
	void terminate() override{
		this->process_all();
		if (!this->input_buffer.get_length())
			return;
		typename Cipher::block_t ret;
		auto read = this->input_buffer.read(ret.data(), ret.size());
		ret = this->process(ret);
		this->output_buffer.write(ret.data(), read);
	}
};

}

}

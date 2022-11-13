#pragma once

#include "source_sink.hpp"
#include "ringbuffer.hpp"

namespace utility{

class Base64Stream : public utility::DataSource, public utility::DataSink{
protected:
	utility::RingBuffer input_buffer;
	utility::RingBuffer output_buffer;
	
	void process_all();
	virtual size_t input_block_size() = 0;
	virtual size_t output_block_size() = 0;
	virtual size_t process(void *, const void *, size_t) = 0;
public:
	Base64Stream(): input_buffer(4 << 10), output_buffer(4 << 10){}
	virtual ~Base64Stream(){}
	Base64Stream(const Base64Stream &) = delete;
	Base64Stream &operator=(const Base64Stream &) = delete;
	Base64Stream(Base64Stream &&other) = delete;
	Base64Stream &operator=(Base64Stream &&other) = delete;
	size_t write(const void *vsrc, size_t size) override;
	size_t read(void *vdst, size_t size) override;
	virtual void terminate() = 0;
	std::optional<size_t> available() const override{
		return this->output_buffer.get_length();
	}
};

class Base64Encoder : public Base64Stream{
	size_t input_block_size() override{
		return 3;
	}
	size_t output_block_size() override{
		return 4;
	}
	size_t process(void *, const void *, size_t) override;
public:
	Base64Encoder() = default;
	Base64Encoder(const Base64Encoder &) = delete;
	Base64Encoder &operator=(const Base64Encoder &) = delete;
	Base64Encoder(Base64Encoder &&other) = delete;
	Base64Encoder &operator=(Base64Encoder &&other) = delete;
	void terminate() override;
	//convenience function:
	static std::string encode(const void *, size_t);
};

class Base64Decoder : public Base64Stream{
	signed char reverse_alphabet[256];
	size_t input_block_size() override{
		return 4;
	}
	size_t output_block_size() override{
		return 3;
	}
	size_t process(void *, const void *, size_t) override;
public:
	Base64Decoder();
	Base64Decoder(const Base64Decoder &) = delete;
	Base64Decoder &operator=(const Base64Decoder &) = delete;
	Base64Decoder(Base64Decoder &&other) = delete;
	Base64Decoder &operator=(Base64Decoder &&other) = delete;
	void terminate() override;
	//convenience function:
	static std::vector<std::uint8_t> decode(const std::string &);
};

}

#include "base64.hpp"
#include <cassert>
#include <stdexcept>

static const char * const base64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

namespace utility{

void Base64Stream::process_all(){
	const auto ibs = this->input_block_size();
	const auto obs = this->output_block_size();
	char iblock[4];
	char oblock[4];
	while (this->input_buffer.get_length() >= ibs && this->output_buffer.free() >= obs){
		this->input_buffer.read(iblock, ibs);
		auto output_size = this->process(oblock, iblock, ibs);
		this->output_buffer.write(oblock, output_size);
	}
}

size_t Base64Stream::write(const void *vsrc, size_t size){
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

size_t Base64Stream::read(void *vdst, size_t size){
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

size_t Base64Encoder::process(void *vdst, const void *vsrc, size_t src_size){
	auto src = (const std::uint8_t *)vsrc;
	auto dst = (std::uint8_t *)vdst;
	switch (src_size){
		case 1:
			dst[0] = base64_alphabet[(src[0] >> 2) & 0b0011'1111];
			dst[1] = base64_alphabet[(src[0] << 4) & 0b0011'0000];
			dst[3] = dst[2] = '=';
			break;
		case 2:
			dst[0] = base64_alphabet[(src[0] >> 2) & 0b0011'1111];
			dst[1] = base64_alphabet[
					(src[0] << 4) & 0b0011'0000 |
					(src[1] >> 4) & 0b0000'1111
			];
			dst[2] = base64_alphabet[(src[1] << 2) & 0b0011'1100];
			dst[3] = '=';
			break;
		case 3:
			dst[0] = base64_alphabet[(src[0] >> 2) & 0b0011'1111];
			dst[1] = base64_alphabet[
					(src[0] << 4) & 0b0011'0000 |
					(src[1] >> 4) & 0b0000'1111
			];
			dst[2] = base64_alphabet[
				(src[1] << 2) & 0b0011'1100 |
				(src[2] >> 6) & 0b0000'0011
			];
			dst[3] = base64_alphabet[src[2] & 0b0011'1111];
			break;
		default:
			assert(false);
	}
	return 4;
}

void Base64Encoder::terminate(){
	this->process_all();
	auto n = this->input_buffer.get_length();
	if (!n || this->output_buffer.free() < 4)
		return;
	char iblock[3];
	char oblock[4];
	this->input_buffer.read(iblock, n);
	this->process(oblock, iblock, n);
	this->output_buffer.write(oblock, 4);
}

Base64Decoder::Base64Decoder(){
	std::fill(this->reverse_alphabet, this->reverse_alphabet + 256, (signed char)-1);
	size_t i = 0;
	for (auto p = base64_alphabet; *p; p++, i++)
		this->reverse_alphabet[*p] = (signed char)i;
}

size_t Base64Decoder::process(void *vdst, const void *vsrc, size_t src_size){
	auto src = (const std::uint8_t *)vsrc;
	auto dst = (std::uint8_t *)vdst;
	std::uint8_t temp[4];
	size_t ret = 0;
	for (size_t i = 0; i < 4; i++){
		if (ret){
			temp[i] = 0;
			continue;
		}
		if (src[i] == '='){
			if (i < 2)
				throw std::runtime_error("invalid base64 input: invalid padding");
			ret = i - 1;
			temp[i] = 0;
			continue;
		}
		auto x = this->reverse_alphabet[src[i]];
		if (x == -1)
			throw std::runtime_error((std::string)"invalid base64 character: " + (char)src[i]);
		temp[i] = x;
	}
	dst[0] = (temp[0] << 2) | (temp[1] >> 4) & 0b0000'0011;
	dst[1] = (temp[1] << 4) | (temp[2] >> 2) & 0b0000'1111;
	dst[2] = (temp[2] << 6) | temp[3];
	return ret ? ret : 3;
}

void Base64Decoder::terminate(){
	this->process_all();
	if (this->input_buffer.get_length())
		throw std::runtime_error("invalid base64 input: invalid length; should be a multiple of 4");
}

template <typename T>
static void flush(T &ret, Base64Stream &encoder){
	while (auto available = encoder.available().value()){
		auto m = ret.size();
		ret.resize(m + available);
		encoder.read(ret.data() + m, available);
	}
}

std::string Base64Encoder::encode(const void *vsrc, size_t size){
	auto src = (const std::uint8_t *)vsrc;
	Base64Encoder encoder;
	
	std::string ret;
	auto predicted_size = (size * 4) / 3;
	predicted_size += (4 - predicted_size) % 4;
	ret.reserve(predicted_size);
	
	while (size){
		auto written = encoder.write(src, size);
		if (!written){
			::utility::flush(ret, encoder);
			continue;
		}
		src += written;
		size -= written;
	}
	::utility::flush(ret, encoder);
	encoder.terminate();
	::utility::flush(ret, encoder);
	return ret;
}

std::vector<std::uint8_t> Base64Decoder::decode(const std::string &input){
	auto src = (const std::uint8_t *)input.data();
	size_t size = input.size();
	Base64Decoder decoder;

	std::vector<std::uint8_t> ret;
	//A little extra just in case.
	ret.reserve(size * 3 / 4 + 8);

	while (size){
		auto written = decoder.write(src, size);
		if (!written){
			::utility::flush(ret, decoder);
			continue;
		}
		src += written;
		size -= written;
	}
	::utility::flush(ret, decoder);
	decoder.terminate();
	::utility::flush(ret, decoder);
	return ret;
}

}

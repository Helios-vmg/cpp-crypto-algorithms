#pragma once

#include "source_sink.hpp"
#include <vector>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <algorithm>
#include <limits>

namespace utility{

class RingBuffer{
	std::vector<std::uint8_t> data;
	size_t offset = 0;
	size_t length = 0;
	size_t capacity = 0;

	template <typename F>
	size_t push(size_t size, const F &f){
		size = std::min(size, this->free());
		size_t ret = 0;
		while (size){
			auto write_pos = (this->offset + this->length) % this->capacity;
			auto write_size = std::min(this->capacity - write_pos, size);
			auto bytes_read = f(&this->data[write_pos], write_size);
			if (!bytes_read)
				break;
			this->length += bytes_read;
			ret += bytes_read;
			size -= bytes_read;
		}
		return ret;
	}
	template <typename F>
	size_t pop(size_t size, const F &f){
		size = std::min(size, this->length);
		size_t ret = 0;
		while (size){
			auto read_pos = this->offset % this->capacity;
			auto read_size = std::min(this->capacity - read_pos, size);
			f(&this->data[read_pos], read_size);
			this->length -= read_size;
			this->offset += read_size;
			ret += read_size;
			size -= read_size;
		}
		if (this->length)
			this->offset %= this->capacity;
		else
			this->offset = 0;
		return ret;
	}
	template <typename F>
	void process(const F &f){
		for (size_t offset = 0; offset < this->length;){
			auto read_pos = this->offset % this->capacity;
			auto read_size = std::min(this->capacity - read_pos, this->length - offset);
			f(&this->data[read_pos], read_size);
			offset += read_size;
		}
	}
public:
	RingBuffer() = default;
	RingBuffer(size_t capacity){
		this->capacity = capacity;
		this->data.resize(this->capacity);
	}
	RingBuffer(const RingBuffer &) = delete;
	RingBuffer &operator=(const RingBuffer &) = delete;
	RingBuffer(RingBuffer &&other){
		*this = std::move(other);
	}
	RingBuffer &operator=(RingBuffer &&other){
		this->data = std::move(other.data);
		this->offset = other.offset;
		this->length = other.length;
		this->capacity = other.capacity;
		other.capacity = other.length = other.offset = 0;
		return *this;
	}
	size_t write(const void *src, size_t size){
		auto src2 = (const std::uint8_t *)src;
		return this->push(size, [&src2](std::uint8_t *dst, size_t size){
			memcpy(dst, src2, size);
			src2 += size;
			return size;
		});
	}
	size_t read(void *dst, size_t size){
		auto dst2 = (std::uint8_t *)dst;
		return this->pop(size, [&dst2](const std::uint8_t *src, size_t size){
			memcpy(dst2, src, size);
			dst2 += size;
		});
	}
	template <typename Hash>
	void update_hash(Hash &hash){
		this->process([&hash](const std::uint8_t *src, size_t size){
			hash.update(src, size);
		});
	}
	size_t write_to_sink(DataSink &sink, size_t max_bytes = std::numeric_limits<size_t>::max()){
		return this->pop(max_bytes, [&sink](const std::uint8_t *src, size_t size){
			sink.write(src, size);
		});
	}
	size_t read_from_source(DataSource &source, size_t max_bytes = std::numeric_limits<size_t>::max()){
		return this->push(max_bytes, [&source](std::uint8_t *dst, size_t size){
			return source.read(dst, size);
		});
	}
	size_t free() const{
		return this->capacity - this->length;
	}
	size_t get_length() const{
		return this->length;
	}
};

}

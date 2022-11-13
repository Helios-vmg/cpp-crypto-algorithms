#pragma once

#include <iostream>
#include <memory>
#include <cstdint>
#include <optional>

namespace utility{

class DataSink;

class DataSource{
public:
	virtual ~DataSource(){}
	virtual size_t read(void *, size_t) = 0;
	//Returns the number of bytes that are available for reading.
	//Returns the null value if the number cannot be determined in advance.
	virtual std::optional<size_t> available() const{
		return {};
	}
	virtual DataSource &operator>>(DataSink &);
};

class DataSink{
public:
	virtual ~DataSink(){}
	virtual size_t write(const void *, size_t) = 0;
	virtual void flush(){}
	virtual DataSink &operator<<(DataSource &);
};

class StdDataSource : public DataSource{
	std::unique_ptr<std::istream> stream;
public:
	StdDataSource() = default;
	StdDataSource(std::unique_ptr<std::istream> &&stream): stream(std::move(stream)){}
	StdDataSource(const StdDataSource &) = delete;
	StdDataSource &operator=(const StdDataSource &) = delete;
	StdDataSource(StdDataSource &&other){
		*this = std::move(other);
	}
	StdDataSource &operator=(StdDataSource &&other){
		this->stream = std::move(other.stream);
		return *this;
	}
	size_t read(void *vdst, size_t size) override{
		auto dst = (std::uint8_t *)vdst;
		size_t ret = 0;
		while (size){
			this->stream->read((char *)dst, size);
			auto read = this->stream->gcount();
			if (!read)
				break;
			dst += read;
			size -= read;
			ret += read;
		}
		return ret;
	}
};

class StdDataSink : public DataSink{
	std::unique_ptr<std::ostream> stream;
public:
	StdDataSink() = default;
	StdDataSink(std::unique_ptr<std::ostream> &&stream): stream(std::move(stream)){}
	StdDataSink(const StdDataSource &) = delete;
	StdDataSink &operator=(const StdDataSink &) = delete;
	StdDataSink(StdDataSink &&other){
		*this = std::move(other);
	}
	StdDataSink &operator=(StdDataSink &&other){
		this->stream = std::move(other.stream);
		return *this;
	}
	size_t write(const void *dst, size_t size) override{
		this->stream->write((const char *)dst, size);
		return size;
	}
	void flush() override{
		this->stream->flush();
	}
};

}

#include "source_sink.hpp"
#include "ringbuffer.hpp"

namespace utility{

DataSource &DataSource::operator>>(DataSink &sink){
	sink << *this;
	return *this;
}

DataSink &DataSink::operator<<(DataSource &source){
	RingBuffer buffer(128 << 10);
	bool ok = true;
	while (true){
		if (ok && !buffer.read_from_source(source))
			ok = false;
		if (!buffer.get_length())
			break;
		buffer.write_to_sink(*this);
	}
	return *this;
}

}

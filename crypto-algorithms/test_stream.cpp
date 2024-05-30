#include "stream.hpp"
#include "aes.hpp"
#include "twofish.hpp"
#include <cstring>
#include <cassert>
#include <vector>
#include <cstdint>
#include <string>
#include <stdexcept>

namespace{

#define CTR_CIPHER 1
#define assert2(x) stream_assert(x, #x)

void stream_assert(bool condition, const char *string){
    if (condition)
        return;
    throw std::runtime_error((std::string)"Failed test: " + string);
}

const char input[] = "High on the walls appear'd the Lycian powers, "
    "Like some black tempest gathering round the towers: The Greeks, oppress'd,"
    " their utmost force unite, Prepared to labour in the unequal fight: The wa"
    "r renews, mix'd shouts and groans arise; Tumultuous clamour mounts, and th"
    "ickens in the skies. Fierce Ajax first the advancing host invades, And sen"
    "ds the brave Epicles to the shades, Sarpedon's friend. Across the warrior'"
    "s way, Rent from the walls, a rocky fragment lay; In modern ages not the s"
    "trongest swain Could heave the unwieldy burden from the plain: He poised, "
    "and swung it round; then toss'd on high, It flew with force, and labour'd "
    "up the sky; Full on the Lycian's helmet thundering down, The ponderous rui"
    "n crush'd his batter'd crown. As skilful divers from some airy steep Headl"
    "ong descend, and shoot into the deep, So falls Epicles; then in groans exp"
    "ires, And murmuring to the shades the soul retires.";

const char * const key = "2b8babb9e36b96a218f23804eb8cbf05760dee19c513b73184c04f20aa3c8aa8";
const char * const iv = "41974bd48bfc51de8be89dead7a5af57";

template <typename C>
std::vector<std::uint8_t> process_ctr(
		const void *input,
		size_t size,
		const typename C::key_t &key,
		const typename C::block_t &iv,
		bool encrypt){
	
    symmetric::stream::CtrCipherStream<C> stream(C(key), iv, encrypt);
    auto m = stream.write(input, size);
    assert2(CTR_CIPHER && size == m);
    stream.terminate();
	
    std::vector<std::uint8_t> ret(size + 1);
    m = stream.read(ret.data(), ret.size());
    assert(CTR_CIPHER && size == m);
    ret.resize(size);
    return ret;
}

template <typename C>
std::vector<std::uint8_t> process_ctr(
		const std::vector<std::uint8_t> &input,
		const typename C::key_t &key,
		const typename C::block_t &iv,
		bool encrypt){
	
    return process_ctr<C>(input.data(), input.size(), key, iv, encrypt);
}

}

template <typename C>
void basic_test_stream(){
	typename C::key_t key(::key);
	typename C::block_t iv = C::block_from_string(::iv);

    auto n = strlen(input);
    auto ciphertext = process_ctr<C>(input, n, key, iv, true);
    auto decrypted = process_ctr<C>(ciphertext, key, iv, false);

    assert(CTR_CIPHER && decrypted.size() == n && !memcmp(input, decrypted.data(), n));
}

void test_stream(){
    basic_test_stream<symmetric::Aes<256>>();
    basic_test_stream<symmetric::Twofish<256>>();
    std::cout << "CtrCipherStream passed the test!\n";
}

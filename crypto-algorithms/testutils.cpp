#include "testutils.hpp"

namespace testutils{

static const auto seed = RngBlock::key_t("4974446f6e27744d61747465724e6f6e2761546869734d617474657320202020");
static const auto iv = RngBlock::block_from_string("6e6f6e27612074686973206d61747465");

Rng init_rng(){
	return Rng(seed, iv);
}

}

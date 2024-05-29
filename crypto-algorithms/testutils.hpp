#pragma once

#include "rng.hpp"
#include "aes.hpp"

namespace testutils{

typedef symmetric::Aes<256> RngBlock;
typedef csprng::BlockCipherRng<RngBlock> Rng;

Rng init_rng();

}

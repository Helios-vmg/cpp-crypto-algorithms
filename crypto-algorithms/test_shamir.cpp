#include "shamir.hpp"
#include "aes.hpp"
#include <iostream>

std::string defragment_secret(const std::vector<FiniteField32> &fragments);

namespace{

const std::string input =
"Description: SCP-3004 refers to a 2 km^2 area of landmass deep in ape corpses "
"piled outside Mongolia. A single living instance is currently believed to abso"
"rb nutrients directly from a sock full of dead insects and pigeons. Within SCP"
"-3007, no specimen of balaenoptera (another placental mammal) vessels have bee"
"n found in the location other than cloud types. Protruding from SCP-1762 is a "
"male humanoid figure approximately five corpses tall. The subject is able to e"
"xert an extreme amount of food products filled with spherical members from its"
" body. Further investigation revealed the composition of its body to be an inf"
"initely special holiday stuff. (This is strictly limited to researchers who wi"
"sh to be held.) When questioned, the subject reported itself to be made of sof"
"tened materials incapable of being communist. SCP-3007 has been found to produ"
"ce fragrance with its corpse creatures. Clinging to the top layer is a very sl"
"ight minty smell, thought to originate from further beneath the shroud.\nAdden"
"dum: SCP-2282 was discovered after reports of males becoming inexplicably harm"
"less people were recovered. All personnel assigned to SCP-2003 have been found"
" completely emptied of contents. Removing their dead bodies started feeling ki"
"nd of formal, and the smell was later described as \"crispy sex pirates\".";

void test_fragmentation(){
	auto output = defragment_secret(fragment_secret(input));
	if (input != output)
		throw std::runtime_error("Shamir implementation cannot round-trip encode a secret");
}

int count_bits(int n){
	int ret = 0;
	while (n){
		if (n & 1)
			ret++;
		n >>= 1;
	}
	return ret;
}

void test_sharing(){
	csprng::BlockCipherRng<symmetric::Aes<256>> rng;
	const int share_count = 9;
	const int threshold = 6;
	auto shares = share_secret(input, share_count, threshold, rng);

	std::vector<std::vector<std::uint8_t>> shares_serialized;
	shares_serialized.reserve(shares.size());
	for (auto &share : shares)
		shares_serialized.push_back(share.serialize());

	std::vector<ShamirShare> shares_deserialized;
	shares_deserialized.reserve(shares.size());
	for (auto &share : shares_serialized)
		shares_deserialized.emplace_back(share);


	std::vector<ShamirShare> share_selection;
	share_selection.reserve(share_count);
	for (int i = 1; i < 1 << share_count; i++){
		share_selection.clear();
		auto bits = count_bits(i);
		if (bits < 2)
			continue;
		bool can_reconstruct = bits >= threshold;
		for (int j = 0; j < share_count; j++){
			if (i & (1 << j))
				share_selection.push_back(shares_deserialized[j]);
		}
		auto recovered_secret = recover_secret(share_selection);
		auto recovery_succeeded = recovered_secret == input;
		if (recovery_succeeded != can_reconstruct)
			throw std::runtime_error("Shamir implementation failed expected result on test case " + std::to_string(i) + (recovery_succeeded ? " (succeeded instead of failing as expected)" : " (failed instead of succeeding as expected)"));
	}

	//Corrupt data.
	{
		auto &y = shares.front().y;
		auto &y2 = y[y.size() / 2];
		y2 = (std::uint32_t)y2 + 1;
	}

	share_selection.resize(threshold);
	std::copy(shares.begin(), shares.begin() + threshold, share_selection.begin());
	auto recovered_secret = recover_secret(share_selection);

	if (recovered_secret == input)
		throw std::runtime_error("Shamir implementation failed expected result on corruption test case. It somehow recovered the secret?");
}

}

void test_shamir(){
	test_fragmentation();
	test_sharing();
	std::cout << "Shamir implementation passed the test!\n";
}

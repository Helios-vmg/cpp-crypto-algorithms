#include "ed25519.hpp"
#include "hex.hpp"
#include "rng.hpp"
#include "aes.hpp"
#include "testutils.hpp"
#include <iostream>

struct test_case{
	const char *input;
	const char *pk;
	const char *sk;
	const char *signature;
};

static const test_case test_cases[] = {
	{
		"PbUJdvBswbyy7k6_RcJwVfIZ7WCWHrnNiAhwDwDuRr-CNtxtANgIwEBePQmo_AyY81pSjWnt4a7zzkBottnbttT-wOq",
		"519bde6c78ea26348be80eb8b2268a89a29c3e02c536d37ecf40acf9b56d5d30",
		"809742a876f470c17861c537605275f10199a15d07ac0b172c16de03f943d8a8519bde6c78ea26348be80eb8b2268a89a29c3e02c536d37ecf40acf9b56d5d30",
		"1c9c9d64609078c41c7a234c94988666ba90dc71df0154c041deea0fc36cd42f09fc389f5f6a11bb110269adffd4f0571aec9ccc05d5abd62d64a77d320a0308"
	},
	{
		"mnb1c5rrSEfr1RRSrF0t3UREJFqnyVYv8v0zIS3CgssJ4S-AJqttwZ1B0DBVxpSLvYUBh3l-h3fNuhuwOhlk",
		"7da3157fc047a6fa7e21dd91635101d75a28a9fb9c2a8cbddabad9394f881e87",
		"21e0133744af48abd5cabfee00ed4523d85a09ecd62b4c5b8d73b53889d895ae7da3157fc047a6fa7e21dd91635101d75a28a9fb9c2a8cbddabad9394f881e87",
		"e108db1b82817242cfcac850f51f17d7aa9fd150aaf3571b014ebd29ef2b6d0f02af3a5b8c9bffff92b83f3e2c2d89c7832065f82888a2e4edfdbdd6dc08b106"
	},
	{
		"BouSDrl7uhA2WiNnczJStOEwNl51k49qYUqYR_uUgpWDylPuNvsML",
		"770fdd71c7957dd88c29d07794dea7169360956a88a17ba1ac93d9ad9a8a62b9",
		"9693aee9f50671482e743a3473afe38c81aa5e9d4a3927a50e4e59da285dd7ae770fdd71c7957dd88c29d07794dea7169360956a88a17ba1ac93d9ad9a8a62b9",
		"94ac3d542427e561d1c750ed6857af4130152cb7d636262b751b04d4ee19cf937d0a6c61ca2a01c76f2aefe8a1959a4c2a86a1a33435d24f9ca3d9fabf0ea208"
	},
	{
		"0vFIx7Z4orBPrvHECvnuszXyr5vu",
		"64498def8fc04710185cd54625b3a474e8c5f124400a4e4f084e1b2443421404",
		"827c27501203ad4dd812a6ff1d976e1da540e6b098602d93d84e80470758945d64498def8fc04710185cd54625b3a474e8c5f124400a4e4f084e1b2443421404",
		"3e975bd3144af72bf6cc282e202809b27a2b172c660ff4a88be32a02fd38ec82a2ff21c65d2346c5facb54315573ddf3ecdfd43b4f731989d2ae48ec0a02df02"
	},
	{
		"UlsOIuup6rHlK_nx8cPwfl0k75E5ghodMOOT6CEXwd4nOGIwgpJho9VwvWJTwBT",
		"3fae315d5f9a8eecb6c35b70659a1df55a85b6754314a202eaaa8129a571a9a0",
		"0a567cd2eab8b7721fd6538ca52e30555538a32ebff45e8ccbd9c2de844c299a3fae315d5f9a8eecb6c35b70659a1df55a85b6754314a202eaaa8129a571a9a0",
		"848561948ae50922fe6423fc3960ab2c46ec80c44748e9c0c13134ea7bc4d7f82f38a1727ef273df02d74765d3f05e36242aea0deea834cc14b0459310b00e03"
	},
	{
		"9qAXPvFQ8SAUthtmg_BjUxE",
		"d69c9122f3ac6136aacfc61880788848d426bd518cc95273283174b7af74e5aa",
		"a577028e3d9f02a45e465423add09924131d254c10eea1771b39d1c38c1b364fd69c9122f3ac6136aacfc61880788848d426bd518cc95273283174b7af74e5aa",
		"6f401aa9a90ae54e90f820d411a7815452d9b365f92e8f1644edf46d33404adc45002b1525aaa6e8f764563e4cbefe7d3738ff3c705d93b364d6323ac5749401"
	},
	{
		"cQ3jX4Mm4EzappZSIxpfXT5V8lXuka5oBBTT3RazWSSywTcOUmKvW-dTjRYg",
		"6d66b94e94d2d63c37d9c275be667cfa0b442deb65fe5f4152b21bed58ccee8f",
		"64d25585915969074d4c6b6a4aea192e1a77d1e27b4fc73be5fcdfddfe9d2b326d66b94e94d2d63c37d9c275be667cfa0b442deb65fe5f4152b21bed58ccee8f",
		"1c2083ade35a9b903bb0d4d51d3713107f416f9813032b5741a827b52d1e1a0325abb195770d5fc467f833581306549f60bde07bace5d05daa51f1af37c64e06"
	},
	{
		"SiXuUBAwjA2i85cWycLYM0wr4czVCqSURb3jHtsBNh-Rq8WWIJSvXf",
		"a9b452895ab8444f6e101aadadbc9ebee95b14287e690a455fb0a4089426c6d8",
		"07607bbb9ffe840137481d978ecbdc56d54542b9572733d1c45bc90865f50e48a9b452895ab8444f6e101aadadbc9ebee95b14287e690a455fb0a4089426c6d8",
		"ecd36b832110b49fc5ba432bd2022c747fe2e08e8a43f6c753b2ccec8c65dccbbeb69ede47e47af9ef1212bad57c01dbfce1f1d93795fcf1a6b030e18218d30a"
	},
	{
		"WrxFVvndtESWc8aqt0ulh7HZA2WWvgos1PFGTFWic3SMikpVVVvti1Tm9vJRhfDN__W",
		"ec9c45ae08551d3d78a866430d7fe6d3d18667e48fbab9484e97155f37cfdc3d",
		"4a5c4743cf34d95b708c652fa37e7281756475b1856289e7d848440235797363ec9c45ae08551d3d78a866430d7fe6d3d18667e48fbab9484e97155f37cfdc3d",
		"992ed130d8e023053abe41a734762002bf2a7f5d3d0fc8a738b760d8048a9a447dc80739845f95dd4d0f86653248da74b5be365a1dff4e26ea94bf4ba7336b0e"
	},
	{
		"wo0dTnApnrqvIOuWRB20TGRSLLVBGRDwt8z-Z9wr_maYmJzZRlsk-Kwe9-xpIdqC7rSj",
		"890b685784cb5a9dcea36b333dc37c0a7045c6b965bab5200fd1a094b4fe9fef",
		"53fc2cb278e05d3f94089447dbf9369ba94e51a9257cf9ec5d6da82eb183ad08890b685784cb5a9dcea36b333dc37c0a7045c6b965bab5200fd1a094b4fe9fef",
		"01f8f7864bc19361297f64ae8c77780109a788a157983e21ff2b2993baa9f0e710cbbaff7a95044760b035fe121355fd54db321bee21c846afd55fd5aac31e0b"
	},
};

static void main_test(){
	using namespace asymmetric::Ed25519;
	for (auto [input_string, pubk_string, privk_string, sig_string] : test_cases){
		auto public_key_data = utility::hex_string_to_buffer<PublicKey::size>(pubk_string);
		PublicKey public_key(public_key_data);
		PrivateKey private_key(utility::hex_string_to_buffer<PrivateKey::size>(privk_string));
		if (private_key.get_public_key() != public_key)
			throw std::runtime_error("Ed25519 failed public key reconstruction");
		auto signature = private_key.sign(input_string, strlen(input_string));
		auto expected_signature = utility::hex_string_to_buffer<Signature::size>(sig_string);
		auto signature_array = signature.get_data();
		if (!!memcmp(signature_array.data(), expected_signature.data(), Signature::size))
			throw std::runtime_error("Ed25519 failed signing");

		std::string temp = input_string;
		if (!signature.verify(temp.data(), temp.size(), public_key))
			throw std::runtime_error("Ed25519 failed signature verification (1)");

		temp[0] ^= 1 << 5;
		if (signature.verify(temp.data(), temp.size(), public_key))
			throw std::runtime_error("Ed25519 failed signature verification (2)");

		temp[0] ^= 1 << 5;
		public_key_data[0] ^= 1 << 5;
		public_key = public_key_data;

		if (signature.verify(temp.data(), temp.size(), public_key))
			throw std::runtime_error("Ed25519 failed signature verification (3)");

		temp[0] ^= 1 << 5;
		if (signature.verify(temp.data(), temp.size(), public_key))
			throw std::runtime_error("Ed25519 failed signature verification (3)");
	}
}

static const size_t data_size = 4096;

using namespace asymmetric::Ed25519;

static std::pair<Signature, PublicKey> get_data(){
	auto rng = testutils::init_rng();
	auto data = rng.get_bytes(data_size);
	auto private_key = PrivateKey::generate(rng);
	auto signature = private_key.sign(data.data(), data.size());
	auto public_key = private_key.get_public_key();

	if (!signature.verify(data.data(), data.size(), public_key))
		throw std::runtime_error("assumption violated");

	return { signature, public_key };
}

static void test_progressive(){
	auto [signature, public_key] = get_data();
	const size_t buffer_size = 32;
	std::uint8_t buffer[buffer_size];
	static_assert(data_size % buffer_size == 0);

	ProgressiveVerifier verifier(signature, public_key);
	{
		auto rng = testutils::init_rng();
		for (size_t i = 0; i < data_size; i += buffer_size){
			rng.get_bytes(buffer);
			verifier.update(buffer, buffer_size);
		}
		if (!verifier.finish())
			throw std::runtime_error("Ed25519 (progressive) failed signature verification (1)");
	}
	{
		auto rng = testutils::init_rng();
		for (size_t i = 0; i < data_size; i += buffer_size){
			rng.get_bytes(buffer);
			static_assert(data_size / buffer_size > 4);
			if (i / buffer_size == 4){
				static_assert(buffer_size > 10);
				buffer[10] ^= 1 << 5;
			}
			verifier.update(buffer, buffer_size);
		}
		if (verifier.finish())
			throw std::runtime_error("Ed25519 (progressive) failed signature verification (2)");
	}
}

void test_ed25519(){
	main_test();
	test_progressive();
	std::cout << "Ed25519 implementation passed the test!\n";
}

#define __STDC_FORMAT_MACROS

#include "../chacha8c.hpp"

#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace c8 = chacha8c;

namespace {

void print_hex_line(const std::uint8_t *p, std::size_t n)
{
	static const char hex[] = "0123456789abcdef";

	for (std::size_t i = 0; i < n; i++) {
		std::putchar(hex[p[i] >> 4]);
		std::putchar(hex[p[i] & 0x0f]);
	}
	std::putchar('\n');
}

} // namespace

int main()
{
	std::uint8_t seed[c8::key_size];
	std::uint64_t uints[3 * ((1024 - 32) / 8)];
	std::size_t uints_len = 0;

	std::memcpy(seed, "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456", c8::key_size);
	c8::ChaCha8 rng = c8::NewChaCha8(seed);

	for (int pass = 0; pass < 3; pass++) {
		std::uint8_t output[1024 - c8::key_size];
		std::size_t output_len = sizeof(output);

		rng.Read(output, output_len);
		for (std::size_t i = 0; i < output_len; i += 8) {
			uints[uints_len++] = c8::load64_le(output + i);
		}

		for (std::size_t i = 0; i < output_len; i += 32) {
			print_hex_line(output + i, 32);
		}
	}

	for (std::size_t i = 0; i < uints_len; i++) {
		if (i % 4 == 0) {
			std::printf("\n");
		}
		std::printf("0x%016" PRIx64 ", ", uints[i]);
	}

	for (int i = 0; i < 100; i++) {
		std::printf("UnbiasedChoice(%d) -> %" PRId64 "\n",
		            i,
		            rng.UnbiasedChoice(static_cast<std::int64_t>(i)));
	}

	return 0;
}

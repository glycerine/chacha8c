#define __STDC_FORMAT_MACROS

#include "../chacha8.hpp"

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
	std::uint8_t input[c8::key_size];
	std::uint64_t uints[3 * ((1024 - 32) / 8)];
	std::size_t uints_len = 0;

	std::memcpy(input, "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456", c8::key_size);

	for (int pass = 0; pass < 3; pass++) {
		std::uint8_t stream[1024];
		std::uint8_t output[1024];
		std::uint8_t *streamp = stream;
		std::size_t output_len = 0;

		c8::chacha8(input, stream, sizeof(stream));

		for (std::uint32_t block = 0; block < 16; block++) {
			std::uint8_t *b = stream + block * c8::block_size;

			c8::store32_le(b + 0 * 4, c8::load32_le(b + 0 * 4) - c8::j0);
			c8::store32_le(b + 1 * 4, c8::load32_le(b + 1 * 4) - c8::j1);
			c8::store32_le(b + 2 * 4, c8::load32_le(b + 2 * 4) - c8::j2);
			c8::store32_le(b + 3 * 4, c8::load32_le(b + 3 * 4) - c8::j3);
			c8::store32_le(b + 12 * 4, c8::load32_le(b + 12 * 4) - block);
		}

		for (std::size_t i = 0; i < 16; i += 4) {
			for (std::size_t word = 0; word < c8::block_size; word += 4) {
				std::memcpy(output + output_len, streamp + 0 * c8::block_size + word, 4);
				output_len += 4;
				std::memcpy(output + output_len, streamp + 1 * c8::block_size + word, 4);
				output_len += 4;
				std::memcpy(output + output_len, streamp + 2 * c8::block_size + word, 4);
				output_len += 4;
				std::memcpy(output + output_len, streamp + 3 * c8::block_size + word, 4);
				output_len += 4;
			}
			streamp += 4 * c8::block_size;
		}

		std::memcpy(input, output + 1024 - c8::key_size, c8::key_size);
		output_len = 1024 - c8::key_size;

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

	return 0;
}

#define __STDC_FORMAT_MACROS

#include "../chacha8.hpp"

#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {

const std::uint32_t j0 = 0x61707865u;
const std::uint32_t j1 = 0x3320646eu;
const std::uint32_t j2 = 0x79622d32u;
const std::uint32_t j3 = 0x6b206574u;

std::uint32_t load32_le(const std::uint8_t *p)
{
	return static_cast<std::uint32_t>(p[0]) |
	       (static_cast<std::uint32_t>(p[1]) << 8) |
	       (static_cast<std::uint32_t>(p[2]) << 16) |
	       (static_cast<std::uint32_t>(p[3]) << 24);
}

std::uint64_t load64_le(const std::uint8_t *p)
{
	return static_cast<std::uint64_t>(load32_le(p)) |
	       (static_cast<std::uint64_t>(load32_le(p + 4)) << 32);
}

void store32_le(std::uint8_t *p, std::uint32_t x)
{
	p[0] = static_cast<std::uint8_t>(x);
	p[1] = static_cast<std::uint8_t>(x >> 8);
	p[2] = static_cast<std::uint8_t>(x >> 16);
	p[3] = static_cast<std::uint8_t>(x >> 24);
}

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
	std::uint8_t input[chacha8c::key_size];
	std::uint64_t uints[3 * ((1024 - 32) / 8)];
	std::size_t uints_len = 0;

	std::memcpy(input, "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456", chacha8c::key_size);

	for (int pass = 0; pass < 3; pass++) {
		std::uint8_t stream[1024];
		std::uint8_t output[1024];
		std::uint8_t *streamp = stream;
		std::size_t output_len = 0;

		chacha8c::chacha8(input, stream, sizeof(stream));

		for (std::uint32_t block = 0; block < 16; block++) {
			std::uint8_t *b = stream + block * chacha8c::block_size;

			store32_le(b + 0 * 4, load32_le(b + 0 * 4) - j0);
			store32_le(b + 1 * 4, load32_le(b + 1 * 4) - j1);
			store32_le(b + 2 * 4, load32_le(b + 2 * 4) - j2);
			store32_le(b + 3 * 4, load32_le(b + 3 * 4) - j3);
			store32_le(b + 12 * 4, load32_le(b + 12 * 4) - block);
		}

		for (std::size_t i = 0; i < 16; i += 4) {
			for (std::size_t word = 0; word < chacha8c::block_size; word += 4) {
				std::memcpy(output + output_len, streamp + 0 * chacha8c::block_size + word, 4);
				output_len += 4;
				std::memcpy(output + output_len, streamp + 1 * chacha8c::block_size + word, 4);
				output_len += 4;
				std::memcpy(output + output_len, streamp + 2 * chacha8c::block_size + word, 4);
				output_len += 4;
				std::memcpy(output + output_len, streamp + 3 * chacha8c::block_size + word, 4);
				output_len += 4;
			}
			streamp += 4 * chacha8c::block_size;
		}

		std::memcpy(input, output + 1024 - chacha8c::key_size, chacha8c::key_size);
		output_len = 1024 - chacha8c::key_size;

		for (std::size_t i = 0; i < output_len; i += 8) {
			uints[uints_len++] = load64_le(output + i);
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

#ifndef TYPE_H
#define TYPE_F

#include <cstddef>
#include <cstdint>
#include <span>

using i8 = char;
using i16 = short;
using i32 = int;
using i64 = long;

using u8 = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;

using Size = std::size_t;

using Byte = u8;

using BytesView = std::span<Byte>;

#endif

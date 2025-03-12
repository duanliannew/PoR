#pragma once
#include <assert.h>

#include <cstddef>
#include <cstdint>
#include <type_traits>

template <typename T>
T RightRotate(T v, size_t i) {
  if constexpr (std::is_integral_v<T> && std::is_unsigned_v<T>) {
    constexpr size_t s = sizeof(v) << 3;
    i = i % s;
    return (v >> i) | (v << (s - i));
  } else {
    // FIXME: for some older compiler static_assert doesn't work right. So I
    // commented out below line. static_assert(false);
    return {};
  }
}
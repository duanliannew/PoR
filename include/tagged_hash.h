#pragma once
#include <cstdint>
#include <vector>

#include "sha256.h"

namespace crypto {
class TaggedHasher {
 public:
  explicit TaggedHasher(const std::vector<uint8_t>& tag);
  size_t Append(const std::vector<uint8_t>& data_chunk);
  std::vector<uint8_t> Hash();
  void Reset();

 private:
  void doReset();
  std::vector<uint8_t> tag_;
  sha256::StreamHasher hasher_;
};
}  // namespace crypto
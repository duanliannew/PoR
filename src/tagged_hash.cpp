#include "tagged_hash.h"

namespace crypto {
TaggedHasher::TaggedHasher(const std::vector<uint8_t>& tag) {
  sha256::BlockHasher block_hasher;
  auto tag_hash = block_hasher.Hash(tag);

  hasher_.Append(tag_hash);
  hasher_.Append(tag_hash);
}

size_t TaggedHasher::Append(const std::vector<uint8_t>& data_chunk) {
  auto size = hasher_.Append(data_chunk);
  // 64 is the twiced "tag hash"
  return size - 64;
}

std::vector<uint8_t> TaggedHasher::Hash() { return hasher_.Hash(); }
}  // namespace crypto
#include "tagged_hash.h"

namespace crypto {
TaggedHasher::TaggedHasher(const std::vector<uint8_t>& tag) : tag_(tag) {
  doReset();
}

size_t TaggedHasher::Append(const std::vector<uint8_t>& data_chunk) {
  auto size = hasher_.Append(data_chunk);
  // 64 is the twiced "tag hash"
  return size - 64;
}

std::vector<uint8_t> TaggedHasher::Hash() { return hasher_.Hash(); }

void TaggedHasher::Reset() { doReset(); }

void TaggedHasher::doReset() {
  hasher_.Reset();

  sha256::BlockHasher block_hasher;
  auto tag_hash = block_hasher.Hash(tag_);

  hasher_.Append(tag_hash);
  hasher_.Append(tag_hash);
}
}  // namespace crypto
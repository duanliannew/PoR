#include "merkle_root.h"

#include "tagged_hash.h"

namespace crypto {
std::vector<uint8_t> MerkleRoot(const std::vector<uint8_t>& leaf_tag,
                                const std::vector<uint8_t>& branch_tag,
                                const std::vector<std::vector<uint8_t>>& data) {
  if (data.empty()) {
    return {};
  }

  std::vector<std::vector<uint8_t>> merkle_hash(data.size(),
                                                std::vector<uint8_t>{});
  size_t i = 0;
  for (const auto& raw_data : data) {
    TaggedHasher hasher(leaf_tag);
    hasher.Append(raw_data);
    merkle_hash[i] = hasher.Hash();
    ++i;
  }

  size_t size = merkle_hash.size();
  while (size != 1) {
    // if the size is odd, duplicate the right-most one
    if (size & 0x01) {
      merkle_hash.push_back(merkle_hash.back());
      ++size;
    }

    for (size_t i = 0; i < (size >> 1); ++i) {
      TaggedHasher hasher(branch_tag);
      hasher.Append(merkle_hash[2 * i]);
      hasher.Append(merkle_hash[2 * i + 1]);
      merkle_hash[i] = hasher.Hash();
    }

    size >>= 1;
    merkle_hash.resize(size);
  }

  return merkle_hash[0];
}
}  // namespace crypto
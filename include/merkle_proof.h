#pragma once
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace crypto {
class MerkleProof {
 public:
  MerkleProof();
  void AddSibling(const std::vector<uint8_t>& hash, bool left);
  std::string GenerateProof(const std::vector<uint8_t>& tag,
                            const std::vector<uint8_t>& root);

 private:
  std::string serializeHash(const std::vector<uint8_t>& hash) const;
  std::vector<std::pair<bool, std::vector<uint8_t>>> raw_data_;
};
}  // namespace crypto
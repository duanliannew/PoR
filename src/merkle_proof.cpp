#include "merkle_proof.h"

#include <iomanip>
#include <sstream>

#include "tagged_hash.h"

namespace crypto {
MerkleProof::MerkleProof() {}

void MerkleProof::AddSibling(const std::vector<uint8_t>& hash, bool left) {
  raw_data_.push_back(std::make_pair(left, hash));
}

std::string MerkleProof::GenerateProof(const std::vector<uint8_t>& tag,
                                       const std::vector<uint8_t>& root) {
  if (raw_data_.empty()) {
    return "";
  }

  // verify if the root matches and construct proof path
  // add the leaf that is to be verified
  std::string proof = "(" + serializeHash(raw_data_[0].second);
  std::vector<uint8_t> calculated_root = raw_data_[0].second;

  // add sibling node of each layer up to merkle root
  TaggedHasher hasher(tag);
  for (size_t i = 1; i < raw_data_.size(); ++i) {
    hasher.Reset();
    proof += " (";
    if (raw_data_[i].first) {
      hasher.Append(raw_data_[i].second);
      hasher.Append(calculated_root);
      proof += "left,";
    } else {
      hasher.Append(calculated_root);
      hasher.Append(raw_data_[i].second);
      proof += "right,";
    }
    proof += serializeHash(raw_data_[i].second);
    proof += ")";

    calculated_root = hasher.Hash();
  }

  // add merkle root
  proof += " " + serializeHash(calculated_root);
  proof += ")";
  if (calculated_root != root) {
    return "";
  }

  return proof;
}

std::string MerkleProof::serializeHash(const std::vector<uint8_t>& hash) const {
  if (hash.empty()) {
    return "";
  }

  std::string proof = "0x";
  std::stringstream ss;
  ss << std::hex << std::setfill('0');
  for (auto b : hash) {
    ss << std::setw(2) << static_cast<unsigned>(b);
  }

  proof += ss.str();
  return proof;
}
}  // namespace crypto
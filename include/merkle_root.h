#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace crypto {
std::vector<uint8_t> MerkleRoot(const std::vector<uint8_t>& leaf_tag,
                                const std::vector<uint8_t>& branch_tag,
                                const std::vector<std::vector<uint8_t>>& data);
}
#include "tagged_hash.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <vector>

#include "sha256.h"

TEST(sha256, tagged_hash) {
  std::string tag = "ProofOfReserve_Leaf";
  crypto::sha256::BlockHasher block_hasher;
  std::vector<uint8_t> tag_vec(tag.cbegin(), tag.cend());
  std::vector<uint8_t> tag_hash = {
      0xc2, 0x74, 0x23, 0x72, 0xf9, 0x3f, 0xde, 0xc9, 0x69, 0x44, 0xc6,
      0xb0, 0xb7, 0x69, 0x48, 0x68, 0x0a, 0x9f, 0xf8, 0xfe, 0x19, 0xac,
      0xec, 0x27, 0xfc, 0x68, 0x60, 0xf0, 0xf0, 0x55, 0xfa, 0xc2};
  EXPECT_EQ(block_hasher.Hash(tag_vec), tag_hash);
  std::vector<uint8_t> data = {0x10, 0xdd, 0xcd, 0xdd, 0x31};

  std::vector<uint8_t> concatenated_data;
  std::copy(tag_hash.cbegin(), tag_hash.cend(),
            std::back_inserter(concatenated_data));
  std::copy(tag_hash.cbegin(), tag_hash.cend(),
            std::back_inserter(concatenated_data));
  std::copy(data.cbegin(), data.cend(), std::back_inserter(concatenated_data));

  crypto::TaggedHasher tagged_hasher(tag_vec);
  tagged_hasher.Append(data);
  EXPECT_EQ(tagged_hasher.Hash(), block_hasher.Hash(concatenated_data));
}
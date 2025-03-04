#include "merkle_root.h"

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "tagged_hash.h"

TEST(sha256, merkle_root) {
  std::string tag = "Bitcoin_Transaction";
  std::vector<std::string> data = {"aaa", "bbb", "ccc", "ddd", "eee"};

  std::vector<uint8_t> tag_vec(tag.cbegin(), tag.cend());
  std::vector<std::vector<uint8_t>> data_vec;
  std::vector<std::vector<uint8_t>> leaf_hash;
  for (const auto& s : data) {
    std::vector<uint8_t> s_vec(s.cbegin(), s.cend());
    data_vec.push_back(s_vec);

    crypto::TaggedHasher hasher(tag_vec);
    hasher.Append(s_vec);
    leaf_hash.push_back(hasher.Hash());
  }

  // calculate level 1
  // because there are 5 leaf, which is odd, we need duplicate the last one to
  // make it even
  leaf_hash.push_back(leaf_hash.back());
  crypto::TaggedHasher hasher_l1_0(tag_vec);
  hasher_l1_0.Append(leaf_hash[0]);
  hasher_l1_0.Append(leaf_hash[1]);
  leaf_hash[0] = hasher_l1_0.Hash();

  crypto::TaggedHasher hasher_l1_1(tag_vec);
  hasher_l1_1.Append(leaf_hash[2]);
  hasher_l1_1.Append(leaf_hash[3]);
  leaf_hash[1] = hasher_l1_1.Hash();

  crypto::TaggedHasher hasher_l1_2(tag_vec);
  hasher_l1_2.Append(leaf_hash[4]);
  hasher_l1_2.Append(leaf_hash[5]);
  leaf_hash[2] = hasher_l1_2.Hash();

  leaf_hash.resize(3);

  // calculate level 2
  leaf_hash.push_back(leaf_hash.back());
  crypto::TaggedHasher hasher_l2_0(tag_vec);
  hasher_l2_0.Append(leaf_hash[0]);
  hasher_l2_0.Append(leaf_hash[1]);
  leaf_hash[0] = hasher_l2_0.Hash();

  crypto::TaggedHasher hasher_l2_1(tag_vec);
  hasher_l2_1.Append(leaf_hash[2]);
  hasher_l2_1.Append(leaf_hash[3]);
  leaf_hash[1] = hasher_l2_1.Hash();

  leaf_hash.resize(2);

  // calculate level 3, here we can get the root
  crypto::TaggedHasher hasher_l3_0(tag_vec);
  hasher_l3_0.Append(leaf_hash[0]);
  hasher_l3_0.Append(leaf_hash[1]);
  leaf_hash[0] = hasher_l3_0.Hash();

  EXPECT_EQ(crypto::MerkleRoot(tag_vec, tag_vec, data_vec), leaf_hash[0]);
}

TEST(sha256, merkle_root_empty) {
  std::vector<uint8_t> tag = {0x10, 0xad, 0xd3};
  std::vector<std::vector<uint8_t>> data = {};
  EXPECT_EQ(crypto::MerkleRoot(tag, tag, data), std::vector<uint8_t>{});
}

TEST(sha256, merkle_root_one) {
  // case 0: the only one data is empty
  std::vector<uint8_t> tag = {0x10, 0xad, 0xd3};
  std::vector<std::vector<uint8_t>> data = {{}};
  crypto::TaggedHasher hasher(tag);
  hasher.Append(data[0]);
  EXPECT_EQ(crypto::MerkleRoot(tag, tag, data), hasher.Hash());

  // case 1: the only one data is non-empty
  data = {{0x0d, 0x3a, 0x3d, 0xff}};
  crypto::TaggedHasher hasher1(tag);
  hasher1.Append(data[0]);
  EXPECT_EQ(crypto::MerkleRoot(tag, tag, data), hasher1.Hash());

  // case 3: with only one data, branch tag takes no effect
  std::vector<uint8_t> tag1 = {0x80, 0x2b, 0xac};
  crypto::TaggedHasher hasher2(tag);
  hasher2.Append(data[0]);
  EXPECT_EQ(crypto::MerkleRoot(tag, tag1, data), hasher2.Hash());
}
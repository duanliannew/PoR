#include "por_db.h"

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <thread>

#include "tagged_hash.h"

TEST(PoRDB, preprocess) {
  std::string user_data_file = "../test/data/user_data/five_users.txt";
  std::string index_file = user_data_file + ".index";
  std::string merkle_file = user_data_file + ".merkle";
  std::filesystem::remove(index_file);
  std::filesystem::remove(merkle_file);

  crypto::PoRDB db;
  db.preprocessUserFile(user_data_file, index_file, merkle_file);
  EXPECT_TRUE(db.verifyFileFingerPrint(index_file, crypto::PoRDB::kIndexMagic));
  EXPECT_TRUE(
      db.verifyFileFingerPrint(merkle_file, crypto::PoRDB::kMerkleMagic));

  std::filesystem::remove(index_file);
  std::filesystem::remove(merkle_file);
}

TEST(PoRDB, retrieve_user_info) {
  auto start = std::chrono::steady_clock::now();
  std::string user_data_file = "../test/data/user_data/eight_users.txt";
  std::string index_file = user_data_file + ".index";
  std::string merkle_file = user_data_file + ".merkle";

  // make sure index and merkle is re-generated
  std::filesystem::remove(index_file);
  std::filesystem::remove(merkle_file);
  crypto::PoRDB db;
  db.Load(user_data_file);
  auto end = std::chrono::steady_clock::now();
  std::cout << "Load file cost: "
            << std::chrono::duration<double, std::micro>(end - start).count()
            << "us" << std::endl;

  std::map<uint64_t, std::string> user_data{
      /*{35, "(35,111111111111)"}, {238330, "(238330,111111111111)"},
      {995350, "(995350,111111111111)"}, {0, ""}*/
      {1, "(1,1111)"}, {2, "(2,2222)"}, {3, "(3,3333)"}, {4, "(4,4444)"},
      {5, "(5,5555)"}, {6, "(6,6666)"}, {7, "(7,7777)"}, {8, "(8,8888)"},
      {0, ""},         {9, ""}};

  start = std::chrono::steady_clock::now();
  std::string unused;
  for (const auto& [id, content] : user_data) {
    EXPECT_EQ(db.UserInfo(id, unused), content);
  }
  end = std::chrono::steady_clock::now();

  std::cout << user_data.size() << " queries cost: "
            << std::chrono::duration<double, std::micro>(end - start).count()
            << "us" << std::endl;

  std::filesystem::remove(index_file);
  std::filesystem::remove(merkle_file);
}

TEST(PoRDB, merkle_proot_no_user) {
  std::string user_data_file = "../test/data/user_data/empty_user.txt";
  std::string index_file = user_data_file + ".index";
  std::string merkle_file = user_data_file + ".merkle";

  // make sure index and merkle is re-generated
  std::filesystem::remove(index_file);
  std::filesystem::remove(merkle_file);

  crypto::PoRDB db;
  db.Load(user_data_file);
  EXPECT_TRUE(db.verifyFileFingerPrint(index_file, crypto::PoRDB::kIndexMagic));
  EXPECT_TRUE(
      db.verifyFileFingerPrint(merkle_file, crypto::PoRDB::kMerkleMagic));
  // 32 byte hash + 8 byte magic + 8 byte count
  EXPECT_EQ(std::filesystem::file_size(merkle_file), 48);

  std::vector<std::pair<bool, std::vector<uint8_t>>> path;
  auto root = db.generateProof(0, path);
  EXPECT_TRUE(root.empty());

  std::filesystem::remove(index_file);
  std::filesystem::remove(merkle_file);
}

TEST(PoRDB, merkle_proot_one_user) {
  std::string user_data_file = "../test/data/user_data/one_user.txt";
  std::string index_file = user_data_file + ".index";
  std::string merkle_file = user_data_file + ".merkle";

  // make sure index and merkle is re-generated
  std::filesystem::remove(index_file);
  std::filesystem::remove(merkle_file);

  crypto::PoRDB db;
  db.Load(user_data_file);
  EXPECT_TRUE(db.verifyFileFingerPrint(index_file, crypto::PoRDB::kIndexMagic));
  EXPECT_TRUE(
      db.verifyFileFingerPrint(merkle_file, crypto::PoRDB::kMerkleMagic));
  // 32 byte hash + 8 byte magic + 8 byte count + 32 byte hash
  EXPECT_EQ(std::filesystem::file_size(merkle_file), 80);

  std::string user_detail = "(1,1111)";
  std::map<uint64_t, std::string> user_data{{1, user_detail}};

  std::string unused;
  for (const auto& [id, content] : user_data) {
    EXPECT_EQ(db.UserInfo(id, unused), content);
  }

  std::vector<std::pair<bool, std::vector<uint8_t>>> path;
  auto root = db.generateProof(0, path);
  EXPECT_TRUE(path.size() == 1 && root == path[0].second);

  crypto::TaggedHasher hasher(crypto::PoRDB::kLeafTag);
  std::vector<uint8_t> data_vec(user_detail.cbegin(), user_detail.cend());
  hasher.Append(data_vec);
  EXPECT_EQ(root, hasher.Hash());

  root = db.generateProof(1, path);
  EXPECT_TRUE(root.empty());

  std::filesystem::remove(index_file);
  std::filesystem::remove(merkle_file);
}

TEST(PoRDB, merkle_proot_two_user) {
  std::string user_data_file = "../test/data/user_data/two_users.txt";
  std::string index_file = user_data_file + ".index";
  std::string merkle_file = user_data_file + ".merkle";

  // make sure index and merkle is re-generated
  std::filesystem::remove(index_file);
  std::filesystem::remove(merkle_file);

  crypto::PoRDB db;
  db.Load(user_data_file);
  EXPECT_TRUE(db.verifyFileFingerPrint(index_file, crypto::PoRDB::kIndexMagic));
  EXPECT_TRUE(
      db.verifyFileFingerPrint(merkle_file, crypto::PoRDB::kMerkleMagic));
  // 32 byte hash + 8 byte magic + 8 byte count + 3*32 byte hash
  EXPECT_EQ(std::filesystem::file_size(merkle_file), 144);

  std::string user1_detail = "(1,1111)";
  std::string user2_detail = "(2,2222)";

  std::map<uint64_t, std::string> user_data{{1, user1_detail},
                                            {2, user2_detail}};
  std::string unused;
  for (const auto& [id, content] : user_data) {
    EXPECT_EQ(db.UserInfo(id, unused), content);
  }

  // calculate merkle tree by hand
  crypto::TaggedHasher hasher(crypto::PoRDB::kLeafTag);
  std::vector<uint8_t> data1_vec(user1_detail.cbegin(), user1_detail.cend());
  hasher.Append(data1_vec);
  auto leaf1 = hasher.Hash();

  hasher.Reset();
  std::vector<uint8_t> data2_vec(user2_detail.cbegin(), user2_detail.cend());
  hasher.Append(data2_vec);
  auto leaf2 = hasher.Hash();

  crypto::TaggedHasher branch_hasher(crypto::PoRDB::kBranchTag);
  std::vector<uint8_t> root_data_vec(leaf1.cbegin(), leaf1.cend());
  root_data_vec.insert(root_data_vec.end(), leaf2.cbegin(), leaf2.cend());
  branch_hasher.Append(root_data_vec);
  auto root = branch_hasher.Hash();

  // check merkle proof against hand-crafted merkle tree
  std::vector<std::pair<bool, std::vector<uint8_t>>> path;
  EXPECT_EQ(db.generateProof(0, path), root);
  EXPECT_EQ(path.size(), 2);
  EXPECT_EQ(path[0].second, leaf1);
  EXPECT_TRUE(path[0].first);
  EXPECT_EQ(path[1].second, leaf2);
  EXPECT_FALSE(path[1].first);

  EXPECT_EQ(db.generateProof(1, path), root);
  EXPECT_EQ(path.size(), 2);
  EXPECT_EQ(path[0].second, leaf2);
  EXPECT_FALSE(path[0].first);
  EXPECT_EQ(path[1].second, leaf1);
  EXPECT_TRUE(path[1].first);

  EXPECT_EQ(db.generateProof(2, path), std::vector<uint8_t>{});

  std::filesystem::remove(index_file);
  std::filesystem::remove(merkle_file);
}

TEST(PoRDB, merkle_proot_three_user) {
  std::string user_data_file = "../test/data/user_data/three_users.txt";
  std::string index_file = user_data_file + ".index";
  std::string merkle_file = user_data_file + ".merkle";

  // make sure index and merkle is re-generated
  std::filesystem::remove(index_file);
  std::filesystem::remove(merkle_file);

  crypto::PoRDB db;
  db.Load(user_data_file);
  EXPECT_TRUE(db.verifyFileFingerPrint(index_file, crypto::PoRDB::kIndexMagic));
  EXPECT_TRUE(
      db.verifyFileFingerPrint(merkle_file, crypto::PoRDB::kMerkleMagic));
  // 32 byte hash + 8 byte magic + 8 byte count + 7*32 byte hash
  EXPECT_EQ(std::filesystem::file_size(merkle_file), 272);

  std::string user1_detail = "(1,1111)";
  std::string user2_detail = "(2,2222)";
  std::string user3_detail = "(3,3333)";

  std::map<uint64_t, std::string> user_data{
      {1, user1_detail}, {2, user2_detail}, {3, user3_detail}};
  std::string unused;
  for (const auto& [id, content] : user_data) {
    EXPECT_EQ(db.UserInfo(id, unused), content);
  }

  // calculate merkle tree by hand
  crypto::TaggedHasher hasher(crypto::PoRDB::kLeafTag);
  std::vector<uint8_t> data1_vec(user1_detail.cbegin(), user1_detail.cend());
  hasher.Append(data1_vec);
  auto leaf1 = hasher.Hash();

  hasher.Reset();
  std::vector<uint8_t> data2_vec(user2_detail.cbegin(), user2_detail.cend());
  hasher.Append(data2_vec);
  auto leaf2 = hasher.Hash();

  hasher.Reset();
  std::vector<uint8_t> data3_vec(user3_detail.cbegin(), user3_detail.cend());
  hasher.Append(data3_vec);
  auto leaf3 = hasher.Hash();

  // calculate upper level hash
  crypto::TaggedHasher branch_hasher(crypto::PoRDB::kBranchTag);
  branch_hasher.Append(leaf1);
  branch_hasher.Append(leaf2);
  auto parent_hash1 = branch_hasher.Hash();

  branch_hasher.Reset();
  branch_hasher.Append(leaf3);
  branch_hasher.Append(leaf3);
  auto parent_hash2 = branch_hasher.Hash();

  // calculate root
  branch_hasher.Reset();
  branch_hasher.Append(parent_hash1);
  branch_hasher.Append(parent_hash2);
  auto root = branch_hasher.Hash();

  // check merkle proof against hand-crafted merkle tree
  std::vector<std::pair<bool, std::vector<uint8_t>>> path;
  EXPECT_EQ(db.generateProof(0, path), root);
  EXPECT_EQ(path.size(), 3);
  EXPECT_EQ(path[0].second, leaf1);
  EXPECT_TRUE(path[0].first);
  EXPECT_EQ(path[1].second, leaf2);
  EXPECT_FALSE(path[1].first);
  EXPECT_EQ(path[2].second, parent_hash2);
  EXPECT_FALSE(path[2].first);

  EXPECT_EQ(db.generateProof(1, path), root);
  EXPECT_EQ(path.size(), 3);
  EXPECT_EQ(path[0].second, leaf2);
  EXPECT_FALSE(path[0].first);
  EXPECT_EQ(path[1].second, leaf1);
  EXPECT_TRUE(path[1].first);
  EXPECT_EQ(path[2].second, parent_hash2);
  EXPECT_FALSE(path[2].first);

  EXPECT_EQ(db.generateProof(2, path), root);
  EXPECT_EQ(path.size(), 3);
  EXPECT_EQ(path[0].second, leaf3);
  EXPECT_TRUE(path[0].first);
  EXPECT_EQ(path[1].second, path[0].second);
  EXPECT_FALSE(path[1].first);
  EXPECT_EQ(path[2].second, parent_hash1);
  EXPECT_TRUE(path[2].first);

  auto user3 = db.UserInfo(3, unused);
  // std::cout << user3 << std::endl;
  // std::cout << unused << std::endl;

  EXPECT_EQ(db.generateProof(3, path), std::vector<uint8_t>{});

  std::filesystem::remove(index_file);
  std::filesystem::remove(merkle_file);
}
/*
TEST(PoRDB, parallel_preprocess) {
  std::vector<std::string> users = {
    "../app/big_user_1.txt",
    "../app/big_user_2.txt",
    "../app/big_user_3.txt",
    "../app/big_user_4.txt",
    "../app/big_user_5.txt",
    "../app/big_user_6.txt",
    "../app/big_user_7.txt",
    "../app/big_user_8.txt"
  };

  auto start = std::chrono::steady_clock::now();

  std::vector<std::thread> threads;

  for (const auto& user : users) {
    auto t = std::thread([user]() {
      std::string index_file = user + ".index";
      std::string merkle_file = user + ".merkle";
      std::filesystem::remove(index_file);
      std::filesystem::remove(merkle_file);

      crypto::PoRDB db;
      db.preprocessUserFile(user, index_file, merkle_file);
      EXPECT_TRUE(db.verifyFileFingerPrint(index_file, crypto::PoRDB::kIndexMagic));
      EXPECT_TRUE(
          db.verifyFileFingerPrint(merkle_file, crypto::PoRDB::kMerkleMagic));

      std::filesystem::remove(index_file);
      std::filesystem::remove(merkle_file);

      std::cout << "processing " + user + " finished" << std::endl;
    });

    threads.push_back(std::move(t));
  }

  for (auto& t : threads) {
    t.join();
  }

  auto end = std::chrono::steady_clock::now();

  std::cout << "parallel preprocessing cost: "
            << std::chrono::duration<double, std::micro>(end - start).count()
            << "us" << std::endl;
}*/
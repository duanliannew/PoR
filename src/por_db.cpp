#include "por_db.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include "merkle_proof.h"
#include "sha256.h"
#include "tagged_hash.h"

namespace crypto {
PoRDB& PoRDB::Instance() {
  static PoRDB db;
  return db;
}

PoRDB::~PoRDB() {
  unmmapFile(index_map);
  unmmapFile(merkle_map);
}

// Preprocess user data file to create index and merkle tree for user data
// Here I tested the performance, given 100000000 user sample data, which is
// around 2GB in size. On my computer(2.8GHz CPU * 8, 16GB RAM), it takes around
// 15 minutes to preprocess the file, and each query would take
// approximately 1.8 milliseconds.
// TODO: boost performance of load and query.
bool PoRDB::Load(const std::string& user_data_file) {
  // ASSUMPTION: orginal user data file: first line total number, following
  // lines are user info, one line for each user.

  // index file format:
  //   sha256    magic      user No#         data offset
  // | 256 bit | 64 bit |    64 bit     | 64 bit id + 64 bit offset | .. |
  // (1,1111) (2,2222)....

  // merkle file format
  //   sha256    magic      user No#      leaf hash and branch node hash
  // | 256 bit | 64 bit |    64 bit     | 256 bit | ..

  // Check if user data file exists and is regular file
  if (!regularFileExists(user_data_file)) {
    return false;
  }

  // if index file and merkle file are either non-existent or invalid, rebuild
  // these file
  std::string index_file = user_data_file + ".index";
  std::string merkle_file = user_data_file + ".merkle";
  if (!regularFileExists(index_file) ||
      !verifyFileFingerPrint(index_file, kIndexMagic) ||
      !regularFileExists(merkle_file) ||
      !verifyFileFingerPrint(merkle_file, kMerkleMagic)) {
    if (regularFileExists(index_file)) {
      std::filesystem::remove(index_file);
    }

    if (regularFileExists(merkle_file)) {
      std::filesystem::remove(index_file);
    }

    // preprocess user data file and generate index and merkle
    if (!preprocessUserFile(user_data_file, index_file, merkle_file)) {
      return false;
    }
  }

  // memory map user file, index file, merkle file into process address space
  index_map = mmapFile(index_file);
  merkle_map = mmapFile(merkle_file);
  return true;
}

std::string PoRDB::UserInfo(uint64_t id, std::string& proof) const {
  if (index_map.file_map == (void*)-1) {
    return "";
  }

  // jump through 32 byte hash and 8 byte magic number
  const uint8_t* p = reinterpret_cast<const uint8_t*>(index_map.file_map);
  p += 40;

  const uint64_t* count = reinterpret_cast<const uint64_t*>(p);
  const struct indexentry* beg_index =
      reinterpret_cast<const struct indexentry*>(count + 1);
  const struct indexentry* end_index =
      reinterpret_cast<const struct indexentry*>(beg_index + *count);

  auto it = std::lower_bound(beg_index, end_index, id,
                             [this](const struct indexentry entry,
                                    uint64_t id) { return entry.id < id; });

  if (it == end_index || it->id != id) {
    return "";
  }

  std::string user_info =
      reinterpret_cast<const char*>(index_map.file_map) + it->offset;

  MerkleProof generator;
  std::vector<std::pair<bool, std::vector<uint8_t>>> path;
  auto root = generateProof(it - beg_index, path);
  for (const auto& node : path) {
    generator.AddSibling(node.second, node.first);
  }

  proof = generator.GenerateProof(kBranchTag, root);

  return user_info;
}

std::vector<uint8_t> PoRDB::generateProof(
    uint64_t order,
    std::vector<std::pair<bool, std::vector<uint8_t>>>& path) const {
  // jump through 32 byte hash and 8 byte magic number
  const uint8_t* p = reinterpret_cast<const uint8_t*>(merkle_map.file_map);
  p += 40;
  uint64_t count = *reinterpret_cast<const uint64_t*>(p);
  p += 8;

  // std::cout << reinterpret_cast<uint64_t>(p) << ":" << order << "," << count
  //           << std::endl;
  if (order >= count) {
    return {};
  }

  path.clear();
  std::vector<uint8_t> node(32, 0);

  // construct merkle root from leaf to root
  std::copy(p + order * 32, p + (order + 1) * 32, node.begin());
  path.push_back(std::make_pair((order & 0x01) == 0x00, node));
  while (count > 1) {
    if ((count & 0x01) == 0x01) {
      ++count;
    }

    if ((order & 0x01) == 0x00) {
      std::copy(p + (order + 1) * 32, p + (order + 2) * 32, node.begin());
      path.push_back(std::make_pair(false, node));
    } else {
      std::copy(p + (order - 1) * 32, p + (order) * 32, node.begin());
      path.push_back(std::make_pair(true, node));
    }

    p += 32 * count;
    count >>= 1;
    order >>= 1;
  }

  // read merkle root
  std::vector<uint8_t> root(32, 0);
  std::copy(p, p + 32, root.begin());
  return root;
}

bool PoRDB::regularFileExists(const std::string& file) {
  std::filesystem::path file_path = file;
  return std::filesystem::exists(file_path) &&
         std::filesystem::status(file_path).type() ==
             std::filesystem::file_type::regular;
}

bool PoRDB::verifyFileFingerPrint(const std::string& file,
                                  const std::vector<uint8_t>& magic) {
  std::filesystem::path path = file;

  // file starts with 32 byte hash, 8 byte magic number, 8 byte as the count of
  // data entries
  if (std::filesystem::file_size(path) < 48) {
    return false;
  }

  std::vector<uint8_t> hv(32, 0);
  std::ifstream f(file, std::ios::in | std::ios::binary);
  f.read(reinterpret_cast<char*>(hv.data()), hv.size());

  std::vector<uint8_t> magic_vec(8, 0);
  f.read(reinterpret_cast<char*>(magic_vec.data()), magic_vec.size());
  if (f.gcount() != magic_vec.size() || magic_vec != magic) {
    return false;
  }

  sha256::StreamHasher hasher;
  hasher.Append(magic_vec);

  // read a block of 512 bytes
  std::vector<uint8_t> buffer(512, 0);
  f.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
  auto size = f.gcount();
  while (size == buffer.size()) {
    hasher.Append(buffer);
    f.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
    size = f.gcount();
  }

  buffer.resize(size);
  hasher.Append(buffer);

  return hv == hasher.Hash();
}

// This function takes quite a while to create index and merkle tree.
// One thought is: preprocess the file in advance before starting service.
bool PoRDB::preprocessUserFile(const std::string& user_data,
                               const std::string& index,
                               const std::string& merkle) {
  std::ifstream user_file(user_data, std::ios::in);

  sha256::StreamHasher index_hasher;
  std::ofstream index_file(index,
                           std::ios::out | std::ios::binary | std::ios::trunc);

  sha256::StreamHasher merkle_hasher;
  std::fstream merkle_file(merkle, std::ios::out | std::ios::in |
                                       std::ios::binary | std::ios::trunc);

  // leave 32 bytes for sha256
  index_file.seekp(32);
  merkle_file.seekp(32);

  // write magic to index and merkle file
  index_file.write(reinterpret_cast<const char*>(kIndexMagic.data()),
                   kIndexMagic.size());
  index_hasher.Append(kIndexMagic);
  merkle_file.write(reinterpret_cast<const char*>(kMerkleMagic.data()),
                    kMerkleMagic.size());
  merkle_hasher.Append(kMerkleMagic);

  // get user data item count
  uint64_t count = 0;
  user_file >> count;

  // convert count to vector
  uint8_t* p_count = reinterpret_cast<uint8_t*>(&count);
  std::vector<uint8_t> count_vec(p_count, p_count + sizeof count);

  // write data count
  index_file.write(reinterpret_cast<char*>(count_vec.data()), count_vec.size());
  index_hasher.Append(count_vec);
  merkle_file.write(reinterpret_cast<char*>(count_vec.data()),
                    count_vec.size());
  merkle_hasher.Append(count_vec);

  // I will copy user data to index file after all the index is created
  uint64_t offset = 32 + 8 + 8 + count * 16;

  // read each line one by one
  std::string line;
  std::vector<uint8_t> index_entry(16, 0x00);
  std::vector<uint8_t> hv;
  TaggedHasher leaf_tag_hasher(kLeafTag);
  // consume the first '\n'
  std::getline(user_file, line);
  for (size_t i = 0; i < count; ++i) {
    if (std::getline(user_file, line)) {
      char unused;
      uint64_t id;
      uint64_t balance;
      std::stringstream ss(line);
      ss >> unused >> id >> unused >> balance >> unused;

      // assemble id and offset as index entry
      std::copy(reinterpret_cast<uint8_t*>(&id),
                reinterpret_cast<uint8_t*>(&id) + 8, index_entry.begin());
      std::copy(reinterpret_cast<uint8_t*>(&offset),
                reinterpret_cast<uint8_t*>(&offset) + 8,
                index_entry.begin() + 8);
      index_file.write(reinterpret_cast<char*>(index_entry.data()),
                       index_entry.size());
      index_hasher.Append(index_entry);

      // put '\0' at the end of string
      offset += line.size() + 1;

      // calculate leaf hash
      std::vector<uint8_t> data(line.cbegin(), line.cend());
      leaf_tag_hasher.Reset();
      leaf_tag_hasher.Append(data);
      hv = leaf_tag_hasher.Hash();
      merkle_file.write(reinterpret_cast<char*>(hv.data()), hv.size());
      merkle_hasher.Append(hv);
    } else {
      return false;
    }
  }

  // if count is an odd number greater than 1, duplicate the last hash
  if (!hv.empty() && count > 1 && (count & 0x01) == 0x01) {
    merkle_file.write(reinterpret_cast<char*>(hv.data()), hv.size());
    merkle_hasher.Append(hv);
    ++count;
  }

  // rescan the user data file and copy user data to index
  user_file.seekg(0);
  std::getline(user_file, line);
  for (size_t i = 0; i < count; ++i) {
    if (std::getline(user_file, line)) {
      std::vector<uint8_t> data_vec(line.cbegin(), line.cend());
      data_vec.push_back('\0');

      index_file.write(reinterpret_cast<char*>(data_vec.data()),
                       data_vec.size());
      index_hasher.Append(data_vec);
    }
  }

  // write sha256 hash to the begining 32 bytes
  index_file.seekp(0);
  hv = index_hasher.Hash();
  index_file.write(reinterpret_cast<char*>(hv.data()), hv.size());
  index_file.close();

  // construct merkle tree
  TaggedHasher branch_tag_hasher(kBranchTag);
  uint64_t read_offset = 48;
  uint64_t write_offset = read_offset + 32 * count;
  std::vector<uint8_t> left(32, 0);
  std::vector<uint8_t> right(32, 0);
  std::vector<uint8_t> branch_hash;
  while (count > 1) {
    for (size_t i = 0; i < (count >> 1); ++i) {
      // read in 2 hashes to calculate branch tagged hash
      merkle_file.seekp(read_offset + 2 * i * 32);
      merkle_file.read(reinterpret_cast<char*>(left.data()), left.size());
      merkle_file.read(reinterpret_cast<char*>(right.data()), right.size());
      branch_tag_hasher.Reset();
      branch_tag_hasher.Append(left);
      branch_tag_hasher.Append(right);

      // write branch tagged hash
      merkle_file.seekp(write_offset + i * 32);
      branch_hash = branch_tag_hasher.Hash();
      merkle_file.write(reinterpret_cast<char*>(branch_hash.data()),
                        branch_hash.size());
      merkle_hasher.Append(branch_hash);
    }

    count >>= 1;
    if (count > 1 && (count & 0x01) == 0x01) {
      merkle_file.seekp(write_offset + count * 32);
      merkle_file.write(reinterpret_cast<char*>(branch_hash.data()),
                        branch_hash.size());
      merkle_hasher.Append(branch_hash);
      ++count;
    }

    read_offset = write_offset;
    write_offset = read_offset + 32 * count;
  }

  // write sha256 hash to the begining
  merkle_file.seekp(0);
  hv = merkle_hasher.Hash();
  merkle_file.write(reinterpret_cast<char*>(hv.data()), hv.size());
  merkle_file.close();
  return true;
}

struct PoRDB::mmmapinfo PoRDB::mmapFile(const std::string& name) {
  PoRDB::mmmapinfo info;
  struct stat stats;
  stat(name.c_str(), &stats);
  info.file_size = stats.st_size;
  info.fd = open(name.c_str(), O_RDONLY);
  info.file_map = mmap(0, info.file_size, PROT_READ, MAP_PRIVATE, info.fd, 0);
  if (info.file_map == (void*)-1) {
    perror("mmap failure");
  }

  // try to lock RAM, there are some other optimization techniques, e.g.
  // MAP_HUGETLB, etc
  mlock2(info.file_map, info.file_size, MLOCK_ONFAULT);

  // close file, it will not invalidate memory mapping
  close(info.fd);
  info.fd = -1;

  return info;
}

void PoRDB::unmmapFile(struct PoRDB::mmmapinfo& info) {
  if (info.file_map != (void*)-1) {
    munmap((char*)info.file_map, info.file_size);
  }
}

const std::vector<uint8_t> PoRDB::kIndexMagic = {0x38, 0x08, 0x0d, 0xf4,
                                                 0x4a, 0x0c, 0x38, 0x73};

const std::vector<uint8_t> PoRDB::kMerkleMagic = {0x68, 0xba, 0x80, 0xa5,
                                                  0x91, 0xd5, 0xf6, 0x43};

const std::string PoRDB::kLeafHashTagStr = "ProofOfReserve_Leaf";
const std::vector<uint8_t> PoRDB::kLeafTag(kLeafHashTagStr.cbegin(),
                                           kLeafHashTagStr.cend());

const std::string PoRDB::kBranchHashTagStr = "ProofOfReserve_Branch";
const std::vector<uint8_t> PoRDB::kBranchTag(kBranchHashTagStr.cbegin(),
                                             kBranchHashTagStr.cend());
}  // namespace crypto
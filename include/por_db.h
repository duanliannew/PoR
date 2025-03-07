#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace crypto {
class PoRDB {
 public:
  static PoRDB& Instance();
  ~PoRDB();
  // 1. read user data file and create index
  // 2. generate and persist merkle tree
  bool Load(const std::string& user_data);

  // Query user info by given user id
  std::string UserInfo(uint64_t id, std::string& proof) const;

 private:
  PoRDB() = default;
  bool regularFileExists(const std::string& file);
  // we put a sha256 value in the begining of index file and merkle file
  bool verifyFileFingerPrint(const std::string& file,
                             const std::vector<uint8_t>& magic);
  bool preprocessUserFile(const std::string& user_data,
                          const std::string& index, const std::string& merkle);

  // return merkle root, and put the path from leaf to root in the out-parameter
  // path, bool indicates if the node is left/right.
  std::vector<uint8_t> generateProof(
      uint64_t order,
      std::vector<std::pair<bool, std::vector<uint8_t>>>& path) const;

  struct mmmapinfo {
    mmmapinfo() : fd(-1), file_size(0), file_map((void*)-1) {}

    int fd;
    size_t file_size;
    const void* file_map;
  } index_map, merkle_map;

  struct mmmapinfo mmapFile(const std::string& name);

  void unmmapFile(struct mmmapinfo& info);

  struct indexentry {
    uint64_t id;
    uint64_t offset;
  };

  const static std::vector<uint8_t> kIndexMagic;
  const static std::vector<uint8_t> kMerkleMagic;
  const static std::string kLeafHashTagStr;
  const static std::vector<uint8_t> kLeafTag;
  const static std::string kBranchHashTagStr;
  const static std::vector<uint8_t> kBranchTag;
};
}  // namespace crypto
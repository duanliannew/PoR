#include "wrapper.h"

#include <string>
#include <cstdlib>

#include "por_db.h"

int LoadDB(const char* path) {
  std::string db_path = path;
  return crypto::PoRDB::Instance().Load(db_path);
}

const char* UserInfo(uint64_t id) {
  std::string proof;
  auto info = crypto::PoRDB::Instance().UserInfo(id, proof);
  if (info.empty()) {
    return 0;
  }

  info += " " + proof;

  size_t size = info.size() + 1;
  char* result = reinterpret_cast<char*>(malloc(size*(sizeof(char))));
  std::copy(info.cbegin(), info.cend(), result);
  result[size] = '\0';
  return result;
}
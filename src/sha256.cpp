#include "sha256.h"

#include <algorithm>

#include "bit_operation.h"

namespace crypto::sha256 {
std::vector<uint8_t> BlockHasher::Hash(const std::vector<uint8_t>& data) {
  auto hv = h;
  auto cursor = data.cbegin();

  // calculate hash value by processing each 512 bit data chunk
  std::array<uint8_t, 64> one_chunk = {0};
  while ((data.cend() - cursor) >= 64) {
    std::copy(cursor, cursor + 64, one_chunk.begin());
    auto w = GenerateMessageSchedule(one_chunk);
    UpdateHash(hv, k, w);

    cursor += 64;
  }

  // process the last chunk of data
  std::vector<uint8_t> last_chunk;
  std::copy(cursor, data.cend(), std::back_inserter(last_chunk));
  PreProcess(last_chunk, 8 * data.size());
  cursor = last_chunk.cbegin();
  while ((last_chunk.cend() - cursor) >= 64) {
    std::copy(cursor, cursor + 64, one_chunk.begin());
    auto w = GenerateMessageSchedule(one_chunk);
    UpdateHash(hv, k, w);

    cursor += 64;
  }

  return HashInByte(hv);
}

StreamHasher::StreamHasher() : h_(h), total_bytes_(0) {}

// return the total bytes accumulated in the stream
size_t StreamHasher::Append(const std::vector<uint8_t>& data_chunk) {
  auto it = data_chunk.cbegin();
  while (it != data_chunk.cend()) {
    size_t offset = total_bytes_ % 64;
    size_t copy_byte =
        std::min(static_cast<size_t>(data_chunk.cend() - it), 64 - offset);
    std::copy(it, it + copy_byte, chunk_cache_.begin() + offset);
    if ((offset + copy_byte) == 64) {
      auto w = GenerateMessageSchedule(chunk_cache_);
      UpdateHash(h_, k, w);
    }

    total_bytes_ += copy_byte;
    it += copy_byte;
  }

  return total_bytes_;
}

std::vector<uint8_t> StreamHasher::Hash() {
  // process the last chunk of data
  std::vector<uint8_t> last_chunk;
  std::copy(chunk_cache_.cbegin(), chunk_cache_.cbegin() + (total_bytes_ % 64),
            std::back_inserter(last_chunk));
  PreProcess(last_chunk, 8 * total_bytes_);
  auto it = last_chunk.cbegin();
  while ((last_chunk.cend() - it) >= 64) {
    std::copy(it, it + 64, chunk_cache_.begin());
    auto w = GenerateMessageSchedule(chunk_cache_);
    UpdateHash(h_, k, w);

    it += 64;
  }

  return HashInByte(h_);
}

void StreamHasher::Reset() {
  h_ = h;
  total_bytes_ = 0;
}

// Preprocess the last chunk of data by padding, such that the size of the
// resulting data is a multiple of 512 bit. suppose the original data is L-bit
// sized.
// 1. append a single '1' bit
// 2. append K '0' bits, where K is the minimum number >= 0 such that (L + 1 +
// K) == 448 mod 512
// 3. append 64 bits to encode total_bits
void PreProcess(std::vector<uint8_t>& data, size_t total_bits) {
  size_t L = data.size() * 8;
  size_t RL = L & 0x1ff;
  size_t K = 0;
  if (RL < 448) {
    K = 448 - RL - 1;
  } else {
    K = 960 - RL - 1;
  }

  // expand the container the appropriate size, with default value 0x00
  size_t s = (L + 1 + K + 64) >> 3;
  data.resize(s, 0x00);

  // append a bit '1' followed by 7 bit '0'
  data[L >> 3] = 0x80;

  // encode L in big endian
  for (size_t i = 1; i <= 8; ++i) {
    data[s - i] = total_bits & 0xffffffff;
    total_bits >>= 8;
  }
}

// Given 512 bit data chunk, return a vector with 64 elements, where each
// element is a 32-bit number
std::array<uint32_t, 64> GenerateMessageSchedule(
    const std::array<uint8_t, 64>& chunk) {
  std::array<uint32_t, 64> w = {0};

  // copy chunk into first 16 words w[0..15] of the message schedule array
  for (size_t i = 0; i < 16; ++i) {
    w[i] = (chunk[4 * i] << 24) | (chunk[4 * i + 1] << 16) |
           (chunk[4 * i + 2] << 8) | (chunk[4 * i + 3]);
  }

  // Extend the first 16 words into the remaining 48 words w[16..63] of the
  // message schedule array
  for (size_t i = 16; i < 64; ++i) {
    auto s0 = RightRotate(w[i - 15], 7) ^ RightRotate(w[i - 15], 18) ^
              (w[i - 15] >> 3);
    auto s1 = RightRotate(w[i - 2], 17) ^ RightRotate(w[i - 2], 19) ^
              (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  return w;
}

// Update hash value
void UpdateHash(std::array<uint32_t, 8>& hv, const std::array<uint32_t, 64>& k,
                const std::array<uint32_t, 64>& w) {
  auto a = hv[0];
  auto b = hv[1];
  auto c = hv[2];
  auto d = hv[3];
  auto e = hv[4];
  auto f = hv[5];
  auto g = hv[6];
  auto h = hv[7];

  for (size_t i = 0; i < 64; ++i) {
    auto s0 = RightRotate(a, 2) ^ RightRotate(a, 13) ^ RightRotate(a, 22);
    auto s1 = RightRotate(e, 6) ^ RightRotate(e, 11) ^ RightRotate(e, 25);
    auto ch = (e & f) ^ ((~e) & g);
    auto temp1 = h + s1 + ch + k[i] + w[i];
    auto maj = (a & b) ^ (a & c) ^ (b & c);
    auto temp2 = s0 + maj;

    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  // update hash value
  hv[0] += a;
  hv[1] += b;
  hv[2] += c;
  hv[3] += d;
  hv[4] += e;
  hv[5] += f;
  hv[6] += g;
  hv[7] += h;
}

std::vector<uint8_t> HashInByte(const std::array<uint32_t, 8>& h) {
  std::vector<uint8_t> hash(32, 0);
  int index = 0;
  for (auto word : h) {
    hash[index + 3] = word & 0x000000ff;
    word >>= 8;
    hash[index + 2] = word & 0x000000ff;
    word >>= 8;
    hash[index + 1] = word & 0x000000ff;
    word >>= 8;
    hash[index] = word & 0x000000ff;
    word >>= 8;

    index += 4;
  }

  return hash;
}
}  // namespace crypto::sha256
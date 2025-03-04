#include "bit_operation.h"

#include <gtest/gtest.h>

TEST(bitop, right_rotate) {
  uint8_t v8 = 0x81;
  EXPECT_EQ(RightRotate(v8, 0), v8);
  EXPECT_EQ(RightRotate(v8, 1), 0xc0);
  EXPECT_EQ(RightRotate(v8, 2), 0x60);
  EXPECT_EQ(RightRotate(v8, 3), 0x30);
  EXPECT_EQ(RightRotate(v8, 4), 0x18);
  EXPECT_EQ(RightRotate(v8, 5), 0x0c);
  EXPECT_EQ(RightRotate(v8, 6), 0x06);
  EXPECT_EQ(RightRotate(v8, 7), 0x03);
  for (size_t i = 0; i < sizeof(v8); ++i) {
    EXPECT_EQ(RightRotate(v8, i), RightRotate(v8, sizeof(v8) * 8 + i));
    EXPECT_EQ(RightRotate(v8, i), RightRotate(v8, 2 * sizeof(v8) * 8 + i));
  }

  uint16_t v16 = 0x8098;
  EXPECT_EQ(RightRotate(v16, 3), 0x1013);
  EXPECT_EQ(RightRotate(v16, 4), 0x8809);
}
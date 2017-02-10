#include "gtest/gtest.h"

#include "proto/tink.pb.h"

using google::cloud::crypto::tink::Keyset;

class TinkProtoTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
  }

  virtual void TearDown() {
  }

};

TEST_F(TinkProtoTest, testKeysetBasic) {
  Keyset keyset;
  keyset.set_primary_key_id(1);
  EXPECT_EQ(1, keyset.primary_key_id());
}


int main(int ac, char* av[]) {
  testing::InitGoogleTest(&ac, av);
  return RUN_ALL_TESTS();
}

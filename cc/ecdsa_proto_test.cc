#include "gtest/gtest.h"

#include "proto/ecdsa.pb.h"

using google::cloud::crypto::tink::EcdsaPublicKey;

class EcdsaProtoTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
  }

  virtual void TearDown() {
  }

};

TEST_F(EcdsaProtoTest, testEcdsaPublicKey) {
  EcdsaPublicKey pubKey;
  pubKey.set_version(1);
  EXPECT_EQ(1, pubKey.version());
}


int main(int ac, char* av[]) {
  testing::InitGoogleTest(&ac, av);
  return RUN_ALL_TESTS();
}

// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "tink/subtle/prf/hkdf_streaming_prf.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/subtle/hkdf.h"
#include "tink/subtle/random.h"
#include "tink/util/input_stream_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace subtle {

namespace {

using ::crypto::tink::test::HexDecodeOrDie;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;
using ::testing::Ge;
using ::testing::Ne;
using ::testing::Not;
using ::testing::SizeIs;

// GENERIC TESTS ===============================================================
//
// These should be satisfied for any streaming prf which generates enough
// output.
TEST(HkdfStreamingPrf, Basic) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  auto streaming_prf_or = HkdfStreamingPrf::New(
      SHA512, util::SecretDataFromStringView("key0123456"), "salt");
  ASSERT_THAT(streaming_prf_or.status(), IsOk());

  std::unique_ptr<InputStream> stream =
      streaming_prf_or.ValueOrDie()->ComputePrf("input");
  auto result_or = ReadBytesFromStream(10, stream.get());
  ASSERT_THAT(result_or.status(), IsOk());

  EXPECT_THAT(result_or.ValueOrDie(), SizeIs(10));
}

TEST(HkdfStreamingPrf, DifferentInputsGiveDifferentvalues) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  auto streaming_prf_or = HkdfStreamingPrf::New(
      SHA512, util::SecretDataFromStringView("key0123456"), "salt");
  ASSERT_THAT(streaming_prf_or.status(), IsOk());

  std::unique_ptr<InputStream> stream =
      streaming_prf_or.ValueOrDie()->ComputePrf("input");
  auto result_or = ReadBytesFromStream(10, stream.get());
  ASSERT_THAT(result_or.status(), IsOk());

  // Different input.
  std::unique_ptr<InputStream> stream2 =
      streaming_prf_or.ValueOrDie()->ComputePrf("input2");
  auto result_or2 = ReadBytesFromStream(10, stream2.get());
  ASSERT_THAT(result_or2.status(), IsOk());
  EXPECT_THAT(result_or2.ValueOrDie(), Ne(result_or.ValueOrDie()));
}

TEST(HkdfStreamingPrf, SameInputTwice) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  auto streaming_prf_or = HkdfStreamingPrf::New(
      SHA512, util::SecretDataFromStringView("key0123456"), "salt");
  ASSERT_THAT(streaming_prf_or.status(), IsOk());

  std::unique_ptr<InputStream> stream =
      streaming_prf_or.ValueOrDie()->ComputePrf("input");
  auto result_or = ReadBytesFromStream(10, stream.get());
  ASSERT_THAT(result_or.status(), IsOk());

  // Same input.
  std::unique_ptr<InputStream> stream2 =
      streaming_prf_or.ValueOrDie()->ComputePrf("input");
  auto result_or2 = ReadBytesFromStream(10, stream2.get());
  ASSERT_THAT(result_or2.status(), IsOk());
  EXPECT_THAT(result_or2.ValueOrDie(), Eq(result_or.ValueOrDie()));
}

// STREAM HANDLING TESTS =======================================================
//
// These check that the buffer handling of the implementation is correct. They
// should be satisfied with any input stream.

// Tests that after Backing up the full stream, we get back the same data.
TEST(HkdfStreamingPrf, BackupFullStream) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  auto streaming_prf_or = HkdfStreamingPrf::New(
      SHA256, util::SecretDataFromStringView("key0123456"), "salt");
  ASSERT_THAT(streaming_prf_or.status(), IsOk());

  std::unique_ptr<InputStream> stream =
      streaming_prf_or.ValueOrDie()->ComputePrf("input");

  const void* data;
  crypto::tink::util::StatusOr<int> result = stream->Next(&data);
  ASSERT_THAT(result.status(), IsOk());
  int bytes_read = result.ValueOrDie();
  std::string first_read =
      std::string(static_cast<const char*>(data), bytes_read);

  stream->BackUp(bytes_read);

  result = stream->Next(&data);
  ASSERT_THAT(result.status(), IsOk());
  // We typically read at least as many bytes the second time -- strictly
  // speaking this might not be satisfied by every InputStream, but it usually
  // will be.
  ASSERT_THAT(result.ValueOrDie(), Ge(bytes_read));

  std::string second_read =
      std::string(static_cast<const char*>(data), bytes_read);
  EXPECT_THAT(first_read, Eq(second_read));
}

// Tests that after Backing up half the stream, we get back the same data.
TEST(HkdfStreamingPrf, BackupHalf) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  auto streaming_prf_or = HkdfStreamingPrf::New(
      SHA256, util::SecretDataFromStringView("key0123456"), "salt");
  ASSERT_THAT(streaming_prf_or.status(), IsOk());

  std::unique_ptr<InputStream> stream =
      streaming_prf_or.ValueOrDie()->ComputePrf("input");

  const void* data;
  crypto::tink::util::StatusOr<int> result = stream->Next(&data);
  ASSERT_THAT(result.status(), IsOk());
  int bytes_read = result.ValueOrDie();
  int backup_amount = bytes_read / 2;
  std::string first_read =
      std::string(static_cast<const char*>(data) + bytes_read - backup_amount,
                  backup_amount);

  stream->BackUp(backup_amount);

  result = stream->Next(&data);
  ASSERT_THAT(result.status(), IsOk());
  // We typically read at least as many bytes the second time -- strictly
  // speaking this might not be satisfied by every InputStream, but it usually
  // will be.
  ASSERT_THAT(result.ValueOrDie(), Ge(backup_amount));

  std::string second_read =
      std::string(static_cast<const char*>(data), backup_amount);
  EXPECT_THAT(first_read, Eq(second_read));
}

// Tests that after Position is correct initially (i.e., 0).
TEST(HkdfStreamingPrf, PositionOneRead) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  auto streaming_prf_or = HkdfStreamingPrf::New(
      SHA256, util::SecretDataFromStringView("key0123456"), "salt");
  ASSERT_THAT(streaming_prf_or.status(), IsOk());

  std::unique_ptr<InputStream> stream =
      streaming_prf_or.ValueOrDie()->ComputePrf("input");

  EXPECT_THAT(stream->Position(), Eq(0));
}

// Tests that after Position is correct after a single read.
TEST(HkdfStreamingPrf, PositionSingleRead) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  auto streaming_prf_or = HkdfStreamingPrf::New(
      SHA256, util::SecretDataFromStringView("key0123456"), "salt");
  ASSERT_THAT(streaming_prf_or.status(), IsOk());

  std::unique_ptr<InputStream> stream =
      streaming_prf_or.ValueOrDie()->ComputePrf("input");

  const void* data;
  crypto::tink::util::StatusOr<int> result = stream->Next(&data);
  ASSERT_THAT(result.status(), IsOk());
  EXPECT_THAT(stream->Position(), Eq(result.ValueOrDie()));
}

// Tests that after Position is correct after a two reads.
TEST(HkdfStreamingPrf, PositionTwoReads) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  auto streaming_prf_or = HkdfStreamingPrf::New(
      SHA256, util::SecretDataFromStringView("key0123456"), "salt");
  ASSERT_THAT(streaming_prf_or.status(), IsOk());

  std::unique_ptr<InputStream> stream =
      streaming_prf_or.ValueOrDie()->ComputePrf("input");

  const void* data;
  crypto::tink::util::StatusOr<int> result = stream->Next(&data);
  ASSERT_THAT(result.status(), IsOk());

  crypto::tink::util::StatusOr<int> result2 = stream->Next(&data);
  ASSERT_THAT(result.status(), IsOk());

  EXPECT_THAT(stream->Position(),
              Eq(result.ValueOrDie() + result2.ValueOrDie()));
}

// Tests that we can backup the first read completely.
TEST(HkdfStreamingPrf, BackupSingleRead) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  auto streaming_prf_or = HkdfStreamingPrf::New(
      SHA256, util::SecretDataFromStringView("key0123456"), "salt");
  ASSERT_THAT(streaming_prf_or.status(), IsOk());

  std::unique_ptr<InputStream> stream =
      streaming_prf_or.ValueOrDie()->ComputePrf("input");

  const void* data;
  crypto::tink::util::StatusOr<int> result = stream->Next(&data);
  ASSERT_THAT(result.status(), IsOk());
  stream->BackUp(result.ValueOrDie());
  EXPECT_THAT(stream->Position(), Eq(0));
}

// Tests that we can backup the second read completely.
TEST(HkdfStreamingPrf, BackupSecondRead) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  auto streaming_prf_or = HkdfStreamingPrf::New(
      SHA256, util::SecretDataFromStringView("key0123456"), "salt");
  ASSERT_THAT(streaming_prf_or.status(), IsOk());

  std::unique_ptr<InputStream> stream =
      streaming_prf_or.ValueOrDie()->ComputePrf("input");

  const void* data;
  crypto::tink::util::StatusOr<int> result = stream->Next(&data);
  ASSERT_THAT(result.status(), IsOk());

  crypto::tink::util::StatusOr<int> result2 = stream->Next(&data);
  ASSERT_THAT(result.status(), IsOk());

  stream->BackUp(result2.ValueOrDie());

  EXPECT_THAT(stream->Position(), Eq(result.ValueOrDie()));
}

// Tests that we can partially backup and position is correct.
TEST(HkdfStreamingPrf, PartialBackup) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  auto streaming_prf_or = HkdfStreamingPrf::New(
      SHA256, util::SecretDataFromStringView("key0123456"), "salt");
  ASSERT_THAT(streaming_prf_or.status(), IsOk());

  std::unique_ptr<InputStream> stream =
      streaming_prf_or.ValueOrDie()->ComputePrf("input");

  const void* data;
  crypto::tink::util::StatusOr<int> result = stream->Next(&data);
  ASSERT_THAT(result.status(), IsOk());

  stream->BackUp(result.ValueOrDie() / 2);

  EXPECT_THAT(stream->Position(),
              Eq(result.ValueOrDie() - result.ValueOrDie() / 2));
}

// HKDF Specific tests =========================================================
// Tests which only apply for Hkdf.
TEST(HkdfStreamingPrf, ExhaustInput) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  auto streaming_prf_or = HkdfStreamingPrf::New(
      SHA512, util::SecretDataFromStringView("key0123456"), "salt");
  ASSERT_THAT(streaming_prf_or.status(), IsOk());

  const int max_output_length = 255 * (512 / 8);
  std::unique_ptr<InputStream> stream =
      streaming_prf_or.ValueOrDie()->ComputePrf("input");
  auto result_or = ReadBytesFromStream(max_output_length, stream.get());
  ASSERT_THAT(result_or.status(), IsOk());
  EXPECT_THAT(result_or.ValueOrDie(), SizeIs(max_output_length));
  result_or = ReadBytesFromStream(50, stream.get());
  ASSERT_THAT(result_or.status(), Not(IsOk()));
}

// TEST VECTORS AND COMPARISON =================================================
// These test are Hkdf specific. We test with the test vectors from RFC 5869 and
// compare with our implementation.
TEST(HkdfStreamingPrf, TestVector1) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  // https://tools.ietf.org/html/rfc5869#appendix-A.1
  HashType hash = SHA256;
  util::SecretData ikm = util::SecretDataFromStringView(
      HexDecodeOrDie("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"));
  std::string salt = HexDecodeOrDie("000102030405060708090a0b0c");
  std::string info = HexDecodeOrDie("f0f1f2f3f4f5f6f7f8f9");
  std::string expected_result = HexDecodeOrDie(
      "3cb25f25faacd57a90434f64d0362f2a"
      "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
      "34007208d5b887185865");

  auto streaming_prf_or = HkdfStreamingPrf::New(hash, ikm, salt);
  ASSERT_THAT(streaming_prf_or.status(), IsOk());
  std::unique_ptr<InputStream> stream =
      streaming_prf_or.ValueOrDie()->ComputePrf(info);
  auto result_or = ReadBytesFromStream(expected_result.size(), stream.get());
  ASSERT_THAT(result_or.status(), IsOk());
  EXPECT_THAT(result_or.ValueOrDie(), Eq(expected_result));
}

crypto::tink::util::StatusOr<std::string> ComputeWithHkdfStreamingPrf(
    HashType hash, util::SecretData ikm, std::string salt, std::string info,
    int length) {
  auto streaming_prf_or = HkdfStreamingPrf::New(hash, std::move(ikm), salt);
  if (!streaming_prf_or.status().ok()) {
    return streaming_prf_or.status();
  }
  std::unique_ptr<InputStream> stream =
      streaming_prf_or.ValueOrDie()->ComputePrf(info);
  return ReadBytesFromStream(length, stream.get());
}

TEST(HkdfStreamingPrf, TestVector2) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  // https://tools.ietf.org/html/rfc5869#appendix-A.2
  HashType hash = SHA256;
  util::SecretData ikm = util::SecretDataFromStringView(
      HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"
                     "101112131415161718191a1b1c1d1e1f"
                     "202122232425262728292a2b2c2d2e2f"
                     "303132333435363738393a3b3c3d3e3f"
                     "404142434445464748494a4b4c4d4e4f"));
  std::string salt = HexDecodeOrDie(
      "606162636465666768696a6b6c6d6e6f"
      "707172737475767778797a7b7c7d7e7f"
      "808182838485868788898a8b8c8d8e8f"
      "909192939495969798999a9b9c9d9e9f"
      "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
  std::string info = HexDecodeOrDie(
      "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
      "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
      "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
      "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
      "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
  std::string expected_result = HexDecodeOrDie(
      "b11e398dc80327a1c8e7f78c596a4934"
      "4f012eda2d4efad8a050cc4c19afa97c"
      "59045a99cac7827271cb41c65e590e09"
      "da3275600c2f09b8367793a9aca3db71"
      "cc30c58179ec3e87c14c01d5c1f3434f"
      "1d87");

  auto result_or = ComputeWithHkdfStreamingPrf(hash, std::move(ikm), salt, info,
                                               expected_result.size());
  ASSERT_THAT(result_or.status(), IsOk());
  EXPECT_THAT(result_or.ValueOrDie(), Eq(expected_result));
}

TEST(HkdfStreamingPrf, TestVector3) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  // https://tools.ietf.org/html/rfc5869#appendix-A.3
  HashType hash = SHA256;
  util::SecretData ikm = util::SecretDataFromStringView(
      HexDecodeOrDie("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"));
  std::string salt = HexDecodeOrDie("");
  std::string info = HexDecodeOrDie("");
  std::string expected_result = HexDecodeOrDie(
      "8da4e775a563c18f715f802a063c5a31"
      "b8a11f5c5ee1879ec3454e5f3c738d2d"
      "9d201395faa4b61a96c8");

  auto result_or = ComputeWithHkdfStreamingPrf(hash, std::move(ikm), salt, info,
                                               expected_result.size());
  ASSERT_THAT(result_or.status(), IsOk());
  EXPECT_THAT(result_or.ValueOrDie(), Eq(expected_result));
}

TEST(HkdfStreamingPrf, TestVector4) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  // https://tools.ietf.org/html/rfc5869#appendix-A.4
  HashType hash = SHA1;
  util::SecretData ikm =
      util::SecretDataFromStringView(HexDecodeOrDie("0b0b0b0b0b0b0b0b0b0b0b"));
  std::string salt = HexDecodeOrDie("000102030405060708090a0b0c");
  std::string info = HexDecodeOrDie("f0f1f2f3f4f5f6f7f8f9");
  std::string expected_result = HexDecodeOrDie(
      "085a01ea1b10f36933068b56efa5ad81"
      "a4f14b822f5b091568a9cdd4f155fda2"
      "c22e422478d305f3f896");

  auto result_or = ComputeWithHkdfStreamingPrf(hash, std::move(ikm), salt, info,
                                               expected_result.size());
  ASSERT_THAT(result_or.status(), IsOk());
  EXPECT_THAT(result_or.ValueOrDie(), Eq(expected_result));
}

TEST(HkdfStreamingPrf, TestVector5) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  // https://tools.ietf.org/html/rfc5869#appendix-A.5
  HashType hash = SHA1;
  util::SecretData ikm = util::SecretDataFromStringView(
      HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"
                     "101112131415161718191a1b1c1d1e1f"
                     "202122232425262728292a2b2c2d2e2f"
                     "303132333435363738393a3b3c3d3e3f"
                     "404142434445464748494a4b4c4d4e4f"));
  std::string salt = HexDecodeOrDie(
      "606162636465666768696a6b6c6d6e6f"
      "707172737475767778797a7b7c7d7e7f"
      "808182838485868788898a8b8c8d8e8f"
      "909192939495969798999a9b9c9d9e9f"
      "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
  std::string info = HexDecodeOrDie(
      "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
      "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
      "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
      "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
      "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
  std::string expected_result = HexDecodeOrDie(
      "0bd770a74d1160f7c9f12cd5912a06eb"
      "ff6adcae899d92191fe4305673ba2ffe"
      "8fa3f1a4e5ad79f3f334b3b202b2173c"
      "486ea37ce3d397ed034c7f9dfeb15c5e"
      "927336d0441f4c4300e2cff0d0900b52"
      "d3b4");

  auto result_or = ComputeWithHkdfStreamingPrf(hash, std::move(ikm), salt, info,
                                               expected_result.size());
  ASSERT_THAT(result_or.status(), IsOk());
  EXPECT_THAT(result_or.ValueOrDie(), Eq(expected_result));
}

TEST(HkdfStreamingPrf, TestVector6) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  // https://tools.ietf.org/html/rfc5869#appendix-A.6
  HashType hash = SHA1;
  util::SecretData ikm = util::SecretDataFromStringView(
      HexDecodeOrDie("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"));
  std::string salt = HexDecodeOrDie("");
  std::string info = HexDecodeOrDie("");
  std::string expected_result = HexDecodeOrDie(
      "0ac1af7002b3d761d1e55298da9d0506"
      "b9ae52057220a306e07b6b87e8df21d0"
      "ea00033de03984d34918");

  auto result_or = ComputeWithHkdfStreamingPrf(hash, std::move(ikm), salt, info,
                                               expected_result.size());
  ASSERT_THAT(result_or.status(), IsOk());
  EXPECT_THAT(result_or.ValueOrDie(), Eq(expected_result));
}

TEST(HkdfStreamingPrf, TestVector7) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  // https://tools.ietf.org/html/rfc5869#appendix-A.7
  HashType hash = SHA1;
  util::SecretData ikm = util::SecretDataFromStringView(
      HexDecodeOrDie("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"));
  // Since HMAC anyhow pads, this is the same as an absent salt.
  std::string salt = HexDecodeOrDie("");
  std::string info = HexDecodeOrDie("");
  std::string expected_result = HexDecodeOrDie(
      "0ac1af7002b3d761d1e55298da9d0506"
      "b9ae52057220a306e07b6b87e8df21d0"
      "ea00033de03984d34918");

  auto result_or = ComputeWithHkdfStreamingPrf(hash, std::move(ikm), salt, info,
                                               expected_result.size());
  ASSERT_THAT(result_or.status(), IsOk());
  EXPECT_THAT(result_or.ValueOrDie(), Eq(expected_result));
}

TEST(HkdfStreamingPrf, TestAgainstHkdfUtil) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  HashType hash = SHA1;
  util::SecretData ikm = Random::GetRandomKeyBytes(123);
  std::string salt = Random::GetRandomBytes(234);
  std::string info = Random::GetRandomBytes(345);

  auto streaming_result_or = ComputeWithHkdfStreamingPrf(
      hash, ikm, salt, info, 456);
  ASSERT_THAT(streaming_result_or.status(), IsOk());

  auto compute_hkdf_result_or =  Hkdf::ComputeHkdf(
      hash, ikm, salt, info, 456);
  util::SecretData compute_hkdf_result =
      std::move(compute_hkdf_result_or).ValueOrDie();
  ASSERT_THAT(compute_hkdf_result_or.status(), IsOk());
  EXPECT_THAT(streaming_result_or.ValueOrDie(),
              Eq(util::SecretDataAsStringView(compute_hkdf_result)));
}

TEST(HkdfStreamingPrf, TestFipsOnly) {
  if (!kUseOnlyFips) {
    GTEST_SKIP() << "Only supported in FIPS-only mode";
  }

  HashType hash = SHA1;
  util::SecretData ikm = Random::GetRandomKeyBytes(123);
  std::string salt = Random::GetRandomBytes(234);
  std::string info = Random::GetRandomBytes(345);

  EXPECT_THAT(HkdfStreamingPrf::New(hash, std::move(ikm), salt).status(),
              StatusIs(util::error::INTERNAL));
}
}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto

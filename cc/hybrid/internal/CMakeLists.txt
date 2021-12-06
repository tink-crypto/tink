tink_module(hybrid::internal)

tink_cc_library(
  NAME hpke_decrypt
  SRCS
    hpke_decrypt.cc
    hpke_decrypt.h
  DEPS
    tink::hybrid::internal::hpke_decrypt_boringssl
    tink::hybrid::internal::hpke_key_boringssl
    absl::status
    absl::strings
    tink::core::hybrid_decrypt
    tink::subtle::common_enums
    tink::subtle::ec_util
    tink::util::status
    tink::util::statusor
    tink::proto::hpke_cc_proto
)

tink_cc_library(
  NAME hpke_decrypt_boringssl
  SRCS
    hpke_decrypt_boringssl.cc
    hpke_decrypt_boringssl.h
  DEPS
    tink::hybrid::internal::hpke_key_boringssl
    tink::hybrid::internal::hpke_util_boringssl
    absl::status
    absl::strings
    crypto
    tink::subtle::subtle_util
    tink::util::status
    tink::util::statusor
    tink::proto::hpke_cc_proto
)

tink_cc_library(
  NAME hpke_encrypt
  SRCS
    hpke_encrypt.cc
    hpke_encrypt.h
  DEPS
    tink::hybrid::internal::hpke_encrypt_boringssl
    absl::status
    absl::strings
    tink::core::hybrid_encrypt
    tink::util::statusor
    tink::proto::hpke_cc_proto
)

tink_cc_library(
  NAME hpke_encrypt_boringssl
  SRCS
    hpke_encrypt_boringssl.cc
    hpke_encrypt_boringssl.h
  DEPS
    tink::hybrid::internal::hpke_util_boringssl
    absl::container
    absl::status
    absl::strings
    crypto
    tink::subtle::subtle_util
    tink::util::status
    tink::util::statusor
    tink::proto::hpke_cc_proto
)

tink_cc_library(
  NAME hpke_key_boringssl
  SRCS
    hpke_key_boringssl.cc
    hpke_key_boringssl.h
  DEPS
    tink::hybrid::internal::hpke_util_boringssl
    absl::status
    crypto
    tink::util::status
    tink::util::statusor
    tink::proto::hpke_cc_proto
)

tink_cc_library(
  NAME hpke_key_manager_util
  SRCS
    hpke_key_manager_util.cc
    hpke_key_manager_util.h
  DEPS
    absl::status
    tink::util::status
    tink::util::validation
    tink::proto::hpke_cc_proto
)

tink_cc_library(
  NAME hpke_private_key_manager
  SRCS
    hpke_private_key_manager.cc
    hpke_private_key_manager.h
  DEPS
    tink::hybrid::internal::hpke_decrypt
    tink::hybrid::internal::hpke_key_manager_util
    absl::status
    tink::core::key_type_manager
    tink::core::private_key_type_manager
    tink::core::hybrid_decrypt
    tink::core::key_manager
    tink::internal::ec_util
    tink::util::constants
    tink::util::status
    tink::util::statusor
    tink::util::validation
    tink::proto::hpke_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME hpke_public_key_manager
  SRCS
    hpke_public_key_manager.cc
    hpke_public_key_manager.h
  DEPS
    tink::hybrid::internal::hpke_encrypt
    tink::hybrid::internal::hpke_key_manager_util
    absl::memory
    absl::strings
    tink::core::key_type_manager
    tink::core::hybrid_encrypt
    tink::core::key_manager
    tink::util::constants
    tink::util::errors
    tink::util::protobuf_helper
    tink::util::status
    tink::util::statusor
    tink::proto::hpke_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME hpke_test_util
  SRCS
    hpke_test_util.cc
    hpke_test_util.h
  DEPS
    absl::status
    absl::strings
    tink::util::status
    tink::util::statusor
    tink::proto::hpke_cc_proto
)

tink_cc_library(
  NAME hpke_util_boringssl
  SRCS
    hpke_util_boringssl.cc
    hpke_util_boringssl.h
  DEPS
    absl::status
    absl::strings
    crypto
    tink::util::status
    tink::util::statusor
    tink::proto::hpke_cc_proto
)

# tests

tink_cc_test(
  NAME hpke_decrypt_boringssl_test
  SRCS
    hpke_decrypt_boringssl_test.cc
  DEPS
    tink::hybrid::internal::hpke_decrypt_boringssl
    tink::hybrid::internal::hpke_test_util
    gmock
    absl::status
    absl::strings
    crypto
    tink::util::status
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::hpke_cc_proto
)

tink_cc_test(
  NAME hpke_decrypt_test
  SRCS
    hpke_decrypt_test.cc
  DEPS
    tink::hybrid::internal::hpke_decrypt
    tink::hybrid::internal::hpke_encrypt
    tink::hybrid::internal::hpke_test_util
    gmock
    absl::status
    absl::strings
    tink::util::status
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::hpke_cc_proto
)

tink_cc_test(
  NAME hpke_encrypt_boringssl_test
  SRCS
    hpke_encrypt_boringssl_test.cc
  DEPS
    tink::hybrid::internal::hpke_encrypt_boringssl
    tink::hybrid::internal::hpke_test_util
    gmock
    absl::status
    absl::strings
    crypto
    tink::util::status
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::hpke_cc_proto
)

tink_cc_test(
  NAME hpke_encrypt_test
  SRCS
    hpke_encrypt_test.cc
  DEPS
    tink::hybrid::internal::hpke_encrypt
    tink::hybrid::internal::hpke_test_util
    gmock
    absl::status
    tink::util::status
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::hpke_cc_proto
)

tink_cc_test(
  NAME hpke_key_boringssl_test
  SRCS
    hpke_key_boringssl_test.cc
  DEPS
    tink::hybrid::internal::hpke_key_boringssl
    tink::hybrid::internal::hpke_test_util
    gmock
    absl::status
    absl::strings
    crypto
    tink::util::status
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::hpke_cc_proto
)

tink_cc_test(
  NAME hpke_key_manager_util_test
  SRCS
    hpke_key_manager_util_test.cc
  DEPS
    tink::hybrid::internal::hpke_key_manager_util
    tink::hybrid::internal::hpke_test_util
    gmock
    absl::status
    tink::util::status
    tink::util::test_matchers
)

tink_cc_test(
  NAME hpke_private_key_manager_test
  SRCS
    hpke_private_key_manager_test.cc
  DEPS
    tink::hybrid::internal::hpke_encrypt
    tink::hybrid::internal::hpke_private_key_manager
    gmock
    absl::status
    tink::core::hybrid_encrypt
    tink::subtle::hybrid_test_util
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::hpke_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME hpke_public_key_manager_test
  SRCS
    hpke_public_key_manager_test.cc
  DEPS
    tink::hybrid::internal::hpke_public_key_manager
    tink::hybrid::internal::hpke_test_util
    gmock
    absl::status
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::hpke_cc_proto
)

tink_cc_test(
  NAME hpke_util_boringssl_test
  SRCS
    hpke_util_boringssl_test.cc
  DEPS
    tink::hybrid::internal::hpke_test_util
    tink::hybrid::internal::hpke_util_boringssl
    gmock
    crypto
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::hpke_cc_proto
)
#include "third_party/absl/status/status.h"

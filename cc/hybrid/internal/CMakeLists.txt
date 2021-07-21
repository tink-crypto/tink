tink_module(hybrid::internal)

tink_cc_library(
  NAME hpke_decrypt
  SRCS
    hpke_decrypt.cc
    hpke_decrypt.h
  DEPS
    absl::strings
    tink::core::hybrid_decrypt
    tink::hybrid::internal::hpke_decrypt_boringssl
    tink::hybrid::internal::hpke_key_boringssl
    tink::proto::hpke_cc_proto
    tink::subtle::common_enums
    tink::subtle::ec_util
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME hpke_decrypt_boringssl
  SRCS
    hpke_decrypt_boringssl.cc
    hpke_decrypt_boringssl.h
  DEPS
    absl::strings
    crypto
    tink::hybrid::internal::hpke_key_boringssl
    tink::hybrid::internal::hpke_util_boringssl
    tink::proto::hpke_cc_proto
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME hpke_encrypt
  SRCS
    hpke_encrypt.cc
    hpke_encrypt.h
  DEPS
    absl::strings
    tink::core::hybrid_encrypt
    tink::hybrid::internal::hpke_encrypt_boringssl
    tink::proto::hpke_cc_proto
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME hpke_encrypt_boringssl
  SRCS
    hpke_encrypt_boringssl.cc
    hpke_encrypt_boringssl.h
  DEPS
    absl::algorithm_container
    absl::strings
    crypto
    tink::hybrid::internal::hpke_util_boringssl
    tink::proto::hpke_cc_proto
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME hpke_key_boringssl
  SRCS
    hpke_key_boringssl.cc
    hpke_key_boringssl.h
  DEPS
    crypto
    tink::hybrid::internal::hpke_util_boringssl
    tink::proto::hpke_cc_proto
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME hpke_test_util
  SRCS
    hpke_test_util.cc
    hpke_test_util.h
  DEPS
    absl::strings
    tink::proto::hpke_cc_proto
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME hpke_util_boringssl
  SRCS
    hpke_util_boringssl.cc
    hpke_util_boringssl.h
  DEPS
    crypto
    tink::proto::hpke_cc_proto
    tink::util::status
    tink::util::statusor
)

# tests

tink_cc_test(
  NAME hpke_decrypt_boringssl_test
  SRCS hpke_decrypt_boringssl_test.cc
  DEPS
    absl::strings
    crypto
    tink::hybrid::internal::hpke_decrypt_boringssl
    tink::hybrid::internal::hpke_test_util
    tink::proto::hpke_cc_proto
    tink::util::status
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME hpke_decrypt_test
  SRCS hpke_decrypt_test.cc
  DEPS
    absl::strings
    tink::hybrid::hpke_decrypt
    tink::hybrid::hpke_encrypt
    tink::hybrid::internal::hpke_test_util
    tink::proto::hpke_cc_proto
    tink::util::status
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME hpke_encrypt_boringssl_test
  SRCS hpke_encrypt_boringssl_test.cc
  DEPS
    absl::strings
    crypto
    tink::hybrid::internal::hpke_encrypt_boringssl
    tink::hybrid::internal::hpke_test_util
    tink::proto::hpke_cc_proto
    tink::util::status
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME hpke_encrypt_test
  SRCS hpke_encrypt_test.cc
  DEPS
    absl::strings
    tink::hybrid::hpke_encrypt
    tink::hybrid::internal::hpke_test_util
    tink::proto::hpke_cc_proto
    tink::util::status
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME hpke_key_boringssl_test
  SRCS hpke_key_boringssl_test.cc
  DEPS
    absl::strings
    crypto
    tink::hybrid::internal::hpke_key_boringssl
    tink::hybrid::internal::hpke_test_util
    tink::proto::hpke_cc_proto
    tink::util::status
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME hpke_util_boringssl_test
  SRCS hpke_util_boringssl_test.cc
  DEPS
    absl::strings
    crypto
    tink::hybrid::internal::hpke_test_util
    tink::hybrid::internal::hpke_util_boringssl
    tink::proto::hpke_cc_proto
    tink::util::test_matchers
    tink::util::test_util
)

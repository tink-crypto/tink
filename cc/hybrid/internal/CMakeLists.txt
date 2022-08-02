tink_module(hybrid::internal)

tink_cc_library(
  NAME hpke_context
  SRCS
    hpke_context.cc
    hpke_context.h
  DEPS
    tink::hybrid::internal::hpke_context_boringssl
    tink::hybrid::internal::hpke_util
    absl::status
    absl::strings
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
  TAGS
    exclude_if_openssl
)

tink_cc_library(
  NAME hpke_context_boringssl
  SRCS
    hpke_context_boringssl.cc
    hpke_context_boringssl.h
  DEPS
    tink::hybrid::internal::hpke_util
    tink::hybrid::internal::hpke_util_boringssl
    absl::strings
    crypto
    tink::internal::ssl_unique_ptr
    tink::subtle::subtle_util
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
  TAGS
    exclude_if_openssl
)

tink_cc_library(
  NAME hpke_decrypt
  SRCS
    hpke_decrypt.cc
    hpke_decrypt.h
  DEPS
    tink::hybrid::internal::hpke_context
    tink::hybrid::internal::hpke_util
    absl::status
    tink::core::hybrid_decrypt
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::proto::hpke_cc_proto
  TAGS
    exclude_if_openssl
)

tink_cc_library(
  NAME hpke_decrypt_boringssl
  SRCS
    hpke_decrypt_boringssl.cc
    hpke_decrypt_boringssl.h
  DEPS
    tink::hybrid::internal::hpke_key_boringssl
    tink::hybrid::internal::hpke_util_boringssl
    absl::core_headers
    absl::status
    absl::strings
    crypto
    tink::subtle::subtle_util
    tink::util::status
    tink::util::statusor
    tink::proto::hpke_cc_proto
  TAGS
    exclude_if_openssl
)

tink_cc_library(
  NAME hpke_encrypt
  SRCS
    hpke_encrypt.cc
    hpke_encrypt.h
  DEPS
    tink::hybrid::internal::hpke_context
    tink::hybrid::internal::hpke_util
    absl::status
    tink::core::hybrid_encrypt
    tink::util::statusor
    tink::proto::hpke_cc_proto
  TAGS
    exclude_if_openssl
)

tink_cc_library(
  NAME hpke_encrypt_boringssl
  SRCS
    hpke_encrypt_boringssl.cc
    hpke_encrypt_boringssl.h
  DEPS
    tink::hybrid::internal::hpke_util_boringssl
    absl::algorithm_container
    absl::core_headers
    absl::status
    absl::strings
    crypto
    tink::subtle::subtle_util
    tink::util::status
    tink::util::statusor
    tink::proto::hpke_cc_proto
  TAGS
    exclude_if_openssl
)

tink_cc_library(
  NAME hpke_key_boringssl
  SRCS
    hpke_key_boringssl.cc
    hpke_key_boringssl.h
  DEPS
    tink::hybrid::internal::hpke_util_boringssl
    absl::core_headers
    absl::status
    crypto
    tink::util::status
    tink::util::statusor
    tink::proto::hpke_cc_proto
  TAGS
    exclude_if_openssl
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
  TAGS
    exclude_if_openssl
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
  TAGS
    exclude_if_openssl
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
  TAGS
    exclude_if_openssl
)

tink_cc_library(
  NAME hpke_test_util
  SRCS
    hpke_test_util.cc
    hpke_test_util.h
  DEPS
    tink::hybrid::internal::hpke_util
    absl::status
    absl::strings
    tink::util::status
    tink::util::statusor
    tink::proto::hpke_cc_proto
  TAGS
    exclude_if_openssl
)

tink_cc_library(
  NAME hpke_util
  SRCS
    hpke_util.cc
    hpke_util.h
  DEPS
    absl::strings
    tink::internal::ec_util
    tink::subtle::common_enums
    tink::util::statusor
    tink::proto::hpke_cc_proto
  TAGS
    exclude_if_openssl
)

tink_cc_library(
  NAME hpke_util_boringssl
  SRCS
    hpke_util_boringssl.cc
    hpke_util_boringssl.h
  DEPS
    tink::hybrid::internal::hpke_util
    absl::status
    absl::strings
    crypto
    tink::util::status
    tink::util::statusor
    tink::proto::hpke_cc_proto
  TAGS
    exclude_if_openssl
)

tink_cc_library(
  NAME test_hpke_context_boringssl
  SRCS
    test_hpke_context_boringssl.cc
    test_hpke_context_boringssl.h
  DEPS
    tink::hybrid::internal::hpke_context_boringssl
    tink::hybrid::internal::hpke_util
    tink::hybrid::internal::hpke_util_boringssl
    absl::strings
    crypto
    tink::internal::ssl_unique_ptr
    tink::subtle::subtle_util
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
  TAGS
    exclude_if_openssl
)

# tests

tink_cc_test(
  NAME hpke_context_test
  SRCS
    hpke_context_test.cc
  DEPS
    tink::hybrid::internal::hpke_context
    tink::hybrid::internal::hpke_test_util
    tink::hybrid::internal::hpke_util
    gmock
    tink::util::secret_data
    tink::util::statusor
    tink::util::test_matchers
  TAGS
    exclude_if_openssl
)

tink_cc_test(
  NAME hpke_context_boringssl_test
  SRCS
    hpke_context_boringssl_test.cc
  DEPS
    tink::hybrid::internal::hpke_context_boringssl
    tink::hybrid::internal::hpke_test_util
    tink::hybrid::internal::hpke_util
    tink::hybrid::internal::test_hpke_context_boringssl
    gmock
    absl::status
    absl::strings
    crypto
    tink::util::secret_data
    tink::util::status
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::hpke_cc_proto
  TAGS
    exclude_if_openssl
)

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
  TAGS
    exclude_if_openssl
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
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::hpke_cc_proto
  TAGS
    exclude_if_openssl
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
  TAGS
    exclude_if_openssl
)

tink_cc_test(
  NAME hpke_encrypt_test
  SRCS
    hpke_encrypt_test.cc
  DEPS
    tink::hybrid::internal::hpke_encrypt
    tink::hybrid::internal::hpke_test_util
    tink::hybrid::internal::hpke_util
    gmock
    absl::status
    absl::strings
    tink::util::test_matchers
    tink::proto::hpke_cc_proto
  TAGS
    exclude_if_openssl
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
  TAGS
    exclude_if_openssl
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
  TAGS
    exclude_if_openssl
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
  TAGS
    exclude_if_openssl
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
  TAGS
    exclude_if_openssl
)

tink_cc_test(
  NAME hpke_util_boringssl_test
  SRCS
    hpke_util_boringssl_test.cc
  DEPS
    tink::hybrid::internal::hpke_test_util
    tink::hybrid::internal::hpke_util
    tink::hybrid::internal::hpke_util_boringssl
    gmock
    crypto
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::hpke_cc_proto
  TAGS
    exclude_if_openssl
)

tink_cc_test(
  NAME hpke_util_test
  SRCS
    hpke_util_test.cc
  DEPS
    tink::hybrid::internal::hpke_test_util
    tink::hybrid::internal::hpke_util
    gmock
    tink::util::test_matchers
    tink::proto::hpke_cc_proto
  TAGS
    exclude_if_openssl
)

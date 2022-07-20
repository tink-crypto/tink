tink_module(aead::internal)

tink_cc_library(
  NAME aead_util
  SRCS
    aead_util.cc
    aead_util.h
  DEPS
    absl::status
    crypto
    tink::util::errors
    tink::util::statusor
)

tink_cc_library(
  NAME wycheproof_aead
  SRCS
    wycheproof_aead.cc
    wycheproof_aead.h
  DEPS
    absl::strings
    tink::subtle::wycheproof_util
    tink::util::statusor
)

tink_cc_library(
  NAME ssl_aead
  SRCS
    ssl_aead.cc
    ssl_aead.h
  DEPS
    tink::aead::internal::aead_util
    absl::cleanup
    absl::memory
    absl::status
    absl::strings
    absl::span
    crypto
    tink::internal::err_util
    tink::internal::ssl_unique_ptr
    tink::internal::util
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME cord_aes_gcm_boringssl
  SRCS
    cord_aes_gcm_boringssl.cc
    cord_aes_gcm_boringssl.h
  DEPS
    tink::aead::internal::aead_util
    absl::status
    absl::strings
    absl::cord
    crypto
    tink::aead::cord_aead
    tink::internal::ssl_unique_ptr
    tink::subtle::random
    tink::subtle::subtle_util
    tink::util::errors
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME mock_zero_copy_aead
  SRCS
    mock_zero_copy_aead.h
  DEPS
    tink::aead::internal::zero_copy_aead
    gmock
    absl::strings
    tink::util::statusor
)

tink_cc_library(
  NAME aead_from_zero_copy
  SRCS
    aead_from_zero_copy.cc
    aead_from_zero_copy.h
  DEPS
    tink::aead::internal::zero_copy_aead
    absl::memory
    absl::status
    tink::core::aead
    tink::subtle::subtle_util
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME zero_copy_aead
  SRCS
    zero_copy_aead.h
  DEPS
    absl::strings
    tink::util::statusor
)

tink_cc_library(
  NAME zero_copy_aead_wrapper
  SRCS
    zero_copy_aead_wrapper.cc
    zero_copy_aead_wrapper.h
  DEPS
    tink::aead::internal::zero_copy_aead
    absl::strings
    tink::core::aead
    tink::core::crypto_format
    tink::core::primitive_set
    tink::core::primitive_wrapper
    tink::subtle::subtle_util
    tink::util::statusor
)

tink_cc_library(
  NAME zero_copy_aes_gcm_boringssl
  SRCS
    zero_copy_aes_gcm_boringssl.cc
    zero_copy_aes_gcm_boringssl.h
  DEPS
    tink::aead::internal::aead_util
    tink::aead::internal::ssl_aead
    tink::aead::internal::zero_copy_aead
    absl::core_headers
    absl::memory
    absl::status
    absl::strings
    tink::internal::util
    tink::subtle::random
    tink::subtle::subtle_util
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
)

tink_cc_test(
  NAME aead_util_test
  SRCS
    aead_util_test.cc
  DEPS
    tink::aead::internal::aead_util
    gmock
    crypto
    tink::util::test_matchers
)

tink_cc_test(
  NAME ssl_aead_test
  SRCS
    ssl_aead_test.cc
  DATA
    wycheproof::testvectors
  DEPS
    tink::aead::internal::ssl_aead
    tink::aead::internal::wycheproof_aead
    gmock
    absl::flat_hash_set
    absl::memory
    absl::status
    absl::strings
    absl::span
    tink::config::tink_fips
    tink::internal::ssl_util
    tink::subtle::subtle_util
    tink::util::secret_data
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_test(
  NAME cord_aes_gcm_boringssl_test
  SRCS
    cord_aes_gcm_boringssl_test.cc
  DATA
    wycheproof::testvectors
  DEPS
    tink::subtle::aes_gcm_boringssl
    tink::subtle::wycheproof_util
    tink::aead::cord_aead
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_util
    tink::util::test_matchers
    absl::strings
    absl::cord
    rapidjson
)

tink_cc_test(
  NAME aead_from_zero_copy_test
  SRCS
    aead_from_zero_copy_test.cc
  DEPS
    tink::aead::internal::aead_from_zero_copy
    tink::aead::internal::mock_zero_copy_aead
    gmock
    absl::memory
    absl::status
    absl::strings
    absl::span
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_test(
  NAME zero_copy_aes_gcm_boringssl_test
  SRCS
    zero_copy_aes_gcm_boringssl_test.cc
  DATA
    wycheproof::testvectors
  DEPS
    tink::aead::internal::wycheproof_aead
    tink::aead::internal::zero_copy_aead
    tink::aead::internal::zero_copy_aes_gcm_boringssl
    gmock
    absl::status
    absl::strings
    absl::span
    crypto
    tink::subtle::subtle_util
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_test(
  NAME ssl_aead_large_inputs_test
  SRCS
    ssl_aead_large_inputs_test.cc
  DEPS
    tink::aead::internal::ssl_aead
    gmock
    absl::flat_hash_set
    absl::memory
    absl::status
    absl::strings
    absl::span
    tink::config::tink_fips
    tink::internal::ssl_util
    tink::subtle::subtle_util
    tink::util::secret_data
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_test(
  NAME zero_copy_aead_wrapper_test
  SRCS
    zero_copy_aead_wrapper_test.cc
  DEPS
    tink::aead::internal::mock_zero_copy_aead
    tink::aead::internal::zero_copy_aead_wrapper
    gmock
    tink::subtle::subtle_util
    tink::util::test_matchers
)

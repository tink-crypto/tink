tink_module(aead::internal)

tink_cc_library(
  NAME aead_util
  SRCS
    aead_util.cc
    aead_util.h
  DEPS
    tink::util::errors
    tink::util::status
    tink::util::statusor
    crypto
    absl::status
)

tink_cc_library(
  NAME cord_aes_gcm_boringssl
  SRCS
    cord_aes_gcm_boringssl.cc
    cord_aes_gcm_boringssl.h
  DEPS
    tink::internal::ssl_unique_ptr
    tink::subtle::random
    tink::subtle::subtle_util
    tink::subtle::subtle_util_boringssl
    tink::aead::cord_aead
    tink::util::errors
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    crypto
    absl::status
    absl::strings
    absl::cord
)

tink_cc_library(
  NAME mock_zero_copy_aead
  SRCS
    mock_zero_copy_aead.h
  DEPS
    tink::aead::internal::zero_copy_aead
    tink::util::statusor
    absl::strings
    gmock
)

tink_cc_library(
  NAME
    aead_from_zero_copy
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
  SRCS zero_copy_aead.h
  DEPS
    tink::util::statusor
    absl::strings
)

tink_cc_library(
  NAME zero_copy_aes_gcm_boringssl
  SRCS
    zero_copy_aes_gcm_boringssl.cc
    zero_copy_aes_gcm_boringssl.h
  DEPS
    absl::core_headers
    absl::memory
    absl::status
    crypto
    tink::aead::internal::aead_util
    tink::internal::ssl_unique_ptr
    tink::aead::internal::zero_copy_aead
    tink::subtle::random
    tink::subtle::subtle_util
    tink::subtle::subtle_util_boringssl
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
)

tink_cc_test(
  NAME aead_util_test
  SRCS aead_util_test.cc
  DEPS
    tink::aead::internal::aead_util
    tink::util::statusor
    tink::util::test_matchers
    crypto
    gmock
)

tink_cc_test(
  NAME
    aead_from_zero_copy_test
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

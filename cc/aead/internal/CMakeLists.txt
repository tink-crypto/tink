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
    absl::strings
    absl::cord
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

tink_module(aead_internal)

tink_cc_library(
  NAME cord_aes_gcm_boringssl
  SRCS
    cord_aes_gcm_boringssl.cc
    cord_aes_gcm_boringssl.h
  DEPS
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


tink_cc_test(
  NAME cord_aes_gcm_boringssl_test
  SRCS cord_aes_gcm_boringssl_test.cc
  DATA wycheproof::testvectors
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
    absl::cord_test_helpers
    rapidjson
)

tink_module(signature::internal)

tink_cc_library(
  NAME ecdsa_raw_sign_boringssl
  SRCS
    ecdsa_raw_sign_boringssl.cc
    ecdsa_raw_sign_boringssl.h
  DEPS
    absl::status
    absl::strings
    crypto
    tink::core::public_key_sign
    tink::internal::bn_util
    tink::internal::ec_util
    tink::internal::err_util
    tink::internal::fips_utils
    tink::internal::md_util
    tink::internal::ssl_unique_ptr
    tink::internal::util
    tink::subtle::common_enums
    tink::subtle::subtle_util_boringssl
    tink::util::errors
    tink::util::statusor
)

tink_cc_test(
  NAME ecdsa_raw_sign_boringssl_test
  SRCS
    ecdsa_raw_sign_boringssl_test.cc
  DEPS
    tink::signature::internal::ecdsa_raw_sign_boringssl
    gmock
    absl::status
    tink::core::public_key_sign
    tink::core::public_key_verify
    tink::internal::ec_util
    tink::internal::fips_utils
    tink::subtle::common_enums
    tink::subtle::ecdsa_verify_boringssl
    tink::subtle::subtle_util_boringssl
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
)

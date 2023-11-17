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

tink_cc_library(
  NAME config_v0
  SRCS
    config_v0.cc
    config_v0.h
  DEPS
    absl::memory
    tink::core::configuration
    tink::internal::configuration_impl
    tink::signature::ecdsa_sign_key_manager
    tink::signature::ecdsa_verify_key_manager
    tink::signature::ed25519_sign_key_manager
    tink::signature::ed25519_verify_key_manager
    tink::signature::public_key_sign_wrapper
    tink::signature::public_key_verify_wrapper
    tink::signature::rsa_ssa_pkcs1_sign_key_manager
    tink::signature::rsa_ssa_pkcs1_verify_key_manager
    tink::signature::rsa_ssa_pss_sign_key_manager
    tink::signature::rsa_ssa_pss_verify_key_manager
    tink::util::status
)

tink_cc_library(
  NAME key_gen_config_v0
  SRCS
    key_gen_config_v0.cc
    key_gen_config_v0.h
  DEPS
    absl::memory
    tink::core::key_gen_configuration
    tink::internal::key_gen_configuration_impl
    tink::signature::ecdsa_sign_key_manager
    tink::signature::ecdsa_verify_key_manager
    tink::signature::ed25519_sign_key_manager
    tink::signature::ed25519_verify_key_manager
    tink::signature::rsa_ssa_pkcs1_sign_key_manager
    tink::signature::rsa_ssa_pkcs1_verify_key_manager
    tink::signature::rsa_ssa_pss_sign_key_manager
    tink::signature::rsa_ssa_pss_verify_key_manager
    tink::util::status
)

tink_cc_library(
  NAME config_fips_140_2
  SRCS
    config_fips_140_2.cc
    config_fips_140_2.h
  DEPS
    absl::memory
    absl::status
    tink::core::configuration
    tink::internal::configuration_impl
    tink::internal::fips_utils
    tink::signature::ecdsa_sign_key_manager
    tink::signature::ecdsa_verify_key_manager
    tink::signature::public_key_sign_wrapper
    tink::signature::public_key_verify_wrapper
    tink::signature::rsa_ssa_pkcs1_sign_key_manager
    tink::signature::rsa_ssa_pkcs1_verify_key_manager
    tink::signature::rsa_ssa_pss_sign_key_manager
    tink::signature::rsa_ssa_pss_verify_key_manager
    tink::util::status
)

# tests

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

tink_cc_test(
  NAME config_v0_test
  SRCS
    config_v0_test.cc
  DEPS
    tink::signature::internal::config_v0
    tink::signature::internal::key_gen_config_v0
    gmock
    tink::core::configuration
    tink::core::key_gen_configuration
    tink::core::keyset_handle
    tink::core::public_key_sign
    tink::core::public_key_verify
    tink::internal::configuration_impl
    tink::internal::key_gen_configuration_impl
    tink::internal::key_type_info_store
    tink::internal::keyset_wrapper_store
    tink::signature::ecdsa_verify_key_manager
    tink::signature::ed25519_verify_key_manager
    tink::signature::rsa_ssa_pkcs1_verify_key_manager
    tink::signature::rsa_ssa_pss_verify_key_manager
    tink::signature::signature_key_templates
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME config_fips_140_2_test
  SRCS
    config_fips_140_2_test.cc
  DEPS
    tink::signature::internal::config_fips_140_2
    tink::signature::internal::key_gen_config_v0
    gmock
    tink::core::configuration
    tink::core::key_gen_configuration
    tink::core::keyset_handle
    tink::core::public_key_sign
    tink::core::public_key_verify
    tink::internal::configuration_impl
    tink::internal::fips_utils
    tink::internal::key_type_info_store
    tink::internal::keyset_wrapper_store
    tink::signature::ecdsa_verify_key_manager
    tink::signature::ed25519_verify_key_manager
    tink::signature::rsa_ssa_pkcs1_verify_key_manager
    tink::signature::rsa_ssa_pss_verify_key_manager
    tink::signature::signature_key_templates
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::tink_cc_proto
)

tink_module(keyderivation)

add_subdirectory(internal)

tink_cc_library(
  NAME key_derivation_config
  SRCS
    key_derivation_config.cc
    key_derivation_config.h
  DEPS
    tink::keyderivation::keyset_deriver_wrapper
    tink::config::tink_fips
    tink::keyderivation::internal::prf_based_deriver_key_manager
    tink::prf::hkdf_prf_key_manager
    tink::util::status
  PUBLIC
)

tink_cc_test(
  NAME key_derivation_config_test
  SRCS
    key_derivation_config_test.cc
  DEPS
    tink::keyderivation::key_derivation_config
    tink::keyderivation::key_derivation_key_templates
    tink::keyderivation::keyset_deriver
    gmock
    tink::core::registry
    tink::aead::aead_config
    tink::aead::aead_key_templates
    tink::aead::aes_gcm_key_manager
    tink::prf::prf_key_templates
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_library(
  NAME key_derivation_key_templates
  SRCS
    key_derivation_key_templates.cc
    key_derivation_key_templates.h
  DEPS
    tink::keyderivation::internal::prf_based_deriver_key_manager
    tink::subtle::random
    tink::util::statusor
    tink::proto::tink_cc_proto
  PUBLIC
)

tink_cc_test(
  NAME key_derivation_key_templates_test
  SRCS
    key_derivation_key_templates_test.cc
  DEPS
    tink::keyderivation::key_derivation_key_templates
    tink::keyderivation::keyset_deriver_wrapper
    gmock
    absl::status
    tink::core::registry
    tink::aead::aead_key_templates
    tink::aead::aes_gcm_key_manager
    tink::keyderivation::internal::prf_based_deriver_key_manager
    tink::prf::hkdf_prf_key_manager
    tink::prf::prf_key_templates
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::prf_based_deriver_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME keyset_deriver
  SRCS
    keyset_deriver.h
  DEPS
    absl::strings
    tink::core::keyset_handle
    tink::util::statusor
  PUBLIC
)

tink_cc_library(
  NAME keyset_deriver_wrapper
  SRCS
    keyset_deriver_wrapper.cc
    keyset_deriver_wrapper.h
  DEPS
    tink::keyderivation::keyset_deriver
    absl::status
    tink::core::cleartext_keyset_handle
    tink::core::primitive_set
    tink::core::primitive_wrapper
    tink::keyderivation::internal::keyset_deriver_set_wrapper_impl
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME keyset_deriver_wrapper_test
  SRCS
    keyset_deriver_wrapper_test.cc
  DEPS
    tink::keyderivation::keyset_deriver_wrapper
    gmock
    absl::status
    tink::core::cleartext_keyset_handle
    tink::util::test_matchers
    tink::proto::tink_cc_proto
)

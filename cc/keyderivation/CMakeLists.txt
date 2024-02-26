tink_module(keyderivation)

add_subdirectory(internal)

tink_cc_library(
  NAME key_derivation_config
  SRCS
    key_derivation_config.cc
    key_derivation_config.h
  DEPS
    tink::keyderivation::keyset_deriver_wrapper
    absl::memory
    tink::core::registry
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
    absl::memory
    tink::core::aead
    tink::core::keyset_handle
    tink::core::registry
    tink::aead::aead_config
    tink::aead::aead_key_templates
    tink::aead::aes_gcm_key_manager
    tink::config::global_registry
    tink::prf::prf_key_templates
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME key_derivation_key_templates
  SRCS
    key_derivation_key_templates.cc
    key_derivation_key_templates.h
  DEPS
    tink::keyderivation::keyset_deriver
    tink::core::keyset_handle
    tink::config::global_registry
    tink::keyderivation::internal::prf_based_deriver_key_manager
    tink::util::statusor
    tink::proto::prf_based_deriver_cc_proto
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
    absl::memory
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
    absl::memory
    absl::status
    absl::string_view
    tink::core::cleartext_keyset_handle
    tink::core::keyset_handle
    tink::core::primitive_set
    tink::core::primitive_wrapper
    tink::util::status
    tink::util::statusor
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME keyset_deriver_wrapper_test
  SRCS
    keyset_deriver_wrapper_test.cc
  DEPS
    tink::keyderivation::keyset_deriver
    tink::keyderivation::keyset_deriver_wrapper
    gmock
    absl::memory
    absl::status
    absl::strings
    absl::string_view
    tink::core::cleartext_keyset_handle
    tink::core::keyset_handle
    tink::core::primitive_set
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME keyset_deriver_test
  SRCS
    keyset_deriver_test.cc
  DEPS
    tink::keyderivation::keyset_deriver
    tink::keyderivation::keyset_deriver_wrapper
    gmock
    absl::memory
    absl::status
    absl::string_view
    absl::optional
    tink::core::insecure_secret_key_access
    tink::core::key
    tink::core::keyset_handle
    tink::core::partial_key_access
    tink::core::partial_key_access_token
    tink::core::registry
    tink::core::restricted_data
    tink::aead::aes_gcm_key
    tink::aead::aes_gcm_parameters
    tink::aead::aes_gcm_proto_serialization
    tink::config::global_registry
    tink::internal::mutable_serialization_registry
    tink::internal::proto_parameters_serialization
    tink::internal::serialization
    tink::keyderivation::internal::prf_based_deriver_key_manager
    tink::prf::hkdf_prf_key_manager
    tink::util::status
    tink::util::statusor
    tink::util::test_keyset_handle
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::hkdf_prf_cc_proto
    tink::proto::prf_based_deriver_cc_proto
    tink::proto::tink_cc_proto
)

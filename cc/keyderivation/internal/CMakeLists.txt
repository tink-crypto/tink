tink_module(keyderivation::internal)

tink_cc_library(
  NAME keyset_deriver_set_wrapper_impl
  SRCS
    keyset_deriver_set_wrapper_impl.h
  DEPS
    tink::core::primitive_set
    tink::keyderivation::keyset_deriver
)

tink_cc_test(
  NAME keyset_deriver_set_wrapper_impl_test
  SRCS
    keyset_deriver_set_wrapper_impl_test.cc
  DEPS
    tink::keyderivation::internal::keyset_deriver_set_wrapper_impl
    gmock
    tink::core::cleartext_keyset_handle
    tink::core::crypto_format
    tink::core::primitive_set
    tink::keyderivation::keyset_deriver
    tink::util::test_matchers
)

tink_cc_library(
  NAME prf_based_deriver
  SRCS
    prf_based_deriver.cc
    prf_based_deriver.h
  DEPS
    tink::core::cleartext_keyset_handle
    tink::core::keyset_handle
    tink::core::registry
    tink::keyderivation::keyset_deriver
    tink::subtle::prf::streaming_prf
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME prf_based_deriver_test
  SRCS
    prf_based_deriver_test.cc
  DEPS
    tink::keyderivation::internal::prf_based_deriver
    gmock
    absl::status
    tink::core::cleartext_keyset_handle
    tink::aead::aead_key_templates
    tink::aead::aes_gcm_key_manager
    tink::prf::hkdf_prf_key_manager
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::aes_gcm_cc_proto
)

tink_cc_library(
  NAME prf_based_deriver_key_manager
  SRCS
    prf_based_deriver_key_manager.h
  DEPS
    tink::keyderivation::internal::prf_based_deriver
    absl::memory
    absl::status
    absl::strings
    tink::keyderivation::keyset_deriver
    tink::proto::prf_based_deriver_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME prf_based_deriver_key_manager_test
  SRCS
    prf_based_deriver_key_manager_test.cc
  DEPS
    tink::keyderivation::internal::prf_based_deriver_key_manager
    gmock
    absl::status
    tink::core::cleartext_keyset_handle
    tink::aead::aead_key_templates
    tink::aead::aes_gcm_key_manager
    tink::keyderivation::keyset_deriver
    tink::prf::hkdf_prf_key_manager
    tink::subtle::subtle
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::aes_gcm_cc_proto
    tink::proto::hkdf_prf_cc_proto
    tink::proto::prf_based_deriver_cc_proto
    tink::proto::tink_cc_proto
)

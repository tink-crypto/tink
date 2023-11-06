tink_module(config::internal)

tink_cc_library(
  NAME aead_v0
  SRCS
    aead_v0.cc
    aead_v0.h
  DEPS
    absl::memory
    tink::core::configuration
    tink::aead::aead_wrapper
    tink::aead::aes_ctr_hmac_aead_key_manager
    tink::aead::aes_eax_key_manager
    tink::aead::aes_gcm_key_manager
    tink::aead::aes_gcm_siv_key_manager
    tink::aead::xchacha20_poly1305_key_manager
    tink::internal::configuration_impl
    tink::util::status
)

tink_cc_library(
  NAME key_gen_aead_v0
  SRCS
    key_gen_aead_v0.cc
    key_gen_aead_v0.h
  DEPS
    absl::memory
    tink::core::key_gen_configuration
    tink::aead::aes_ctr_hmac_aead_key_manager
    tink::aead::aes_eax_key_manager
    tink::aead::aes_gcm_key_manager
    tink::aead::aes_gcm_siv_key_manager
    tink::aead::xchacha20_poly1305_key_manager
    tink::internal::key_gen_configuration_impl
    tink::util::status
)

tink_cc_test(
  NAME aead_v0_test
  SRCS
    aead_v0_test.cc
  DEPS
    tink::config::internal::aead_v0
    tink::config::internal::key_gen_aead_v0
    gmock
    tink::core::aead
    tink::core::configuration
    tink::core::key_gen_configuration
    tink::core::keyset_handle
    tink::aead::aead_key_templates
    tink::aead::aes_ctr_hmac_aead_key_manager
    tink::aead::aes_eax_key_manager
    tink::aead::aes_gcm_key_manager
    tink::aead::aes_gcm_siv_key_manager
    tink::aead::xchacha20_poly1305_key_manager
    tink::internal::configuration_impl
    tink::internal::key_gen_configuration_impl
    tink::internal::key_type_info_store
    tink::internal::keyset_wrapper_store
    tink::internal::ssl_util
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::tink_cc_proto
)

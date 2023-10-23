tink_module(daead::internal)

tink_cc_library(
  NAME config_v0
  SRCS
    config_v0.cc
    config_v0.h
  DEPS
    absl::memory
    tink::core::configuration
    tink::daead::aes_siv_key_manager
    tink::daead::deterministic_aead_wrapper
    tink::internal::configuration_impl
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
    tink::daead::aes_siv_key_manager
    tink::internal::key_gen_configuration_impl
    tink::util::status
)

tink_cc_test(
  NAME config_v0_test
  SRCS
    config_v0_test.cc
  DEPS
    tink::daead::internal::config_v0
    tink::daead::internal::key_gen_config_v0
    gmock
    tink::core::configuration
    tink::core::deterministic_aead
    tink::core::key_gen_configuration
    tink::core::keyset_handle
    tink::daead::aes_siv_key_manager
    tink::daead::deterministic_aead_key_templates
    tink::internal::configuration_impl
    tink::internal::key_gen_configuration_impl
    tink::internal::key_type_info_store
    tink::internal::keyset_wrapper_store
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::tink_cc_proto
)

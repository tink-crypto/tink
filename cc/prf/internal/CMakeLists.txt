tink_module(prf::internal)

tink_cc_library(
  NAME config_v0
  SRCS
    config_v0.cc
    config_v0.h
  DEPS
    absl::memory
    tink::core::configuration
    tink::internal::configuration_impl
    tink::prf::aes_cmac_prf_key_manager
    tink::prf::hkdf_prf_key_manager
    tink::prf::hmac_prf_key_manager
    tink::prf::prf_set_wrapper
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
    tink::prf::aes_cmac_prf_key_manager
    tink::prf::hkdf_prf_key_manager
    tink::prf::hmac_prf_key_manager
    tink::util::status
)

tink_cc_test(
  NAME config_v0_test
  SRCS
    config_v0_test.cc
  DEPS
    tink::prf::internal::config_v0
    tink::prf::internal::key_gen_config_v0
    gmock
    tink::core::configuration
    tink::core::key_gen_configuration
    tink::core::keyset_handle
    tink::internal::configuration_impl
    tink::internal::key_gen_configuration_impl
    tink::internal::key_type_info_store
    tink::internal::keyset_wrapper_store
    tink::prf::aes_cmac_prf_key_manager
    tink::prf::hkdf_prf_key_manager
    tink::prf::hmac_prf_key_manager
    tink::prf::prf_key_templates
    tink::prf::prf_set
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::tink_cc_proto
)

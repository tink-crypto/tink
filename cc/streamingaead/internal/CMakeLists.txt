tink_module(streamingaead::internal)

tink_cc_library(
  NAME config_v0
  SRCS
    config_v0.cc
    config_v0.h
  DEPS
    absl::memory
    tink::core::configuration
    tink::internal::configuration_impl
    tink::streamingaead::aes_ctr_hmac_streaming_key_manager
    tink::streamingaead::aes_gcm_hkdf_streaming_key_manager
    tink::streamingaead::streaming_aead_wrapper
    tink::util::status
)

tink_cc_test(
  NAME config_v0_test
  SRCS
    config_v0_test.cc
  DEPS
    tink::streamingaead::internal::config_v0
    tink::streamingaead::internal::key_gen_config_v0
    gmock
    absl::memory
    tink::core::configuration
    tink::core::input_stream
    tink::core::key_gen_configuration
    tink::core::keyset_handle
    tink::core::output_stream
    tink::core::streaming_aead
    tink::internal::configuration_impl
    tink::internal::key_gen_configuration_impl
    tink::internal::key_type_info_store
    tink::internal::keyset_wrapper_store
    tink::streamingaead::aes_ctr_hmac_streaming_key_manager
    tink::streamingaead::aes_gcm_hkdf_streaming_key_manager
    tink::streamingaead::streaming_aead_key_templates
    tink::subtle::test_util
    tink::util::istream_input_stream
    tink::util::ostream_output_stream
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::tink_cc_proto
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
    tink::streamingaead::aes_ctr_hmac_streaming_key_manager
    tink::streamingaead::aes_gcm_hkdf_streaming_key_manager
    tink::util::status
)

tink_module(streamingaead)

tink_cc_library(
  NAME streaming_aead_wrapper
  SRCS
    streaming_aead_wrapper.cc
    streaming_aead_wrapper.h
  DEPS
    absl::strings
    tink::core::crypto_format
    tink::core::input_stream
    tink::core::output_stream
    tink::core::primitive_set
    tink::core::primitive_wrapper
    tink::core::registry
    tink::core::streaming_aead
    tink::proto::tink_cc_proto
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME streaming_aead_catalogue
  SRCS
    streaming_aead_catalogue.cc
    streaming_aead_catalogue.h
  DEPS
    absl::strings
    tink::core::catalogue
    tink::core::key_manager
    tink::core::streaming_aead
    tink::streamingaead::aes_gcm_hkdf_streaming_key_manager
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME streaming_aead_config
  SRCS
    streaming_aead_config.cc
    streaming_aead_config.h
  DEPS
    absl::memory
    tink::core::config
    tink::core::registry
    tink::proto::config_cc_proto
    tink::streamingaead::streaming_aead_catalogue
    tink::streamingaead::streaming_aead_wrapper
    tink::util::status
)

tink_cc_library(
  NAME streaming_aead_key_templates
  SRCS
    streaming_aead_key_templates.cc
    streaming_aead_key_templates.h
  DEPS
    tink::proto::aes_gcm_hkdf_streaming_cc_proto
    tink::proto::common_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME aes_gcm_hkdf_streaming_key_manager
  SRCS
    aes_gcm_hkdf_streaming_key_manager.cc
    aes_gcm_hkdf_streaming_key_manager.h
  DEPS
    absl::strings
    tink::core::key_manager
    tink::core::key_manager_base
    tink::core::streaming_aead
    tink::proto::aes_gcm_hkdf_streaming_cc_proto
    tink::proto::common_cc_proto
    tink::proto::tink_cc_proto
    tink::subtle::aes_gcm_hkdf_streaming
    tink::subtle::random
    tink::util::enums
    tink::util::errors
    tink::util::protobuf_helper
    tink::util::status
    tink::util::statusor
    tink::util::validation
)

tink_cc_library(
  NAME buffered_input_stream
  SRCS
    buffered_input_stream.cc
    buffered_input_stream.h
  DEPS
    absl::memory
    tink::core::input_stream
    tink::core::registry
    tink::util::errors
    tink::util::status
    tink::util::statusor
)

# tests

tink_cc_test(
  NAME streaming_aead_wrapper_test
  SRCS streaming_aead_wrapper_test.cc
  DEPS
    tink::core::input_stream
    tink::core::output_stream
    tink::core::primitive_set
    tink::core::streaming_aead
    tink::proto::tink_cc_proto
    tink::streamingaead::streaming_aead_wrapper
    tink::util::istream_input_stream
    tink::util::ostream_output_stream
    tink::util::status
    tink::util::test_util
)

tink_cc_test(
  NAME aes_gcm_hkdf_streaming_key_manager_test
  SRCS aes_gcm_hkdf_streaming_key_manager_test.cc
  DEPS
    absl::strings
    tink::core::streaming_aead
    tink::proto::aes_eax_cc_proto
    tink::proto::aes_gcm_hkdf_streaming_cc_proto
    tink::proto::common_cc_proto
    tink::proto::tink_cc_proto
    tink::streamingaead::aes_gcm_hkdf_streaming_key_manager
    tink::subtle::random
    tink::subtle::test_util
    tink::util::istream_input_stream
    tink::util::ostream_output_stream
    tink::util::status
    tink::util::statusor
)

tink_cc_test(
  NAME streaming_aead_key_templates_test
  SRCS streaming_aead_key_templates_test.cc
  DEPS
    tink::proto::aes_gcm_hkdf_streaming_cc_proto
    tink::proto::common_cc_proto
    tink::proto::tink_cc_proto
    tink::streamingaead::aes_gcm_hkdf_streaming_key_manager
    tink::streamingaead::streaming_aead_key_templates
)

tink_cc_test(
  NAME streaming_aead_catalogue_test
  SRCS streaming_aead_catalogue_test.cc
  DEPS
    tink::core::catalogue
    tink::core::streaming_aead
    tink::streamingaead::streaming_aead_catalogue
    tink::streamingaead::streaming_aead_config
    tink::util::status
    tink::util::statusor
)

tink_cc_test(
  NAME streaming_aead_config_test
  SRCS streaming_aead_config_test.cc
  DEPS
    absl::memory
    tink::core::catalogue
    tink::core::config
    tink::core::keyset_handle
    tink::core::registry
    tink::core::streaming_aead
    tink::streamingaead::streaming_aead_config
    tink::streamingaead::streaming_aead_key_templates
    tink::util::status
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME buffered_input_stream_test
  SRCS buffered_input_stream_test.cc
  DEPS
    absl::memory
    absl::strings
    gmock
    tink::core::input_stream
    tink::streamingaead::buffered_input_stream
    tink::subtle::random
    tink::subtle::test_util
    tink::util::istream_input_stream
    tink::util::status
    tink::util::test_matchers
)


tink_module(streamingaead)


tink_cc_library(
  NAME streaming_aead_wrapper
  SRCS
    streaming_aead_wrapper.cc
    streaming_aead_wrapper.h
  DEPS
    absl::status
    absl::strings
    tink::core::crypto_format
    tink::core::input_stream
    tink::core::output_stream
    tink::core::primitive_set
    tink::core::primitive_wrapper
    tink::core::random_access_stream
    tink::core::registry
    tink::core::streaming_aead
    tink::proto::tink_cc_proto
    tink::streamingaead::decrypting_input_stream
    tink::streamingaead::decrypting_random_access_stream
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
    tink::config::config_util
    tink::config::tink_fips
    tink::core::registry
    tink::proto::config_cc_proto
    tink::streamingaead::aes_ctr_hmac_streaming_key_manager
    tink::streamingaead::aes_gcm_hkdf_streaming_key_manager
    tink::streamingaead::streaming_aead_wrapper
    tink::util::status
    absl::base
)

tink_cc_library(
  NAME streaming_aead_key_templates
  SRCS
    streaming_aead_key_templates.cc
    streaming_aead_key_templates.h
  DEPS
    tink::proto::aes_ctr_hmac_streaming_cc_proto
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
    absl::memory
    absl::strings
    tink::core::key_manager
    tink::core::key_type_manager
    tink::core::streaming_aead
    tink::proto::aes_gcm_hkdf_streaming_cc_proto
    tink::proto::tink_cc_proto
    tink::subtle::aes_gcm_hkdf_stream_segment_encrypter
    tink::subtle::aes_gcm_hkdf_streaming
    tink::subtle::random
    tink::util::constants
    tink::util::enums
    tink::util::errors
    tink::util::input_stream_util
    tink::util::protobuf_helper
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::validation
)

tink_cc_library(
  NAME aes_ctr_hmac_streaming_key_manager
  SRCS
    aes_ctr_hmac_streaming_key_manager.cc
    aes_ctr_hmac_streaming_key_manager.h
  DEPS
    absl::memory
    absl::strings
    tink::core::key_manager
    tink::core::key_type_manager
    tink::core::streaming_aead
    tink::proto::aes_ctr_hmac_streaming_cc_proto
    tink::proto::tink_cc_proto
    tink::subtle::aes_ctr_hmac_streaming
    tink::subtle::random
    tink::util::constants
    tink::util::enums
    tink::util::errors
    tink::util::input_stream_util
    tink::util::protobuf_helper
    tink::util::secret_data
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

tink_cc_library(
  NAME shared_input_stream
  SRCS shared_input_stream.h
  DEPS
    absl::memory
    tink::core::input_stream
    tink::util::errors
    tink::util::statusor
)

tink_cc_library(
  NAME shared_random_access_stream
  SRCS shared_random_access_stream.h
  DEPS
    absl::memory
    tink::core::random_access_stream
    tink::util::buffer
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME decrypting_input_stream
  SRCS
    decrypting_input_stream.cc
    decrypting_input_stream.h
  DEPS
    tink::core::input_stream
    tink::core::primitive_set
    tink::core::streaming_aead
    tink::streamingaead::buffered_input_stream
    tink::streamingaead::shared_input_stream
    tink::util::errors
    tink::util::status
    tink::util::statusor
    absl::memory
    absl::status
)

tink_cc_library(
  NAME decrypting_random_access_stream
  SRCS
    decrypting_random_access_stream.cc
    decrypting_random_access_stream.h
  DEPS
    absl::memory
    absl::status
    absl::synchronization
    tink::core::primitive_set
    tink::core::random_access_stream
    tink::core::streaming_aead
    tink::streamingaead::shared_random_access_stream
    tink::util::buffer
    tink::util::errors
    tink::util::status
    tink::util::statusor
)

# tests

tink_cc_test(
  NAME streaming_aead_wrapper_test
  SRCS streaming_aead_wrapper_test.cc
  DEPS
    absl::memory
    absl::strings
    tink::core::input_stream
    tink::core::output_stream
    tink::core::primitive_set
    tink::core::random_access_stream
    tink::core::streaming_aead
    tink::proto::tink_cc_proto
    tink::streamingaead::streaming_aead_wrapper
    tink::subtle::random
    tink::subtle::test_util
    tink::util::buffer
    tink::util::file_random_access_stream
    tink::util::istream_input_stream
    tink::util::ostream_output_stream
    tink::util::status
    tink::util::test_matchers
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
    tink::subtle::aes_gcm_hkdf_streaming
    tink::subtle::common_enums
    tink::subtle::random
    tink::subtle::streaming_aead_test_util
    tink::subtle::test_util
    tink::util::istream_input_stream
    tink::util::ostream_output_stream
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_test(
  NAME aes_ctr_hmac_streaming_key_manager_test
  SRCS aes_ctr_hmac_streaming_key_manager_test.cc
  DEPS
    absl::strings
    tink::core::streaming_aead
    tink::proto::aes_eax_cc_proto
    tink::proto::aes_ctr_hmac_streaming_cc_proto
    tink::proto::common_cc_proto
    tink::proto::tink_cc_proto
    tink::streamingaead::aes_ctr_hmac_streaming_key_manager
    tink::subtle::aes_ctr_hmac_streaming
    tink::subtle::common_enums
    tink::subtle::random
    tink::subtle::streaming_aead_test_util
    tink::subtle::test_util
    tink::util::istream_input_stream
    tink::util::ostream_output_stream
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_test(
  NAME streaming_aead_key_templates_test
  SRCS streaming_aead_key_templates_test.cc
  DEPS
    tink::proto::aes_ctr_hmac_streaming_cc_proto
    tink::proto::aes_gcm_hkdf_streaming_cc_proto
    tink::proto::common_cc_proto
    tink::proto::tink_cc_proto
    tink::streamingaead::aes_ctr_hmac_streaming_key_manager
    tink::streamingaead::aes_gcm_hkdf_streaming_key_manager
    tink::streamingaead::streaming_aead_key_templates
    tink::util::test_matchers
)

tink_cc_test(
  NAME streaming_aead_config_test
  SRCS streaming_aead_config_test.cc
  DEPS
    absl::memory
    tink::config::tink_fips
    tink::core::config
    tink::core::keyset_handle
    tink::core::registry
    tink::core::streaming_aead
    tink::streamingaead::aes_ctr_hmac_streaming_key_manager
    tink::streamingaead::aes_gcm_hkdf_streaming_key_manager
    tink::streamingaead::streaming_aead_config
    tink::streamingaead::streaming_aead_key_templates
    tink::util::status
    tink::util::test_matchers
    tink::util::test_util
    absl::status
)

tink_cc_test(
  NAME buffered_input_stream_test
  SRCS buffered_input_stream_test.cc
  DEPS
    absl::memory
    absl::status
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

tink_cc_test(
  NAME decrypting_input_stream_test
  SRCS decrypting_input_stream_test.cc
  DEPS
    absl::memory
    absl::strings
    tink::streamingaead::decrypting_input_stream
    tink::core::input_stream
    tink::core::output_stream
    tink::core::primitive_set
    tink::core::streaming_aead
    tink::proto::tink_cc_proto
    tink::subtle::random
    tink::subtle::test_util
    tink::util::istream_input_stream
    tink::util::ostream_output_stream
    tink::util::status
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME decrypting_random_access_stream_test
  SRCS decrypting_random_access_stream_test.cc
  DEPS
    absl::memory
    absl::strings
    tink::core::output_stream
    tink::core::primitive_set
    tink::core::random_access_stream
    tink::core::streaming_aead
    tink::proto::tink_cc_proto
    tink::streamingaead::decrypting_random_access_stream
    tink::subtle::random
    tink::subtle::test_util
    tink::util::file_random_access_stream
    tink::util::ostream_output_stream
    tink::util::status
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME shared_input_stream_test
  SRCS shared_input_stream_test.cc
  DEPS
    absl::memory
    absl::status
    absl::strings
    tink::core::input_stream
    tink::streamingaead::buffered_input_stream
    tink::streamingaead::shared_input_stream
    tink::subtle::random
    tink::subtle::test_util
    tink::util::istream_input_stream
    tink::util::status
    tink::util::test_matchers
)

tink_cc_test(
  NAME shared_random_access_stream_test
  SRCS shared_random_access_stream_test.cc
  DEPS
    absl::memory
    absl::strings
    tink::core::random_access_stream
    tink::streamingaead::shared_random_access_stream
    tink::util::buffer
    tink::util::file_random_access_stream
    tink::util::status
    tink::util::test_util
)

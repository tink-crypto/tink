tink_module(streamingaead)

tink_cc_library(
  NAME streaming_aead_wrapper
  SRCS
    streaming_aead_wrapper.cc
    streaming_aead_wrapper.h
  DEPS
    tink::core::crypto_format
    tink::core::input_stream
    tink::core::output_stream
    tink::core::primitive_set
    tink::core::primitive_wrapper
    tink::core::registry
    tink::core::streaming_aead
    tink::util::status
    tink::util::statusor
    tink::proto::tink
    absl::strings
)

# tests

tink_cc_test(
  NAME streaming_aead_wrapper_test
  SRCS streaming_aead_wrapper_test.cc
  DEPS
    tink::streamingaead::streaming_aead_wrapper
    tink::core::input_stream
    tink::core::output_stream
    tink::core::primitive_set
    tink::core::streaming_aead
    tink::util::istream_input_stream
    tink::util::ostream_output_stream
    tink::util::status
    tink::util::test_util
    tink::proto::tink
)

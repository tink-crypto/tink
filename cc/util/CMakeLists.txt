tink_module(util)

tink_cc_library(
  NAME constants
  SRCS
    constants.cc
    constants.h
  DEPS
    absl::base
)

tink_cc_library(
  NAME errors
  SRCS
    errors.cc
    errors.h
  DEPS
    tink::util::status
)

tink_cc_library(
  NAME enums
  SRCS
    enums.cc
    enums.h
  DEPS
    tink::subtle::common_enums
    tink::proto::common_cc_proto
    tink::proto::ecdsa_cc_proto
    tink::proto::tink_cc_proto
    absl::strings
)

tink_cc_library(
  NAME status
  SRCS
    status.cc
    status.h
  PUBLIC
)

tink_cc_library(
  NAME statusor
  SRCS
    statusor.h
  DEPS
    tink::util::status
  PUBLIC
)

tink_cc_library(
  NAME validation
  SRCS
    validation.cc
    validation.h
  DEPS
    tink::util::errors
    tink::util::status
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME file_input_stream
  SRCS
    file_input_stream.cc
    file_input_stream.h
  DEPS
    tink::util::errors
    tink::util::status
    tink::util::statusor
    tink::core::input_stream
    absl::memory
)

tink_cc_library(
  NAME file_output_stream
  SRCS
    file_output_stream.cc
    file_output_stream.h
  DEPS
    tink::util::errors
    tink::util::status
    tink::util::statusor
    tink::core::output_stream
    absl::memory
)

tink_cc_library(
  NAME istream_input_stream
  SRCS
    istream_input_stream.cc
    istream_input_stream.h
  DEPS
    tink::util::errors
    tink::util::status
    tink::util::statusor
    tink::core::input_stream
    absl::memory
)

tink_cc_library(
  NAME ostream_output_stream
  SRCS
    ostream_output_stream.cc
    ostream_output_stream.h
  DEPS
    tink::util::errors
    tink::util::status
    tink::util::statusor
    tink::core::output_stream
    absl::memory
)

tink_cc_library(
  NAME test_util
  SRCS
    test_util.cc
    test_util.h
  DEPS
    tink::util::enums
    tink::util::protobuf_helper
    tink::util::status
    tink::util::statusor
    tink::core::aead
    tink::core::cleartext_keyset_handle
    tink::core::deterministic_aead
    tink::core::hybrid_decrypt
    tink::core::hybrid_encrypt
    tink::core::input_stream
    tink::core::keyset_handle
    tink::core::mac
    tink::core::output_stream
    tink::core::public_key_sign
    tink::core::public_key_verify
    tink::core::streaming_aead
    tink::aead::aes_gcm_key_manager
    tink::subtle::subtle_util_boringssl
    tink::proto::aes_gcm_cc_proto
    tink::proto::common_cc_proto
    tink::proto::ecdsa_cc_proto
    tink::proto::ecies_aead_hkdf_cc_proto
    tink::proto::ed25519_cc_proto
    tink::proto::tink_cc_proto
    absl::memory
    absl::strings
)

tink_cc_library(
  NAME test_matchers
  SRCS
    test_matchers.h
  DEPS
    tink::util::status
    gmock
)

tink_cc_library(
  NAME test_keyset_handle
  SRCS
    test_keyset_handle.cc
    test_keyset_handle.h
  DEPS
    tink::core::keyset_handle
    tink::proto::tink_cc_proto
    absl::memory
)

tink_cc_library(
  NAME protobuf_helper
  SRCS protobuf_helper.h
  DEPS protobuf::libprotobuf-lite
)

# tests

tink_cc_test(
  NAME errors_test
  SRCS
    errors_test.cc
  DEPS
    tink::util::errors
    tink::util::status
)

tink_cc_test(
  NAME enums_test
  SRCS
    enums_test.cc
  DEPS
    tink::util::enums
    tink::subtle::common_enums
    tink::proto::common_cc_proto
)

tink_cc_test(
  NAME file_input_stream_test
  SRCS
    file_input_stream_test.cc
  DEPS
    tink::util::file_input_stream
    tink::util::test_util
    tink::subtle::random
    absl::memory
    absl::strings
)

tink_cc_test(
  NAME file_output_stream_test
  SRCS
    file_output_stream_test.cc
  DEPS
    tink::util::file_output_stream
    tink::util::test_util
    tink::subtle::random
    absl::memory
    absl::strings
)

tink_cc_test(
  NAME istream_input_stream_test
  SRCS
    istream_input_stream_test.cc
  DEPS
    tink::util::istream_input_stream
    tink::util::test_util
    tink::subtle::random
    absl::memory
    absl::strings
)

tink_cc_test(
  NAME ostream_output_stream_test
  SRCS
    ostream_output_stream_test.cc
  DEPS
    tink::util::ostream_output_stream
    tink::util::test_util
    tink::subtle::random
    absl::memory
    absl::strings
)

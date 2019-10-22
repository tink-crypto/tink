tink_module(util)

tink_cc_library(
  NAME buffer
  SRCS
    buffer.cc
    buffer.h
  DEPS
    absl::memory
    tink::util::status
    tink::util::statusor
)

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
  DEPS
    absl::base
    absl::strings
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
  NAME file_random_access_stream
  SRCS
    file_random_access_stream.cc
    file_random_access_stream.h
  DEPS
    tink::util::buffer
    tink::util::errors
    tink::util::status
    tink::util::statusor
    tink::core::random_access_stream
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
    tink::util::constants
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
    tink::core::kms_client
    tink::core::mac
    tink::core::output_stream
    tink::core::public_key_sign
    tink::core::public_key_verify
    tink::core::random_access_stream
    tink::core::streaming_aead
    tink::aead::aes_ctr_hmac_aead_key_manager
    tink::aead::aes_gcm_key_manager
    tink::aead::xchacha20_poly1305_key_manager
    tink::subtle::random
    tink::subtle::subtle_util_boringssl
    tink::proto::aes_ctr_hmac_aead_cc_proto
    tink::proto::aes_gcm_cc_proto
    tink::proto::common_cc_proto
    tink::proto::ecdsa_cc_proto
    tink::proto::ecies_aead_hkdf_cc_proto
    tink::proto::ed25519_cc_proto
    tink::proto::tink_cc_proto
    tink::proto::xchacha20_poly1305_cc_proto
    tink::util::buffer
    absl::core_headers
    absl::memory
    absl::strings
    absl::synchronization
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
  NAME protobuf_helper
  SRCS protobuf_helper.h
  DEPS protobuf::libprotobuf-lite
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
  NAME input_stream_util
  SRCS
    input_stream_util.cc
    input_stream_util.h
  DEPS
    tink::core::input_stream
    tink::util::statusor
    absl::strings
)

# tests

tink_cc_test(
  NAME buffer_test
  SRCS
    buffer_test.cc
  DEPS
    absl::memory
    absl::strings
    tink::subtle::random
    tink::util::buffer
    tink::util::status
    tink::util::test_matchers
)

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
  NAME file_random_access_stream_test
  SRCS
    file_random_access_stream_test.cc
  DEPS
    tink::util::buffer
    tink::util::file_random_access_stream
    tink::util::test_util
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

tink_cc_test(
  NAME test_util_test
  SRCS
    test_util_test.cc
  DEPS
    tink::proto::aes_gcm_cc_proto
    tink::proto::tink_cc_proto
    tink::util::test_util
    tink::subtle::random
    absl::strings
    gmock
)

tink_cc_test(
  NAME validation_test
  SRCS
    validation_test.cc
  DEPS
    tink::util::test_matchers
    tink::util::validation
    gmock
)

tink_cc_test(
  NAME input_stream_util_test
  SRCS input_stream_util_test.cc
  DEPS
    tink::util::input_stream_util
    tink::util::istream_input_stream
    tink::util::test_matchers
    absl::memory
    gmock
)

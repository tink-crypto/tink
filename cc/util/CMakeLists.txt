tink_module(util)

tink_cc_library(
  NAME buffer
  SRCS
    buffer.cc
    buffer.h
  DEPS
    tink::util::status
    tink::util::statusor
    absl::memory
    absl::status
)

tink_cc_library(
  NAME constants
  SRCS
    constants.cc
    constants.h
  DEPS
    absl::core_headers
)

tink_cc_library(
  NAME errors
  SRCS
    errors.h
  DEPS
    tink::util::status
    absl::str_format
)

tink_cc_library(
  NAME enums
  SRCS
    enums.cc
    enums.h
  DEPS
    tink::util::statusor
    absl::status
    absl::strings
    tink::subtle::common_enums
    tink::proto::common_cc_proto
    tink::proto::ecdsa_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME status
  SRCS
    status.cc
    status.h
  DEPS
    absl::core_headers
    absl::status
    absl::strings
  PUBLIC
)

tink_cc_library(
  NAME statusor
  SRCS
    statusor.h
    statusor.h
  DEPS
    tink::util::status
    absl::statusor
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
    absl::status
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
    absl::memory
    absl::status
    tink::core::input_stream
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
    absl::memory
    absl::status
    tink::core::output_stream
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
    absl::memory
    absl::status
    tink::core::random_access_stream
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
    absl::memory
    absl::status
    tink::core::input_stream
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
    absl::memory
    absl::status
    tink::core::output_stream
)

tink_cc_library(
  NAME test_util
  SRCS
    test_util.cc
    test_util.h
  DEPS
    tink::util::buffer
    tink::util::constants
    tink::util::enums
    tink::util::protobuf_helper
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    absl::core_headers
    absl::memory
    absl::status
    absl::strings
    absl::cord
    absl::synchronization
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
    tink::aead::cord_aead
    tink::aead::xchacha20_poly1305_key_manager
    tink::daead::aes_siv_key_manager
    tink::internal::ec_util
    tink::subtle::common_enums
    tink::subtle::random
    tink::subtle::mac::stateful_mac
    tink::proto::aes_ctr_hmac_aead_cc_proto
    tink::proto::aes_siv_cc_proto
    tink::proto::common_cc_proto
    tink::proto::ecdsa_cc_proto
    tink::proto::ecies_aead_hkdf_cc_proto
    tink::proto::ed25519_cc_proto
    tink::proto::tink_cc_proto
    tink::proto::xchacha20_poly1305_cc_proto
)

tink_cc_library(
  NAME test_matchers
  SRCS
    test_matchers.h
  DEPS
    tink::util::status
    tink::util::statusor
    gmock
    absl::status
)

tink_cc_library(
  NAME protobuf_helper
  SRCS
    protobuf_helper.h
  DEPS
    protobuf::libprotobuf-lite
)

tink_cc_library(
  NAME test_keyset_handle
  SRCS
    test_keyset_handle.cc
    test_keyset_handle.h
  DEPS
    absl::memory
    tink::core::keyset_handle
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME input_stream_util
  SRCS
    input_stream_util.cc
    input_stream_util.h
  DEPS
    tink::util::secret_data
    tink::util::statusor
    absl::algorithm_container
    absl::strings
    absl::span
    tink::core::input_stream
)

tink_cc_library(
  NAME keyset_util
  SRCS
    keyset_util.cc
    keyset_util.h
  DEPS
    tink::proto::tink_cc_proto
)

# tests

tink_cc_test(
  NAME buffer_test
  SRCS
    buffer_test.cc
  DEPS
    tink::util::buffer
    tink::util::status
    tink::util::test_matchers
    gmock
    absl::memory
    absl::status
    absl::strings
    tink::subtle::random
)

tink_cc_test(
  NAME errors_test
  SRCS
    errors_test.cc
  DEPS
    tink::util::errors
    tink::util::status
    gmock
    absl::status
)

tink_cc_test(
  NAME enums_test
  SRCS
    enums_test.cc
  DEPS
    tink::util::enums
    gmock
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
    gmock
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
    gmock
    absl::memory
    absl::strings
    tink::subtle::random
)

tink_cc_test(
  NAME file_random_access_stream_test
  SRCS
    file_random_access_stream_test.cc
  DEPS
    tink::util::buffer
    tink::util::file_random_access_stream
    tink::util::test_util
    gmock
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
    gmock
    absl::memory
    absl::strings
    tink::subtle::random
)

tink_cc_test(
  NAME ostream_output_stream_test
  SRCS
    ostream_output_stream_test.cc
  DEPS
    tink::util::ostream_output_stream
    tink::util::test_util
    gmock
    absl::memory
    absl::strings
    tink::subtle::random
)

tink_cc_test(
  NAME test_util_test
  SRCS
    test_util_test.cc
  DEPS
    tink::util::test_matchers
    tink::util::test_util
    gmock
    tink::subtle::subtle
    tink::proto::aes_gcm_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME validation_test
  SRCS
    validation_test.cc
  DEPS
    tink::util::test_matchers
    tink::util::validation
    gmock
    absl::status
)

tink_cc_test(
  NAME input_stream_util_test
  SRCS
    input_stream_util_test.cc
  DEPS
    tink::util::input_stream_util
    tink::util::istream_input_stream
    tink::util::secret_data
    tink::util::status
    tink::util::test_matchers
    gmock
    absl::memory
)

tink_cc_library(
  NAME secret_data_internal
  SRCS
    secret_data_internal.h
  DEPS
    absl::strings
    absl::base
    crypto
)

tink_cc_library(
  NAME secret_data
  SRCS
    secret_data.h
  DEPS
    tink::util::secret_data_internal
    absl::strings
)

tink_cc_test(
  NAME secret_data_test
  SRCS
    secret_data_test.cc
  DEPS
    tink::util::secret_data
    gmock
    absl::strings
)

tink_cc_library(
  NAME secret_proto
  SRCS
    secret_proto.h
  DEPS
    tink::util::secret_data
    protobuf::libprotobuf
    absl::memory
)

tink_cc_test(
  NAME secret_proto_test
  SRCS
    secret_proto_test.cc
  DEPS
    tink::util::secret_proto
    protobuf::libprotobuf
    gmock
    absl::memory
    tink::proto::test_proto_cc_proto
)

tink_cc_library(
  NAME fake_kms_client
  SRCS
    fake_kms_client.cc
    fake_kms_client.h
  DEPS
    tink::util::errors
    tink::util::status
    tink::util::statusor
    absl::status
    absl::strings
    tink::core::aead
    tink::core::binary_keyset_reader
    tink::core::binary_keyset_writer
    tink::core::cleartext_keyset_handle
    tink::core::keyset_handle
    tink::core::kms_client
    tink::core::kms_clients
    tink::aead::aead_key_templates
)

tink_cc_test(
  NAME fake_kms_client_test
  SRCS
    fake_kms_client_test.cc
  DEPS
    tink::util::fake_kms_client
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    gmock
    tink::aead::aead_config
    tink::aead::aead_key_templates
    tink::proto::kms_aead_cc_proto
    tink::proto::kms_envelope_cc_proto
)

tink_cc_test(
  NAME status_test
  SRCS
    status_test.cc
  DEPS
    tink::util::status
    gmock
    absl::status
)

tink_cc_test(
  NAME statusor_test
  SRCS
    statusor_test.cc
  DEPS
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    gmock
    absl::memory
    absl::status
    absl::statusor
)

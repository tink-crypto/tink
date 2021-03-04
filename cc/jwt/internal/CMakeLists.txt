tink_module(jwt::internal)

tink_cc_library(
  NAME raw_jwt_hmac_key_manager
  SRCS
    raw_jwt_hmac_key_manager.cc
    raw_jwt_hmac_key_manager.h
  DEPS
    tink::core::key_type_manager
    tink::core::mac
    tink::subtle::hmac_boringssl
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
    tink::proto::common_cc_proto
    tink::proto::jwt_hmac_cc_proto
    tink::proto::tink_cc_proto
    absl::memory
    absl::strings
)

tink_cc_library(
  NAME json_util
  SRCS
    json_util.cc
    json_util.h
  DEPS
    protobuf::libprotobuf
    tink::util::status
    tink::util::statusor
    absl::strings
)

tink_cc_test(
  NAME raw_jwt_hmac_key_manager_test
  SRCS raw_jwt_hmac_key_manager_test.cc
  DEPS
    tink::jwt::internal::raw_jwt_hmac_key_manager
    tink::core::key_manager_impl
    tink::core::mac
    tink::mac::mac_config
    tink::core::registry
    tink::core::keyset_handle
    tink::util::istream_input_stream
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::jwt_hmac_cc_proto
    gmock
)

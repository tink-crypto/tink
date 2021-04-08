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
  NAME json_util_test
  SRCS json_util_test.cc
  DEPS
    tink::jwt::internal::json_util
    tink::util::test_matchers
    tink::util::test_util
    gmock
)

tink_cc_library(
  NAME jwt_format
  SRCS
    jwt_format.cc
    jwt_format.h
  DEPS
    tink::jwt::internal::json_util
    tink::util::status
    tink::util::statusor
    absl::strings
)

tink_cc_test(
  NAME jwt_format_test
  SRCS jwt_format_test.cc
  DEPS
    tink::jwt::internal::jwt_format
    tink::util::test_matchers
    tink::util::test_util
    gmock
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

tink_cc_library(
  NAME jwt_mac_impl
  SRCS
    jwt_mac_impl.cc
    jwt_mac_impl.h
  DEPS
    tink::jwt::internal::json_util
    tink::jwt::internal::jwt_format
    tink::core::mac
    tink::jwt::jwt_validator
    tink::jwt::raw_jwt
    tink::jwt::jwt_mac
    tink::util::status
    tink::util::statusor
    absl::strings
)

tink_cc_test(
  NAME jwt_mac_impl_test
  SRCS jwt_mac_impl_test.cc
  DEPS
    tink::jwt::internal::jwt_format
    tink::jwt::internal::jwt_mac_impl
    tink::jwt::jwt_mac
    tink::jwt::jwt_validator
    tink::jwt::raw_jwt
    tink::jwt::verified_jwt
    tink::subtle::hmac_boringssl
    tink::util::constants
    tink::util::enums
    tink::util::errors
    tink::util::protobuf_helper
    tink::util::secret_data
    tink::util::test_matchers
    tink::util::test_util
    gmock
    absl::strings
)

tink_cc_library(
  NAME jwt_hmac_key_manager
  SRCS
    jwt_hmac_key_manager.cc
    jwt_hmac_key_manager.h
  DEPS
    tink::core::key_type_manager
    tink::core::mac
    tink::jwt::jwt_mac
    tink::jwt::internal::jwt_mac_impl
    tink::jwt::internal::raw_jwt_hmac_key_manager
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
    absl::memory
    absl::strings
)

tink_cc_test(
  NAME jwt_hmac_key_manager_test
  SRCS jwt_hmac_key_manager_test.cc
  DEPS
    tink::jwt::internal::jwt_hmac_key_manager
    tink::core::key_manager_impl
    tink::core::mac
    tink::jwt::jwt_mac
    tink::util::istream_input_stream
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::jwt_hmac_cc_proto
    gmock
)

tink_cc_library(
  NAME jwt_mac_wrapper
  SRCS
    jwt_mac_wrapper.cc
    jwt_mac_wrapper.h
  DEPS
    tink::core::primitive_set
    tink::core::primitive_wrapper
    tink::jwt::jwt_mac
    tink::util::status
    tink::util::statusor
)

tink_cc_test(
  NAME jwt_mac_wrapper_test
  SRCS jwt_mac_wrapper_test.cc
  DEPS
    tink::jwt::internal::jwt_hmac_key_manager
    tink::jwt::internal::jwt_mac_wrapper
    tink::core::keyset_manager
    tink::core::primitive_set
    tink::proto::jwt_hmac_cc_proto
    tink::proto::tink_cc_proto
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    gmock
)

tink_cc_library(
  NAME raw_jwt_ecdsa_sign_key_manager
  SRCS
    raw_jwt_ecdsa_sign_key_manager.cc
    raw_jwt_ecdsa_sign_key_manager.h
  DEPS
    tink::jwt::internal::raw_jwt_ecdsa_verify_key_manager
    tink::proto::jwt_ecdsa_cc_proto
    tink::util::constants
    tink::util::enums
    tink::util::errors
    tink::util::protobuf_helper
    tink::util::status
    tink::util::statusor
    tink::util::validation
    tink::subtle::ecdsa_sign_boringssl
    tink::subtle::subtle_util_boringssl
    tink::core::public_key_sign
    tink::core::private_key_type_manager
    absl::memory
    absl::strings
)

tink_cc_test(
  NAME raw_jwt_ecdsa_sign_key_manager_test
  SRCS raw_jwt_ecdsa_sign_key_manager_test.cc
  DEPS
    tink::jwt::internal::raw_jwt_ecdsa_sign_key_manager
    tink::jwt::internal::raw_jwt_ecdsa_verify_key_manager
    tink::core::public_key_sign
    tink::core::public_key_verify
    tink::subtle::ecdsa_verify_boringssl
    tink::subtle::subtle_util_boringssl
    tink::util::enums
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    gmock
)

tink_cc_library(
  NAME raw_jwt_ecdsa_verify_key_manager
  SRCS
    raw_jwt_ecdsa_verify_key_manager.cc
    raw_jwt_ecdsa_verify_key_manager.h
  DEPS
    tink::core::key_type_manager
    tink::core::public_key_verify
    tink::subtle::ecdsa_verify_boringssl
    tink::subtle::subtle_util_boringssl
    tink::proto::common_cc_proto
    tink::proto::jwt_ecdsa_cc_proto
    tink::util::constants
    tink::util::enums
    tink::util::errors
    tink::util::protobuf_helper
    tink::util::status
    tink::util::statusor
    tink::util::validation
    absl::memory
    absl::strings
)

tink_cc_test(
  NAME raw_jwt_ecdsa_verify_key_manager_test
  SRCS raw_jwt_ecdsa_verify_key_manager_test.cc
  DEPS
    tink::jwt::internal::raw_jwt_ecdsa_sign_key_manager
    tink::jwt::internal::raw_jwt_ecdsa_verify_key_manager
    tink::core::public_key_sign
    tink::core::public_key_verify
    tink::subtle::ecdsa_sign_boringssl
    tink::subtle::subtle_util_boringssl
    tink::util::enums
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::jwt_ecdsa_cc_proto
    gmock
)

tink_cc_library(
  NAME jwt_public_key_sign_impl
  SRCS
    jwt_public_key_sign_impl.cc
    jwt_public_key_sign_impl.h
  DEPS
    tink::jwt::internal::jwt_format
    tink::core::public_key_sign
    tink::jwt::jwt_public_key_sign
    tink::jwt::raw_jwt
    tink::util::status
    tink::util::statusor
    absl::strings
)

tink_cc_library(
  NAME jwt_public_key_verify_impl
  SRCS
    jwt_public_key_verify_impl.cc
    jwt_public_key_verify_impl.h
  DEPS
    tink::jwt::internal::jwt_format
    tink::core::public_key_verify
    tink::jwt::jwt_public_key_verify
    tink::jwt::jwt_validator
    tink::jwt::raw_jwt
    tink::jwt::verified_jwt
    tink::util::status
    tink::util::statusor
    absl::strings
)

tink_cc_test(
  NAME jwt_public_key_sign_verify_impl_test
  SRCS jwt_public_key_sign_verify_impl_test.cc
  DEPS
    tink::jwt::internal::jwt_format
    tink::jwt::internal::jwt_public_key_sign_impl
    tink::jwt::internal::jwt_public_key_verify_impl
    tink::jwt::jwt_public_key_sign
    tink::jwt::jwt_public_key_verify
    tink::jwt::jwt_validator
    tink::jwt::raw_jwt
    tink::jwt::verified_jwt
    tink::subtle::ecdsa_sign_boringssl
    tink::subtle::ecdsa_verify_boringssl
    tink::util::test_matchers
    absl::strings
    gmock
)

tink_module(jwt)

add_subdirectory(internal)

tink_cc_library(
  NAME raw_jwt
  SRCS
    raw_jwt.cc
    raw_jwt.h
  DEPS
    protobuf::libprotobuf
    absl::status
    absl::strings
    absl::str_format
    absl::time
    tink::jwt::internal::json_util
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME jwt_validator
  SRCS
    jwt_validator.cc
    jwt_validator.h
  DEPS
    tink::jwt::raw_jwt
    absl::status
    absl::strings
    absl::time
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME verified_jwt
  SRCS
    verified_jwt.cc
    verified_jwt.h
  DEPS
    tink::jwt::raw_jwt
    protobuf::libprotobuf
    absl::strings
    absl::str_format
    absl::time
    tink::jwt::internal::json_util
    tink::util::status
    tink::util::statusor
)

# tests

tink_cc_test(
  NAME raw_jwt_test
  SRCS
    raw_jwt_test.cc
  DEPS
    tink::jwt::raw_jwt
    gmock
    absl::strings
    absl::time
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME verified_jwt_test
  SRCS
    verified_jwt_test.cc
  DEPS
    tink::jwt::jwt_mac
    tink::jwt::jwt_validator
    tink::jwt::raw_jwt
    tink::jwt::verified_jwt
    gmock
    absl::status
    absl::strings
    tink::jwt::internal::jwt_mac_impl
    tink::jwt::internal::jwt_mac_internal
    tink::subtle::hmac_boringssl
    tink::util::constants
    tink::util::enums
    tink::util::errors
    tink::util::protobuf_helper
    tink::util::secret_data
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME jwt_validator_test
  SRCS
    jwt_validator_test.cc
  DEPS
    tink::jwt::jwt_validator
    tink::jwt::raw_jwt
    gmock
    absl::strings
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_library(
  NAME jwt_mac
  SRCS
    jwt_mac.h
  DEPS
    tink::jwt::jwt_validator
    tink::jwt::raw_jwt
    tink::jwt::verified_jwt
    absl::strings
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME jwt_public_key_sign
  SRCS
    jwt_public_key_sign.h
  DEPS
    absl::strings
    tink::jwt::raw_jwt
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME jwt_public_key_verify
  SRCS
    jwt_public_key_verify.h
  DEPS
    absl::strings
    tink::jwt::jwt_validator
    tink::jwt::verified_jwt
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME jwk_set_converter
  SRCS
    jwk_set_converter.cc
    jwk_set_converter.h
  DEPS
    tink::jwt::jwt_public_key_sign
    tink::jwt::raw_jwt
    absl::strings
    tink::core::binary_keyset_writer
    tink::core::keyset_handle
    tink::jwt::internal::json_util
    tink::jwt::internal::jwt_format
    tink::util::keyset_util
    tink::util::statusor
    tink::proto::common_cc_proto
    tink::proto::jwt_ecdsa_cc_proto
    tink::proto::jwt_rsa_ssa_pkcs1_cc_proto
    tink::proto::jwt_rsa_ssa_pss_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME jwt_mac_config
  SRCS
    jwt_mac_config.cc
    jwt_mac_config.h
  DEPS
    absl::core_headers
    absl::memory
    tink::core::registry
    tink::config::config_util
    tink::config::tink_fips
    tink::jwt::internal::jwt_hmac_key_manager
    tink::jwt::internal::jwt_mac_wrapper
    tink::util::status
    tink::proto::config_cc_proto
)

tink_cc_library(
  NAME jwt_signature_config
  SRCS
    jwt_signature_config.cc
    jwt_signature_config.h
  DEPS
    absl::core_headers
    absl::memory
    tink::core::registry
    tink::config::config_util
    tink::config::tink_fips
    tink::jwt::internal::jwt_ecdsa_sign_key_manager
    tink::jwt::internal::jwt_ecdsa_verify_key_manager
    tink::jwt::internal::jwt_public_key_sign_wrapper
    tink::jwt::internal::jwt_public_key_verify_wrapper
    tink::jwt::internal::jwt_rsa_ssa_pkcs1_sign_key_manager
    tink::jwt::internal::jwt_rsa_ssa_pkcs1_verify_key_manager
    tink::jwt::internal::jwt_rsa_ssa_pss_sign_key_manager
    tink::jwt::internal::jwt_rsa_ssa_pss_verify_key_manager
    tink::util::status
    tink::proto::config_cc_proto
)

tink_cc_library(
  NAME jwt_key_templates
  SRCS
    jwt_key_templates.cc
    jwt_key_templates.h
  DEPS
    crypto
    tink::internal::ssl_unique_ptr
    tink::subtle::subtle_util_boringssl
    tink::util::statusor
    tink::proto::common_cc_proto
    tink::proto::jwt_ecdsa_cc_proto
    tink::proto::jwt_hmac_cc_proto
    tink::proto::jwt_rsa_ssa_pkcs1_cc_proto
    tink::proto::jwt_rsa_ssa_pss_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME jwt_key_templates_test
  SRCS
    jwt_key_templates_test.cc
  DEPS
    tink::jwt::jwt_key_templates
    tink::jwt::jwt_mac
    tink::jwt::jwt_mac_config
    tink::jwt::jwt_public_key_sign
    tink::jwt::jwt_public_key_verify
    tink::jwt::jwt_signature_config
    tink::jwt::jwt_validator
    tink::jwt::raw_jwt
    tink::jwt::verified_jwt
    gmock
    tink::util::status
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME jwk_set_converter_test
  SRCS
    jwk_set_converter_test.cc
  DEPS
    tink::jwt::jwk_set_converter
    tink::jwt::jwt_public_key_sign
    tink::jwt::jwt_public_key_verify
    tink::jwt::jwt_signature_config
    tink::jwt::jwt_validator
    tink::jwt::verified_jwt
    protobuf::libprotobuf
    gmock
    absl::strings
    tink::core::cleartext_keyset_handle
    tink::core::json_keyset_reader
    tink::core::json_keyset_writer
    tink::core::keyset_handle
    tink::jwt::internal::json_util
    tink::util::test_matchers
    tink::proto::jwt_ecdsa_cc_proto
    tink::proto::jwt_rsa_ssa_pkcs1_cc_proto
)

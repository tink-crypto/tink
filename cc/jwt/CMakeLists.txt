tink_module(jwt)

add_subdirectory(internal)

tink_cc_library(
  NAME raw_jwt
  SRCS
    raw_jwt.cc
    raw_jwt.h
  DEPS
    tink::jwt::internal::json_util
    tink::util::status
    tink::util::statusor
    protobuf::libprotobuf
    absl::strings
    absl::time
)

tink_cc_library(
  NAME jwt_validator
  SRCS
    jwt_validator.cc
    jwt_validator.h
  DEPS
    tink::jwt::raw_jwt
    tink::util::status
    tink::util::statusor
    protobuf::libprotobuf
    absl::strings
    absl::time
)

tink_cc_library(
  NAME verified_jwt
  SRCS
    verified_jwt.cc
    verified_jwt.h
  DEPS
    tink::jwt::raw_jwt
    tink::util::status
    tink::util::statusor
    protobuf::libprotobuf
    absl::strings
    absl::time
)

# tests

tink_cc_test(
  NAME raw_jwt_test
  SRCS raw_jwt_test.cc
  DEPS
    tink::jwt::raw_jwt
    tink::util::status
    tink::util::statusor
    tink::util::test_util
    protobuf::libprotobuf
    absl::strings
    gmock
)

tink_cc_test(
  NAME verified_jwt_test
  SRCS verified_jwt_test.cc
  DEPS
    tink::jwt::jwt_mac
    tink::jwt::jwt_validator
    tink::jwt::raw_jwt
    tink::jwt::verified_jwt
    tink::jwt::internal::jwt_mac_impl
    tink::subtle::hmac_boringssl
    tink::util::constants
    tink::util::enums
    tink::util::errors
    tink::util::protobuf_helper
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_util
    protobuf::libprotobuf
    absl::strings
    gmock
)

tink_cc_test(
  NAME jwt_validator_test
  SRCS jwt_validator_test.cc
  DEPS
    tink::jwt::raw_jwt
    tink::jwt::jwt_validator
    tink::util::status
    tink::util::statusor
    tink::util::test_util
    protobuf::libprotobuf
    absl::strings
    gmock
)

tink_cc_library(
  NAME jwt_mac
  SRCS mac.h
  DEPS
    tink::jwt::jwt_validator
    tink::jwt::raw_jwt
    tink::jwt::verified_jwt
    tink::util::status
    tink::util::statusor
    absl::strings
)

tink_cc_library(
  NAME jwt_public_key_sign
  SRCS jwt_public_key_sign.h
  DEPS
    tink::jwt::raw_jwt
    tink::util::statusor
    absl::strings
)

tink_cc_library(
  NAME jwt_public_key_verify
  SRCS jwt_public_key_verify.h
  DEPS
    tink::jwt::jwt_validator
    tink::jwt::verified_jwt
    tink::util::status
    absl::strings
)

tink_cc_library(
  NAME jwt_mac_config
  SRCS
    jwt_mac_config.cc
    jwt_mac_config.h
  DEPS
    tink::jwt::internal::jwt_hmac_key_manager
    tink::jwt::internal::jwt_mac_wrapper
    tink::config::config_util
    tink::config::tink_fips
    tink::core::registry
    tink::util::status
    tink::proto::config_cc_proto
    absl::base
    absl::memory
)


tink_cc_library(
  NAME jwt_signature_config
  SRCS
    jwt_signature_config.cc
    jwt_signature_config.h
  DEPS
    tink::jwt::internal::jwt_ecdsa_sign_key_manager
    tink::jwt::internal::jwt_ecdsa_verify_key_manager
    tink::jwt::internal::jwt_rsa_ssa_pkcs1_sign_key_manager
    tink::jwt::internal::jwt_rsa_ssa_pkcs1_verify_key_manager
    tink::jwt::internal::jwt_rsa_ssa_pss_sign_key_manager
    tink::jwt::internal::jwt_rsa_ssa_pss_verify_key_manager
    tink::jwt::internal::jwt_public_key_sign_wrapper
    tink::jwt::internal::jwt_public_key_verify_wrapper
    tink::config::config_util
    tink::config::tink_fips
    tink::core::registry
    tink::util::status
    tink::proto::config_cc_proto
    absl::base
    absl::memory
)

tink_cc_library(
  NAME jwt_key_templates
  SRCS
    jwt_key_templates.cc
    jwt_key_templates.h
  DEPS
    tink::proto::common_cc_proto
    tink::proto::jwt_ecdsa_cc_proto
    tink::proto::jwt_rsa_ssa_pkcs1_cc_proto
    tink::proto::jwt_rsa_ssa_pss_cc_proto
    tink::proto::jwt_hmac_cc_proto
    tink::proto::tink_cc_proto
    tink::subtle::subtle_util_boringssl
    crypto
)

tink_cc_test(
  NAME jwt_key_templates_test
  SRCS jwt_key_templates_test.cc
  DEPS
    tink::jwt::jwt_public_key_sign
    tink::jwt::jwt_public_key_verify
    tink::jwt::jwt_key_templates
    tink::jwt::jwt_mac_config
    tink::jwt::jwt_signature_config
    tink::jwt::jwt_mac
    tink::jwt::jwt_validator
    tink::jwt::raw_jwt
    tink::jwt::verified_jwt
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    protobuf::libprotobuf
    absl::strings
    gmock
)

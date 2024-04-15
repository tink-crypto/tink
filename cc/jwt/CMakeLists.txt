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
    absl::optional
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
    absl::optional
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
    tink::jwt::raw_jwt
    absl::strings
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME jwt_public_key_verify
  SRCS
    jwt_public_key_verify.h
  DEPS
    tink::jwt::jwt_validator
    tink::jwt::verified_jwt
    absl::strings
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME jwk_set_converter
  SRCS
    jwk_set_converter.cc
    jwk_set_converter.h
  DEPS
    protobuf::libprotobuf
    absl::memory
    absl::status
    absl::strings
    absl::optional
    crypto
    tink::core::binary_keyset_writer
    tink::core::keyset_handle
    tink::internal::ec_util
    tink::internal::ssl_unique_ptr
    tink::jwt::internal::json_util
    tink::jwt::internal::jwt_format
    tink::subtle::common_enums
    tink::util::keyset_util
    tink::util::status
    tink::util::statusor
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
    tink::internal::bn_util
    tink::internal::ssl_unique_ptr
    tink::util::statusor
    tink::proto::common_cc_proto
    tink::proto::jwt_ecdsa_cc_proto
    tink::proto::jwt_hmac_cc_proto
    tink::proto::jwt_rsa_ssa_pkcs1_cc_proto
    tink::proto::jwt_rsa_ssa_pss_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME jwt_mac_parameters
  SRCS
    jwt_mac_parameters.h
  DEPS
    tink::core::parameters
)

tink_cc_library(
  NAME jwt_mac_key
  SRCS
    jwt_mac_key.h
  DEPS
    tink::jwt::jwt_mac_parameters
    absl::optional
    tink::core::key
)

tink_cc_library(
  NAME jwt_hmac_parameters
  SRCS
    jwt_hmac_parameters.cc
    jwt_hmac_parameters.h
  DEPS
    tink::jwt::jwt_mac_parameters
    absl::status
    absl::strings
    tink::core::parameters
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME jwt_hmac_key
  SRCS
    jwt_hmac_key.cc
    jwt_hmac_key.h
  DEPS
    tink::jwt::jwt_hmac_parameters
    tink::jwt::jwt_mac_key
    absl::endian
    absl::status
    absl::strings
    absl::string_view
    absl::optional
    tink::core::key
    tink::core::partial_key_access_token
    tink::core::restricted_data
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME jwt_hmac_proto_serialization
  SRCS
    jwt_hmac_proto_serialization.cc
    jwt_hmac_proto_serialization.h
  DEPS
    tink::jwt::jwt_hmac_parameters
    absl::status
    absl::string_view
    tink::internal::mutable_serialization_registry
    tink::internal::parameters_parser
    tink::internal::parameters_serializer
    tink::internal::proto_parameters_serialization
    tink::util::status
    tink::util::statusor
    tink::proto::common_cc_proto
    tink::proto::jwt_hmac_cc_proto
    tink::proto::tink_cc_proto
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
    tink::util::statusor
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
    absl::memory
    absl::status
    absl::strings
    absl::time
    absl::optional
    tink::core::mac
    tink::jwt::internal::jwt_mac_impl
    tink::jwt::internal::jwt_mac_internal
    tink::subtle::hmac_boringssl
    tink::util::constants
    tink::util::enums
    tink::util::errors
    tink::util::protobuf_helper
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::common_cc_proto
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
    absl::time
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
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
    tink::core::keyset_handle
    tink::config::global_registry
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::tink_cc_proto
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
    tink::jwt::raw_jwt
    tink::jwt::verified_jwt
    protobuf::libprotobuf
    gmock
    absl::strings
    crypto
    tink::core::cleartext_keyset_handle
    tink::core::json_keyset_reader
    tink::core::keyset_handle
    tink::core::keyset_reader
    tink::config::global_registry
    tink::jwt::internal::json_util
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::ecdsa_cc_proto
    tink::proto::jwt_ecdsa_cc_proto
    tink::proto::jwt_rsa_ssa_pkcs1_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME jwt_signature_config_test
  SRCS
    jwt_signature_config_test.cc
  DEPS
    tink::jwt::jwt_key_templates
    tink::jwt::jwt_signature_config
    gmock
    crypto
    tink::core::keyset_handle
    tink::core::registry
    tink::config::global_registry
    tink::internal::fips_utils
    tink::util::test_matchers
)

tink_cc_test(
  NAME jwt_mac_config_test
  SRCS
    jwt_mac_config_test.cc
  DEPS
    tink::jwt::jwt_key_templates
    tink::jwt::jwt_mac_config
    gmock
    crypto
    tink::core::keyset_handle
    tink::core::registry
    tink::config::global_registry
    tink::internal::fips_utils
    tink::util::test_matchers
)

tink_cc_test(
  NAME jwt_hmac_parameters_test
  SRCS
    jwt_hmac_parameters_test.cc
  DEPS
    tink::jwt::jwt_hmac_parameters
    gmock
    absl::status
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_test(
  NAME jwt_hmac_key_test
  SRCS
    jwt_hmac_key_test.cc
  DEPS
    tink::jwt::jwt_hmac_key
    tink::jwt::jwt_hmac_parameters
    gmock
    absl::status
    absl::optional
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_test(
  NAME jwt_hmac_proto_serialization_test
  SRCS
    jwt_hmac_proto_serialization_test.cc
  DEPS
    tink::jwt::jwt_hmac_parameters
    tink::jwt::jwt_hmac_proto_serialization
    gmock
    absl::status
    absl::string_view
    absl::optional
    tink::core::parameters
    tink::internal::mutable_serialization_registry
    tink::internal::proto_parameters_serialization
    tink::internal::serialization
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::common_cc_proto
    tink::proto::jwt_hmac_cc_proto
    tink::proto::tink_cc_proto
)

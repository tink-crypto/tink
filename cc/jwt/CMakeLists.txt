tink_module(jwt)

add_subdirectory(internal)

tink_cc_library(
  NAME jwt_names
  SRCS
    jwt_names.h
  DEPS
    absl::strings
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME jwt_algorithms
  SRCS
    jwt_algorithms.h
  DEPS
    absl::strings
)

tink_cc_library(
  NAME raw_jwt
  SRCS
    raw_jwt.cc
    raw_jwt.h
  DEPS
    tink::jwt::jwt_names
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
    tink::jwt::jwt_names
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
    tink::jwt::jwt_names
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
    tink::jwt::jwt_names
    tink::jwt::raw_jwt
    tink::jwt::verified_jwt
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


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
  NAME json_field_types
  SRCS
    json_field_types.h
)

tink_cc_library(
  NAME json_object
  SRCS
    json_object.cc
    json_object.h
  DEPS
    tink::jwt::internal::json_util
    tink::jwt::json_util
    tink::jwt::json_field_types
    protobuf::libprotobuf
    absl::strings
    absl::time
    absl::flat_hash_map
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME json_util
  SRCS
    json_struct_util.h
  DEPS
    protobuf::libprotobuf
    tink::util::status
    tink::util::statusor
    absl::strings
)

tink_cc_library(
  NAME jwt_object
  SRCS
    jwt_object.cc
    jwt_object.h
  DEPS
    tink::jwt::json_object
    tink::jwt::json_field_types
    tink::jwt::jwt_names
    absl::flat_hash_map
    protobuf::libprotobuf
    absl::strings
    absl::time
    tink::util::status
    tink::util::statusor
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
  NAME json_object_test
  SRCS json_object_test.cc
  DEPS
    tink::jwt::json_object
    tink::jwt::json_util
    tink::jwt::json_field_types
    absl::strings
    absl::flat_hash_map
    tink::util::status
    tink::util::statusor
    tink::util::test_util
    protobuf::libprotobuf
    gmock
)

tink_cc_test(
  NAME jwt_object_test
  SRCS jwt_object_test.cc
  DEPS
    tink::jwt::jwt_object
    tink::jwt::json_field_types
    absl::flat_hash_map
    tink::jwt::json_util
    absl::strings
    tink::util::status
    tink::util::statusor
    tink::util::test_util
    protobuf::libprotobuf
    gmock
)

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

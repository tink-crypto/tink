tink_module(jwt)

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
  NAME json_object
  SRCS
    json_object.cc
    json_object.h
  DEPS
    tink::jwt::json_util
    protobuf::libprotobuf
    absl::strings
    absl::time
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME jwt_object
  SRCS
    jwt_object.cc
    jwt_object.h
  DEPS
    tink::jwt::json_object
    tink::jwt::jwt_names
    protobuf::libprotobuf
    absl::strings
    absl::time
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME json_util
  SRCS
    json_struct_util.h
    json_struct_util.cc
  DEPS
    protobuf::libprotobuf
    tink::util::status
    tink::util::statusor
    absl::strings
)

# tests

tink_cc_test(
  NAME json_object_test
  SRCS json_object_test.cc
  DEPS
    tink::jwt::json_object
    tink::jwt::json_util
    absl::strings
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
    tink::jwt::json_util
    absl::strings
    tink::util::status
    tink::util::statusor
    tink::util::test_util
    protobuf::libprotobuf
    gmock
)

tink_module(jwt)

tink_cc_library(
  NAME jwt_names
  SRCS
    jwt_names.cc
    jwt_names.h
  DEPS
    absl::strings
    absl::strings:str_format
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME jwt
  SRCS
    jwt.cc
    jwt.h
  DEPS
    jwt_names
    protobuf:libprotobuf,
    absl::strings
    absl::strings:str_format
    absl::time
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME json_util
  SRCS
    json_struct_util.h
  DEPS
    protobuf:libprotobuf,
)

# tests

tink_cc_test(
  NAME jwt_test
  SRCS jwt_test.cc
  DEPS
    jwt
    json_util
    absl::strings
    absl::strings:string_view
    tink::util::status
    tink::util::statusor
    tink::util::test_util
    protobuf:libprotobuf,
    gmock,
)

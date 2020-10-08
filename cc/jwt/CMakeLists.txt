tink_module(jwt)

tink_cc_library(
  NAME json_object
  SRCS
    json_object.cc
    json_object.h
  DEPS
    json_util
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
    json_struct_util.cc
  DEPS
    protobuf:libprotobuf,
    tink::util::status,
    tink::util::statusor,
    absl::strings
)

# tests

tink_cc_test(
  NAME json_object_test
  SRCS json_object_test.cc
  DEPS
    json_object
    json_util
    absl::strings
    absl::strings:string_view
    tink::util::status
    tink::util::statusor
    tink::util::test_util
    protobuf:libprotobuf,
    gmock,
)

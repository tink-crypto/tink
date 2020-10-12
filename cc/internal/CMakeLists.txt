tink_module(internal)

tink_cc_library(
  NAME keyset_wrapper
  SRCS
    keyset_wrapper.h
  DEPS
    tink::util::statusor
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME keyset_wrapper_impl
  SRCS
    keyset_wrapper_impl.h
  DEPS
    tink::internal::key_info
    tink::internal::keyset_wrapper
    tink::core::primitive_set
    tink::util::statusor
    tink::util::validation
    tink::proto::tink_cc_proto
)

tink_cc_library(
    NAME key_info
    SRCS
      key_info.h
      key_info.cc
    DEPS
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME keyset_wrapper_impl_test
  SRCS
    keyset_wrapper_impl_test.cc
  DEPS
    tink::internal::keyset_wrapper
    tink::internal::keyset_wrapper_impl
    tink::util::statusor
    tink::util::test_util
    tink::proto::tink_cc_proto
    absl::strings
    absl::flat_hash_map
    gmock
)

tink_cc_test(
  NAME key_info_test
  SRCS key_info_test.cc
  DEPS
    tink::internal::key_info
    tink::proto::tink_cc_proto
    gmock
)

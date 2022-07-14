tink_module(chunkedmac::internal)

tink_cc_library(
  NAME chunked_mac_impl
  SRCS
    chunked_mac_impl.cc
    chunked_mac_impl.h
  DEPS
    absl::strings
    crypto
    tink::core::chunked_mac
    tink::subtle::stateful_cmac_boringssl
    tink::subtle::stateful_hmac_boringssl
    tink::subtle::mac::stateful_mac
    tink::util::enums
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::proto::aes_cmac_cc_proto
    tink::proto::hmac_cc_proto
)

tink_cc_library(
  NAME chunked_mac_wrapper
  SRCS
    chunked_mac_wrapper.cc
    chunked_mac_wrapper.h
  DEPS
    absl::status
    absl::strings
    tink::core::chunked_mac
    tink::core::crypto_format
    tink::core::primitive_set
    tink::core::primitive_wrapper
    tink::internal::util
    tink::util::status
    tink::util::statusor
    tink::proto::tink_cc_proto
)

# tests

tink_cc_test(
  NAME chunked_mac_impl_test
  SRCS
    chunked_mac_impl_test.cc
  DEPS
    tink::chunkedmac::internal::chunked_mac_impl
    gmock
    tink::core::chunked_mac
    tink::subtle::mac::stateful_mac
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::aes_cmac_cc_proto
    tink::proto::common_cc_proto
    tink::proto::hmac_cc_proto
)

tink_cc_test(
  NAME chunked_mac_wrapper_test
  SRCS
    chunked_mac_wrapper_test.cc
  DEPS
    tink::chunkedmac::internal::chunked_mac_impl
    tink::chunkedmac::internal::chunked_mac_wrapper
    gmock
    absl::strings
    tink::core::chunked_mac
    tink::subtle::mac::stateful_mac
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::tink_cc_proto
)

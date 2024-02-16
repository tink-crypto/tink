tink_module(mac::internal)

tink_cc_library(
  NAME chunked_mac_impl
  SRCS
    chunked_mac_impl.cc
    chunked_mac_impl.h
  DEPS
    absl::memory
    absl::status
    absl::strings
    crypto
    tink::core::chunked_mac
    tink::subtle::common_enums
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
    absl::memory
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

tink_cc_library(
  NAME config_v0
  SRCS
    config_v0.cc
    config_v0.h
  DEPS
    tink::mac::internal::chunked_mac_wrapper
    absl::memory
    tink::core::configuration
    tink::internal::configuration_impl
    tink::mac::aes_cmac_key_manager
    tink::mac::hmac_key_manager
    tink::mac::mac_wrapper
    tink::util::status
)

tink_cc_library(
  NAME key_gen_config_v0
  SRCS
    key_gen_config_v0.cc
    key_gen_config_v0.h
  DEPS
    absl::memory
    tink::core::key_gen_configuration
    tink::internal::key_gen_configuration_impl
    tink::mac::aes_cmac_key_manager
    tink::mac::hmac_key_manager
    tink::util::status
)

# tests

tink_cc_test(
  NAME chunked_mac_impl_test
  SRCS
    chunked_mac_impl_test.cc
  DEPS
    tink::mac::internal::chunked_mac_impl
    gmock
    absl::memory
    absl::status
    absl::string_view
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
    tink::mac::internal::chunked_mac_impl
    tink::mac::internal::chunked_mac_wrapper
    gmock
    absl::memory
    absl::status
    absl::strings
    tink::core::chunked_mac
    tink::core::primitive_set
    tink::subtle::mac::stateful_mac
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME chunked_mac_test
  SRCS
    chunked_mac_test.cc
  DEPS
    gmock
    absl::status
    tink::core::chunked_mac
    tink::core::keyset_handle
    tink::core::mac
    tink::config::global_registry
    tink::mac::mac_config
    tink::mac::mac_key_templates
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME config_v0_test
  SRCS
    config_v0_test.cc
  DEPS
    tink::mac::internal::config_v0
    tink::mac::internal::key_gen_config_v0
    gmock
    tink::core::chunked_mac
    tink::core::configuration
    tink::core::key_gen_configuration
    tink::core::keyset_handle
    tink::core::mac
    tink::internal::configuration_impl
    tink::internal::key_gen_configuration_impl
    tink::internal::key_type_info_store
    tink::internal::keyset_wrapper_store
    tink::mac::aes_cmac_key_manager
    tink::mac::hmac_key_manager
    tink::mac::mac_key_templates
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::tink_cc_proto
)

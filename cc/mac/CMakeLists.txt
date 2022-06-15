tink_module(mac)

tink_cc_library(
  NAME mac_wrapper
  SRCS
    mac_wrapper.cc
    mac_wrapper.h
  DEPS
    absl::status
    absl::strings
    tink::core::crypto_format
    tink::core::mac
    tink::core::primitive_set
    tink::core::primitive_wrapper
    tink::internal::util
    tink::util::status
    tink::util::statusor
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME mac_config
  SRCS
    mac_config.cc
    mac_config.h
  DEPS
    tink::mac::aes_cmac_key_manager
    tink::mac::hmac_key_manager
    tink::mac::mac_wrapper
    absl::core_headers
    absl::memory
    tink::core::registry
    tink::config::config_util
    tink::config::tink_fips
    tink::util::status
    tink::proto::config_cc_proto
)

tink_cc_library(
  NAME mac_factory
  SRCS
    mac_factory.cc
    mac_factory.h
  DEPS
    tink::mac::mac_wrapper
    absl::core_headers
    tink::core::key_manager
    tink::core::keyset_handle
    tink::core::mac
    tink::core::registry
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME mac_key_templates
  SRCS
    mac_key_templates.cc
    mac_key_templates.h
  DEPS
    tink::proto::aes_cmac_cc_proto
    tink::proto::common_cc_proto
    tink::proto::hmac_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME aes_cmac_key_manager
  SRCS
    aes_cmac_key_manager.h
  DEPS
    absl::memory
    absl::status
    absl::strings
    tink::core::key_type_manager
    tink::core::key_manager
    tink::core::mac
    tink::subtle::aes_cmac_boringssl
    tink::subtle::random
    tink::util::constants
    tink::util::errors
    tink::util::protobuf_helper
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::validation
    tink::proto::aes_cmac_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME hmac_key_manager
  SRCS
    hmac_key_manager.cc
    hmac_key_manager.h
  DEPS
    absl::memory
    absl::status
    absl::strings
    tink::core::key_type_manager
    tink::core::mac
    tink::subtle::hmac_boringssl
    tink::subtle::random
    tink::util::constants
    tink::util::enums
    tink::util::errors
    tink::util::input_stream_util
    tink::util::protobuf_helper
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::validation
    tink::proto::common_cc_proto
    tink::proto::hmac_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME mac_key_format
  SRCS
    mac_key_format.h
  DEPS
    tink::core::key_format
)

tink_cc_library(
  NAME mac_key
  SRCS
    mac_key.h
  DEPS
    tink::mac::mac_key_format
    absl::statusor
    tink::core::key
)

# tests

tink_cc_test(
  NAME mac_wrapper_test
  SRCS
    mac_wrapper_test.cc
  DEPS
    tink::mac::mac_wrapper
    gmock
    absl::strings
    tink::core::crypto_format
    tink::core::mac
    tink::core::primitive_set
    tink::util::status
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME mac_config_test
  SRCS
    mac_config_test.cc
  DEPS
    tink::mac::hmac_key_manager
    tink::mac::mac_config
    tink::mac::mac_key_templates
    gmock
    absl::status
    crypto
    tink::core::config
    tink::core::keyset_handle
    tink::core::mac
    tink::core::registry
    tink::config::tink_fips
    tink::util::status
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME mac_factory_test
  SRCS
    mac_factory_test.cc
  DEPS
    tink::mac::hmac_key_manager
    tink::mac::mac_config
    tink::mac::mac_factory
    gmock
    tink::core::crypto_format
    tink::core::keyset_handle
    tink::core::mac
    tink::internal::key_info
    tink::util::status
    tink::util::test_keyset_handle
    tink::util::test_util
    tink::proto::common_cc_proto
    tink::proto::hmac_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME mac_key_templates_test
  SRCS
    mac_key_templates_test.cc
  DEPS
    tink::mac::aes_cmac_key_manager
    tink::mac::hmac_key_manager
    tink::mac::mac_key_templates
    gmock
    tink::core::key_manager_impl
    tink::util::test_matchers
    tink::proto::aes_cmac_cc_proto
    tink::proto::common_cc_proto
    tink::proto::hmac_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME aes_cmac_key_manager_test
  SRCS
    aes_cmac_key_manager_test.cc
  DEPS
    tink::mac::aes_cmac_key_manager
    gmock
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::aes_cmac_cc_proto
)

tink_cc_test(
  NAME hmac_key_manager_test
  SRCS
    hmac_key_manager_test.cc
  DEPS
    tink::mac::hmac_key_manager
    gmock
    absl::status
    tink::core::key_manager_impl
    tink::core::mac
    tink::util::istream_input_stream
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::hmac_cc_proto
)

tink_cc_library(
  NAME failing_mac
  SRCS
    failing_mac.cc
    failing_mac.h
  DEPS
    absl::strings
    tink::core::mac
)

tink_cc_test(
  NAME failing_mac_test
  SRCS
    failing_mac_test.cc
  DEPS
    tink::mac::failing_mac
    gmock
    absl::status
    tink::util::test_matchers
)

tink_module(mac)

add_subdirectory(internal)

tink_cc_library(
  NAME mac_wrapper
  SRCS
    mac_wrapper.cc
    mac_wrapper.h
  DEPS
    absl::memory
    absl::status
    absl::strings
    tink::core::crypto_format
    tink::core::mac
    tink::core::primitive_set
    tink::core::primitive_wrapper
    tink::internal::monitoring_util
    tink::internal::registry_impl
    tink::internal::util
    tink::monitoring::monitoring
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
    tink::mac::aes_cmac_proto_serialization
    tink::mac::hmac_key_manager
    tink::mac::hmac_proto_serialization
    tink::mac::mac_wrapper
    absl::core_headers
    absl::memory
    tink::core::registry
    tink::config::config_util
    tink::config::tink_fips
    tink::mac::internal::chunked_mac_wrapper
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
    tink::core::chunked_mac
    tink::core::key_type_manager
    tink::core::template_util
    tink::core::key_manager
    tink::core::mac
    tink::mac::internal::chunked_mac_impl
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
    tink::core::chunked_mac
    tink::core::key_type_manager
    tink::core::template_util
    tink::core::input_stream
    tink::core::mac
    tink::internal::fips_utils
    tink::mac::internal::chunked_mac_impl
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
  NAME mac_parameters
  SRCS
    mac_parameters.h
  DEPS
    tink::core::parameters
)

tink_cc_library(
  NAME mac_key
  SRCS
    mac_key.h
  DEPS
    tink::mac::mac_parameters
    absl::string_view
    tink::core::key
    tink::util::statusor
)

tink_cc_library(
  NAME failing_mac
  SRCS
    failing_mac.cc
    failing_mac.h
  DEPS
    absl::memory
    absl::status
    absl::strings
    tink::core::mac
    tink::util::status
    tink::util::statusor
  TESTONLY
)

tink_cc_library(
  NAME aes_cmac_parameters
  SRCS
    aes_cmac_parameters.cc
    aes_cmac_parameters.h
  DEPS
    tink::mac::mac_parameters
    absl::log
    absl::status
    absl::strings
    tink::core::crypto_format
    tink::core::parameters
    tink::internal::util
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME aes_cmac_key
  SRCS
    aes_cmac_key.cc
    aes_cmac_key.h
  DEPS
    tink::mac::aes_cmac_parameters
    tink::mac::mac_key
    absl::core_headers
    absl::status
    absl::strings
    absl::str_format
    absl::optional
    crypto
    tink::core::key
    tink::core::partial_key_access_token
    tink::core::restricted_data
    tink::subtle::subtle_util
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME aes_cmac_proto_serialization
  SRCS
    aes_cmac_proto_serialization.cc
    aes_cmac_proto_serialization.h
  DEPS
    tink::mac::aes_cmac_key
    tink::mac::aes_cmac_parameters
    absl::status
    absl::string_view
    absl::optional
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::core::secret_key_access_token
    tink::internal::key_parser
    tink::internal::key_serializer
    tink::internal::mutable_serialization_registry
    tink::internal::parameters_parser
    tink::internal::parameters_serializer
    tink::internal::proto_key_serialization
    tink::internal::proto_parameters_serialization
    tink::util::status
    tink::util::statusor
    tink::proto::aes_cmac_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME hmac_parameters
  SRCS
    hmac_parameters.cc
    hmac_parameters.h
  DEPS
    tink::mac::mac_parameters
    absl::log
    absl::status
    absl::strings
    tink::core::crypto_format
    tink::core::parameters
    tink::internal::util
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME hmac_key
  SRCS
    hmac_key.cc
    hmac_key.h
  DEPS
    tink::mac::hmac_parameters
    tink::mac::mac_key
    absl::core_headers
    absl::status
    absl::strings
    absl::str_format
    absl::optional
    tink::core::key
    tink::core::partial_key_access_token
    tink::core::restricted_data
    tink::subtle::subtle_util
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME hmac_proto_serialization
  SRCS
    hmac_proto_serialization.cc
    hmac_proto_serialization.h
  DEPS
    tink::mac::hmac_key
    tink::mac::hmac_parameters
    absl::status
    absl::string_view
    absl::optional
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::core::secret_key_access_token
    tink::internal::key_parser
    tink::internal::key_serializer
    tink::internal::mutable_serialization_registry
    tink::internal::parameters_parser
    tink::internal::parameters_serializer
    tink::internal::proto_key_serialization
    tink::internal::proto_parameters_serialization
    tink::util::status
    tink::util::statusor
    tink::proto::common_cc_proto
    tink::proto::hmac_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME config_v0
  SRCS
    config_v0.cc
    config_v0.h
  DEPS
    absl::check
    tink::core::configuration
    tink::mac::internal::config_v0
)

tink_cc_library(
  NAME key_gen_config_v0
  SRCS
    key_gen_config_v0.cc
    key_gen_config_v0.h
  DEPS
    absl::check
    tink::core::key_gen_configuration
    tink::mac::internal::key_gen_config_v0
)

# tests

tink_cc_test(
  NAME mac_wrapper_test
  SRCS
    mac_wrapper_test.cc
  DEPS
    tink::mac::failing_mac
    tink::mac::mac_wrapper
    gmock
    absl::flat_hash_map
    absl::memory
    absl::status
    absl::strings
    tink::core::crypto_format
    tink::core::mac
    tink::core::primitive_set
    tink::core::registry
    tink::internal::registry_impl
    tink::monitoring::monitoring
    tink::monitoring::monitoring_client_mocks
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME mac_config_test
  SRCS
    mac_config_test.cc
  DEPS
    tink::mac::aes_cmac_key
    tink::mac::aes_cmac_key_manager
    tink::mac::aes_cmac_parameters
    tink::mac::hmac_key
    tink::mac::hmac_key_manager
    tink::mac::hmac_parameters
    tink::mac::mac_config
    tink::mac::mac_key_templates
    gmock
    absl::memory
    absl::status
    crypto
    tink::core::chunked_mac
    tink::core::insecure_secret_key_access
    tink::core::key
    tink::core::keyset_handle
    tink::core::mac
    tink::core::parameters
    tink::core::partial_key_access
    tink::core::primitive_set
    tink::core::registry
    tink::core::restricted_data
    tink::config::global_registry
    tink::internal::fips_utils
    tink::internal::mutable_serialization_registry
    tink::internal::proto_key_serialization
    tink::internal::proto_parameters_serialization
    tink::internal::serialization
    tink::subtle::random
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::aes_cmac_cc_proto
    tink::proto::common_cc_proto
    tink::proto::hmac_cc_proto
    tink::proto::tink_cc_proto
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
    tink::core::mac
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
    tink::core::chunked_mac
    tink::core::mac
    tink::subtle::aes_cmac_boringssl
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::aes_cmac_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME hmac_key_manager_test
  SRCS
    hmac_key_manager_test.cc
  DEPS
    tink::mac::hmac_key_manager
    gmock
    absl::memory
    absl::status
    tink::core::chunked_mac
    tink::core::key_manager_impl
    tink::core::mac
    tink::subtle::hmac_boringssl
    tink::util::enums
    tink::util::istream_input_stream
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::hmac_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME failing_mac_test
  SRCS
    failing_mac_test.cc
  DEPS
    tink::mac::failing_mac
    gmock
    absl::status
    tink::core::mac
    tink::util::test_matchers
)

tink_cc_test(
  NAME aes_cmac_parameters_test
  SRCS
    aes_cmac_parameters_test.cc
  DEPS
    tink::mac::aes_cmac_parameters
    gmock
    absl::status
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_test(
  NAME aes_cmac_key_test
  SRCS
    aes_cmac_key_test.cc
  DEPS
    tink::mac::aes_cmac_key
    tink::mac::aes_cmac_parameters
    gmock
    absl::status
    absl::optional
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_test(
  NAME aes_cmac_proto_serialization_test
  SRCS
    aes_cmac_proto_serialization_test.cc
  DEPS
    tink::mac::aes_cmac_key
    tink::mac::aes_cmac_parameters
    tink::mac::aes_cmac_proto_serialization
    gmock
    absl::status
    absl::optional
    tink::core::insecure_secret_key_access
    tink::core::key
    tink::core::parameters
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::internal::mutable_serialization_registry
    tink::internal::proto_key_serialization
    tink::internal::proto_parameters_serialization
    tink::internal::serialization
    tink::subtle::random
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::aes_cmac_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME hmac_parameters_test
  SRCS
    hmac_parameters_test.cc
  DEPS
    tink::mac::hmac_parameters
    gmock
    absl::status
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_test(
  NAME hmac_key_test
  SRCS
    hmac_key_test.cc
  DEPS
    tink::mac::hmac_key
    tink::mac::hmac_parameters
    gmock
    absl::status
    absl::optional
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_test(
  NAME hmac_proto_serialization_test
  SRCS
    hmac_proto_serialization_test.cc
  DEPS
    tink::mac::hmac_key
    tink::mac::hmac_parameters
    tink::mac::hmac_proto_serialization
    gmock
    absl::status
    absl::optional
    tink::core::insecure_secret_key_access
    tink::core::key
    tink::core::parameters
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::internal::mutable_serialization_registry
    tink::internal::proto_key_serialization
    tink::internal::proto_parameters_serialization
    tink::internal::serialization
    tink::subtle::random
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::common_cc_proto
    tink::proto::hmac_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME config_v0_test
  SRCS
    config_v0_test.cc
  DEPS
    tink::mac::config_v0
    tink::mac::key_gen_config_v0
    tink::mac::mac_key_templates
    gmock
    tink::core::chunked_mac
    tink::core::key_gen_configuration
    tink::core::keyset_handle
    tink::core::mac
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::tink_cc_proto
)

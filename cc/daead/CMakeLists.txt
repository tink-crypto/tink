add_subdirectory(subtle)

tink_module(daead)

tink_cc_library(
  NAME aes_siv_key_manager
  SRCS
    aes_siv_key_manager.h
  DEPS
    absl::memory
    absl::status
    absl::strings
    tink::core::key_type_manager
    tink::core::deterministic_aead
    tink::subtle::aes_siv_boringssl
    tink::subtle::random
    tink::util::constants
    tink::util::errors
    tink::util::input_stream_util
    tink::util::protobuf_helper
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::validation
    tink::proto::aes_siv_cc_proto
)

tink_cc_library(
  NAME deterministic_aead_wrapper
  SRCS
    deterministic_aead_wrapper.cc
    deterministic_aead_wrapper.h
  DEPS
    absl::status
    absl::strings
    tink::core::crypto_format
    tink::core::deterministic_aead
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
  NAME deterministic_aead_config
  SRCS
    deterministic_aead_config.cc
    deterministic_aead_config.h
  DEPS
    tink::daead::aes_siv_key_manager
    tink::daead::aes_siv_proto_serialization
    tink::daead::deterministic_aead_wrapper
    absl::core_headers
    absl::memory
    tink::core::registry
    tink::config::tink_fips
    tink::util::status
    tink::proto::config_cc_proto
)

tink_cc_library(
  NAME deterministic_aead_factory
  SRCS
    deterministic_aead_factory.cc
    deterministic_aead_factory.h
  DEPS
    tink::daead::deterministic_aead_wrapper
    absl::core_headers
    tink::core::deterministic_aead
    tink::core::key_manager
    tink::core::keyset_handle
    tink::core::registry
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME deterministic_aead_key_templates
  SRCS
    deterministic_aead_key_templates.cc
    deterministic_aead_key_templates.h
  DEPS
    tink::proto::aes_siv_cc_proto
    tink::proto::common_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME failing_daead
  SRCS
    failing_daead.cc
    failing_daead.h
  DEPS
    absl::strings
    tink::core::deterministic_aead
)

tink_cc_library(
  NAME deterministic_aead_parameters
  SRCS
    deterministic_aead_parameters.h
  DEPS
    tink::core::parameters
)

tink_cc_library(
  NAME deterministic_aead_key
  SRCS
    deterministic_aead_key.h
  DEPS
    tink::daead::deterministic_aead_parameters
    absl::strings
    tink::core::key
)

tink_cc_library(
  NAME aes_siv_parameters
  SRCS
    aes_siv_parameters.cc
    aes_siv_parameters.h
  DEPS
    tink::daead::deterministic_aead_parameters
    tink::util::statusor
)

tink_cc_library(
  NAME aes_siv_key
  SRCS
    aes_siv_key.cc
    aes_siv_key.h
  DEPS
    tink::daead::aes_siv_parameters
    tink::daead::deterministic_aead_key
    absl::strings
    absl::optional
    tink::core::partial_key_access_token
    tink::core::restricted_data
    tink::subtle::subtle_util
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME aes_siv_proto_serialization
  SRCS
    aes_siv_proto_serialization.cc
    aes_siv_proto_serialization.h
  DEPS
    tink::daead::aes_siv_key
    tink::daead::aes_siv_parameters
    absl::status
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
    tink::proto::aes_siv_cc_proto
    tink::proto::tink_cc_proto
)

# tests

tink_cc_test(
  NAME aes_siv_key_manager_test
  SRCS
    aes_siv_key_manager_test.cc
  DEPS
    tink::daead::aes_siv_key_manager
    gmock
    absl::status
    tink::core::deterministic_aead
    tink::util::istream_input_stream
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::aes_siv_cc_proto
)

tink_cc_test(
  NAME deterministic_aead_wrapper_test
  SRCS
    deterministic_aead_wrapper_test.cc
  DEPS
    tink::daead::deterministic_aead_wrapper
    tink::daead::failing_daead
    gmock
    absl::status
    tink::core::deterministic_aead
    tink::core::primitive_set
    tink::internal::registry_impl
    tink::monitoring::monitoring
    tink::monitoring::monitoring_client_mocks
    tink::util::status
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME deterministic_aead_config_test
  SRCS
    deterministic_aead_config_test.cc
  DEPS
    tink::daead::aes_siv_key
    tink::daead::aes_siv_key_manager
    tink::daead::aes_siv_parameters
    tink::daead::deterministic_aead_config
    tink::daead::deterministic_aead_key_templates
    gmock
    absl::status
    tink::core::deterministic_aead
    tink::core::insecure_secret_key_access
    tink::core::keyset_handle
    tink::core::partial_key_access
    tink::core::registry
    tink::config::tink_fips
    tink::internal::mutable_serialization_registry
    tink::internal::proto_key_serialization
    tink::internal::proto_parameters_serialization
    tink::util::status
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME deterministic_aead_factory_test
  SRCS
    deterministic_aead_factory_test.cc
  DEPS
    tink::daead::aes_siv_key_manager
    tink::daead::deterministic_aead_config
    tink::daead::deterministic_aead_factory
    gmock
    tink::core::key_manager_impl
    tink::core::crypto_format
    tink::core::deterministic_aead
    tink::core::keyset_handle
    tink::internal::key_info
    tink::util::status
    tink::util::test_keyset_handle
    tink::util::test_util
    tink::proto::aes_siv_cc_proto
)

tink_cc_test(
  NAME deterministic_aead_key_templates_test
  SRCS
    deterministic_aead_key_templates_test.cc
  DEPS
    tink::daead::aes_siv_key_manager
    tink::daead::deterministic_aead_key_templates
    gmock
    tink::core::key_manager_impl
    tink::proto::aes_siv_cc_proto
    tink::proto::common_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME failing_daead_test
  SRCS
    failing_daead_test.cc
  DEPS
    tink::daead::failing_daead
    gmock
    absl::status
    tink::util::test_matchers
)

tink_cc_test(
  NAME aes_siv_parameters_test
  SRCS
    aes_siv_parameters_test.cc
  DEPS
    tink::daead::aes_siv_parameters
    gmock
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_test(
  NAME aes_siv_key_test
  SRCS
    aes_siv_key_test.cc
  DEPS
    tink::daead::aes_siv_key
    tink::daead::aes_siv_parameters
    gmock
    absl::optional
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_test(
  NAME aes_siv_proto_serialization_test
  SRCS
    aes_siv_proto_serialization_test.cc
  DEPS
    tink::daead::aes_siv_key
    tink::daead::aes_siv_parameters
    tink::daead::aes_siv_proto_serialization
    gmock
    tink::core::insecure_secret_key_access
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::internal::mutable_serialization_registry
    tink::internal::proto_key_serialization
    tink::internal::proto_parameters_serialization
    tink::subtle::random
    tink::util::test_matchers
    tink::proto::aes_siv_cc_proto
    tink::proto::tink_cc_proto
)

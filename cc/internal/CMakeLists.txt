tink_module(internal)

tink_cc_library(
  NAME ssl_util
  SRCS
    ssl_util.h
  DEPS
    crypto
)

tink_cc_library(
  NAME keyset_wrapper
  SRCS
    keyset_wrapper.h
  DEPS
    absl::flat_hash_map
    tink::util::statusor
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME util
  SRCS
    util.cc
    util.h
  DEPS
    absl::core_headers
    absl::log
    absl::strings
)

tink_cc_library(
  NAME test_file_util
  SRCS
    test_file_util.cc
    test_file_util_cmake.cc
    test_file_util.h
  DEPS
    absl::check
    absl::strings
    gmock
    tink::subtle::random
    tink::util::status
    tink::util::test_util
  TESTONLY
)

tink_cc_library(
  NAME keyset_wrapper_impl
  SRCS
    keyset_wrapper_impl.h
  DEPS
    tink::internal::key_info
    tink::internal::keyset_wrapper
    absl::flat_hash_map
    tink::core::primitive_set
    tink::core::primitive_wrapper
    tink::util::status
    tink::util::statusor
    tink::util::validation
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME ssl_unique_ptr
  SRCS
    ssl_unique_ptr.h
  DEPS
    crypto
)

tink_cc_library(
  NAME err_util
  SRCS
    err_util.cc
    err_util.h
  DEPS
    crypto
)

tink_cc_library(
  NAME key_info
  SRCS
    key_info.cc
    key_info.h
  DEPS
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME registry_impl
  SRCS
    registry_impl.cc
    registry_impl.h
  DEPS
    tink::internal::fips_utils
    tink::internal::key_type_info_store
    tink::internal::keyset_wrapper
    tink::internal::keyset_wrapper_store
    absl::core_headers
    absl::flat_hash_map
    absl::memory
    absl::status
    absl::strings
    absl::synchronization
    tink::core::key_type_manager
    tink::core::private_key_type_manager
    tink::core::input_stream
    tink::core::key_manager
    tink::core::primitive_set
    tink::core::primitive_wrapper
    tink::monitoring::monitoring
    tink::util::errors
    tink::util::status
    tink::util::statusor
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME fips_utils
  SRCS
    fips_utils.cc
    fips_utils.h
  DEPS
    absl::core_headers
    absl::status
    crypto
    tink::util::status
)

tink_cc_library(
  NAME ec_util
  SRCS
    ec_util.cc
    ec_util.h
  DEPS
    tink::internal::bn_util
    tink::internal::err_util
    tink::internal::fips_utils
    tink::internal::ssl_unique_ptr
    absl::memory
    absl::status
    absl::strings
    absl::span
    crypto
    tink::subtle::common_enums
    tink::subtle::random
    tink::subtle::subtle_util
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME bn_util
  SRCS
    bn_util.cc
    bn_util.h
  DEPS
    tink::internal::ssl_unique_ptr
    absl::status
    absl::strings
    absl::span
    crypto
    tink::subtle::subtle_util
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME rsa_util
  SRCS
    rsa_util.cc
    rsa_util.h
  DEPS
    tink::internal::bn_util
    tink::internal::err_util
    tink::internal::fips_utils
    tink::internal::ssl_unique_ptr
    tink::internal::ssl_util
    absl::status
    absl::statusor
    absl::strings
    crypto
    tink::config::tink_fips
    tink::subtle::common_enums
    tink::util::errors
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
)

tink_cc_test(
  NAME util_test
  SRCS
    util_test.cc
  DEPS
    tink::internal::util
    gmock
    absl::strings
)

tink_cc_test(
  NAME keyset_wrapper_impl_test
  SRCS
    keyset_wrapper_impl_test.cc
  DEPS
    tink::internal::keyset_wrapper_impl
    gmock
    absl::flat_hash_map
    absl::memory
    absl::status
    absl::strings
    tink::core::primitive_set
    tink::core::primitive_wrapper
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME key_info_test
  SRCS
    key_info_test.cc
  DEPS
    tink::internal::key_info
    gmock
    protobuf::libprotobuf-lite
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME registry_impl_test
  SRCS
    registry_impl_test.cc
  DEPS
    tink::internal::fips_utils
    tink::internal::registry_impl
    gmock
    absl::memory
    absl::status
    absl::statusor
    absl::strings
    crypto
    tink::core::aead
    tink::core::key_manager_impl
    tink::core::key_type_manager
    tink::core::private_key_manager_impl
    tink::core::private_key_type_manager
    tink::core::template_util
    tink::core::hybrid_decrypt
    tink::core::input_stream
    tink::core::key_manager
    tink::core::mac
    tink::core::primitive_set
    tink::core::primitive_wrapper
    tink::core::registry
    tink::aead::aead_wrapper
    tink::aead::aes_gcm_key_manager
    tink::hybrid::ecies_aead_hkdf_private_key_manager
    tink::hybrid::ecies_aead_hkdf_public_key_manager
    tink::monitoring::monitoring_client_mocks
    tink::subtle::aes_gcm_boringssl
    tink::subtle::random
    tink::util::input_stream_util
    tink::util::istream_input_stream
    tink::util::protobuf_helper
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::aes_ctr_hmac_aead_cc_proto
    tink::proto::aes_gcm_cc_proto
    tink::proto::common_cc_proto
    tink::proto::ecdsa_cc_proto
    tink::proto::ecies_aead_hkdf_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME err_util_test
  SRCS
    err_util_test.cc
  DEPS
    tink::internal::err_util
    gmock
    absl::strings
    crypto
)

tink_cc_test(
  NAME bn_util_test
  SRCS
    bn_util_test.cc
  DEPS
    tink::internal::bn_util
    tink::internal::ssl_unique_ptr
    gmock
    absl::strings
    absl::span
    crypto
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_test(
  NAME rsa_util_test
  SRCS
    rsa_util_test.cc
  DEPS
    tink::internal::bn_util
    tink::internal::rsa_util
    tink::internal::ssl_unique_ptr
    gmock
    absl::status
    absl::strings
    crypto
    tink::subtle::random
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_test(
  NAME fips_utils_test
  SRCS
    fips_utils_test.cc
  DEPS
    tink::internal::fips_utils
    gmock
    absl::status
    crypto
    tink::util::status
    tink::util::test_matchers
)

tink_cc_test(
  NAME ec_util_test
  SRCS
    ec_util_test.cc
  DATA
    wycheproof::testvectors
  DEPS
    tink::internal::bn_util
    tink::internal::ec_util
    tink::internal::fips_utils
    tink::internal::ssl_unique_ptr
    tink::internal::ssl_util
    gmock
    absl::status
    absl::strings
    absl::span
    crypto
    rapidjson
    tink::subtle::common_enums
    tink::subtle::subtle_util
    tink::subtle::wycheproof_util
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_library(
  NAME md_util
  SRCS
    md_util.cc
    md_util.h
  DEPS
    tink::internal::err_util
    tink::internal::util
    absl::status
    absl::strings
    crypto
    tink::subtle::common_enums
    tink::subtle::subtle_util
    tink::util::status
    tink::util::statusor
)

tink_cc_test(
  NAME md_util_test
  SRCS
    md_util_test.cc
  DEPS
    tink::internal::md_util
    gmock
    absl::strings
    crypto
    tink::subtle::common_enums
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_library(
  NAME aes_util
  SRCS
    aes_util.cc
    aes_util.h
  DEPS
    tink::internal::util
    absl::status
    absl::strings
    absl::span
    crypto
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
)

tink_cc_test(
  NAME aes_util_test
  SRCS
    aes_util_test.cc
  DEPS
    tink::internal::aes_util
    gmock
    absl::status
    absl::strings
    absl::span
    crypto
    tink::subtle::subtle_util
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_library(
  NAME monitoring_util
  SRCS
    monitoring_util.h
  DEPS
    tink::internal::key_status_util
    absl::flat_hash_map
    absl::status
    absl::strings
    tink::core::key_status
    tink::core::primitive_set
    tink::monitoring::monitoring
    tink::util::status
    tink::util::statusor
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME monitoring_util_test
  SRCS
    monitoring_util_test.cc
  DEPS
    tink::internal::monitoring_util
    gmock
    absl::flat_hash_map
    absl::memory
    absl::status
    absl::strings
    tink::core::key_status
    tink::core::primitive_set
    tink::monitoring::monitoring
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME serialization
  SRCS
    serialization.h
  DEPS
    absl::strings
)

tink_cc_library(
  NAME proto_parameters_serialization
  SRCS
    proto_parameters_serialization.cc
    proto_parameters_serialization.h
  DEPS
    tink::internal::serialization
    tink::internal::util
    absl::status
    absl::strings
    tink::util::status
    tink::util::statusor
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME proto_parameters_serialization_test
  SRCS
    proto_parameters_serialization_test.cc
  DEPS
    tink::internal::proto_parameters_serialization
    gmock
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::test_proto_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME proto_key_serialization
  SRCS
    proto_key_serialization.cc
    proto_key_serialization.h
  DEPS
    tink::internal::serialization
    tink::internal::util
    absl::status
    absl::strings
    absl::optional
    tink::core::restricted_data
    tink::util::status
    tink::util::statusor
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME proto_key_serialization_test
  SRCS
    proto_key_serialization_test.cc
  DEPS
    tink::internal::proto_key_serialization
    gmock
    absl::status
    absl::optional
    tink::core::insecure_secret_key_access
    tink::core::restricted_data
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME legacy_proto_parameters
  SRCS
    legacy_proto_parameters.cc
    legacy_proto_parameters.h
  DEPS
    tink::internal::proto_parameters_serialization
    tink::core::parameters
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME legacy_proto_parameters_test
  SRCS
    legacy_proto_parameters_test.cc
  DEPS
    tink::internal::legacy_proto_parameters
    tink::internal::proto_parameters_serialization
    gmock
    tink::core::parameters
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::test_proto_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME legacy_proto_key
  SRCS
    legacy_proto_key.cc
    legacy_proto_key.h
  DEPS
    tink::internal::proto_key_serialization
    absl::status
    absl::strings
    absl::optional
    tink::core::key
    tink::core::parameters
    tink::core::secret_key_access_token
    tink::util::status
    tink::util::statusor
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME legacy_proto_key_test
  SRCS
    legacy_proto_key_test.cc
  DEPS
    tink::internal::legacy_proto_key
    tink::internal::proto_key_serialization
    gmock
    absl::status
    absl::optional
    tink::core::insecure_secret_key_access
    tink::core::key
    tink::core::parameters
    tink::core::restricted_data
    tink::core::secret_key_access_token
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME parser_index
  SRCS
    parser_index.h
  DEPS
    tink::internal::serialization
    absl::strings
)

tink_cc_test(
  NAME parser_index_test
  SRCS
    parser_index_test.cc
  DEPS
    tink::internal::parser_index
    tink::internal::serialization
    gmock
    absl::strings
)

tink_cc_library(
  NAME serializer_index
  SRCS
    serializer_index.h
  DEPS
    tink::internal::serialization
    tink::core::key
    tink::core::parameters
)

tink_cc_test(
  NAME serializer_index_test
  SRCS
    serializer_index_test.cc
  DEPS
    tink::internal::serialization_test_util
    tink::internal::serializer_index
    gmock
)

tink_cc_library(
  NAME parameters_parser
  SRCS
    parameters_parser.h
  DEPS
    tink::internal::parser_index
    tink::internal::serialization
    absl::status
    absl::strings
    tink::core::parameters
    tink::util::status
    tink::util::statusor
)

tink_cc_test(
  NAME parameters_parser_test
  SRCS
    parameters_parser_test.cc
  DEPS
    tink::internal::parameters_parser
    tink::internal::parser_index
    tink::internal::serialization
    tink::internal::serialization_test_util
    gmock
    absl::memory
    absl::status
    tink::core::parameters
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_library(
  NAME parameters_serializer
  SRCS
    parameters_serializer.h
  DEPS
    tink::internal::serialization
    tink::internal::serializer_index
    absl::status
    absl::strings
    tink::core::parameters
    tink::util::status
    tink::util::statusor
)

tink_cc_test(
  NAME parameters_serializer_test
  SRCS
    parameters_serializer_test.cc
  DEPS
    tink::internal::parameters_serializer
    tink::internal::serialization
    tink::internal::serialization_test_util
    tink::internal::serializer_index
    gmock
    absl::memory
    absl::status
    tink::core::parameters
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_library(
  NAME key_parser
  SRCS
    key_parser.h
  DEPS
    tink::internal::parser_index
    tink::internal::serialization
    absl::function_ref
    absl::log
    absl::status
    absl::strings
    absl::optional
    tink::core::key
    tink::core::secret_key_access_token
    tink::util::status
    tink::util::statusor
)

tink_cc_test(
  NAME key_parser_test
  SRCS
    key_parser_test.cc
  DEPS
    tink::internal::key_parser
    tink::internal::parser_index
    tink::internal::serialization
    tink::internal::serialization_test_util
    gmock
    absl::memory
    absl::status
    absl::optional
    tink::core::insecure_secret_key_access
    tink::core::key
    tink::core::parameters
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_library(
  NAME key_serializer
  SRCS
    key_serializer.h
  DEPS
    tink::internal::serialization
    tink::internal::serializer_index
    absl::function_ref
    absl::log
    absl::status
    absl::optional
    tink::core::key
    tink::core::secret_key_access_token
    tink::util::status
    tink::util::statusor
)

tink_cc_test(
  NAME key_serializer_test
  SRCS
    key_serializer_test.cc
  DEPS
    tink::internal::key_serializer
    tink::internal::serialization
    tink::internal::serialization_test_util
    tink::internal::serializer_index
    gmock
    absl::memory
    absl::status
    tink::core::insecure_secret_key_access
    tink::core::key
    tink::core::secret_key_access_token
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_library(
  NAME key_status_util
  SRCS
    key_status_util.cc
    key_status_util.h
  DEPS
    absl::status
    tink::core::key_status
    tink::util::status
    tink::util::statusor
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME key_status_util_test
  SRCS
    key_status_util_test.cc
  DEPS
    tink::internal::key_status_util
    gmock
    absl::status
    tink::core::key_status
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME keyset_handle_builder_entry
  SRCS
    keyset_handle_builder_entry.cc
    keyset_handle_builder_entry.h
  DEPS
    tink::internal::key_status_util
    tink::internal::legacy_proto_key
    tink::internal::legacy_proto_parameters
    tink::internal::mutable_serialization_registry
    tink::internal::proto_key_serialization
    tink::internal::proto_parameters_serialization
    tink::internal::serialization
    absl::status
    absl::strings
    absl::optional
    tink::core::insecure_secret_key_access
    tink::core::key
    tink::core::key_status
    tink::core::parameters
    tink::core::registry
    tink::core::restricted_data
    tink::core::secret_key_access_token
    tink::util::status
    tink::util::statusor
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME keyset_handle_builder_entry_test
  SRCS
    keyset_handle_builder_entry_test.cc
  DEPS
    tink::internal::keyset_handle_builder_entry
    tink::internal::legacy_proto_key
    tink::internal::legacy_proto_parameters
    tink::internal::proto_key_serialization
    tink::internal::proto_parameters_serialization
    gmock
    absl::memory
    absl::status
    absl::optional
    tink::core::insecure_secret_key_access
    tink::core::key
    tink::core::key_status
    tink::core::keyset_handle
    tink::core::keyset_handle_builder
    tink::core::parameters
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::core::secret_key_access_token
    tink::config::tink_config
    tink::mac::aes_cmac_key
    tink::mac::aes_cmac_parameters
    tink::mac::mac_key_templates
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME serialization_registry
  SRCS
    serialization_registry.cc
    serialization_registry.h
  DEPS
    tink::internal::key_parser
    tink::internal::key_serializer
    tink::internal::parameters_parser
    tink::internal::parameters_serializer
    tink::internal::parser_index
    tink::internal::serialization
    tink::internal::serializer_index
    absl::flat_hash_map
    absl::status
    absl::str_format
    tink::core::insecure_secret_key_access
    tink::core::key
    tink::core::parameters
    tink::util::status
    tink::util::statusor
)

tink_cc_test(
  NAME serialization_registry_test
  SRCS
    serialization_registry_test.cc
  DEPS
    tink::internal::key_parser
    tink::internal::key_serializer
    tink::internal::parameters_parser
    tink::internal::parameters_serializer
    tink::internal::serialization
    tink::internal::serialization_registry
    tink::internal::serialization_test_util
    gmock
    absl::status
    tink::core::key
    tink::core::parameters
    tink::core::secret_key_access_token
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_library(
  NAME mutable_serialization_registry
  SRCS
    mutable_serialization_registry.cc
    mutable_serialization_registry.h
  DEPS
    tink::internal::key_parser
    tink::internal::key_serializer
    tink::internal::legacy_proto_key
    tink::internal::parameters_parser
    tink::internal::parameters_serializer
    tink::internal::proto_key_serialization
    tink::internal::serialization
    tink::internal::serialization_registry
    absl::core_headers
    absl::memory
    absl::status
    absl::synchronization
    tink::core::insecure_secret_key_access
    tink::core::key
    tink::core::parameters
    tink::core::secret_key_access_token
    tink::util::status
    tink::util::statusor
)

tink_cc_test(
  NAME mutable_serialization_registry_test
  SRCS
    mutable_serialization_registry_test.cc
  DEPS
    tink::internal::key_parser
    tink::internal::key_serializer
    tink::internal::mutable_serialization_registry
    tink::internal::parameters_parser
    tink::internal::parameters_serializer
    tink::internal::proto_key_serialization
    tink::internal::serialization
    tink::internal::serialization_test_util
    gmock
    absl::status
    tink::core::insecure_secret_key_access
    tink::core::key
    tink::core::parameters
    tink::core::restricted_data
    tink::core::secret_key_access_token
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME serialization_test_util
  SRCS
    serialization_test_util.h
  DEPS
    tink::internal::serialization
    absl::strings
    absl::optional
    tink::core::key
    tink::core::parameters
    tink::core::secret_key_access_token
    tink::util::statusor
  TESTONLY
)

tink_cc_test(
  NAME serialization_test_util_test
  SRCS
    serialization_test_util_test.cc
  DEPS
    tink::internal::serialization_test_util
    gmock
    absl::optional
    tink::core::insecure_secret_key_access
    tink::core::parameters
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_library(
  NAME test_random_access_stream
  SRCS
    test_random_access_stream.cc
    test_random_access_stream.h
  DEPS
    absl::status
    absl::strings
    tink::core::random_access_stream
    tink::util::buffer
    tink::util::status
    tink::util::statusor
  TESTONLY
)

tink_cc_test(
  NAME test_random_access_stream_test
  SRCS
    test_random_access_stream_test.cc
  DEPS
    tink::internal::test_random_access_stream
    gmock
    absl::status
    tink::subtle::random
    tink::util::buffer
    tink::util::status
    tink::util::test_matchers
)

tink_cc_library(
  NAME configuration_impl
  SRCS
    configuration_impl.h
  DEPS
    tink::internal::key_type_info_store
    tink::internal::keyset_wrapper_store
    tink::core::configuration
)

tink_cc_test(
  NAME configuration_impl_test
  SRCS
    configuration_impl_test.cc
  DEPS
    tink::internal::configuration_impl
    gmock
    tink::core::configuration
    tink::subtle::random
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::aes_gcm_cc_proto
    tink::proto::rsa_ssa_pss_cc_proto
)

tink_cc_library(
  NAME key_type_info_store
  SRCS
    key_type_info_store.cc
    key_type_info_store.h
  DEPS
    tink::internal::fips_utils
    absl::flat_hash_map
    absl::status
    absl::strings
    tink::core::key_manager_impl
    tink::core::key_type_manager
    tink::core::private_key_manager_impl
    tink::core::private_key_type_manager
    tink::core::key_manager
    tink::util::status
    tink::util::statusor
)

tink_cc_test(
  NAME key_type_info_store_test
  SRCS
    key_type_info_store_test.cc
  DEPS
    tink::internal::fips_utils
    tink::internal::key_type_info_store
    gmock
    absl::status
    absl::optional
    tink::core::aead
    tink::core::key_manager_impl
    tink::core::key_manager
    tink::aead::aes_gcm_key_manager
    tink::aead::cord_aead
    tink::aead::kms_envelope_aead_key_manager
    tink::signature::ecdsa_sign_key_manager
    tink::signature::ecdsa_verify_key_manager
    tink::util::test_matchers
    tink::proto::aes_gcm_cc_proto
    tink::proto::common_cc_proto
    tink::proto::ecdsa_cc_proto
)

tink_cc_library(
  NAME keyset_wrapper_store
  SRCS
    keyset_wrapper_store.h
  DEPS
    tink::internal::keyset_wrapper
    tink::internal::keyset_wrapper_impl
    tink::core::primitive_wrapper
    tink::util::status
    tink::util::statusor
)

tink_cc_test(
  NAME keyset_wrapper_store_test
  SRCS
    keyset_wrapper_store_test.cc
  DEPS
    tink::internal::keyset_wrapper_store
    tink::internal::registry_impl
    gmock
    absl::status
    tink::core::primitive_set
    tink::core::primitive_wrapper
    tink::mac::mac_wrapper
    tink::subtle::random
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::aes_gcm_cc_proto
)

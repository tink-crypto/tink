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
    absl::strings
)

tink_cc_library(
  NAME test_file_util
  SRCS
    test_file_util_cmake.cc
    test_file_util.h
  DEPS
    absl::strings
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
    tink::internal::keyset_wrapper
    tink::internal::keyset_wrapper_impl
    absl::core_headers
    absl::flat_hash_map
    absl::memory
    absl::status
    absl::strings
    absl::synchronization
    absl::optional
    tink::core::catalogue
    tink::core::key_manager_impl
    tink::core::key_type_manager
    tink::core::private_key_manager_impl
    tink::core::private_key_type_manager
    tink::core::key_manager
    tink::core::primitive_set
    tink::core::primitive_wrapper
    tink::monitoring::monitoring
    tink::util::errors
    tink::util::protobuf_helper
    tink::util::status
    tink::util::statusor
    tink::util::validation
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
    tink::internal::ssl_unique_ptr
    tink::internal::ssl_util
    absl::status
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
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME registry_impl_test
  SRCS
    registry_impl_test.cc
  DEPS
    gmock
    absl::memory
    absl::status
    absl::strings
    crypto
    tink::core::aead
    tink::core::catalogue
    tink::core::key_manager_impl
    tink::core::key_type_manager
    tink::core::crypto_format
    tink::core::keyset_manager
    tink::core::registry
    tink::aead::aead_wrapper
    tink::aead::aes_gcm_key_manager
    tink::config::tink_fips
    tink::hybrid::ecies_aead_hkdf_private_key_manager
    tink::hybrid::ecies_aead_hkdf_public_key_manager
    tink::monitoring::monitoring
    tink::monitoring::monitoring_client_mocks
    tink::subtle::aes_gcm_boringssl
    tink::subtle::random
    tink::util::istream_input_stream
    tink::util::protobuf_helper
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_keyset_handle
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::aes_ctr_hmac_aead_cc_proto
    tink::proto::aes_gcm_cc_proto
    tink::proto::common_cc_proto
    tink::proto::ecdsa_cc_proto
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
    crypto
    tink::util::secret_data
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
    absl::strings
    crypto
    tink::subtle::random
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
    absl::strings
    absl::span
    crypto
    tink::subtle::common_enums
    tink::subtle::subtle_util
    tink::subtle::wycheproof_util
    tink::util::secret_data
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
    absl::span
    crypto
    tink::subtle::common_enums
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
    absl::status
    absl::strings
    tink::core::key_status
    tink::core::primitive_set
    tink::monitoring::monitoring
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
    absl::strings
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
    tink::core::restricted_data
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
    tink::core::key
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
    tink::core::insecure_secret_key_access
    tink::core::restricted_data
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME parameters_parser
  SRCS
    parameters_parser.h
  DEPS
    absl::strings
    tink::util::statusor
)

tink_cc_test(
  NAME parameters_parser_test
  SRCS
    parameters_parser_test.cc
  DEPS
    tink::internal::parameters_parser
    tink::internal::serialization
    gmock
    tink::core::parameters
    tink::util::test_matchers
)

tink_cc_library(
  NAME parameters_serializer
  SRCS
    parameters_serializer.h
  DEPS
    absl::strings
    tink::util::statusor
)

tink_cc_test(
  NAME parameters_serializer_test
  SRCS
    parameters_serializer_test.cc
  DEPS
    tink::internal::parameters_serializer
    tink::internal::serialization
    gmock
    tink::core::parameters
    tink::util::test_matchers
)

tink_cc_library(
  NAME key_parser
  SRCS
    key_parser.h
  DEPS
    absl::function_ref
    absl::strings
    tink::core::secret_key_access_token
    tink::util::statusor
)

tink_cc_test(
  NAME key_parser_test
  SRCS
    key_parser_test.cc
  DEPS
    tink::internal::key_parser
    tink::internal::serialization
    gmock
    tink::core::insecure_secret_key_access
    tink::core::key
    tink::core::parameters
    tink::util::test_matchers
)

tink_cc_library(
  NAME key_serializer
  SRCS
    key_serializer.h
  DEPS
    absl::function_ref
    tink::core::secret_key_access_token
    tink::util::statusor
)

tink_cc_test(
  NAME key_serializer_test
  SRCS
    key_serializer_test.cc
  DEPS
    tink::internal::key_serializer
    tink::internal::serialization
    gmock
    tink::core::insecure_secret_key_access
    tink::core::key
    tink::core::parameters
    tink::core::secret_key_access_token
    tink::util::test_matchers
)

tink_cc_library(
  NAME key_status_util
  SRCS
    key_status_util.cc
    key_status_util.h
  DEPS
    tink::core::key_status
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
    tink::internal::proto_key_serialization
    tink::internal::proto_parameters_serialization
    absl::strings
    absl::optional
    tink::core::insecure_secret_key_access
    tink::core::key
    tink::core::key_status
    tink::core::parameters
    tink::core::registry
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
    tink::core::insecure_secret_key_access
    tink::core::keyset_handle
    tink::core::keyset_handle_builder
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::config::tink_config
    tink::mac::aes_cmac_key
    tink::mac::aes_cmac_parameters
    tink::mac::mac_key_templates
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME test_random_access_stream
  SRCS
    test_random_access_stream.cc
    test_random_access_stream.h
  DEPS
    absl::strings
    tink::core::random_access_stream
)

tink_cc_test(
  NAME test_random_access_stream_test
  SRCS
    test_random_access_stream_test.cc
  DEPS
    tink::internal::test_random_access_stream
    gmock
    absl::status
    absl::strings
    tink::subtle::random
    tink::util::buffer
    tink::util::status
    tink::util::test_matchers
)

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
    absl::flat_hash_map
    absl::status
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
    tink::core::primitive_set
    tink::monitoring::monitoring
    tink::util::test_matchers
    tink::proto::tink_cc_proto
)

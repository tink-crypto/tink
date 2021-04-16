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
    tink::core::primitive_wrapper
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

tink_cc_library(
  NAME registry_impl
  SRCS
    registry_impl.cc
    registry_impl.h
  DEPS
    tink::internal::fips_utils
    tink::core::catalogue
    tink::core::key_manager
    tink::core::key_type_manager
    tink::core::key_manager_impl
    tink::core::private_key_manager_impl
    tink::core::private_key_type_manager
    tink::core::primitive_set
    tink::core::primitive_wrapper
    tink::internal::keyset_wrapper
    tink::internal::keyset_wrapper_impl
    tink::util::errors
    tink::util::protobuf_helper
    tink::util::status
    tink::util::statusor
    tink::util::validation
    tink::proto::tink_cc_proto
    absl::base
    absl::flat_hash_map
    absl::memory
    absl::optional
    absl::strings
    absl::synchronization
)

tink_cc_library(
  NAME fips_utils
  SRCS
    fips_utils.cc
    fips_utils.h
  DEPS
    absl::base
    crypto
    tink::util::status
)


tink_cc_test(
  NAME keyset_wrapper_impl_test
  SRCS
    keyset_wrapper_impl_test.cc
  DEPS
    tink::internal::keyset_wrapper
    tink::internal::keyset_wrapper_impl
    tink::core::primitive_wrapper
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

tink_cc_test(
  NAME registry_impl_test
  SRCS registry_impl_test.cc
  DEPS
    tink::core::aead
    tink::core::catalogue
    tink::core::crypto_format
    tink::core::key_manager_impl
    tink::core::key_type_manager
    tink::core::keyset_manager
    tink::core::registry
    tink::aead::aead_wrapper
    tink::aead::aes_gcm_key_manager
    tink::hybrid::ecies_aead_hkdf_private_key_manager
    tink::hybrid::ecies_aead_hkdf_public_key_manager
    tink::util::istream_input_stream
    tink::util::protobuf_helper
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_keyset_handle
    tink::util::test_util
    tink::util::test_matchers
    tink::proto::aes_ctr_hmac_aead_cc_proto
    tink::proto::aes_gcm_cc_proto
    tink::proto::common_cc_proto
    tink::proto::ecdsa_cc_proto
    tink::proto::tink_cc_proto
    absl::memory
    gmock
)

tink_module(signature)

tink_cc_library(
  NAME public_key_verify_wrapper
  SRCS
    public_key_verify_wrapper.cc
    public_key_verify_wrapper.h
  DEPS
    tink::core::crypto_format
    tink::core::primitive_set
    tink::core::primitive_wrapper
    tink::core::public_key_verify
    tink::subtle::subtle_util_boringssl
    tink::util::status
    tink::util::statusor
    tink::proto::tink_cc_proto
    absl::strings
)

tink_cc_library(
  NAME public_key_verify_factory
  SRCS
    public_key_verify_factory.cc
    public_key_verify_factory.h
  DEPS
    tink::signature::public_key_verify_wrapper
    tink::core::key_manager
    tink::core::keyset_handle
    tink::core::primitive_set
    tink::core::public_key_verify
    tink::core::registry
    tink::util::status
    tink::util::statusor
    absl::base
)

tink_cc_library(
  NAME public_key_sign_wrapper
  SRCS
    public_key_sign_wrapper.cc
    public_key_sign_wrapper.h
  DEPS
    tink::core::crypto_format
    tink::core::primitive_set
    tink::core::primitive_wrapper
    tink::core::public_key_sign
    tink::subtle::subtle_util_boringssl
    tink::util::status
    tink::util::statusor
    tink::proto::tink_cc_proto
    absl::strings
)

tink_cc_library(
  NAME public_key_sign_factory
  SRCS
    public_key_sign_factory.cc
    public_key_sign_factory.h
  DEPS
    tink::signature::public_key_sign_wrapper
    tink::core::key_manager
    tink::core::keyset_handle
    tink::core::primitive_set
    tink::core::public_key_sign
    tink::core::registry
    tink::util::status
    tink::util::statusor
    absl::base
)

tink_cc_library(
  NAME signature_key_templates
  SRCS
    signature_key_templates.cc
    signature_key_templates.h
  DEPS
    tink::subtle::subtle_util_boringssl
    tink::util::constants
    tink::proto::common_cc_proto
    tink::proto::ecdsa_cc_proto
    tink::proto::ed25519_cc_proto
    tink::proto::rsa_ssa_pkcs1_cc_proto
    tink::proto::rsa_ssa_pss_cc_proto
    tink::proto::tink_cc_proto
    crypto
    absl::core_headers
    absl::memory
    absl::strings
)

tink_cc_library(
  NAME ecdsa_sign_key_manager
  SRCS
    ecdsa_sign_key_manager.cc
    ecdsa_sign_key_manager.h
  DEPS
    tink::signature::ecdsa_verify_key_manager
    tink::config::tink_fips
    tink::core::private_key_type_manager
    tink::core::public_key_sign
    tink::subtle::ecdsa_sign_boringssl
    tink::subtle::subtle_util_boringssl
    tink::util::constants
    tink::util::enums
    tink::util::errors
    tink::util::input_stream_util
    tink::util::protobuf_helper
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::proto::ecdsa_cc_proto
    absl::memory
    absl::strings
)

tink_cc_library(
  NAME ecdsa_verify_key_manager
  SRCS
    ecdsa_verify_key_manager.cc
    ecdsa_verify_key_manager.h
  DEPS
    tink::core::key_type_manager
    tink::core::public_key_verify
    tink::subtle::ecdsa_verify_boringssl
    tink::subtle::subtle_util_boringssl
    tink::util::constants
    tink::util::enums
    tink::util::errors
    tink::util::protobuf_helper
    tink::util::status
    tink::util::statusor
    tink::proto::ecdsa_cc_proto
    absl::memory
    absl::strings
)

tink_cc_library(
  NAME ed25519_sign_key_manager
  SRCS
    ed25519_sign_key_manager.cc
    ed25519_sign_key_manager.h
  DEPS
    tink::signature::ed25519_verify_key_manager
    tink::core::private_key_type_manager
    tink::core::public_key_sign
    tink::subtle::ed25519_sign_boringssl
    tink::subtle::subtle_util_boringssl
    tink::util::constants
    tink::util::enums
    tink::util::errors
    tink::util::input_stream_util
    tink::util::protobuf_helper
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::validation
    tink::proto::ed25519_cc_proto
    absl::memory
    absl::strings
)

tink_cc_library(
  NAME ed25519_verify_key_manager
  SRCS
    ed25519_verify_key_manager.cc
    ed25519_verify_key_manager.h
  DEPS
    tink::core::key_type_manager
    tink::core::public_key_verify
    tink::subtle::ed25519_verify_boringssl
    tink::subtle::subtle_util_boringssl
    tink::util::constants
    tink::util::errors
    tink::util::protobuf_helper
    tink::util::status
    tink::util::statusor
    tink::util::validation
    tink::proto::ed25519_cc_proto
    absl::memory
    absl::strings
)

tink_cc_library(
  NAME sig_util
  SRCS
    sig_util.cc
    sig_util.h
  DEPS
    tink::core::public_key_sign
    tink::core::public_key_verify
    tink::util::status
)

tink_cc_library(
  NAME rsa_ssa_pkcs1_sign_key_manager
  SRCS
    rsa_ssa_pkcs1_sign_key_manager.cc
    rsa_ssa_pkcs1_sign_key_manager.h
  DEPS
    tink::signature::rsa_ssa_pkcs1_verify_key_manager
    tink::signature::sig_util
    tink::core::private_key_type_manager
    tink::core::public_key_sign
    tink::core::public_key_verify
    tink::subtle::rsa_ssa_pkcs1_sign_boringssl
    tink::subtle::subtle_util_boringssl
    tink::util::constants
    tink::util::enums
    tink::util::errors
    tink::util::protobuf_helper
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::validation
    tink::proto::rsa_ssa_pkcs1_cc_proto
    absl::memory
    absl::strings
)

tink_cc_library(
  NAME rsa_ssa_pkcs1_verify_key_manager
  SRCS
    rsa_ssa_pkcs1_verify_key_manager.cc
    rsa_ssa_pkcs1_verify_key_manager.h
  DEPS
    tink::core::key_type_manager
    tink::core::public_key_verify
    tink::subtle::rsa_ssa_pkcs1_verify_boringssl
    tink::subtle::subtle_util_boringssl
    tink::util::constants
    tink::util::enums
    tink::util::errors
    tink::util::protobuf_helper
    tink::util::status
    tink::util::statusor
    tink::util::validation
    tink::proto::rsa_ssa_pkcs1_cc_proto
    absl::memory
    absl::strings
)

tink_cc_library(
  NAME rsa_ssa_pss_sign_key_manager
  SRCS
    rsa_ssa_pss_sign_key_manager.cc
    rsa_ssa_pss_sign_key_manager.h
  DEPS
    tink::signature::rsa_ssa_pss_verify_key_manager
    tink::signature::sig_util
    tink::core::key_type_manager
    tink::core::private_key_type_manager
    tink::core::public_key_sign
    tink::subtle::rsa_ssa_pss_sign_boringssl
    tink::subtle::subtle_util_boringssl
    tink::util::constants
    tink::util::enums
    tink::util::errors
    tink::util::protobuf_helper
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::proto::common_cc_proto
    tink::proto::rsa_ssa_pss_cc_proto
    tink::proto::tink_cc_proto
    absl::memory
    absl::strings
)

tink_cc_library(
  NAME rsa_ssa_pss_verify_key_manager
  SRCS
    rsa_ssa_pss_verify_key_manager.cc
    rsa_ssa_pss_verify_key_manager.h
  DEPS
    tink::core::key_manager
    tink::core::public_key_verify
    tink::core::public_key_sign
    tink::subtle::rsa_ssa_pss_verify_boringssl
    tink::subtle::subtle_util_boringssl
    tink::util::constants
    tink::util::enums
    tink::util::errors
    tink::util::protobuf_helper
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::proto::common_cc_proto
    tink::proto::rsa_ssa_pss_cc_proto
    tink::proto::tink_cc_proto
    absl::memory
    absl::strings
)

tink_cc_library(
  NAME signature_config
  SRCS
    signature_config.cc
    signature_config.h
  DEPS
    tink::signature::ecdsa_sign_key_manager
    tink::signature::ed25519_sign_key_manager
    tink::signature::rsa_ssa_pkcs1_sign_key_manager
    tink::signature::rsa_ssa_pss_sign_key_manager
    tink::signature::ecdsa_verify_key_manager
    tink::signature::ed25519_verify_key_manager
    tink::signature::rsa_ssa_pkcs1_verify_key_manager
    tink::signature::rsa_ssa_pss_verify_key_manager
    tink::signature::public_key_sign_wrapper
    tink::signature::public_key_verify_wrapper
    tink::config::config_util
    tink::config::tink_fips
    tink::core::registry
    tink::util::status
    tink::proto::config_cc_proto
    absl::base
    absl::memory
)

tink_cc_library(
  NAME signature_pem_keyset_reader
  SRCS
    signature_pem_keyset_reader.cc
    signature_pem_keyset_reader.h
  DEPS
    tink::signature::rsa_ssa_pkcs1_sign_key_manager
    tink::signature::rsa_ssa_pkcs1_verify_key_manager
    tink::signature::rsa_ssa_pss_sign_key_manager
    tink::signature::rsa_ssa_pss_verify_key_manager
    tink::subtle::pem_parser_boringssl
    tink::subtle::subtle_util_boringssl
    tink::util::enums
    tink::util::keyset_util
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::proto::common_cc_proto
    tink::proto::rsa_ssa_pkcs1_cc_proto
    tink::proto::rsa_ssa_pss_cc_proto
    tink::proto::tink_cc_proto
    absl::memory
    absl::strings
)

# tests

tink_cc_test(
  NAME public_key_verify_wrapper_test
  SRCS public_key_verify_wrapper_test.cc
  DEPS
    tink::signature::public_key_verify_wrapper
    tink::core::primitive_set
    tink::core::public_key_sign
    tink::core::public_key_verify
    tink::util::status
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME public_key_verify_factory_test
  SRCS public_key_verify_factory_test.cc
  DEPS
    tink::signature::ecdsa_verify_key_manager
    tink::signature::public_key_verify_factory
    tink::signature::signature_config
    tink::core::config
    tink::core::keyset_handle
    tink::core::public_key_verify
    tink::core::registry
    tink::util::test_keyset_handle
    tink::util::status
    tink::util::test_util
    tink::proto::ecdsa_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME public_key_sign_wrapper_test
  SRCS public_key_sign_wrapper_test.cc
  DEPS
    tink::signature::public_key_sign_wrapper
    tink::core::crypto_format
    tink::core::primitive_set
    tink::core::public_key_sign
    tink::core::public_key_verify
    tink::util::status
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::tink_cc_proto
    absl::memory
)

tink_cc_test(
  NAME public_key_sign_factory_test
  SRCS public_key_sign_factory_test.cc
  DEPS
    tink::signature::ecdsa_sign_key_manager
    tink::signature::public_key_sign_factory
    tink::signature::signature_config
    tink::core::config
    tink::core::keyset_handle
    tink::core::public_key_sign
    tink::core::registry
    tink::util::test_keyset_handle
    tink::util::status
    tink::util::test_util
    tink::proto::ecdsa_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME ecdsa_verify_key_manager_test
  SRCS ecdsa_verify_key_manager_test.cc
  DEPS
    tink::signature::ecdsa_sign_key_manager
    tink::signature::ecdsa_verify_key_manager
    tink::core::public_key_sign
    tink::core::public_key_verify
    tink::subtle::ecdsa_sign_boringssl
    tink::subtle::subtle_util_boringssl
    tink::util::enums
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::ecdsa_cc_proto
    gmock
)

tink_cc_test(
  NAME ed25519_verify_key_manager_test
  SRCS ed25519_verify_key_manager_test.cc
  DEPS
    tink::signature::ed25519_sign_key_manager
    tink::signature::ed25519_verify_key_manager
    tink::core::public_key_sign
    tink::core::public_key_verify
    tink::core::registry
    tink::subtle::ed25519_sign_boringssl
    tink::util::enums
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::ed25519_cc_proto
    gmock
)

tink_cc_test(
  NAME rsa_ssa_pkcs1_verify_key_manager_test
  SRCS rsa_ssa_pkcs1_verify_key_manager_test.cc
  DEPS
    tink::signature::rsa_ssa_pkcs1_sign_key_manager
    tink::signature::rsa_ssa_pkcs1_verify_key_manager
    tink::core::public_key_sign
    tink::core::public_key_verify
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_util
    tink::util::test_matchers
    tink::proto::rsa_ssa_pkcs1_cc_proto
    tink::proto::tink_cc_proto
    absl::strings
    crypto
    gmock
)

tink_cc_test(
  NAME rsa_ssa_pss_verify_key_manager_test
  SRCS rsa_ssa_pss_verify_key_manager_test.cc
  DEPS
    tink::signature::rsa_ssa_pss_sign_key_manager
    tink::signature::rsa_ssa_pss_verify_key_manager
    tink::core::public_key_sign
    tink::core::public_key_verify
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_util
    tink::util::test_matchers
    tink::proto::rsa_ssa_pss_cc_proto
    absl::strings
    crypto
    gmock
)

tink_cc_test(
  NAME ecdsa_sign_key_manager_test
  SRCS ecdsa_sign_key_manager_test.cc
  DEPS
    tink::signature::ecdsa_sign_key_manager
    tink::signature::ecdsa_verify_key_manager
    tink::signature::signature_key_templates
    tink::core::public_key_sign
    tink::core::public_key_verify
    tink::subtle::ecdsa_verify_boringssl
    tink::subtle::subtle_util_boringssl
    tink::util::enums
    tink::util::istream_input_stream
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::ecdsa_cc_proto
    gmock
)

tink_cc_test(
  NAME ed25519_sign_key_manager_test
  SRCS ed25519_sign_key_manager_test.cc
  DEPS
    tink::signature::ed25519_sign_key_manager
    tink::signature::ed25519_verify_key_manager
    tink::core::public_key_sign
    tink::core::registry
    tink::subtle::ed25519_verify_boringssl
    tink::util::enums
    tink::util::istream_input_stream
    tink::util::protobuf_helper
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::ed25519_cc_proto
    absl::flat_hash_set
    gmock
)

tink_cc_test(
  NAME rsa_ssa_pkcs1_sign_key_manager_test
  SRCS rsa_ssa_pkcs1_sign_key_manager_test.cc
  DEPS
    tink::signature::rsa_ssa_pkcs1_sign_key_manager
    tink::signature::rsa_ssa_pkcs1_verify_key_manager
    tink::core::public_key_sign
    tink::core::public_key_verify
    tink::subtle::rsa_ssa_pkcs1_verify_boringssl
    tink::subtle::subtle_util_boringssl
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::rsa_ssa_pkcs1_cc_proto
    tink::proto::tink_cc_proto
    crypto
    gmock
    absl::flat_hash_set
)

tink_cc_test(
  NAME rsa_ssa_pss_sign_key_manager_test
  SRCS rsa_ssa_pss_sign_key_manager_test.cc
  DEPS
    tink::signature::rsa_ssa_pss_sign_key_manager
    tink::signature::rsa_ssa_pss_verify_key_manager
    tink::signature::signature_key_templates
    tink::core::public_key_sign
    tink::subtle::rsa_ssa_pss_verify_boringssl
    tink::subtle::subtle_util_boringssl
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::rsa_ssa_pss_cc_proto
    absl::flat_hash_set
    crypto
    gmock
)

tink_cc_test(
  NAME signature_config_test
  SRCS signature_config_test.cc
  DEPS
    tink::signature::rsa_ssa_pss_sign_key_manager
    tink::signature::rsa_ssa_pss_verify_key_manager
    tink::signature::signature_config
    tink::signature::signature_key_templates
    tink::config::tink_fips
    tink::core::config
    tink::core::keyset_handle
    tink::core::public_key_sign
    tink::core::public_key_verify
    tink::core::registry
    tink::util::status
    tink::util::test_matchers
    tink::util::test_util
    absl::memory
    crypto
)

tink_cc_test(
  NAME signature_key_templates_test
  SRCS signature_key_templates_test.cc
  DEPS
    tink::signature::ecdsa_sign_key_manager
    tink::signature::ed25519_sign_key_manager
    tink::signature::rsa_ssa_pkcs1_sign_key_manager
    tink::signature::rsa_ssa_pss_sign_key_manager
    tink::signature::signature_key_templates
    tink::subtle::subtle_util_boringssl
    tink::proto::common_cc_proto
    tink::proto::ecdsa_cc_proto
    tink::proto::ed25519_cc_proto
    tink::proto::empty_cc_proto
    tink::proto::rsa_ssa_pkcs1_cc_proto
    tink::proto::rsa_ssa_pss_cc_proto
    tink::proto::tink_cc_proto
    crypto
)

tink_cc_test(
  NAME signature_pem_keyset_reader_test
  SRCS signature_pem_keyset_reader_test.cc
  DEPS
    tink::signature::signature_pem_keyset_reader
    tink::signature::rsa_ssa_pss_sign_key_manager
    tink::signature::rsa_ssa_pss_verify_key_manager
    tink::signature::signature_config
    tink::subtle::pem_parser_boringssl
    tink::subtle::subtle_util_boringssl
    tink::util::enums
    tink::util::keyset_util
    tink::util::secret_data
    tink::util::status
    tink::util::test_util
    tink::proto::common_cc_proto
    tink::proto::rsa_ssa_pss_cc_proto
    tink::proto::tink_cc_proto
    absl::strings
    gmock
)

tink_module(config::internal)

tink_cc_library(
  NAME global_registry
  SRCS
    global_registry.cc
    global_registry.h
  DEPS
    absl::check
    tink::core::configuration
    tink::core::key_gen_configuration
    tink::internal::configuration_impl
    tink::internal::key_gen_configuration_impl
)

tink_cc_test(
  NAME global_registry_test
  SRCS
    global_registry_test.cc
  DEPS
    tink::config::internal::global_registry
    gmock
    absl::status
    tink::core::keyset_handle
    tink::util::test_matchers
    tink::proto::aes_gcm_cc_proto
    tink::proto::tink_cc_proto
)

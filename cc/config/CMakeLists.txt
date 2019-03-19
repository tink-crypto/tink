tink_module(config)

tink_cc_library(
  NAME tink_config
  SRCS
    tink_config.cc
    tink_config.h
  DEPS
    tink::core::config
    tink::core::key_manager
    tink::daead::deterministic_aead_config
    tink::hybrid::hybrid_config
    tink::signature::signature_config
    tink::util::status
    tink::proto::config_cc_proto
)

# tests

tink_cc_test(
  NAME tink_config_test
  SRCS tink_config_test.cc
  DEPS
    tink::config::tink_config
    tink::core::aead
    tink::core::catalogue
    tink::core::config
    tink::core::deterministic_aead
    tink::core::hybrid_decrypt
    tink::core::hybrid_encrypt
    tink::core::mac
    tink::core::registry
    tink::util::status
)

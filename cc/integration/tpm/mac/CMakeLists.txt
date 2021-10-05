tink_module(tpm_mac)

tink_cc_library(
    NAME tpm_hmac_key_manager
    SRCS
      tpm_hmac_key_manager.cc
      tpm_hmac_key_manager.h
    DEPS
        tink::core::key_type_manager
        tink::core::mac
        tink::util::constants
        tink::util::errors
        tink::util::status
        tink::util::statusor
        tink::util::validation
        tink::proto::common_cc_proto
        tink::proto::tpm_hmac_cc_proto
        tink::proto::tpm_common_cc_proto
        absl::flat_hash_map
)

tink_cc_test(
  NAME tpm_hmac_key_manager_test
  SRCS tpm_hmac_key_manager_test.cc
  DEPS
    tink::mac::tpm_hmac_key_manager
    tink::util::test_matchers
    tink::proto::common_cc_proto
    tink::proto::hmac_cc_proto
    tink::proto::tpm_hmac_cc_proto
    gmock
)

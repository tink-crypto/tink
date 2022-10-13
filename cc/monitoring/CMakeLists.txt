tink_module(monitoring)

tink_cc_library(
  NAME monitoring
  SRCS
    monitoring.h
  DEPS
    absl::flat_hash_map
    tink::core::key_status
    tink::util::statusor
)

tink_cc_library(
  NAME monitoring_client_mocks
  SRCS
    monitoring_client_mocks.h
  DEPS
    tink::monitoring::monitoring
    gmock
)

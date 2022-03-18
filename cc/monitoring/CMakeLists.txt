tink_module(monitoring)

tink_cc_library(
  NAME monitoring
  SRCS
    monitoring.h
  DEPS
    absl::flat_hash_map
    tink::util::statusor
)

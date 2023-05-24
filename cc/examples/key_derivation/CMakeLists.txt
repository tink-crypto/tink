add_executable(key_derivation_cli key_derivation_cli.cc)
target_include_directories(key_derivation_cli PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${TINK_EXAMPLES_INCLUDE_PATH}")
target_link_libraries(key_derivation_cli
  tink::static
  absl::check
  absl::flags_parse
  util)

add_test(
  NAME key_derivation_cli_test
  COMMAND "${BASH_PROGRAM}"
    "${CMAKE_CURRENT_SOURCE_DIR}/key_derivation_cli_test.sh"
    "${CMAKE_CURRENT_BINARY_DIR}/key_derivation_cli"
    "${CMAKE_CURRENT_SOURCE_DIR}/keyset.json"

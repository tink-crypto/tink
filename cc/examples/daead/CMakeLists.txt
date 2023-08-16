add_executable(deterministic_aead_cli deterministic_aead_cli.cc)
target_include_directories(deterministic_aead_cli PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${TINK_EXAMPLES_INCLUDE_PATH}")
target_link_libraries(deterministic_aead_cli
  tink::static
  absl::check
  absl::flags_parse
  util)

add_test(
  NAME deterministic_aead_cli_test
  COMMAND "${BASH_PROGRAM}"
    "${CMAKE_CURRENT_SOURCE_DIR}/deterministic_aead_cli_test.sh"
    "${CMAKE_CURRENT_BINARY_DIR}/deterministic_aead_cli"
    "${CMAKE_CURRENT_SOURCE_DIR}/deterministic_aead_test_keyset.json")

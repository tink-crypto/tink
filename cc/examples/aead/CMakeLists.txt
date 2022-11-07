add_executable(aead_cli aead_cli.cc)
target_include_directories(aead_cli PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${TINK_EXAMPLES_INCLUDE_PATH}")
target_link_libraries(aead_cli
  tink::static
  absl::flags_parse
  util)

add_test(
  NAME aead_cli_test
  COMMAND "${BASH_PROGRAM}"
    "${CMAKE_CURRENT_SOURCE_DIR}/aead_cli_test.sh"
    "${CMAKE_CURRENT_BINARY_DIR}/aead_cli"
    "${CMAKE_CURRENT_SOURCE_DIR}/aead_test_keyset.json")

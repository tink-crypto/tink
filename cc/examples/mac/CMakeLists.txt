add_executable(mac_cli mac_cli.cc)
target_include_directories(mac_cli PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${TINK_EXAMPLES_INCLUDE_PATH}")
target_link_libraries(mac_cli
  tink::static
  absl::flags_parse
  util)

add_test(
  NAME mac_cli_test
  COMMAND "${BASH_PROGRAM}"
    "${CMAKE_CURRENT_SOURCE_DIR}/mac_cli_test.sh"
    "${CMAKE_CURRENT_BINARY_DIR}/mac_cli"
    "${CMAKE_CURRENT_SOURCE_DIR}/mac_test_keyset.json")

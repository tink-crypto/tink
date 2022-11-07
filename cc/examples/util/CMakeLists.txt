add_library(util util.cc util.h)
target_include_directories(util PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${TINK_EXAMPLES_INCLUDE_PATH}")
target_link_libraries(util tink::static)

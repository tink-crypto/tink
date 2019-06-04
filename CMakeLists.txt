cmake_minimum_required(VERSION 3.5)
project(Tink CXX)

# Deviate from the naming convention for consistency with tink_version.bzl.
include(tink_version.cmake)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

option(TINK_BUILD_TESTS "Build Tink tests" OFF)

# Build libtink.so and the bundle tarball (libtink + dependent headers).
# This is useful to create a self-contained export of Tink, to be used in
# projects that do not wish to include the full set of Tink targets in their
# build system, or do not use CMake.
#
# Together with libtink, TinkConfig.cmake is created too, which allows to pull
# Tink into your project as an external dependency using find_package().
#
# Off by default, since we don't currently support Windows and the shared lib
# requires position independent code, which adds a small performance penalty.
option(TINK_BUILD_SHARED_LIB "Build libtink bundle it with the headers" OFF)

if (TINK_BUILD_SHARED_LIB)
  set(CMAKE_POSITION_INDEPENDENT_CODE ON CACHE BOOL "libtink override" FORCE)
endif()

set(CPACK_GENERATOR TGZ)
set(CPACK_PACKAGE_VERSION ${TINK_VERSION_LABEL})

include(CPack)
include(TinkWorkspace)
include(TinkBuildRules)
include(TinkUtil)

# Bazel rewrites import paths so that "cc/example/foo.h" can be included as
# "tink/example/foo.h". The following lines simulate this behaviour by creating
# a symlink to cc/ called tink/, and placing it in a separate subdirectory,
# which is then specified as a global include path.
#
# It's important to create a separate directory and not just drop the link in
# CMAKE_CURRENT_BINARY_DIR, since adding that to the include paths will
# make the whole contents of that directory visible to the compiled files,
# which may result in undeclared dependencies that nevertheless happen to work.
#
set(TINK_INCLUDE_ALIAS_DIR "${CMAKE_CURRENT_BINARY_DIR}/__include_alias")
add_directory_alias(
  "${CMAKE_CURRENT_SOURCE_DIR}/cc" "${TINK_INCLUDE_ALIAS_DIR}/tink")
list(APPEND TINK_INCLUDE_DIRS "${TINK_INCLUDE_ALIAS_DIR}")

add_subdirectory(cc)
add_subdirectory(proto)

if (TINK_BUILD_SHARED_LIB)
  install(FILES README.md LICENSE DESTINATION "share/doc/tink")

  # The trailing slash in a directory name is used to strip it from the paths
  # being installed. Do not add or remove it just for style reasons.
  install(
    DIRECTORY
      "${CMAKE_CURRENT_SOURCE_DIR}/cc/"
      "${TINK_GENFILE_DIR}/tink/"
      "${TINK_GENFILE_DIR}/proto"
    DESTINATION "include/tink"
    FILES_MATCHING PATTERN "*.h"
  )

  # Bundle Abseil and BoringSSL headers with Tink.
  install(
    DIRECTORY
      "${com_google_absl_SOURCE_DIR}/absl"
      "${com_google_protobuf_SOURCE_DIR}/src/google"
    DESTINATION "include"
    FILES_MATCHING
      REGEX "\\.(h|inc)$"
      PATTERN "testdata" EXCLUDE
  )

  export(EXPORT Tink FILE TinkConfig.cmake)
endif()

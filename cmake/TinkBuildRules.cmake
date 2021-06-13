# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Partially adapted from Abseil's CMake helpers
# https://github.com/abseil/abseil-cpp/blob/master/CMake/AbseilHelpers.cmake

# Rules for declaring Tink targets in a way similar to Bazel.
#
# These functions are intended to reduce the difficulty of supporting completely
# different build systems, and are designed for Tink internal usage only.
# They may work outside this project too, but we don't support that.
#
# A set of global variables influences the behavior of the rules:
#
#   TINK_MODULE name used to build more descriptive names and for namespaces.
#   TINK_GENFILE_DIR generated content root, such pb.{cc,h} files.
#   TINK_INCLUDE_DIRS list of global include paths.
#   TINK_CXX_STANDARD C++ standard to enforce, 11 for now.
#   TINK_BUILD_TESTS flag, set to false to disable tests (default false).
#
# Sensible defaults are provided for all variables, except TINK_MODULE, which is
# defined by calls to tink_module(). Please don't alter it directly.

include(CMakeParseArguments)

if (NOT ${CMAKE_VERSION} VERSION_LESS 3.9)
  include(GoogleTest)
endif()


if (TINK_BUILD_TESTS)
  enable_testing()
endif()

if (NOT DEFINED TINK_GENFILE_DIR)
  set(TINK_GENFILE_DIR "${PROJECT_BINARY_DIR}/__generated")
endif()

if (NOT DEFINED TINK_CXX_STANDARD)
  set(TINK_CXX_STANDARD 11)
  if (DEFINED CMAKE_CXX_STANDARD_REQUIRED AND CMAKE_CXX_STANDARD_REQUIRED AND DEFINED CMAKE_CXX_STANDARD)
    set(TINK_CXX_STANDARD ${CMAKE_CXX_STANDARD})
  endif()
endif()

list(APPEND TINK_INCLUDE_DIRS "${TINK_GENFILE_DIR}")

set(TINK_IDE_FOLDER "Tink")

# Declare the beginning of a new Tink library namespace.
#
# As a rule of thumb, every CMakeLists.txt should be a different module, named
# after the directory that contains it, and this function should appear at the
# top of each CMakeLists script.
#
# This is not a requirement, though. Targets should be grouped logically, and
# multiple directories can be part of the same module as long as target names
# do not collide.
#
macro(tink_module NAME)
  set(TINK_MODULE ${NAME})
endmacro()

# Declare a Tink library. Produces a static library that can be linked into
# other test, binary or library targets. Tink libraries are mainly meant as
# a way to organise code and speed up compilation.
#
# Arguments:
#   NAME base name of the target. See below for target naming conventions.
#   SRCS list of source files, including headers.
#   DEPS list of dependency targets.
#   PUBLIC flag, signal that this target is intended for external use.
#
# If SRCS contains only headers, an INTERFACE rule is created. This rule carries
# include path and link library information, but is not directly buildable.
#
# The corresponding build target is named tink_<MODULE>_<NAME> if PUBLIC is
# specified, or tink_internal_<MODULE>_<NAME> otherwise. An alias is also
# defined for use in CMake scripts, in the tink::<MODULE>::<NAME> form.
#
# Unlike Bazel, CMake does not enforce the rule that all dependencies must be
# listed. CMake DEPS just carry include, build and link flags that are passed
# to the compiler. Because of this, a target might compile even if a dependency
# is not specified, but that could break at any time. So make sure that all
# dependencies are explicitly specified.
#
function(tink_cc_library)
  cmake_parse_arguments(PARSE_ARGV 0 tink_cc_library
    "PUBLIC"
    "NAME"
    "SRCS;DEPS"
  )

  if (NOT DEFINED TINK_MODULE)
    message(FATAL_ERROR
            "TINK_MODULE not defined, perhaps you are missing a tink_module() statement?")
  endif()

  # We replace :: with __ in targets, because :: may not appear in target names.
  # However, the module name should still span multiple name spaces.
  STRING(REPLACE "::" "__" _ESCAPED_TINK_MODULE ${TINK_MODULE})

  set(_is_headers_only_lib true)
  foreach(_src_file ${tink_cc_library_SRCS})
    if(${_src_file} MATCHES "\\.cc$")
      set(_is_headers_only_lib false)
      break()
    endif()
  endforeach()

  if (tink_cc_library_PUBLIC)
    set(_target_name "tink_${_ESCAPED_TINK_MODULE}_${tink_cc_library_NAME}")
  else()
    set(_target_name "tink_internal_${_ESCAPED_TINK_MODULE}_${tink_cc_library_NAME}")
  endif()

  if(NOT _is_headers_only_lib)
    add_library(${_target_name} STATIC "")
    target_sources(${_target_name} PRIVATE ${tink_cc_library_SRCS})
    target_include_directories(${_target_name} PUBLIC ${TINK_INCLUDE_DIRS})
    target_link_libraries(${_target_name} PUBLIC ${tink_cc_library_DEPS})
    set_property(TARGET ${_target_name} PROPERTY CXX_STANDARD ${TINK_CXX_STANDARD})
    set_property(TARGET ${_target_name} PROPERTY CXX_STANDARD_REQUIRED true)
    if (tink_cc_library_PUBLIC)
      set_property(TARGET ${_target_name}
                   PROPERTY FOLDER "${TINK_IDE_FOLDER}")
    else()
      set_property(TARGET ${_target_name}
                   PROPERTY FOLDER "${TINK_IDE_FOLDER}/Internal")
    endif()
  else()
    add_library(${_target_name} INTERFACE)
    target_include_directories(${_target_name} INTERFACE ${TINK_INCLUDE_DIRS})
    target_link_libraries(${_target_name} INTERFACE ${tink_cc_library_DEPS})
  endif()

  add_library(
    tink::${TINK_MODULE}::${tink_cc_library_NAME} ALIAS ${_target_name})
endfunction(tink_cc_library)

# Declare a Tink test using googletest, with a syntax similar to Bazel.
#
# Parameters:
#   NAME base name of the test.
#   SRCS list of test source files, headers included.
#   DEPS list of dependencies, see tink_cc_library above.
#   DATA list of non-code dependencies, such as test vectors.
#
# Tests added with this macro are automatically registered.
# Each test produces a build target named tink_test_<MODULE>_<NAME>.
#
function(tink_cc_test)
  cmake_parse_arguments(PARSE_ARGV 0 tink_cc_test
    ""
    "NAME"
    "SRCS;DEPS;DATA"
  )

  if (NOT TINK_BUILD_TESTS)
    return()
  endif()

  if (NOT DEFINED TINK_MODULE)
    message(FATAL_ERROR "TINK_MODULE not defined")
  endif()

  # We replace :: with __ in targets, because :: may not appear in target names.
  # However, the module name should still span multiple name spaces.
  STRING(REPLACE "::" "__" _ESCAPED_TINK_MODULE ${TINK_MODULE})

  set(_target_name "tink_test_${_ESCAPED_TINK_MODULE}_${tink_cc_test_NAME}")

  add_executable(${_target_name}
    ${tink_cc_test_SRCS}
  )

  target_link_libraries(${_target_name}
    gtest_main
    ${tink_cc_test_DEPS}
  )

  set_property(TARGET ${_target_name}
               PROPERTY FOLDER "${TINK_IDE_FOLDER}/Tests")
  set_property(TARGET ${_target_name} PROPERTY CXX_STANDARD ${TINK_CXX_STANDARD})
  set_property(TARGET ${_target_name} PROPERTY CXX_STANDARD_REQUIRED true)

  if (${CMAKE_VERSION} VERSION_LESS 3.9)
    add_test(NAME ${_target_name} COMMAND ${_target_name})
  else()
    gtest_discover_tests(${_target_name})
  endif()
endfunction(tink_cc_test)

# Declare a C++ Proto library.
#
# Parameters:
#   NAME base name of the library.
#   SRCS list of .proto source files.
#   DEPS list of proto library dependencies, produced by tink_cc_proto or not.
#
# The resulting library follows the same naming convention as tink_cc_library.
#
function(tink_cc_proto)
  cmake_parse_arguments(PARSE_ARGV 0 tink_cc_proto
    ""
    "NAME"
    "SRCS;DEPS"
  )

  set(tink_cc_proto_GEN_SRCS)
  foreach(_src_path ${tink_cc_proto_SRCS})
    get_filename_component(_src_absolute_path "${_src_path}" ABSOLUTE)
    get_filename_component(_src_basename "${_src_path}" NAME_WE)
    get_filename_component(_src_dir "${_src_absolute_path}" DIRECTORY)
    file(RELATIVE_PATH _src_rel_path "${PROJECT_SOURCE_DIR}" "${_src_dir}")

    set(_gen_srcs)
    foreach(_gen_ext .pb.h .pb.cc)
      list(APPEND _gen_srcs
           "${TINK_GENFILE_DIR}/${_src_rel_path}/${_src_basename}${_gen_ext}")
    endforeach()

    list(APPEND tink_cc_proto_GEN_SRCS ${_gen_srcs})

    add_custom_command(
      COMMAND protobuf::protoc
      ARGS
        --cpp_out "${TINK_GENFILE_DIR}"
        -I "${PROJECT_SOURCE_DIR}"
        "${_src_absolute_path}"
      OUTPUT
        ${_gen_srcs}
      DEPENDS
        protobuf::protoc
        ${_src_absolute_path}
      COMMENT "Running CXX protocol buffer compiler on ${_src_path}"
      VERBATIM
    )
  endforeach()

  set_source_files_properties(
    ${tink_cc_proto_GEN_SRCS} PROPERTIES GENERATED true)

  tink_cc_library(
    NAME ${tink_cc_proto_NAME}
    SRCS ${tink_cc_proto_GEN_SRCS}
    DEPS
      protobuf::libprotoc
      ${tink_cc_proto_DEPS}
  )
endfunction()

# Declare an empty target, that depends on all those specified. Use this rule
# to group dependencies that are logically related and give them a single name.
#
# Parameters:
#   NAME base name of the target.
#   DEPS list of dependencies to group.
#
# Each tink_target_group produces a target named tink_<MODULE>_<NAME>.
function(tink_target_group)
  cmake_parse_arguments(PARSE_ARGV 0 tink_target_group "" "NAME" "DEPS")
  set(_target_name "tink_${TINK_MODULE}_${tink_target_group_NAME}")
  add_custom_target(${_target_name})
  add_dependencies(${_target_name} ${tink_target_group_DEPS})
endfunction()

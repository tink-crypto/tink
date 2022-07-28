#!/bin/bash
# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
################################################################################

# This scripts checks that a given Go workspace has its generated Bazel files up
# to date.
#
# NOTEs:
#   * Bazel and go must be already installed.
#
# Usage:
#   ./kokoro/testutils/check_go_generated_files_up_to_date.sh <go project dir>

check_go_generated_files_up_to_date() {
  local go_project_dir="$1"

  (
    cd "${go_project_dir}"
    local -r temp_dir_current_generated_files="$(mktemp -dt \
      current_tink_go_build_files.XXXXXX)"
    local -r go_generated_files=(
      ./go.mod
      ./go.sum
      ./deps.bzl
    )

    # Copy all current generated files into temp_dir_current_generated_files.
    local current_go_generated_files=( "${go_generated_files[@]}" )
    while read -r -d $'\0' generated_file; do
      current_go_generated_files+=("${generated_file}")
    done < <(find . -name BUILD.bazel -print0)
    readonly current_go_generated_files

    for generated_file_path in "${current_go_generated_files[@]}"; do
      mkdir -p \
        "$(dirname "${temp_dir_current_generated_files}/${generated_file_path}")"
      cp "${generated_file_path}" \
        "${temp_dir_current_generated_files}/${generated_file_path}"
    done

    # Update build files
    go mod tidy
    # Update deps.bzl
    bazel run //:gazelle-update-repos
    # Update all BUILD.bazel files
    bazel run //:gazelle

    # Compare current with new build files
    local new_go_generated_files=( "${go_generated_files[@]}" )
    while read -r -d $'\0' generated_file; do
      new_go_generated_files+=("${generated_file}")
    done < <(find . -name BUILD.bazel -print0)
    readonly new_go_generated_files

    for generated_file_path in "${new_go_generated_files[@]}"; do
      if ! cmp -s "${generated_file_path}" \
          "${temp_dir_current_generated_files}/${generated_file_path}"; then
        echo "FAIL: ${generated_file_path} needs to be updated. Please follow \
the instructions on go/tink-workflows#update-go-build."
        exit 1
      fi
    done
  )
}

check_go_generated_files_up_to_date "$@"

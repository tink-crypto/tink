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

# This script upgrades GCC when running on Kokoro.
#
# Currently this is only needed for Ubuntu 1604 (gcc-5 => gcc-7).
#
# Usage instructions:
#
#  ./kokoro/testutils/upgrade_gcc.sh
set -e

upgrade_gcc() {
  # Install gcc-7.
  sudo apt install build-essential software-properties-common -y
  sudo add-apt-repository ppa:ubuntu-toolchain-r/test -y
  sudo apt update
  sudo apt install gcc-7 g++-7 -y
  sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-7 70 \
    --slave /usr/bin/g++ g++ /usr/bin/g++-7
  gcc -v
}

if [[ -n "${KOKORO_ARTIFACTS_DIR:-}" ]] ; then
  upgrade_gcc
fi

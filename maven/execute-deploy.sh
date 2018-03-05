#!/bin/sh

# Copyright 2017 Google Inc.
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
####################################################################################

# Fail on any error.
set -e

# Display commands to stderr.
set -x

readonly MVN_GOAL="$1"
readonly VERSION="$2"
shift 2
readonly EXTRA_MAVEN_ARGS=("$@")

if [ -z "${VERSION}" ]
then
  echo "Must set the VERSION variable"
  exit 1
fi

library_output_file() {
  library=$1
  library_output=bazel-bin/$library
  if [[ ! -e $library_output ]]; then
     library_output=bazel-genfiles/$library
  fi
  if [[ ! -e $library_output ]]; then
    echo "Could not find bazel output file for $library"
    exit 1
  fi
  echo -n $library_output
}

deploy_library() {
  library=$1
  javadoc=$2
  pomfile=$3
  bazel build $library $javadoc

  # Update the version
  sed -i \
    's/VERSION_PLACEHOLDER/'"$VERSION"'/' \
    $pomfile

  mvn $MVN_GOAL \
    -Dfile=$(library_output_file $library) \
    -Djavadoc=$(library_output_file $javadoc) \
    -DpomFile=$pomfile \
    "${EXTRA_MAVEN_ARGS[@]:+${EXTRA_MAVEN_ARGS[@]}}"

  # Reverse the version change
  sed -i \
    's/'"$VERSION"'/VERSION_PLACEHOLDER/' \
    $pomfile
}

deploy_library \
  java/libtink.jar \
  java/libtink-javadoc.jar \
  $(dirname $0)/tink.pom.xml

deploy_library \
  java/libtink-android.jar \
  java/libtink-android-javadoc.jar \
  $(dirname $0)/tink-android.pom.xml

deploy_library \
  apps/paymentmethodtoken/libpaymentmethodtoken.jar \
  apps/paymentmethodtoken/libpaymentmethodtoken-javadoc.jar \
  $(dirname $0)/apps-paymentmethodtoken.pom.xml

deploy_library \
  apps/rewardedads/java/libjava.jar \
  apps/rewardedads/java/librewardedads-javadoc.jar \
  $(dirname $0)/apps-rewardedads.pom.xml

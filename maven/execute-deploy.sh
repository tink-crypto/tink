#!/bin/sh

# Fail on any error.
set -e

# Display commands to stderr.
set -x

readonly MVN_GOAL="$1"
shift 1
readonly EXTRA_MAVEN_ARGS=("$@")

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

  mvn $MVN_GOAL \
    -Dfile=$(library_output_file $library) \
    -Djavadoc=$(library_output_file $javadoc) \
    -DpomFile=$pomfile \
    "${EXTRA_MAVEN_ARGS[@]:+${EXTRA_MAVEN_ARGS[@]}}"
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

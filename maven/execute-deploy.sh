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

#!/bin/sh

# Fail on any error.
set -e

readonly MVN_GOAL="$1"
readonly VERSION="$2"
shift 2
readonly EXTRA_MAVEN_ARGS=("$@")

if [ -z "${VERSION}" ]
then
  echo "Must set the VERSION variable"
  exit 1
fi

git config --global user.email "noreply@google.com"
git config --global user.name "Tink Team"

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
  library_name=$1
  library=$2
  srcjar=$3
  javadoc=$4
  pomfile=$5
  bazel build $library $srcjar $javadoc

  # Update the version
  sed -i \
    's/VERSION_PLACEHOLDER/'"$VERSION"'/' \
    $pomfile

  mvn $MVN_GOAL \
    -Dfile=$(library_output_file $library) \
    -Dsources=$(library_output_file $srcjar) \
    -Djavadoc=$(library_output_file $javadoc) \
    -DpomFile=$pomfile \
    "${EXTRA_MAVEN_ARGS[@]:+${EXTRA_MAVEN_ARGS[@]}}"

  # Reverse the version change
  sed -i \
    's/'"$VERSION"'/VERSION_PLACEHOLDER/' \
    $pomfile

  publish_javadoc_to_github_pages $library_name $javadoc
}

publish_javadoc_to_github_pages() {
  library_name=$1
  javadoc=$(library_output_file $2)

  # The account is ise-crypto and its access token is pulled from Keystore.
  git_url=https://ise-crypto:${GITHUB_ACCESS_TOKEN}@github.com/google/tink.git
  if [ -z "${KOKORO_ROOT}" ]; then
    git_url=git@github.com:google/tink.git
  fi

  rm -rf gh-pages
  git clone --quiet --branch=gh-pages $git_url gh-pages > /dev/null

  cd gh-pages
  if [ -d javadoc/$library_name/$VERSION ]; then
    git rm -rf javadoc/$library_name/$VERSION
  fi
  mkdir -p javadoc/$library_name/$VERSION

  unzip ../$javadoc -d javadoc/$library_name/$VERSION
  rm -rf javadoc/$library_name/$VERSION/META-INF/
  git add -f javadoc/$library_name/$VERSION
  if [[ `git status --porcelain` ]]; then
    # Changes
    git commit -m "${library_name}-${VERSION} Javadoc auto-pushed to gh-pages"
    git push -fq origin gh-pages > /dev/null
    echo -e "Published Javadoc to gh-pages.\n"
  else
    # No changes
    echo -e "No changes in ${library_name}-${VERSION} Javadoc.\n"
  fi
  cd ..
}

deploy_library \
  tink \
  java/maven.jar \
  java/maven-src.jar \
  java/maven-javadoc.jar \
  $(dirname $0)/tink.pom.xml

deploy_library \
  tink-android \
  java/maven-android.jar \
  java/maven-android-src.jar \
  java/maven-android-javadoc.jar \
  $(dirname $0)/tink-android.pom.xml

deploy_library \
  apps-paymentmethodtoken \
  apps/paymentmethodtoken/maven.jar \
  apps/paymentmethodtoken/maven-src.jar \
  apps/paymentmethodtoken/maven-javadoc.jar \
  $(dirname $0)/apps-paymentmethodtoken.pom.xml

deploy_library \
  apps-rewardedads \
  apps/rewardedads/maven.jar \
  apps/rewardedads/maven-src.jar \
  apps/rewardedads/maven-javadoc.jar \
  $(dirname $0)/apps-rewardedads.pom.xml

deploy_library \
  apps-webpush \
  apps/webpush/maven.jar \
  apps/webpush/maven-src.jar \
  apps/webpush/maven-javadoc.jar \
  $(dirname $0)/apps-webpush.pom.xml

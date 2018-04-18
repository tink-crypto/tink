#!/bin/bash

set -eu

if [ $# -lt 2 ]; then
  echo "usage $0 <gpg-key> <version-name>"
  exit 1;
fi

key=$1
version_name=$2
shift 2

if [[ ! "$version_name" =~ ^1\. ]]; then
  echo 'Version name must begin with "1."'
  exit 2
fi

if [[ "$version_name" =~ " " ]]; then
  echo "Version name must not have any spaces"
  exit 3
fi

#validate key
keystatus=$(gpg --list-keys | grep ${key} | awk '{print $1}')
if [ "${keystatus}" != "pub" ]; then
  echo "Could not find public key with label ${key}"
  echo -n "Available keys from: "
  gpg --list-keys | grep --invert-match '^sub'

  exit 64
fi

bazel test //... -//objc/...

bash $(dirname $0)/execute-deploy.sh \
  "gpg:sign-and-deploy-file" \
  "$version_name" \
  "-DrepositoryId=sonatype-nexus-staging" \
  "-Durl=https://oss.sonatype.org/service/local/staging/deploy/maven2/" \
  "-Dgpg.keyname=${key}"

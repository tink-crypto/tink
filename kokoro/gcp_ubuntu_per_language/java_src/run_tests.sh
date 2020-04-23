#!/bin/bash

set -euxo pipefail

cd java_src
time bazel build -- ...
time bazel test -- ...

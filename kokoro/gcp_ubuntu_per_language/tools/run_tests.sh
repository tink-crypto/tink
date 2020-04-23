#!/bin/bash

set -euxo pipefail

cd tools
time bazel build -- ...
time bazel test -- ...

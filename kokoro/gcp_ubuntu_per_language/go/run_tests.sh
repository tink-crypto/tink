#!/bin/bash

set -euxo pipefail

cd go
time bazel build -- ...
time bazel test -- ...

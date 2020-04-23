#!/bin/bash

set -euxo pipefail

cd cc
time bazel build -- ...
time bazel test -- ...

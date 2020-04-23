#!/bin/bash

set -euxo pipefail

cd apps
time bazel build -- ...
time bazel test -- ...

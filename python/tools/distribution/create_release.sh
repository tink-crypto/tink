#!/bin/bash
# This script creates a release of Tink Python which includes a source
# distribution and binary wheels for Linux. The release script automatically
# all Python tests on each binary wheel and the source distribution.
set -euo pipefail

mkdir -p release

TINK_BASE=${PWD}/..

# Use signatures for getting images from registry (see https://docs.docker.com/engine/security/trust/content_trust/)
export DOCKER_CONTENT_TRUST=1

# Build binary wheels
docker run --volume $TINK_BASE:/tmp/tink --workdir /tmp/tink/python quay.io/pypa/manylinux2014_x86_64@sha256:cf8940dd5ce452d7741c592e229c28e802cbce5b3074d88a299e4f67f55efba4 /tmp/tink/python/tools/distribution/build_linux_binary_wheels.sh

# Test binary wheels
docker run --volume $TINK_BASE:/tmp/tink --workdir /tmp/tink/python quay.io/pypa/manylinux2014_x86_64@sha256:cf8940dd5ce452d7741c592e229c28e802cbce5b3074d88a299e4f67f55efba4 /tmp/tink/python/tools/distribution/test_linux_binary_wheels.sh

# Build source wheels
pip3 install wheel
export TINK_PYTHON_SETUPTOOLS_OVERRIDE_BASE_PATH=$TINK_BASE
sudo python3 setup.py sdist
cp dist/*.tar.gz release/

# Test install from source wheel
pip3 install release/*.tar.gz
find tink/ -not -path "*cc/pybind*" -type f -name "*_test.py" -print0 | xargs -0 -n1 python3

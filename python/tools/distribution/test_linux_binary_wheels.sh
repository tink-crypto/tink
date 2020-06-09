#!/bin/bash

set -euo pipefail

export TINK_SRC_PATH=/tmp/tink

# This link is required on CentOS, as curl used in the AWS SDK looks for the
# certificates in this location. Removing this line will cause the AWS KMS tests
# to fail.
ln -s /etc/ssl/certs/ca-bundle.trust.crt /etc/ssl/certs/ca-certificates.crt

# Test wheel for Python 3.7
(
  PATH=$PATH:/opt/python/cp37-cp37m/bin
  pip3 install release/*-cp37-cp37m-manylinux2014_x86_64.whl
  find tink/ -not -path "*cc/pybind*" -type f -name "*_test.py" -print0 | xargs -0 -n1 python3
)

# Test wheel for Python 3.8
(
  PATH=$PATH:/opt/python/cp38-cp38/bin
  pip3 install release/*-cp38-cp38-manylinux2014_x86_64.whl
  find tink/ -not -path "*cc/pybind*" -type f -name "*_test.py" -print0 | xargs -0 -n1 python3
)

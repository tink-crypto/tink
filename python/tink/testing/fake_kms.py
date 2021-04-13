# Copyright 2021 Google LLC
#
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
"""A client for Fake KMS."""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

from tink.cc.pybind import tink_bindings


def register_client(key_uri=None, credentials_path=None) -> None:
  """Registers a fake KMS client."""
  if not key_uri:
    key_uri = ''
  if not credentials_path:
    credentials_path = ''
  tink_bindings.register_fake_kms_client_testonly(key_uri, credentials_path)

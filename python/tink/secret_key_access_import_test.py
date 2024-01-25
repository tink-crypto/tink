# Copyright 2023 Google LLC
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
"""Tests for secret_key_access."""

from absl.testing import absltest

import tink
from tink import aead
from tink import daead
from tink import hybrid
from tink import jwt
from tink import mac
from tink import prf
from tink import signature
from tink import streaming_aead


class SecretKeyAccessImportTest(absltest.TestCase):

  def test_tink_secret_key_access_not_imported(self):
    _ = tink
    _ = aead
    _ = daead
    _ = hybrid
    _ = jwt
    _ = mac
    _ = prf
    _ = signature
    _ = streaming_aead
    self.assertFalse(hasattr(tink, "secret_key_access"))


if __name__ == "__main__":
  absltest.main()

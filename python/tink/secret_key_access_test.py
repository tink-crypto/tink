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
"""Tests for secret_key_access."""

from absl.testing import absltest

import tink
from tink import secret_key_access


class OtherKeyAccess(tink.KeyAccess):
  pass


class SecretKeyAccessTest(absltest.TestCase):

  def test_has_secret_access(self):
    self.assertTrue(
        tink.has_secret_key_access(secret_key_access.TOKEN))

  def test_public_key_access_does_not_have_secret_access(self):
    self.assertFalse(
        tink.has_secret_key_access(tink.PUBLIC_KEY_ACCESS_TOKEN))

  def test_other_key_access_does_not_have_secret_access(self):
    other_token = OtherKeyAccess()
    self.assertFalse(tink.has_secret_key_access(other_token))


if __name__ == '__main__':
  absltest.main()

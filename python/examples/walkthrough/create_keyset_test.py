# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS-IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Test for create_keyset."""
from absl.testing import absltest

from tink import aead

import create_keyset


class CreateKeysetTest(absltest.TestCase):

  def test_create_keyset_produces_a_valid_keyset(self):
    aead.register()
    keyset_handle = create_keyset.CreateAead128GcmKeyset()
    # Make sure that we can use this primitive.
    aead_primitive = keyset_handle.primitive(aead.Aead)
    cleartext = b'Some cleartext'
    associated_data = b'Some associated data'
    ciphertext = aead_primitive.encrypt(cleartext, associated_data)
    self.assertEqual(
        aead_primitive.decrypt(ciphertext, associated_data), cleartext)


if __name__ == '__main__':
  absltest.main()

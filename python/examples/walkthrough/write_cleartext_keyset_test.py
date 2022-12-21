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
"""Test for write_cleartext_keyset."""
import io

from absl.testing import absltest

from tink import aead

import create_keyset
import load_cleartext_keyset
import write_cleartext_keyset


class LoadCleartextKeysetTest(absltest.TestCase):

  def test_write_cleartext_keyset_serializes_a_keyset_correctly(self):
    aead.register()
    keyset_handle = create_keyset.CreateAead128GcmKeyset()
    string_io = io.StringIO()
    write_cleartext_keyset.WriteKeyset(keyset_handle, string_io)

    # Make sure that we can deserialize the keyset and use the contained
    # primitive.
    deserialized_keyset_handle = load_cleartext_keyset.LoadKeyset(
        string_io.getvalue())
    deserialized_aead_primitive = deserialized_keyset_handle.primitive(
        aead.Aead)
    aead_primitive = keyset_handle.primitive(aead.Aead)

    plaintext = b'Some plaintext'
    associated_data = b'Some associated data'

    self.assertEqual(
        deserialized_aead_primitive.decrypt(
            aead_primitive.encrypt(plaintext, associated_data),
            associated_data), plaintext)

    self.assertEqual(
        aead_primitive.decrypt(
            deserialized_aead_primitive.encrypt(plaintext, associated_data),
            associated_data), plaintext)


if __name__ == '__main__':
  absltest.main()

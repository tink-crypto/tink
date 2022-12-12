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
"""Test for write_keyset."""
import io

from absl.testing import absltest
import tink
from tink import aead

import create_keyset
import load_encrypted_keyset
import write_keyset

from tink.testing import fake_kms

# Fake KMS keys are base64-encoded keysets. This was generated from
# an AEAD keyser by first serializing it to bytes using a
# tink.BinaryKeysetWriter, and then encoding it as base64.
_FAKE_KMS_KEY_URI = (
    'fake-kms://COiSsYwBEmQKWAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnR'
    'pbmsuQWVzR2NtS2V5EiIaIFbJR8aBiTdFNGGP8shTNK50haXKMJ-0I7KlOvSMI1IuGAEQARjok'
    'rGMASAB')


class CreateKeysetTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    aead.register()
    fake_kms.register_client()

  def test_write_keyset_fails_if_kms_key_is_invalid(self):
    keyset_handle = create_keyset.CreateAead128GcmKeyset()
    text_io = io.StringIO()
    with self.assertRaises(tink.TinkError):
      write_keyset.WriteEncryptedKeyset(
          keyset_handle,
          text_io,
          kms_kek_uri='fake-kms://invalid-kms-key',
          associated_data=b'')

  def test_write_keyset_serializes_a_keyset_correctly(self):
    associated_data = b'some associated data'
    keyset_handle = create_keyset.CreateAead128GcmKeyset()
    text_io = io.StringIO()
    write_keyset.WriteEncryptedKeyset(keyset_handle, text_io, _FAKE_KMS_KEY_URI,
                                      associated_data)

    # Make sure that we can use this primitive.
    aead_primitive = keyset_handle.primitive(aead.Aead)

    loaded_keyset_handle = load_encrypted_keyset.LoadEncryptedKeyset(
        text_io.getvalue(), _FAKE_KMS_KEY_URI, associated_data)
    loaded_aead = loaded_keyset_handle.primitive(aead.Aead)
    plaintext = b'some plaintext'

    self.assertEqual(
        loaded_aead.decrypt(
            aead_primitive.encrypt(plaintext, associated_data),
            associated_data), plaintext)
    self.assertEqual(
        aead_primitive.decrypt(
            loaded_aead.encrypt(plaintext, associated_data), associated_data),
        plaintext)


if __name__ == '__main__':
  absltest.main()

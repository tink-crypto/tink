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
"""Tests for tink.testing.cross_language.util.keyset_builder."""

from absl.testing import absltest
# from absl.testing import parameterized

import tink
from tink import aead

from util import keyset_builder


def setUpModule():
  aead.register()


class KeysetBuilderTest(absltest.TestCase):

  def test_keyset_handle_conversion(self):
    keyset_handle1 = tink.new_keyset_handle(aead.aead_key_templates.AES128_GCM)
    p1 = keyset_handle1.primitive(aead.Aead)
    builder = keyset_builder.from_keyset_handle(keyset_handle1)
    keyset_handle2 = builder.keyset_handle()
    p2 = keyset_handle2.primitive(aead.Aead)
    ciphertext = p1.encrypt(b'plaintext', b'ad')
    self.assertEqual(p2.decrypt(ciphertext, b'ad'), b'plaintext')

  def test_keyset_conversion(self):
    builder1 = keyset_builder.new_keyset_builder()
    new_key_id = builder1.add_new_key(aead.aead_key_templates.AES128_GCM)
    builder1.set_primary_key(new_key_id)
    keyset = builder1.keyset()
    keyset_handle1 = builder1.keyset_handle()
    p1 = keyset_handle1.primitive(aead.Aead)
    builder2 = keyset_builder.from_keyset(keyset)
    keyset_handle2 = builder2.keyset_handle()
    p2 = keyset_handle2.primitive(aead.Aead)
    ciphertext = p1.encrypt(b'plaintext', b'ad')
    self.assertEqual(p2.decrypt(ciphertext, b'ad'), b'plaintext')

  def test_add_new_key_new_id(self):
    builder = keyset_builder.new_keyset_builder()
    key_id1 = builder.add_new_key(aead.aead_key_templates.AES128_GCM)
    key_id2 = builder.add_new_key(aead.aead_key_templates.AES128_GCM)
    self.assertNotEqual(key_id1, key_id2)

  def test_set_primary_success(self):
    builder = keyset_builder.new_keyset_builder()
    secondary_key_id = builder.add_new_key(aead.aead_key_templates.AES128_GCM)
    builder.set_primary_key(secondary_key_id)

  def test_operation_on_unknown_key_fails(self):
    builder = keyset_builder.new_keyset_builder()
    key_id = builder.add_new_key(
        aead.aead_key_templates.AES128_GCM)
    unknown_key_id = key_id + 1
    with self.assertRaises(tink.TinkError):
      builder.set_primary_key(unknown_key_id)
    with self.assertRaises(tink.TinkError):
      builder.enable_key(unknown_key_id)
    with self.assertRaises(tink.TinkError):
      builder.disable_key(unknown_key_id)
    with self.assertRaises(tink.TinkError):
      builder.delete_key(unknown_key_id)

  def test_key_rotation(self):
    builder = keyset_builder.new_keyset_builder()
    older_key_id = builder.add_new_key(aead.aead_key_templates.AES128_GCM)
    builder.set_primary_key(older_key_id)
    p1 = builder.keyset_handle().primitive(aead.Aead)

    newer_key_id = builder.add_new_key(aead.aead_key_templates.AES128_GCM)
    p2 = builder.keyset_handle().primitive(aead.Aead)

    builder.set_primary_key(newer_key_id)
    p3 = builder.keyset_handle().primitive(aead.Aead)

    builder.disable_key(older_key_id)
    p4 = builder.keyset_handle().primitive(aead.Aead)

    builder.delete_key(older_key_id)

    self.assertNotEqual(older_key_id, newer_key_id)
    # p1 encrypts with the older key. So p1, p2 and p3 can decrypt it,
    # but not p4.
    ciphertext1 = p1.encrypt(b'plaintext', b'ad')
    self.assertEqual(p1.decrypt(ciphertext1, b'ad'), b'plaintext')
    self.assertEqual(p2.decrypt(ciphertext1, b'ad'), b'plaintext')
    self.assertEqual(p3.decrypt(ciphertext1, b'ad'), b'plaintext')
    with self.assertRaises(tink.TinkError):
      _ = p4.decrypt(ciphertext1, b'ad')

    # p2 encrypts with the older key. So p1, p2 and p3 can decrypt it,
    # but not p4.
    ciphertext2 = p2.encrypt(b'plaintext', b'ad')
    self.assertEqual(p1.decrypt(ciphertext2, b'ad'), b'plaintext')
    self.assertEqual(p2.decrypt(ciphertext2, b'ad'), b'plaintext')
    self.assertEqual(p3.decrypt(ciphertext2, b'ad'), b'plaintext')
    with self.assertRaises(tink.TinkError):
      _ = p4.decrypt(ciphertext2, b'ad')

    # p3 encrypts with the newer key. So p2, p3 and p4 can decrypt it,
    # but not p1.
    ciphertext3 = p3.encrypt(b'plaintext', b'ad')
    with self.assertRaises(tink.TinkError):
      _ = p1.decrypt(ciphertext3, b'ad')
    self.assertEqual(p2.decrypt(ciphertext3, b'ad'), b'plaintext')
    self.assertEqual(p3.decrypt(ciphertext3, b'ad'), b'plaintext')
    self.assertEqual(p4.decrypt(ciphertext3, b'ad'), b'plaintext')

    # p4 encrypts with the newer key. So p2, p3 and p4 can decrypt it,
    # but not p1.
    ciphertext4 = p3.encrypt(b'plaintext', b'ad')
    with self.assertRaises(tink.TinkError):
      _ = p1.decrypt(ciphertext4, b'ad')
    self.assertEqual(p2.decrypt(ciphertext4, b'ad'), b'plaintext')
    self.assertEqual(p3.decrypt(ciphertext4, b'ad'), b'plaintext')
    self.assertEqual(p4.decrypt(ciphertext4, b'ad'), b'plaintext')


if __name__ == '__main__':
  absltest.main()

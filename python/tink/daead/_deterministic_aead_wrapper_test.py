# Copyright 2019 Google LLC.
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

"""Tests for tink.python.tink.aead_wrapper."""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

from absl.testing import absltest
from absl.testing import parameterized
import tink
from tink import daead
from tink.testing import keyset_builder


DAEAD_TEMPLATE = daead.deterministic_aead_key_templates.AES256_SIV
RAW_DAEAD_TEMPLATE = keyset_builder.raw_template(DAEAD_TEMPLATE)


def setUpModule():
  daead.register()


class AeadWrapperTest(parameterized.TestCase):

  @parameterized.parameters([DAEAD_TEMPLATE, RAW_DAEAD_TEMPLATE])
  def test_encrypt_decrypt(self, template):
    keyset_handle = tink.new_keyset_handle(template)
    primitive = keyset_handle.primitive(daead.DeterministicAead)
    ciphertext = primitive.encrypt_deterministically(
        b'plaintext', b'associated_data')
    self.assertEqual(
        primitive.decrypt_deterministically(ciphertext, b'associated_data'),
        b'plaintext')

  @parameterized.parameters([DAEAD_TEMPLATE, RAW_DAEAD_TEMPLATE])
  def test_decrypt_unknown_ciphertext_fails(self, template):
    unknown_handle = tink.new_keyset_handle(template)
    unknown_primitive = unknown_handle.primitive(daead.DeterministicAead)
    unknown_ciphertext = unknown_primitive.encrypt_deterministically(
        b'plaintext', b'associated_data')

    keyset_handle = tink.new_keyset_handle(template)
    primitive = keyset_handle.primitive(daead.DeterministicAead)

    with self.assertRaises(tink.TinkError):
      primitive.decrypt_deterministically(unknown_ciphertext,
                                          b'associated_data')

  @parameterized.parameters([DAEAD_TEMPLATE, RAW_DAEAD_TEMPLATE])
  def test_decrypt_wrong_associated_data_fails(self, template):
    keyset_handle = tink.new_keyset_handle(template)
    primitive = keyset_handle.primitive(daead.DeterministicAead)

    ciphertext = primitive.encrypt_deterministically(b'plaintext',
                                                     b'associated_data')
    with self.assertRaises(tink.TinkError):
      primitive.decrypt_deterministically(ciphertext, b'wrong_associated_data')

  @parameterized.parameters([(DAEAD_TEMPLATE, DAEAD_TEMPLATE),
                             (RAW_DAEAD_TEMPLATE, DAEAD_TEMPLATE),
                             (DAEAD_TEMPLATE, RAW_DAEAD_TEMPLATE),
                             (RAW_DAEAD_TEMPLATE, RAW_DAEAD_TEMPLATE)])
  def test_encrypt_decrypt_with_key_rotation(self, template1, template2):
    builder = keyset_builder.new_keyset_builder()
    older_key_id = builder.add_new_key(template1)
    builder.set_primary_key(older_key_id)
    p1 = builder.keyset_handle().primitive(daead.DeterministicAead)

    newer_key_id = builder.add_new_key(template2)
    p2 = builder.keyset_handle().primitive(daead.DeterministicAead)

    builder.set_primary_key(newer_key_id)
    p3 = builder.keyset_handle().primitive(daead.DeterministicAead)

    builder.disable_key(older_key_id)
    p4 = builder.keyset_handle().primitive(daead.DeterministicAead)

    self.assertNotEqual(older_key_id, newer_key_id)
    # p1 encrypts with the older key. So p1, p2 and p3 can decrypt it,
    # but not p4.
    ciphertext1 = p1.encrypt_deterministically(b'plaintext', b'ad')
    self.assertEqual(p1.decrypt_deterministically(ciphertext1, b'ad'),
                     b'plaintext')
    self.assertEqual(p2.decrypt_deterministically(ciphertext1, b'ad'),
                     b'plaintext')
    self.assertEqual(p3.decrypt_deterministically(ciphertext1, b'ad'),
                     b'plaintext')
    with self.assertRaises(tink.TinkError):
      _ = p4.decrypt_deterministically(ciphertext1, b'ad')

    # p2 encrypts with the older key. So p1, p2 and p3 can decrypt it,
    # but not p4.
    ciphertext2 = p2.encrypt_deterministically(b'plaintext', b'ad')
    self.assertEqual(p1.decrypt_deterministically(ciphertext2, b'ad'),
                     b'plaintext')
    self.assertEqual(p2.decrypt_deterministically(ciphertext2, b'ad'),
                     b'plaintext')
    self.assertEqual(p3.decrypt_deterministically(ciphertext2, b'ad'),
                     b'plaintext')
    with self.assertRaises(tink.TinkError):
      _ = p4.decrypt_deterministically(ciphertext2, b'ad')

    # p3 encrypts with the newer key. So p2, p3 and p4 can decrypt it,
    # but not p1.
    ciphertext3 = p3.encrypt_deterministically(b'plaintext', b'ad')
    with self.assertRaises(tink.TinkError):
      _ = p1.decrypt_deterministically(ciphertext3, b'ad')
    self.assertEqual(p2.decrypt_deterministically(ciphertext3, b'ad'),
                     b'plaintext')
    self.assertEqual(p3.decrypt_deterministically(ciphertext3, b'ad'),
                     b'plaintext')
    self.assertEqual(p4.decrypt_deterministically(ciphertext3, b'ad'),
                     b'plaintext')

    # p4 encrypts with the newer key. So p2, p3 and p4 can decrypt it,
    # but not p1.
    ciphertext4 = p4.encrypt_deterministically(b'plaintext', b'ad')
    with self.assertRaises(tink.TinkError):
      _ = p1.decrypt_deterministically(ciphertext4, b'ad')
    self.assertEqual(p2.decrypt_deterministically(ciphertext4, b'ad'),
                     b'plaintext')
    self.assertEqual(p3.decrypt_deterministically(ciphertext4, b'ad'),
                     b'plaintext')
    self.assertEqual(p4.decrypt_deterministically(ciphertext4, b'ad'),
                     b'plaintext')


if __name__ == '__main__':
  absltest.main()

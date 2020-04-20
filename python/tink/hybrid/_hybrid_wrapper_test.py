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
from __future__ import print_function

from absl.testing import absltest
from tink.proto import tink_pb2
from tink import core
from tink import hybrid
from tink.testing import helper


def setUpModule():
  hybrid.register()


def new_primitives_and_keys(key_id, output_prefix_type):
  fake_dec_key = helper.fake_key(
      key_material_type=tink_pb2.KeyData.ASYMMETRIC_PRIVATE,
      key_id=key_id,
      output_prefix_type=output_prefix_type)
  fake_enc_key = helper.fake_key(
      key_material_type=tink_pb2.KeyData.ASYMMETRIC_PUBLIC,
      key_id=key_id, output_prefix_type=output_prefix_type)
  fake_hybrid_decrypt = helper.FakeHybridDecrypt(
      'fakeHybrid {}'.format(key_id))
  fake_hybrid_encrypt = helper.FakeHybridEncrypt(
      'fakeHybrid {}'.format(key_id))
  return fake_hybrid_decrypt, fake_hybrid_encrypt, fake_dec_key, fake_enc_key


class HybridWrapperTest(absltest.TestCase):

  def test_encrypt_decrypt(self):
    dec, enc, dec_key, enc_key = new_primitives_and_keys(1234, tink_pb2.TINK)
    dec_pset = core.new_primitive_set(hybrid.HybridDecrypt)
    dec_pset.set_primary(dec_pset.add_primitive(dec, dec_key))
    wrapped_dec = core.Registry.wrap(dec_pset)

    enc_pset = core.new_primitive_set(hybrid.HybridEncrypt)
    enc_pset.set_primary(enc_pset.add_primitive(enc, enc_key))
    wrapped_enc = core.Registry.wrap(enc_pset)

    ciphertext = wrapped_enc.encrypt(b'plaintext', b'context_info')
    self.assertEqual(
        wrapped_dec.decrypt(ciphertext, b'context_info'), b'plaintext')

  def test_encrypt_decrypt_with_key_rotation(self):
    dec, enc, dec_key, enc_key = new_primitives_and_keys(1234, tink_pb2.TINK)
    enc_pset = core.new_primitive_set(hybrid.HybridEncrypt)
    enc_pset.set_primary(enc_pset.add_primitive(enc, enc_key))
    wrapped_enc = core.Registry.wrap(enc_pset)
    ciphertext = wrapped_enc.encrypt(b'plaintext', b'context_info')

    new_dec, new_enc, new_dec_key, new_enc_key = new_primitives_and_keys(
        5678, tink_pb2.TINK)
    new_enc_pset = core.new_primitive_set(hybrid.HybridEncrypt)
    new_enc_pset.set_primary(new_enc_pset.add_primitive(new_enc, new_enc_key))
    new_wrapped_enc = core.Registry.wrap(
        new_enc_pset)

    new_dec, new_enc, new_dec_key, new_enc_key = new_primitives_and_keys(
        5678, tink_pb2.TINK)
    new_dec_pset = core.new_primitive_set(hybrid.HybridDecrypt)
    new_dec_pset.add_primitive(dec, dec_key)
    new_dec_pset.set_primary(new_dec_pset.add_primitive(new_dec, new_dec_key))
    new_wrapped_dec = core.Registry.wrap(
        new_dec_pset)

    new_ciphertext = new_wrapped_enc.encrypt(b'new_plaintext',
                                             b'new_context_info')
    self.assertEqual(
        new_wrapped_dec.decrypt(ciphertext, b'context_info'),
        b'plaintext')
    self.assertEqual(
        new_wrapped_dec.decrypt(new_ciphertext, b'new_context_info'),
        b'new_plaintext')

  def test_encrypt_decrypt_with_key_rotation_from_raw(self):
    raw_dec, raw_enc, raw_dec_key, raw_enc_key = new_primitives_and_keys(
        1234, tink_pb2.RAW)
    old_raw_ciphertext = raw_enc.encrypt(b'old_raw_ciphertext', b'context_info')

    new_dec, new_enc, new_dec_key, new_enc_key = new_primitives_and_keys(
        5678, tink_pb2.TINK)
    enc_pset = core.new_primitive_set(hybrid.HybridEncrypt)
    enc_pset.add_primitive(raw_enc, raw_enc_key)
    enc_pset.set_primary(enc_pset.add_primitive(new_enc, new_enc_key))
    wrapped_enc = core.Registry.wrap(
        enc_pset)

    dec_pset = core.new_primitive_set(hybrid.HybridDecrypt)
    dec_pset.add_primitive(raw_dec, raw_dec_key)
    dec_pset.set_primary(dec_pset.add_primitive(new_dec, new_dec_key))
    wrapped_dec = core.Registry.wrap(dec_pset)

    new_ciphertext = wrapped_enc.encrypt(b'new_plaintext', b'new_context_info')
    self.assertEqual(
        wrapped_dec.decrypt(old_raw_ciphertext, b'context_info'),
        b'old_raw_ciphertext')
    self.assertEqual(
        wrapped_dec.decrypt(new_ciphertext, b'new_context_info'),
        b'new_plaintext')

  def test_encrypt_decrypt_two_raw_keys(self):
    dec1, enc1, dec1_key, _ = new_primitives_and_keys(
        1234, tink_pb2.RAW)
    raw_ciphertext1 = enc1.encrypt(b'plaintext1', b'context_info1')
    dec2, enc2, dec2_key, _ = new_primitives_and_keys(
        1234, tink_pb2.RAW)
    raw_ciphertext2 = enc2.encrypt(b'plaintext2', b'context_info2')

    dec_pset = core.new_primitive_set(hybrid.HybridDecrypt)
    dec_pset.add_primitive(dec1, dec1_key)
    dec_pset.set_primary(dec_pset.add_primitive(dec2, dec2_key))
    wrapped_dec = core.Registry.wrap(dec_pset)

    self.assertEqual(
        wrapped_dec.decrypt(raw_ciphertext1, b'context_info1'),
        b'plaintext1')
    self.assertEqual(
        wrapped_dec.decrypt(raw_ciphertext2, b'context_info2'),
        b'plaintext2')

  def test_decrypt_unknown_ciphertext_fails(self):
    unknown_enc = helper.FakeHybridEncrypt('unknownHybrid')
    unknown_ciphertext = unknown_enc.encrypt(b'plaintext', b'context_info')

    dec_pset = core.new_primitive_set(hybrid.HybridDecrypt)

    dec1, _, dec1_key, _ = new_primitives_and_keys(1234, tink_pb2.RAW)
    dec2, _, dec2_key, _ = new_primitives_and_keys(5678, tink_pb2.TINK)
    dec_pset.add_primitive(dec1, dec1_key)
    dec_pset.set_primary(dec_pset.add_primitive(dec2, dec2_key))

    wrapped_dec = core.Registry.wrap(dec_pset)

    with self.assertRaisesRegex(core.TinkError, 'Decryption failed'):
      wrapped_dec.decrypt(unknown_ciphertext, b'context_info')

  def test_decrypt_wrong_associated_data_fails(self):
    dec, enc, dec_key, enc_key = new_primitives_and_keys(1234, tink_pb2.TINK)
    dec_pset = core.new_primitive_set(hybrid.HybridDecrypt)
    dec_pset.set_primary(dec_pset.add_primitive(dec, dec_key))
    wrapped_dec = core.Registry.wrap(dec_pset)

    enc_pset = core.new_primitive_set(hybrid.HybridEncrypt)
    enc_pset.set_primary(enc_pset.add_primitive(enc, enc_key))
    wrapped_enc = core.Registry.wrap(enc_pset)

    ciphertext = wrapped_enc.encrypt(b'plaintext', b'context_info')
    with self.assertRaisesRegex(core.TinkError, 'Decryption failed'):
      wrapped_dec.decrypt(ciphertext, b'wrong_context_info')


if __name__ == '__main__':
  absltest.main()

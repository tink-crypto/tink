# Copyright 2019 Google LLC
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

"""Tests for tink.python.tink.tink_config."""

import os
import tempfile

from absl.testing import absltest

import tink
from tink import aead
from tink import daead
from tink import hybrid
from tink import mac
from tink import prf
from tink import signature
from tink import streaming_aead
from tink import tink_config


def setUpModule():
  tink_config.register()


class TinkConfigTest(absltest.TestCase):

  def test_aead_encrypt_decrypt(self):
    keyset_handle = tink.new_keyset_handle(aead.aead_key_templates.AES256_GCM)
    primitive = keyset_handle.primitive(aead.Aead)
    self.assertEqual(
        primitive.decrypt(primitive.encrypt(b'plaintext', b'ad'), b'ad'),
        b'plaintext')

  def test_mac_compute_verify(self):
    keyset_handle = tink.new_keyset_handle(
        mac.mac_key_templates.HMAC_SHA256_128BITTAG)
    primitive = keyset_handle.primitive(mac.Mac)
    mac_value = primitive.compute_mac(b'data')
    self.assertIsNone(primitive.verify_mac(mac_value, b'data'))
    self.assertEqual(primitive.compute_mac(b'data'), mac_value)

  def test_deterministic_aead_wrapper_is_correctly_registered(self):
    keyset_handle = tink.new_keyset_handle(
        daead.deterministic_aead_key_templates.AES256_SIV)
    primitive = keyset_handle.primitive(daead.DeterministicAead)
    ciphertext = primitive.encrypt_deterministically(b'plaintext', b'ad')
    self.assertEqual(
        primitive.decrypt_deterministically(ciphertext, b'ad'), b'plaintext')
    self.assertEqual(
        primitive.encrypt_deterministically(b'plaintext', b'ad'), ciphertext)

  def test_hybrid_encrypt_decrypt(self):
    keyset_handle = tink.new_keyset_handle(
        hybrid.hybrid_key_templates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM)
    decrypt = keyset_handle.primitive(hybrid.HybridDecrypt)
    public_keyset_handle = keyset_handle.public_keyset_handle()
    encrypt = public_keyset_handle.primitive(hybrid.HybridEncrypt)
    self.assertEqual(
        decrypt.decrypt(encrypt.encrypt(b'plaintext', b'ad'), b'ad'),
        b'plaintext')

  def test_signatures_sign_verify(self):
    keyset_handle = tink.new_keyset_handle(
        signature.signature_key_templates.ECDSA_P256)
    sign = keyset_handle.primitive(signature.PublicKeySign)
    public_keyset_handle = keyset_handle.public_keyset_handle()
    verify = public_keyset_handle.primitive(signature.PublicKeyVerify)
    sig = sign.sign(b'data')
    verify.verify(sig, b'data')

  def test_prf_compute(self):
    keyset_handle = tink.new_keyset_handle(prf.prf_key_templates.HMAC_SHA256)
    primitive = keyset_handle.primitive(prf.PrfSet)
    output = primitive.primary().compute(b'input_data', output_length=15)
    self.assertLen(output, 15)
    self.assertEqual(
        primitive.all()[primitive.primary_id()].compute(
            b'input_data', output_length=15), output)

  def test_streaming_aead_encrypt_decrypt(self):
    key_template = streaming_aead.streaming_aead_key_templates.AES128_GCM_HKDF_4KB
    keyset_handle = tink.new_keyset_handle(key_template)
    primitive = keyset_handle.primitive(streaming_aead.StreamingAead)
    plaintext = b'plaintext'
    associated_data = b'associated_data'
    with tempfile.TemporaryDirectory() as tmpdirname:
      filename = os.path.join(tmpdirname, 'encrypted_file')
      dest = open(filename, 'wb')
      with primitive.new_encrypting_stream(dest, associated_data) as es:
        es.write(plaintext)

      src = open(filename, 'rb')
      with primitive.new_decrypting_stream(src, associated_data) as ds:
        output = ds.read()
      self.assertEqual(output, plaintext)


if __name__ == '__main__':
  absltest.main()

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
"""Tests for tink.testing.cross_language.util.testing_server."""

from absl.testing import absltest
from absl.testing import parameterized


import tink
from tink import aead
from tink import daead
from tink import hybrid
from tink import mac
from tink import signature

from util import testing_servers


def setUpModule():
  testing_servers.start()


def tearDownModule():
  testing_servers.stop()


class TestingServersTest(parameterized.TestCase):

  @parameterized.parameters(testing_servers.LANGUAGES)
  def test_aead(self, lang):
    keyset_handle = testing_servers.new_keyset_handle(
        lang, aead.aead_key_templates.AES128_GCM)
    plaintext = b'The quick brown fox jumps over the lazy dog'
    associated_data = b'associated_data'
    aead_primitive = testing_servers.aead(lang, keyset_handle)
    ciphertext = aead_primitive.encrypt(plaintext, associated_data)
    output = aead_primitive.decrypt(ciphertext, associated_data)
    self.assertEqual(output, plaintext)

    with self.assertRaises(tink.TinkError):
      aead_primitive.decrypt(b'foo', associated_data)

  @parameterized.parameters(testing_servers.LANGUAGES)
  def test_daead(self, lang):
    keyset_handle = testing_servers.new_keyset_handle(
        lang, daead.deterministic_aead_key_templates.AES256_SIV)
    plaintext = b'The quick brown fox jumps over the lazy dog'
    associated_data = b'associated_data'
    daead_primitive = testing_servers.deterministic_aead(lang, keyset_handle)
    ciphertext = daead_primitive.encrypt_deterministically(
        plaintext, associated_data)
    output = daead_primitive.decrypt_deterministically(
        ciphertext, associated_data)
    self.assertEqual(output, plaintext)

    with self.assertRaises(tink.TinkError):
      daead_primitive.decrypt_deterministically(b'foo', associated_data)

  @parameterized.parameters(testing_servers.LANGUAGES)
  def test_mac(self, lang):
    keyset_handle = testing_servers.new_keyset_handle(
        lang, mac.mac_key_templates.HMAC_SHA256_128BITTAG)
    data = b'The quick brown fox jumps over the lazy dog'
    mac_primitive = testing_servers.mac(lang, keyset_handle)
    mac_value = mac_primitive.compute_mac(data)
    mac_primitive.verify_mac(mac_value, data)

    with self.assertRaises(tink.TinkError):
      mac_primitive.verify_mac(b'foo', data)

  @parameterized.parameters(['go', 'java', 'python'])
  def test_hybrid(self, lang):
    private_handle = testing_servers.new_keyset_handle(
        lang,
        hybrid.hybrid_key_templates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM)
    public_handle = testing_servers.public_keyset_handle(lang, private_handle)
    enc_primitive = testing_servers.hybrid_encrypt(lang, public_handle)
    data = b'The quick brown fox jumps over the lazy dog'
    context_info = b'context'
    ciphertext = enc_primitive.encrypt(data, context_info)
    dec_primitive = testing_servers.hybrid_decrypt(lang, private_handle)
    output = dec_primitive.decrypt(ciphertext, context_info)
    self.assertEqual(output, data)

    with self.assertRaises(tink.TinkError):
      dec_primitive.decrypt(b'foo', context_info)

  @parameterized.parameters(['go', 'java', 'python'])
  def test_signature(self, lang):
    private_handle = testing_servers.new_keyset_handle(
        lang, signature.signature_key_templates.ED25519)
    public_handle = testing_servers.public_keyset_handle(lang, private_handle)
    sign_primitive = testing_servers.public_key_sign(lang, private_handle)
    data = b'The quick brown fox jumps over the lazy dog'
    signature_value = sign_primitive.sign(data)
    verify_primitive = testing_servers.public_key_verify(lang, public_handle)
    verify_primitive.verify(signature_value, data)

    with self.assertRaises(tink.TinkError):
      verify_primitive.verify(b'foo', data)

if __name__ == '__main__':
  absltest.main()

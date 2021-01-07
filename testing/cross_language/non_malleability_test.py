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
"""Cross-language tests for the non-malleability of Tink primitives.

These tests check that modified ciphertexts (or signatures or tags) are always
rejected.

The tests use the property-based testing framework "hypothesis", see
https://hypothesis.readthedocs.io/en/latest/.

We draw the test data interactivly, which is described here:
https://hypothesis.readthedocs.io/en/latest/data.html#interactive-draw
"""

from absl.testing import absltest

import hypothesis
from hypothesis import strategies as st

import tink

from util import supported_key_types
from util import testing_servers

SUPPORTED_LANGUAGES = testing_servers.SUPPORTED_LANGUAGES_BY_PRIMITIVE['aead']


def setUpModule():
  testing_servers.start('non-malleability')


def tearDownModule():
  testing_servers.stop()


def _bit_modify(data: bytes, st_data: st.SearchStrategy) -> bytes:
  """Modifies a bit in data."""
  i = st_data.draw(
      st.integers(min_value=0, max_value=8*len(data)-1))
  modified_data = bytearray(data)
  modified_data[i // 8] ^= 1 << (i % 8)
  return bytes(modified_data)


def _remove_prefix(data: bytes) -> bytes:
  """Removes 5 byte prefix, which is often used by Tink primitives."""
  return data[:5]


def _draw_lang_template_from_key_type(key_types, st_data):
  key_type = st_data.draw(st.sampled_from(key_types))
  template_name = st_data.draw(st.sampled_from(
      supported_key_types.KEY_TEMPLATE_NAMES[key_type]))
  template = supported_key_types.KEY_TEMPLATE[template_name]
  lang = st_data.draw(
      st.sampled_from(
          supported_key_types
          .SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME[template_name]))
  return (lang, template)


class NonMalleabilityTest(absltest.TestCase):

  @hypothesis.given(st.data())
  def test_modified_aead_ciphertext_fails(self, st_data):
    """A modified AEAD ciphertext should always be rejected."""
    lang, template = _draw_lang_template_from_key_type(
        supported_key_types.AEAD_KEY_TYPES, st_data)
    keyset = testing_servers.new_keyset(lang, template)
    plaintext = st_data.draw(st.binary())
    aad = st_data.draw(st.binary())
    primitive = testing_servers.aead(lang, keyset)
    ciphertext = primitive.encrypt(plaintext, aad)
    with self.assertRaises(tink.TinkError):
      primitive.decrypt(_remove_prefix(ciphertext), aad)
    with self.assertRaises(tink.TinkError):
      primitive.decrypt(_bit_modify(ciphertext, st_data), aad)

  @hypothesis.given(st.data())
  def test_modified_deterministic_aead_ciphertext_fails(self, st_data):
    """A modified deterministic AEAD ciphertext should always be rejected."""
    lang, template = _draw_lang_template_from_key_type(
        supported_key_types.DAEAD_KEY_TYPES, st_data)
    keyset = testing_servers.new_keyset(lang, template)
    plaintext = st_data.draw(st.binary())
    aad = st_data.draw(st.binary())
    primitive = testing_servers.deterministic_aead(lang, keyset)
    ciphertext = primitive.encrypt_deterministically(plaintext, aad)
    with self.assertRaises(tink.TinkError):
      primitive.decrypt_deterministically(_remove_prefix(ciphertext), aad)
    with self.assertRaises(tink.TinkError):
      primitive.decrypt_deterministically(_bit_modify(ciphertext, st_data), aad)

  @hypothesis.given(st.data())
  def test_modified_mac_value_fails(self, st_data):
    """A modified MAC tag should always be rejected."""
    lang, template = _draw_lang_template_from_key_type(
        supported_key_types.MAC_KEY_TYPES, st_data)
    keyset = testing_servers.new_keyset(lang, template)
    message = st_data.draw(st.binary())
    primitive = testing_servers.mac(lang, keyset)
    mac_value = primitive.compute_mac(message)
    with self.assertRaises(tink.TinkError):
      primitive.verify_mac(_remove_prefix(mac_value), message)
    with self.assertRaises(tink.TinkError):
      primitive.verify_mac(_bit_modify(mac_value, st_data), message)

  @hypothesis.settings(deadline=None)
  @hypothesis.given(st.data())
  def test_modified_hybrid_encryption_ciphertext_fails(self, st_data):
    """A modified hybrid encryption ciphertext should always be rejected."""
    lang, template = _draw_lang_template_from_key_type(
        supported_key_types.HYBRID_PRIVATE_KEY_TYPES, st_data)
    private_keyset = testing_servers.new_keyset(lang, template)
    plaintext = st_data.draw(st.binary())
    context_info = st_data.draw(st.binary())
    dec = testing_servers.hybrid_decrypt(lang, private_keyset)
    public_keyset = testing_servers.public_keyset(lang, private_keyset)
    enc = testing_servers.hybrid_encrypt(lang, public_keyset)
    ciphertext = enc.encrypt(plaintext, context_info)
    with self.assertRaises(tink.TinkError):
      dec.decrypt(_remove_prefix(ciphertext), context_info)
    with self.assertRaises(tink.TinkError):
      dec.decrypt(_bit_modify(ciphertext, st_data), context_info)

  @hypothesis.settings(deadline=None, max_examples=30)
  @hypothesis.given(st.data())
  def test_modified_signature_fails(self, st_data):
    """A modified signature should always be rejected."""
    lang, template = _draw_lang_template_from_key_type(
        supported_key_types.SIGNATURE_KEY_TYPES, st_data)
    private_keyset = testing_servers.new_keyset(lang, template)
    message = st_data.draw(st.binary())
    signer = testing_servers.public_key_sign(lang, private_keyset)
    public_keyset = testing_servers.public_keyset(lang, private_keyset)
    verifier = testing_servers.public_key_verify(lang, public_keyset)
    sign = signer.sign(message)
    with self.assertRaises(tink.TinkError):
      verifier.verify(_remove_prefix(sign), message)
    with self.assertRaises(tink.TinkError):
      verifier.verify(_bit_modify(sign, st_data), message)


if __name__ == '__main__':
  absltest.main()

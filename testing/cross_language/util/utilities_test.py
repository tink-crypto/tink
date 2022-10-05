# Copyright 2020 Google LLC
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
"""Tests for tink.testing.cross_language.supported_key_types."""


from absl.testing import absltest
from tink import aead
from tink import mac

from tink.proto import tink_pb2
import tink_config
from util import test_keys
from util import utilities


def all_key_template_names():
  for _, names in utilities.KEY_TEMPLATE_NAMES.items():
    for name in names:
      yield name


def setUpModule():
  aead.register()


class SupportedKeyTypesTest(absltest.TestCase):

  def test_template_types_subset(self):
    """Tests that all key types which have a template are in all_key_types()."""
    self.assertContainsSubset(
        set(utilities.KEY_TEMPLATE_NAMES.keys()),
        set(tink_config.all_key_types()))

  def test_all_key_templates_present(self):
    self.assertEqual(
        list(all_key_template_names()),
        list(utilities.KEY_TEMPLATE.keys()))

  def test_supported_lang_by_template_name_all_present(self):
    self.assertEqual(
        list(all_key_template_names()),
        list(utilities.SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME.keys()))

  def test_supported_langauges_by_template_name(self):
    self.assertEqual(
        utilities.SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME[
            'ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM'],
        ['cc', 'java', 'go', 'python'])

  def test_tinkey_template_names_for(self):
    self.assertEqual(
        list(utilities.tinkey_template_names_for(mac.Mac)), [
            'AES_CMAC', 'HMAC_SHA256_128BITTAG', 'HMAC_SHA256_256BITTAG',
            'HMAC_SHA512_256BITTAG', 'HMAC_SHA512_512BITTAG'
        ])

  def test_key_types_in_keyset_single_key(self):
    aes_gcm_keyset = test_keys.new_or_stored_keyset(
        aead.aead_key_templates.AES128_GCM)
    self.assertEqual(
        utilities.key_types_in_keyset(aes_gcm_keyset), ['AesGcmKey'])

  def test_key_types_in_keyset_multiple_keys(self):
    key1 = test_keys.new_or_stored_key(aead.aead_key_templates.AES128_GCM)
    key2 = test_keys.new_or_stored_key(aead.aead_key_templates.AES256_GCM)
    key3 = test_keys.new_or_stored_key(aead.aead_key_templates.AES128_EAX)
    keyset = tink_pb2.Keyset(key=[key1, key2, key3], primary_key_id=key1.key_id)
    self.assertEqual(
        utilities.key_types_in_keyset(keyset.SerializeToString()),
        ['AesGcmKey', 'AesGcmKey', 'AesEaxKey'])

if __name__ == '__main__':
  absltest.main()

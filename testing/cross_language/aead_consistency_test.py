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
"""Cross-language consistency tests for AEAD.

These tests generate different kind of AEAD keysets, some are valid, some are
invalid. The test succeeds if all implementation treat the keyset consistently,
so either encryption/decryption works as expected, or the keyset is rejected.
"""

import itertools
from typing import List
from typing import Tuple

from absl.testing import absltest
from absl.testing import parameterized
import tink

from tink.proto import aes_ctr_hmac_aead_pb2
from tink.proto import aes_eax_pb2
from tink.proto import aes_gcm_pb2
from tink.proto import common_pb2
from tink.proto import tink_pb2
from util import supported_key_types
from util import testing_servers

HASH_TYPES = [
    common_pb2.UNKNOWN_HASH, common_pb2.SHA1, common_pb2.SHA224,
    common_pb2.SHA256, common_pb2.SHA384, common_pb2.SHA512
]


def setUpModule():
  tink.aead.register()
  testing_servers.start('aead_consistency')


def tearDownModule():
  testing_servers.stop()


def _gen_keyset(
    type_url: str, value: bytes,
    key_material_type: tink_pb2.KeyData.KeyMaterialType) -> tink_pb2.Keyset:
  """Generates a new Keyset."""
  keyset = tink_pb2.Keyset()
  key = keyset.key.add()
  key.key_data.type_url = type_url
  key.key_data.value = value
  key.key_data.key_material_type = key_material_type
  key.status = tink_pb2.ENABLED
  key.key_id = 42
  key.output_prefix_type = tink_pb2.TINK
  keyset.primary_key_id = 42
  return keyset


def _gen_key_value(size: int) -> bytes:
  """Returns a fixed key_value of a given size."""
  return bytes(i for i in range(size))


def aes_eax_key_test_cases():
  def _test_case(key_size=16, iv_size=16, key_version=0):
    key = aes_eax_pb2.AesEaxKey()
    key.version = key_version
    key.key_value = _gen_key_value(key_size)
    key.params.iv_size = iv_size
    keyset = _gen_keyset(
        'type.googleapis.com/google.crypto.tink.AesEaxKey',
        key.SerializeToString(),
        tink_pb2.KeyData.SYMMETRIC)
    return ('AesEaxKey(%d,%d,%d)' % (key_size, iv_size, key_version), keyset)
  for key_size in [15, 16, 24, 32, 64, 96]:
    for iv_size in [11, 12, 16, 17, 24, 32]:
      yield _test_case(key_size=key_size, iv_size=iv_size)
  yield _test_case(key_version=1)


def aes_gcm_key_test_cases():
  def _test_case(key_size=16, key_version=0):
    key = aes_gcm_pb2.AesGcmKey()
    key.version = key_version
    key.key_value = _gen_key_value(key_size)
    keyset = _gen_keyset(
        'type.googleapis.com/google.crypto.tink.AesGcmKey',
        key.SerializeToString(),
        tink_pb2.KeyData.SYMMETRIC)
    return ('AesGcmKey(%d,%d)' % (key_size, key_version), keyset)
  for key_size in [15, 16, 24, 32, 64, 96]:
    yield _test_case(key_size=key_size)
  yield _test_case(key_version=1)


def aes_ctr_hmac_aead_key_test_cases():
  def _test_case(aes_key_size=16,
                 iv_size=16,
                 hmac_key_size=16,
                 hmac_tag_size=16,
                 hash_type=common_pb2.SHA256,
                 key_version=0,
                 aes_ctr_version=0,
                 hmac_version=0):
    key = aes_ctr_hmac_aead_pb2.AesCtrHmacAeadKey()
    key.version = key_version
    key.aes_ctr_key.version = aes_ctr_version
    key.aes_ctr_key.params.iv_size = iv_size
    key.aes_ctr_key.key_value = _gen_key_value(aes_key_size)
    key.hmac_key.version = hmac_version
    key.hmac_key.params.tag_size = hmac_tag_size
    key.hmac_key.params.hash = hash_type
    key.hmac_key.key_value = _gen_key_value(hmac_key_size)
    keyset = _gen_keyset(
        'type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey',
        key.SerializeToString(), tink_pb2.KeyData.SYMMETRIC)
    return ('AesCtrHmacAeadKey(%d,%d,%d,%d,%s,%d,%d,%d)' %
            (aes_key_size, iv_size, hmac_key_size, hmac_tag_size,
             common_pb2.HashType.Name(hash_type), key_version, aes_ctr_version,
             hmac_version), keyset)

  yield _test_case()
  for aes_key_size in [15, 16, 24, 32, 64, 96]:
    for iv_size in [11, 12, 16, 17, 24, 32]:
      yield _test_case(aes_key_size=aes_key_size, iv_size=iv_size)
  for hmac_key_size in [15, 16, 24, 32, 64, 96]:
    for hmac_tag_size in [9, 10, 16, 20, 21, 24, 32, 33, 64, 65]:
      yield _test_case(hmac_key_size=hmac_key_size, hmac_tag_size=hmac_tag_size)
  for hash_type in HASH_TYPES:
    yield _test_case(hash_type=hash_type)
  yield _test_case(key_version=1)
  yield _test_case(aes_ctr_version=1)
  yield _test_case(hmac_version=1)


class AeadKeyConsistencyTest(parameterized.TestCase):
  """Tests that all implementation treat all generated keyset in the same way.

  We only consider keyset with single keys. This should be fine, since most
  inconsistencies between languages will occur in the key validation, and
  that is done for each key independently.
  """

  def _create_aeads_ignore_errors(
      self, keyset: tink_pb2.Keyset) -> List[Tuple[tink.aead.Aead, str]]:
    """Creates AEADs for the given keyset in each language.

    Args:
      keyset: A keyset as 'keyset' proto.

    Returns:
      A list of pairs (aead, language)
    """

    result = []
    for lang in supported_key_types.ALL_LANGUAGES:
      try:
        aead = testing_servers.aead(lang, keyset.SerializeToString())
        result.append((aead, lang))
      except tink.TinkError:
        pass
    return result

  @parameterized.parameters(
      itertools.chain(aes_eax_key_test_cases(), aes_gcm_key_test_cases(),
                      aes_ctr_hmac_aead_key_test_cases()))
  def test_aead_creation_supported_languages_consistent(self, name, keyset):
    """Tests that AEAD creation is consistent in all supporeted languages."""
    supported_langs = supported_key_types.SUPPORTED_LANGUAGES[
        supported_key_types.KEY_TYPE_FROM_URL[keyset.key[0].key_data.type_url]]

    langs = [lang for _, lang in self._create_aeads_ignore_errors(keyset)]

    if langs:
      with self.subTest('When creating AEAD objects for %s' % name):
        self.assertEqual(langs, supported_langs)

  @parameterized.parameters(
      itertools.chain(aes_eax_key_test_cases(), aes_gcm_key_test_cases(),
                      aes_ctr_hmac_aead_key_test_cases()))
  def test_aead_creation_non_supported_languages_fail(self, name, keyset):
    """Tests that AEAD creation fails in all unsupported languages."""
    supported_langs = supported_key_types.SUPPORTED_LANGUAGES[
        supported_key_types.KEY_TYPE_FROM_URL[keyset.key[0].key_data.type_url]]

    langs = [lang for _, lang in self._create_aeads_ignore_errors(keyset)]

    for lang in supported_key_types.ALL_LANGUAGES:
      if lang not in supported_langs:
        self.assertNotIn(
            lang, langs,
            'AEAD-Creation should fail in language %s for %s' % (lang, name))

  @parameterized.parameters(
      itertools.chain(aes_eax_key_test_cases(), aes_gcm_key_test_cases(),
                      aes_ctr_hmac_aead_key_test_cases()))
  def test_aead_pairwise_consistency(self, name, keyset):
    """Tests that created AEADS behave consistently."""

    aead_and_lang = self._create_aeads_ignore_errors(keyset)
    plaintext = b'plaintext'
    associated_data = b'associated_data'

    for aead, lang in aead_and_lang:
      aead0 = aead_and_lang[0][0]
      lang0 = aead_and_lang[0][1]

      with self.subTest('Comparing %s-aead to %s-aead for %s ' %
                        (lang0, lang, name)):
        ciphertext = aead.encrypt(plaintext, associated_data)
        self.assertEqual(aead0.decrypt(ciphertext, associated_data), plaintext)

        ciphertext = aead0.encrypt(plaintext, associated_data)
        self.assertEqual(aead.decrypt(ciphertext, associated_data), plaintext)


if __name__ == '__main__':
  absltest.main()

# Copyright 2022 Google LLC
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
"""Cross-language tests for reading and writing encrypted keysets."""

from typing import Iterable

from absl.testing import absltest
from absl.testing import parameterized

import tink
from tink import aead
from tink.proto import tink_pb2
from util import key_util
from util import supported_key_types
from util import testing_servers


def setUpModule():
  testing_servers.start('keyset_read_write')


def tearDownModule():
  testing_servers.stop()


def all_aead_key_template_names() -> Iterable[str]:
  """Yields all AEAD key template names."""
  for key_type in supported_key_types.AEAD_KEY_TYPES:
    for key_template_name in supported_key_types.KEY_TEMPLATE_NAMES[key_type]:
      yield key_template_name


class KeysetReadWriteTest(parameterized.TestCase):

  @parameterized.parameters(all_aead_key_template_names())
  def test_read_write_encrypted_keyset(self, key_template_name):
    # Use an arbitrary AEAD template that's supported in all languages,
    # and use an arbitrary language to generate the master_aead_keyset.
    keyset_encryption_keyset = testing_servers.new_keyset(
        'cc', aead.aead_key_templates.AES128_GCM)

    supported_langs = supported_key_types.SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME[
        key_template_name]
    self.assertNotEmpty(supported_langs)
    key_template = supported_key_types.KEY_TEMPLATE[key_template_name]

    # Take the first supported language to generate the keyset.
    keyset = testing_servers.new_keyset(supported_langs[0], key_template)

    for associated_data in [None, b'', b'associated_data']:
      for write_lang in supported_langs:
        encrypted_keyset = testing_servers.keyset_write_encrypted(
            write_lang, keyset, keyset_encryption_keyset, associated_data,
            'KEYSET_WRITER_BINARY')
        for read_lang in supported_langs:
          decrypted_keyset = testing_servers.keyset_read_encrypted(
              read_lang, encrypted_keyset, keyset_encryption_keyset,
              associated_data, 'KEYSET_READER_BINARY')
          # Both keyset and decrypted_keyset are serialized tink_pb2.Keyset.
          key_util.assert_tink_proto_equal(
              self,
              tink_pb2.Keyset.FromString(keyset),
              tink_pb2.Keyset.FromString(decrypted_keyset),
              msg=('keysets are not equal when writing in '
                   '%s and reading in %s' % (write_lang, read_lang)))

          with self.assertRaises(tink.TinkError):
            testing_servers.keyset_read_encrypted(read_lang, encrypted_keyset,
                                                  keyset_encryption_keyset,
                                                  b'invalid_associated_data',
                                                  'KEYSET_READER_BINARY')

  @parameterized.parameters(testing_servers.LANGUAGES)
  def test_read_encrypted_ignores_keyset_info(self, lang):
    # Use an arbitrary AEAD template that's supported in all languages,
    # and use an arbitrary language to generate the master_aead_keyset.
    master_aead_keyset = testing_servers.new_keyset(
        'cc', aead.aead_key_templates.AES128_GCM)
    # Also, generate an arbitrary keyset.
    keyset = testing_servers.new_keyset('cc',
                                        aead.aead_key_templates.AES128_GCM)
    associated_data = b'associated_data'

    encrypted_keyset = testing_servers.keyset_write_encrypted(
        lang, keyset, master_aead_keyset, associated_data,
        'KEYSET_WRITER_BINARY')

    # encrypted_keyset is a serialized tink_pb2.EncryptedKeyset
    parsed_encrypted_keyset = tink_pb2.EncryptedKeyset.FromString(
        encrypted_keyset)

    # Note that some implementations (currently C++) do not set keyset_info.
    # But we require that values are correct when they are set.
    if parsed_encrypted_keyset.HasField('keyset_info'):
      self.assertLen(parsed_encrypted_keyset.keyset_info.key_info, 1)
      self.assertEqual(parsed_encrypted_keyset.keyset_info.primary_key_id,
                       parsed_encrypted_keyset.keyset_info.key_info[0].key_id)

    # keyset_info should be ignored when reading a keyset.
    # to test this, we add something invalid and check that read still works.
    parsed_encrypted_keyset.keyset_info.key_info.append(
        tink_pb2.KeysetInfo.KeyInfo(type_url='invalid', key_id=123))
    modified_encrypted_keyset = parsed_encrypted_keyset.SerializeToString()

    decrypted_keyset = testing_servers.keyset_read_encrypted(
        lang, modified_encrypted_keyset, master_aead_keyset, associated_data,
        'KEYSET_READER_BINARY')
    # Both keyset and decrypted_keyset are serialized tink_pb2.Keyset.
    key_util.assert_tink_proto_equal(
        self, tink_pb2.Keyset.FromString(keyset),
        tink_pb2.Keyset.FromString(decrypted_keyset))


if __name__ == '__main__':
  absltest.main()

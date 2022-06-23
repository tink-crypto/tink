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

from typing import Iterable, Tuple, Optional

from absl.testing import absltest
from absl.testing import parameterized
import tink
from tink import aead
from tink.proto import tink_pb2
from util import key_util
from util import testing_servers
from google.protobuf import json_format
from google3.net.proto2.python.public import text_format

# Contains keys with different status and output_prefix_type
SYMMETRIC_KEYSET = r"""
primary_key_id: 2178398476
key {
  key_data {
    type_url: "type.googleapis.com/google.crypto.tink.HmacKey"
    value: "\032 \216\300\2643\375\353)\347?\034q\006\325~\322\377\365\364\202\205\320m\005\327Y\3213\213\217i>\034\022\004\020\020\010\003"
    key_material_type: SYMMETRIC
  }
  status: ENABLED
  key_id: 2178398476
  output_prefix_type: TINK
}
key {
  key_data {
    type_url: "type.googleapis.com/google.crypto.tink.HmacKey"
    value: "\032@\212}\023kK\247.\300\030\377 \351\321\234}rFuJ\367\201\260b)0\271k\001v,\0346D\363mM\255\272\317\007\340M\225d\270[\210\262\362\352\3544&\037\005(\370\320\031\335}\311\374\n\022\004\020 \010\004"
    key_material_type: SYMMETRIC
  }
  status: DISABLED
  key_id: 1021124131
  output_prefix_type: LEGACY
}
key {
  key_data {
    type_url: "type.googleapis.com/google.crypto.tink.HmacKey"
    value: "\032 \312\272\026\243]t\023\024\310\"\2331\361c\r\202\372\363o\260\335\274\2726#\365\034yU\365)\264\022\004\020\020\010\003"
    key_material_type: SYMMETRIC
  }
  status: ENABLED
  key_id: 1531888792
  output_prefix_type: CRUNCHY
}
key {
  key_data {
    type_url: "type.googleapis.com/google.crypto.tink.HmacKey"
    value: "\032 \363q\0337,\254\303\215$\370yR\304`\206uf{V\243\271\367\254\351\034\020\247M\'\240+\320\022\004\020\020\010\003"
    key_material_type: SYMMETRIC
  }
  status: DESTROYED
  key_id: 3173753038
  output_prefix_type: RAW
}
"""

PRIVATE_KEYSET = r"""
primary_key_id: 3858784341
key {
  key_data {
    type_url: "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey"
    value: "\032 \021U\231BC\265\337\020$\351n\336di\245\245\371\004-\215k\214\262\344*\306\224\367\360I\317\330\022L\" e\356\202K\367I{\247T\314o\032\222\000\267\266\024\263u\234H\236<\374\340sDK<;6\242\032 c\264\n\200\340\317\001\351\352\372\305\345\371i\3625\200\305 \367\257\335\256\221\313\313\263\036!\270\305\020\022\006\030\002\020\002\010\003"
    key_material_type: ASYMMETRIC_PRIVATE
  }
  status: ENABLED
  key_id: 3858784341
  output_prefix_type: TINK
}
key {
  key_data {
    type_url: "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey"
    value: "\032 :]\010\201.YK\214\372\302P}\250\354Q\246\322(\216\213\345T\316Lp\013\037#\347\316Sr\022L\" M\014\237i\213\010\252\246\216\342\222\374\026\303\334\010u4\357\323\332\227\250\177\336\216|\217\264\3424\207\032 \013\367.n\035\323\274\337\350\252\233\214)\007\347!\327\313B\223\336jp\251\035\371\247h\014\272\357\317\022\006\030\002\020\002\010\003"
    key_material_type: ASYMMETRIC_PRIVATE
  }
  status: ENABLED
  key_id: 465053161
  output_prefix_type: RAW
}
"""

PUBLIC_KEYSET = r"""
primary_key_id: 768876193
key {
  key_data {
    type_url: "type.googleapis.com/google.crypto.tink.EcdsaPublicKey"
    value: "\" \336\302\324\330=\026.|\\\224\314A\301Ka\241\324{\035\210Tp\222\306\263\317\236\307\032q\010\252\032 }\261\033x\347Gx\224&V\314hx\000\217Q\272G\361b\302\346Fb?r\334\223w\304y\325\022\006\030\002\020\002\010\003"
    key_material_type: ASYMMETRIC_PUBLIC
  }
  status: ENABLED
  key_id: 768876193
  output_prefix_type: TINK
}
"""

TEST_KEYSETS = [
    ('symmetric', SYMMETRIC_KEYSET),
    ('private', PRIVATE_KEYSET),
    ('public', PUBLIC_KEYSET),
]


def setUpModule():
  testing_servers.start('keyset_read_write')


def tearDownModule():
  testing_servers.stop()


def read_write_encrypted_test_cases(
) -> Iterable[Tuple[str, bytes, str, str, str, str, Optional[bytes]]]:
  """Yields (test_name, test_parameters...) tuples to test."""
  for keyset_name, keyset_text_proto in TEST_KEYSETS:
    keyset_proto = text_format.Parse(keyset_text_proto, tink_pb2.Keyset())
    keyset = keyset_proto.SerializeToString()
    for write_lang in testing_servers.LANGUAGES:
      for read_lang in testing_servers.LANGUAGES:
        for associated_data in [None, b'', b'associated_data']:
          yield ('_bin_%s, r in %s, w in %s, ad=%s' %
                 (keyset_name, read_lang, write_lang, associated_data), keyset,
                 read_lang, 'KEYSET_READER_BINARY', write_lang,
                 'KEYSET_WRITER_BINARY', associated_data)
          yield ('_json_%s, r in %s, w in %s, ad=%s' %
                 (keyset_name, write_lang, read_lang, associated_data), keyset,
                 read_lang, 'KEYSET_READER_JSON', write_lang,
                 'KEYSET_WRITER_JSON', associated_data)


class KeysetReadWriteTest(parameterized.TestCase):

  @parameterized.named_parameters(TEST_KEYSETS)
  def test_to_from_json(self, keyset_text_proto):
    keyset_proto = text_format.Parse(keyset_text_proto, tink_pb2.Keyset())
    keyset = keyset_proto.SerializeToString()
    for to_lang in testing_servers.LANGUAGES:
      json_keyset = testing_servers.keyset_to_json(to_lang, keyset)
      for from_lang in testing_servers.LANGUAGES:
        keyset_from_json = testing_servers.keyset_from_json(
            from_lang, json_keyset)
        key_util.assert_tink_proto_equal(
            self,
            tink_pb2.Keyset.FromString(keyset),
            tink_pb2.Keyset.FromString(keyset_from_json),
            msg=('keysets are not equal when converting to JSON in '
                 '%s and back in %s' % (to_lang, from_lang)))

  @parameterized.named_parameters(read_write_encrypted_test_cases())
  def test_read_write_encrypted_keyset(self, keyset, read_lang, reader_type,
                                       write_lang, writer_type,
                                       associated_data):
    # Use an arbitrary AEAD template that's supported in all languages,
    # and use an arbitrary language to generate the keyset_encryption_keyset.
    keyset_encryption_keyset = testing_servers.new_keyset(
        'cc', aead.aead_key_templates.AES128_GCM)

    encrypted_keyset = testing_servers.keyset_write_encrypted(
        write_lang, keyset, keyset_encryption_keyset, associated_data,
        writer_type)
    decrypted_keyset = testing_servers.keyset_read_encrypted(
        read_lang, encrypted_keyset, keyset_encryption_keyset,
        associated_data, reader_type)
    # Both keyset and decrypted_keyset are serialized tink_pb2.Keyset.
    key_util.assert_tink_proto_equal(
        self, tink_pb2.Keyset.FromString(keyset),
        tink_pb2.Keyset.FromString(decrypted_keyset))

    with self.assertRaises(tink.TinkError):
      testing_servers.keyset_read_encrypted(read_lang, encrypted_keyset,
                                            keyset_encryption_keyset,
                                            b'invalid_associated_data',
                                            reader_type)

  @parameterized.parameters(testing_servers.LANGUAGES)
  def test_read_encrypted_ignores_keyset_info_binary(self, lang):
    # Use an arbitrary AEAD template that's supported in all languages,
    # and use an arbitrary language to generate the keyset_encryption_keyset.
    keyset_encryption_keyset = testing_servers.new_keyset(
        'cc', aead.aead_key_templates.AES128_GCM)
    # Also, generate an arbitrary keyset.
    keyset = testing_servers.new_keyset('cc',
                                        aead.aead_key_templates.AES128_GCM)
    associated_data = b'associated_data'

    encrypted_keyset = testing_servers.keyset_write_encrypted(
        lang, keyset, keyset_encryption_keyset, associated_data,
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
        lang, modified_encrypted_keyset, keyset_encryption_keyset,
        associated_data, 'KEYSET_READER_BINARY')
    # Both keyset and decrypted_keyset are serialized tink_pb2.Keyset.
    key_util.assert_tink_proto_equal(
        self, tink_pb2.Keyset.FromString(keyset),
        tink_pb2.Keyset.FromString(decrypted_keyset))

  @parameterized.parameters(testing_servers.LANGUAGES)
  def test_read_encrypted_ignores_keyset_info_json(self, lang):
    # Use an arbitrary AEAD template that's supported in all languages,
    # and use an arbitrary language to generate the keyset_encryption_keyset.
    keyset_encryption_keyset = testing_servers.new_keyset(
        'cc', aead.aead_key_templates.AES128_GCM)
    # Also, generate an arbitrary keyset.
    keyset = testing_servers.new_keyset('cc',
                                        aead.aead_key_templates.AES128_GCM)
    associated_data = b'associated_data'

    encrypted_keyset = testing_servers.keyset_write_encrypted(
        lang, keyset, keyset_encryption_keyset, associated_data,
        'KEYSET_WRITER_JSON')

    # encrypted_keyset is a JSON serialized tink_pb2.EncryptedKeyset
    parsed_encrypted_keyset = json_format.Parse(encrypted_keyset,
                                                tink_pb2.EncryptedKeyset())

    # Note that some implementations (currently C++) do not set keyset_info.
    # But we require that values are correct when they are set.
    if parsed_encrypted_keyset.HasField('keyset_info'):
      self.assertLen(parsed_encrypted_keyset.keyset_info.key_info, 1)
      self.assertEqual(parsed_encrypted_keyset.keyset_info.primary_key_id,
                       parsed_encrypted_keyset.keyset_info.key_info[0].key_id)

    # keyset_info should be ignored when reading a keyset.
    # To test this, we add something invalid and check that read still works.
    # Some languages (C++ and Java) however do check that the fields of
    # keyset_info are present. So we have to set all required fields here.
    parsed_encrypted_keyset.keyset_info.key_info.append(
        tink_pb2.KeysetInfo.KeyInfo(
            type_url='invalid',
            status=tink_pb2.ENABLED,
            key_id=123,
            output_prefix_type=tink_pb2.LEGACY))
    parsed_encrypted_keyset.keyset_info.primary_key_id = 123
    modified_encrypted_keyset = json_format.MessageToJson(
        parsed_encrypted_keyset).encode('utf8')

    decrypted_keyset = testing_servers.keyset_read_encrypted(
        lang, modified_encrypted_keyset, keyset_encryption_keyset,
        associated_data, 'KEYSET_READER_JSON')
    # Both keyset and decrypted_keyset are serialized tink_pb2.Keyset.
    key_util.assert_tink_proto_equal(
        self, tink_pb2.Keyset.FromString(keyset),
        tink_pb2.Keyset.FromString(decrypted_keyset))

if __name__ == '__main__':
  absltest.main()
